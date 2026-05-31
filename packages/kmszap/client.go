// Package kmszap is the ZAP-native counterpart to packages/kmsapi.
//
// It implements the kmsapi.Transport interface over the binary ZAP
// wire protocol exposed by luxfi/kms/pkg/zapserver (opcodes 0x0040..
// 0x0043). Service-to-service KMS reads inside the same cluster can
// then bypass JSON-over-HTTP entirely; the secret travels as
// AEAD-sealed bytes over a single ZAP frame with sub-100µs latency.
//
// Wire layout (one round-trip per operation):
//
//	REQUEST:  opcode(2 LE) || JSON payload
//	RESPONSE: status(1) || JSON payload | base64 value
//
// The underlying luxfi/kms/pkg/zapclient handles the hybrid PQ
// handshake (X25519 + ML-KEM-768), session sealing, mDNS discovery,
// and direct-address dial. This package only adds the kmsapi shape.
//
// Auth model — important divergence from HTTP:
//
//	HTTP transport: clientId+clientSecret -> bearer token via IAM proxy.
//	ZAP transport:  peer NodeID established at handshake, authorised
//	                via the kmsd-side ACL file (KMS_ZAP_ACL).
//
// There is no IAM client_credentials grant over ZAP today. The KMS
// daemon's ZAP server does not accept IAM tokens — it accepts the
// transport peer's NodeID as the principal. Operator deployments
// wanting to use ZAP MUST therefore register their NodeID in the KMS
// ACL with the appropriate role + path prefix. See:
//
//	~/work/lux/kms/pkg/zapserver/auth.go (ACL file format)
//	~/work/hanzo/kms/CLAUDE.md          (KMS_ZAP_ACL env)
//
// The Transport.Login / LoginCached calls on this client return a
// synthetic token of the form "zap:<nodeID>". Subsequent calls on
// this client ignore the token argument and rely on the connection.
package kmszap

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hanzoai/kms-operator/packages/kmsapi"
	"github.com/luxfi/kms/pkg/zapclient"
)

// Client wraps a long-lived *zapclient.Client and exposes the
// kmsapi.Transport interface. It is safe for concurrent use by
// multiple reconciler goroutines. A single Client instance dials one
// KMS peer; build one Client per `(host, nodeID)` pair.
type Client struct {
	mu       sync.Mutex
	dial     dialFunc
	cfg      Config
	conn     *zapclient.Client
	connHost string
}

// Config configures a Client.
type Config struct {
	// NodeID is the identity this client presents to the KMS peer. The
	// peer MUST authorise this NodeID in its ACL (KMS_ZAP_ACL). Empty
	// means generate a random one — only useful when the KMS server
	// runs in open mode (ACL absent).
	NodeID string

	// Port the local ZAP node listens on. 0 means OS-assigned. The
	// listener exists because the underlying luxfi/zap node always
	// listens; the operator does not accept inbound calls.
	Port int

	// DialTimeout caps the time spent on a single Dial. Zero means
	// 10 seconds.
	DialTimeout time.Duration
}

// dialFunc is overridable for tests.
type dialFunc func(ctx context.Context, cfg zapclient.Config) (*zapclient.Client, error)

// New returns a Client ready to be used as a kmsapi.Transport. The
// underlying ZAP node is lazily dialled on first secret call; the
// connection is reused for subsequent calls until the host changes.
func New(cfg Config) *Client {
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	return &Client{
		cfg:  cfg,
		dial: zapclient.DialWithConfig,
	}
}

// dialIfNeeded ensures the long-lived zap connection targets host. If
// host changes (a re-spec'd CR pointing at a different KMS) the
// previous connection is closed and a new one is dialled.
func (c *Client) dialIfNeeded(ctx context.Context, host string) (*zapclient.Client, error) {
	peer, err := parsePeerAddr(host)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil && c.connHost == host {
		return c.conn, nil
	}
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
		c.connHost = ""
	}

	dctx, cancel := context.WithTimeout(ctx, c.cfg.DialTimeout)
	defer cancel()

	zcfg := zapclient.Config{
		NodeID:   c.cfg.NodeID,
		Port:     c.cfg.Port,
		PeerAddr: peer,
	}
	conn, err := c.dial(dctx, zcfg)
	if err != nil {
		return nil, fmt.Errorf("kmszap: dial %s: %w", host, err)
	}
	c.conn = conn
	c.connHost = host
	return conn, nil
}

// Close tears down the long-lived ZAP connection. Safe to call
// multiple times; safe to call before any operation.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
		c.connHost = ""
	}
}

// parsePeerAddr turns a "zap://host:port" or "zap+mdns://..." host
// into the host:port form luxfi/kms/pkg/zapclient expects. An empty
// host means use mDNS discovery (we pass an empty PeerAddr to the
// underlying Dial, which switches to discovery).
func parsePeerAddr(host string) (string, error) {
	h := strings.TrimSpace(host)
	if h == "" {
		return "", errors.New("kmszap: empty host")
	}
	low := strings.ToLower(h)
	if strings.HasPrefix(low, "zap+mdns://") {
		return "", nil
	}
	if strings.HasPrefix(low, "zap://") {
		u, err := url.Parse(h)
		if err != nil {
			return "", fmt.Errorf("kmszap: parse host %q: %w", host, err)
		}
		if u.Host == "" {
			return "", fmt.Errorf("kmszap: host missing in %q", host)
		}
		return u.Host, nil
	}
	return "", fmt.Errorf("kmszap: unsupported scheme in %q (want zap://… or zap+mdns://…)", host)
}

// syntheticToken returns the opaque string returned by Login /
// LoginCached. The reconciler's token cache stores this verbatim;
// downstream GetSecret calls ignore it.
func (c *Client) syntheticToken() string {
	id := c.cfg.NodeID
	if id == "" {
		id = "anonymous"
	}
	return "zap:" + id
}

// ────────────────────────────────────────────────────────────────────────
// kmsapi.Transport implementation
// ────────────────────────────────────────────────────────────────────────

// Login establishes a ZAP connection if not already up and returns a
// synthetic token bound to the local NodeID. The clientID /
// clientSecret arguments are ignored — the peer authorises this
// NodeID via its ACL, not via IAM client_credentials. We keep the
// signature compatible with kmsapi.Transport so reconcilers can swap
// transports without code changes.
func (c *Client) Login(ctx context.Context, host, _, _ string) (kmsapi.LoginResponse, error) {
	if _, err := c.dialIfNeeded(ctx, host); err != nil {
		return kmsapi.LoginResponse{}, err
	}
	return kmsapi.LoginResponse{
		AccessToken: c.syntheticToken(),
		ExpiresIn:   int64(24 * 3600), // arbitrary; ZAP session has no expiry
		TokenType:   "ZAPNodeID",
	}, nil
}

// LoginCached is identical to Login on the ZAP path — the synthetic
// token is constant for the life of this Client, so there's nothing
// to cache. We still dial-if-needed to ensure the connection is hot.
func (c *Client) LoginCached(ctx context.Context, host, clientID, clientSecret string) (string, error) {
	r, err := c.Login(ctx, host, clientID, clientSecret)
	if err != nil {
		return "", err
	}
	return r.AccessToken, nil
}

// InvalidateToken is a no-op on the ZAP path; the synthetic token
// never expires. Implementations supplied via the Transport
// interface must satisfy this method.
func (c *Client) InvalidateToken(_, _, _ string) {}

// GetSecret fetches a secret value. Token is ignored — auth is the
// connection's NodeID. The luxfi/kms/pkg/zapclient.GetAt method
// handles status decoding; ErrNotFound surfaces as zapclient's
// sentinel which we translate to kmsapi.ErrNotFound.
func (c *Client) GetSecret(ctx context.Context, host, _, org, env, path, name string) (kmsapi.SecretResponse, error) {
	conn, err := c.dialIfNeeded(ctx, host)
	if err != nil {
		return kmsapi.SecretResponse{}, err
	}
	if err := validateInputs(org, env, path, name); err != nil {
		return kmsapi.SecretResponse{}, err
	}
	v, err := conn.GetAt(ctx, path, name, env)
	if err != nil {
		if errors.Is(err, zapclient.ErrNotFound) {
			return kmsapi.SecretResponse{}, kmsapi.ErrNotFound
		}
		if errors.Is(err, zapclient.ErrForbidden) {
			return kmsapi.SecretResponse{}, fmt.Errorf("kmszap: forbidden (peer ACL: %w)", err)
		}
		return kmsapi.SecretResponse{}, fmt.Errorf("kmszap: get %s/%s: %w", path, name, err)
	}
	if kmsapi.ContainsUnsafeControl(v) {
		return kmsapi.SecretResponse{}, errors.New("kmszap: secret value contains control bytes")
	}
	// Version is not surfaced over ZAP today (the opcode response is
	// the value only). The HTTP client populates Version from the
	// server response; on ZAP we report 0 — reconcilers that need
	// CAS must use the HTTP transport.
	return kmsapi.SecretResponse{Value: v, Version: 0}, nil
}

// CreateSecret writes a secret via the ZAP OpSecretPut opcode. Admin
// role on the ACL is required by the server. Returns 0 (no version
// surfaced over ZAP).
func (c *Client) CreateSecret(ctx context.Context, host, _, org, env, path, name, value string) (int64, error) {
	conn, err := c.dialIfNeeded(ctx, host)
	if err != nil {
		return 0, err
	}
	if err := validateInputs(org, env, path, name); err != nil {
		return 0, err
	}
	if kmsapi.ContainsUnsafeControl(value) {
		return 0, errors.New("kmszap: value contains control bytes")
	}
	if err := conn.PutAt(ctx, path, name, env, value); err != nil {
		if errors.Is(err, zapclient.ErrForbidden) {
			return 0, fmt.Errorf("kmszap: forbidden (peer ACL: %w)", err)
		}
		return 0, fmt.Errorf("kmszap: put %s/%s: %w", path, name, err)
	}
	return 0, nil
}

// UpdateSecret is the same as CreateSecret on the ZAP path —
// OpSecretPut is upsert. expectedVersion is ignored because the
// opcode does not carry a CAS field. Reconcilers that need version
// CAS must use the HTTP transport.
func (c *Client) UpdateSecret(ctx context.Context, host, token, org, env, path, name, value string, _ int64) (int64, error) {
	return c.CreateSecret(ctx, host, token, org, env, path, name, value)
}

// DeleteSecret removes a secret via OpSecretDelete. Admin role on
// the ACL is required.
func (c *Client) DeleteSecret(ctx context.Context, host, _, org, env, path, name string) error {
	conn, err := c.dialIfNeeded(ctx, host)
	if err != nil {
		return err
	}
	if err := validateInputs(org, env, path, name); err != nil {
		return err
	}
	if err := conn.DeleteAt(ctx, path, name, env); err != nil {
		if errors.Is(err, zapclient.ErrNotFound) {
			return kmsapi.ErrNotFound
		}
		if errors.Is(err, zapclient.ErrForbidden) {
			return fmt.Errorf("kmszap: forbidden (peer ACL: %w)", err)
		}
		return fmt.Errorf("kmszap: delete %s/%s: %w", path, name, err)
	}
	return nil
}

// validateInputs mirrors the HTTP client's bounds checks. The ZAP
// transport doesn't strictly need them because the wire is binary,
// but the server applies the same rules and we'd rather fail fast
// at the client.
func validateInputs(org, env, path, name string) error {
	if org == "" {
		return errors.New("kmszap: org is required")
	}
	if env == "" {
		return errors.New("kmszap: env is required")
	}
	if name == "" {
		return errors.New("kmszap: name is required")
	}
	if len(org) > kmsapi.MaxSlugLen {
		return fmt.Errorf("kmszap: org > %d chars", kmsapi.MaxSlugLen)
	}
	if len(env) > kmsapi.MaxSlugLen {
		return fmt.Errorf("kmszap: env > %d chars", kmsapi.MaxSlugLen)
	}
	if len(path) > kmsapi.MaxPathLen {
		return fmt.Errorf("kmszap: path > %d chars", kmsapi.MaxPathLen)
	}
	if len(name) > kmsapi.MaxKeyLen {
		return fmt.Errorf("kmszap: name > %d chars", kmsapi.MaxKeyLen)
	}
	if kmsapi.ContainsUnsafeControl(org) || kmsapi.ContainsUnsafeControl(env) ||
		kmsapi.ContainsUnsafeControl(path) || kmsapi.ContainsUnsafeControl(name) {
		return errors.New("kmszap: scope contains control bytes")
	}
	return nil
}

// Compile-time check.
var _ kmsapi.Transport = (*Client)(nil)
