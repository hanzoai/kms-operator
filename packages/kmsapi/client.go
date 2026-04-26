// Package kmsapi is the in-tree HTTP client for the canonical luxfi/kms
// surface (~/work/hanzo/kms cmd/kmsd, served at kms.hanzo.ai).
//
// Wire format — authoritative: cmd/kmsd/main.go.
//
//	POST /v1/kms/auth/login
//	  body: {clientId, clientSecret}
//	  resp: {accessToken, expiresIn, tokenType}
//
//	GET  /v1/kms/orgs/{org}/secrets/{path...}/{name}?env={env}
//	  hdr: Authorization: Bearer {token}
//	  resp: {"secret":{"value":"..."}, "version":N}
//
//	POST /v1/kms/orgs/{org}/secrets
//	  body: {path, name, env, value}
//	  resp: {"ok":true,"version":N}
//
//	PATCH /v1/kms/orgs/{org}/secrets/{path...}/{name}
//	  body: {value, version|If-Match, env}
//	  resp: {"ok":true,"version":N}  | 409 on version mismatch
//
//	DELETE /v1/kms/orgs/{org}/secrets/{path...}/{name}?env={env}
//	  resp: {"ok":true} | 404 if absent
//
// There is NO list endpoint. Every read MUST enumerate the exact
// {org, env, path, name} tuple. Push reconcilers carry their own
// managed-keys roster on the CR status — there is no server-side
// discovery mechanism.
//
// Hardening (mirror of ~/work/lux/operator/src/kms_controller.rs
// 7164368, the freshly-ported Rust spec):
//
//   - Bearer token cache. Key is SHA-256(clientId|clientSecret|host).
//     A swapped host or a rotated credential invalidates the entry
//     atomically. 60s refresh skew. Default 1h TTL on a 0/missing
//     expiresIn.
//   - Hijack guard. Tokens are bound to the host that minted them;
//     the cache key includes the host string verbatim.
//   - Control-byte rejection. Inputs (path, env, name) and values
//     are scanned for NUL and C0 control bytes (allowing TAB / LF /
//     CR). PEM blobs and pretty-printed JSON pass; NUL never does.
//   - Resync clamp. (caller-side) — see util.ConvertIntervalToDuration
//     and the new clamp helpers in this package.
//   - Input bounds. host ≤512, slug ≤64, path ≤256, key ≤128 chars,
//     ≤128 keys/CR. Validated before URL construction so a malicious
//     spec cannot synthesise multi-megabyte requests.
//   - Empty-fetch fail-closed. The KMSSecret reconciler refuses to
//     project a Secret when the keys roster came back empty.
//   - Same-namespace credentialsRef. Enforced in util.HandleUniversalAuth.
package kmsapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ErrNotFound is returned by GetSecret/DeleteSecret when the server
// answers 404. Callers can distinguish "absent" from a transport
// failure with errors.Is.
var ErrNotFound = errors.New("kms: secret not found")

// ErrVersionConflict is returned by UpdateSecret when the server
// rejects a PATCH because the supplied version did not match.
var ErrVersionConflict = errors.New("kms: version conflict (replayed or stale update)")

// Bounds — must mirror lux/operator/src/kms_controller.rs.
const (
	MaxHostLen   = 512
	MaxSlugLen   = 64
	MaxPathLen   = 256
	MaxKeyLen    = 128
	MaxKeysPerCR = 128
)

const (
	httpTimeout          = 15 * time.Second
	tokenRefreshSkew     = 60 * time.Second
	defaultTokenTTL      = time.Hour
	maxResponseBodyBytes = 4 * 1024 * 1024 // 4 MiB hard cap on KMS response size
)

// Client is a thread-safe HTTP client targeting the canonical luxfi/kms
// surface. Each Client owns one bearer-token cache, scoped to that Client
// instance. Reuse a Client across reconciles to share the cache; build
// a fresh Client whenever the trust root changes.
type Client struct {
	httpClient *http.Client
	userAgent  string

	mu    sync.Mutex
	cache map[string]cachedToken
}

type cachedToken struct {
	token     string
	expiresAt time.Time
}

// Config configures a Client. Zero-values are safe.
type Config struct {
	// CACertPEM is an optional PEM bundle to trust in addition to the
	// system roots. Empty means use the system roots only.
	CACertPEM string
	// UserAgent is sent on every request. Defaults to "kms-operator".
	UserAgent string
	// HTTPTimeout overrides the default 15s per-request timeout. Zero
	// means use the default. Negative is treated as zero.
	HTTPTimeout time.Duration
}

// New constructs a Client. cfg may be a zero value.
func New(cfg Config) (*Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CACertPEM != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(cfg.CACertPEM)) {
			return nil, errors.New("kmsapi: CA bundle has no parsable certificates")
		}
		tlsCfg.RootCAs = pool
	}

	timeout := cfg.HTTPTimeout
	if timeout <= 0 {
		timeout = httpTimeout
	}

	ua := cfg.UserAgent
	if ua == "" {
		ua = "kms-operator"
	}

	return &Client{
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig:       tlsCfg,
				ForceAttemptHTTP2:     true,
				ResponseHeaderTimeout: timeout,
			},
		},
		userAgent: ua,
		cache:     make(map[string]cachedToken),
	}, nil
}

// LoginResponse is the decoded shape of POST /v1/kms/auth/login.
type LoginResponse struct {
	AccessToken string `json:"accessToken"`
	ExpiresIn   int64  `json:"expiresIn"`
	TokenType   string `json:"tokenType"`
}

// SecretResponse is the decoded shape of GET /v1/kms/orgs/{org}/secrets/{rest...}.
type SecretResponse struct {
	Value   string
	Version int64
}

// Login performs POST /v1/kms/auth/login and returns the bearer token
// without caching. Most callers want LoginCached.
func (c *Client) Login(ctx context.Context, host, clientID, clientSecret string) (LoginResponse, error) {
	host = NormaliseHost(host)
	if host == "" {
		return LoginResponse{}, errors.New("kmsapi: host is required")
	}
	if clientID == "" || clientSecret == "" {
		return LoginResponse{}, errors.New("kmsapi: clientId and clientSecret are required")
	}
	if ContainsUnsafeControl(clientID) || ContainsUnsafeControl(clientSecret) {
		return LoginResponse{}, errors.New("kmsapi: credentials contain control bytes")
	}

	body, err := json.Marshal(struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
	}{clientID, clientSecret})
	if err != nil {
		return LoginResponse{}, fmt.Errorf("kmsapi: encode login body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, host+"/v1/kms/auth/login", bytes.NewReader(body))
	if err != nil {
		return LoginResponse{}, fmt.Errorf("kmsapi: build login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return LoginResponse{}, fmt.Errorf("kmsapi: login request failed: %w", err)
	}
	defer resp.Body.Close()

	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if resp.StatusCode/100 != 2 {
		return LoginResponse{}, fmt.Errorf("kmsapi: login HTTP %d at %s: %s",
			resp.StatusCode, req.URL.Redacted(), truncate(string(rawBody), 256))
	}

	var decoded LoginResponse
	if err := json.Unmarshal(rawBody, &decoded); err != nil {
		return LoginResponse{}, fmt.Errorf("kmsapi: decode login response: %w", err)
	}
	if decoded.AccessToken == "" {
		return LoginResponse{}, errors.New("kmsapi: login returned empty accessToken")
	}
	return decoded, nil
}

// LoginCached returns a bearer token, calling Login only when the
// cache is cold or near expiry. The cache key is bound to host so a
// rogue DNS flip cannot reuse a token minted for a different KMS.
func (c *Client) LoginCached(ctx context.Context, host, clientID, clientSecret string) (string, error) {
	host = NormaliseHost(host)
	key := tokenCacheKey(host, clientID, clientSecret)

	now := time.Now()
	c.mu.Lock()
	if ct, ok := c.cache[key]; ok && ct.expiresAt.After(now.Add(tokenRefreshSkew)) {
		token := ct.token
		c.mu.Unlock()
		return token, nil
	}
	c.mu.Unlock()

	resp, err := c.Login(ctx, host, clientID, clientSecret)
	if err != nil {
		return "", err
	}

	ttl := time.Duration(resp.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = defaultTokenTTL
	}
	c.mu.Lock()
	c.cache[key] = cachedToken{token: resp.AccessToken, expiresAt: now.Add(ttl)}
	c.mu.Unlock()
	return resp.AccessToken, nil
}

// InvalidateToken drops any cached bearer for the given (host, clientID,
// clientSecret) triple. Call this after a 401 response to force a fresh
// login on the next request.
func (c *Client) InvalidateToken(host, clientID, clientSecret string) {
	host = NormaliseHost(host)
	key := tokenCacheKey(host, clientID, clientSecret)
	c.mu.Lock()
	delete(c.cache, key)
	c.mu.Unlock()
}

// GetSecret performs GET /v1/kms/orgs/{org}/secrets/{path...}/{name}?env={env}.
// Returns ErrNotFound on 404. Empty path is legal (root scope).
func (c *Client) GetSecret(ctx context.Context, host, token, org, env, path, name string) (SecretResponse, error) {
	u, err := buildSecretURL(host, org, path, name, env)
	if err != nil {
		return SecretResponse{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return SecretResponse{}, fmt.Errorf("kmsapi: build GET request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return SecretResponse{}, fmt.Errorf("kmsapi: GET %s: %w", req.URL.Redacted(), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return SecretResponse{}, ErrNotFound
	}
	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if resp.StatusCode/100 != 2 {
		return SecretResponse{}, fmt.Errorf("kmsapi: GET HTTP %d at %s: %s",
			resp.StatusCode, req.URL.Redacted(), truncate(string(rawBody), 256))
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rawBody, &raw); err != nil {
		return SecretResponse{}, fmt.Errorf("kmsapi: decode GET response: %w", err)
	}
	val, err := parseSecretValue(raw)
	if err != nil {
		return SecretResponse{}, err
	}
	if ContainsUnsafeControl(val) {
		return SecretResponse{}, errors.New("kmsapi: secret value contains control bytes (NUL or C0)")
	}
	var ver int64
	if vRaw, ok := raw["version"]; ok && len(vRaw) > 0 {
		_ = json.Unmarshal(vRaw, &ver)
	}
	return SecretResponse{Value: val, Version: ver}, nil
}

// CreateSecret performs POST /v1/kms/orgs/{org}/secrets. The server
// is upsert-on-create — repeated POST with the same path/name is
// equivalent to update without CAS. Returns the new version.
func (c *Client) CreateSecret(ctx context.Context, host, token, org, env, path, name, value string) (int64, error) {
	if err := validateScope(org, env, path, name); err != nil {
		return 0, err
	}
	if ContainsUnsafeControl(value) {
		return 0, errors.New("kmsapi: secret value contains control bytes — refusing to ship to KMS")
	}
	body, err := json.Marshal(struct {
		Path  string `json:"path"`
		Name  string `json:"name"`
		Env   string `json:"env"`
		Value string `json:"value"`
	}{Path: path, Name: name, Env: env, Value: value})
	if err != nil {
		return 0, fmt.Errorf("kmsapi: encode CreateSecret body: %w", err)
	}
	u := NormaliseHost(host) + "/v1/kms/orgs/" + url.PathEscape(org) + "/secrets"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("kmsapi: build POST request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("kmsapi: POST %s: %w", req.URL.Redacted(), err)
	}
	defer resp.Body.Close()
	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if resp.StatusCode/100 != 2 {
		return 0, fmt.Errorf("kmsapi: POST HTTP %d at %s: %s",
			resp.StatusCode, req.URL.Redacted(), truncate(string(rawBody), 256))
	}
	var decoded struct {
		Version int64 `json:"version"`
	}
	_ = json.Unmarshal(rawBody, &decoded)
	return decoded.Version, nil
}

// UpdateSecret performs PATCH /v1/kms/orgs/{org}/secrets/{path...}/{name}.
// expectedVersion implements server-side CAS — the server returns
// 409 (mapped to ErrVersionConflict) if the row was rotated since the
// version we observed. expectedVersion < 0 means "no CAS"; the kmsd
// server requires CAS, so callers normally pass the value returned
// by GetSecret.
func (c *Client) UpdateSecret(ctx context.Context, host, token, org, env, path, name, value string, expectedVersion int64) (int64, error) {
	if err := validateScope(org, env, path, name); err != nil {
		return 0, err
	}
	if ContainsUnsafeControl(value) {
		return 0, errors.New("kmsapi: secret value contains control bytes — refusing to ship to KMS")
	}
	u, err := buildSecretURL(host, org, path, name, env)
	if err != nil {
		return 0, err
	}
	bodyMap := map[string]any{"value": value, "env": env}
	if expectedVersion >= 0 {
		bodyMap["version"] = expectedVersion
	}
	body, err := json.Marshal(bodyMap)
	if err != nil {
		return 0, fmt.Errorf("kmsapi: encode UpdateSecret body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, u, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("kmsapi: build PATCH request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if expectedVersion >= 0 {
		req.Header.Set("If-Match", fmt.Sprintf("%d", expectedVersion))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("kmsapi: PATCH %s: %w", req.URL.Redacted(), err)
	}
	defer resp.Body.Close()
	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if resp.StatusCode == http.StatusConflict {
		return 0, ErrVersionConflict
	}
	if resp.StatusCode/100 != 2 {
		return 0, fmt.Errorf("kmsapi: PATCH HTTP %d at %s: %s",
			resp.StatusCode, req.URL.Redacted(), truncate(string(rawBody), 256))
	}
	var decoded struct {
		Version int64 `json:"version"`
	}
	_ = json.Unmarshal(rawBody, &decoded)
	return decoded.Version, nil
}

// DeleteSecret performs DELETE /v1/kms/orgs/{org}/secrets/{path...}/{name}?env={env}.
// Returns ErrNotFound if the server answers 404 (idempotent at the
// caller's discretion).
func (c *Client) DeleteSecret(ctx context.Context, host, token, org, env, path, name string) error {
	u, err := buildSecretURL(host, org, path, name, env)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return fmt.Errorf("kmsapi: build DELETE request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("kmsapi: DELETE %s: %w", req.URL.Redacted(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("kmsapi: DELETE HTTP %d at %s: %s",
			resp.StatusCode, req.URL.Redacted(), truncate(string(rawBody), 256))
	}
	return nil
}

// ── Pure helpers (testable; no IO) ───────────────────────────────────────

// NormaliseHost strips a trailing slash and a trailing /api segment.
// kmsd serves all routes at the root; both
// "https://kms.hanzo.ai/api" and "https://kms.hanzo.ai" point at the
// same effective base.
func NormaliseHost(raw string) string {
	s := strings.TrimRight(strings.TrimSpace(raw), "/")
	if strings.HasSuffix(s, "/api") {
		s = s[:len(s)-4]
	}
	return s
}

// NormaliseScopePath strips leading and trailing slashes from a
// path. The empty path (root) is legal.
func NormaliseScopePath(raw string) string {
	return strings.Trim(strings.TrimSpace(raw), "/")
}

// ContainsUnsafeControl reports whether s contains NUL or any C0
// control byte (other than TAB / LF / CR). NUL is the truncation
// primitive for env-var propagation on POSIX; the other C0 controls
// have no legitimate place in a stored secret value or a URL segment.
// PEM blobs and pretty-printed JSON pass.
func ContainsUnsafeControl(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b == 0x00 || (b < 0x20 && b != 0x09 && b != 0x0A && b != 0x0D) {
			return true
		}
	}
	return false
}

// tokenCacheKey hashes the (clientID, clientSecret, host) triple to a
// hex SHA-256 digest. A rotated credential or swapped host invalidates
// the cache entry without leaking the secret as a key.
func tokenCacheKey(host, clientID, clientSecret string) string {
	h := sha256.New()
	_, _ = h.Write([]byte(clientID))
	_, _ = h.Write([]byte{':'})
	_, _ = h.Write([]byte(clientSecret))
	_, _ = h.Write([]byte{'@'})
	_, _ = h.Write([]byte(host))
	return hex.EncodeToString(h.Sum(nil))
}

// validateScope enforces upper bounds and rejects control bytes on
// every URL-relevant input. Bails on the first violation.
func validateScope(org, env, path, name string) error {
	if org == "" {
		return errors.New("kmsapi: org is required")
	}
	if env == "" {
		return errors.New("kmsapi: env is required")
	}
	if name == "" {
		return errors.New("kmsapi: secret name is required")
	}
	if len(org) > MaxSlugLen {
		return fmt.Errorf("kmsapi: org exceeds %d chars", MaxSlugLen)
	}
	if len(env) > MaxSlugLen {
		return fmt.Errorf("kmsapi: env exceeds %d chars", MaxSlugLen)
	}
	if len(path) > MaxPathLen {
		return fmt.Errorf("kmsapi: path exceeds %d chars", MaxPathLen)
	}
	if len(name) > MaxKeyLen {
		return fmt.Errorf("kmsapi: name exceeds %d chars", MaxKeyLen)
	}
	if ContainsUnsafeControl(org) || ContainsUnsafeControl(env) ||
		ContainsUnsafeControl(path) || ContainsUnsafeControl(name) {
		return errors.New("kmsapi: scope inputs contain control bytes")
	}
	return nil
}

func buildSecretURL(host, org, path, name, env string) (string, error) {
	if err := validateScope(org, env, path, name); err != nil {
		return "", err
	}
	scope := NormaliseScopePath(path)
	rest := escapePath(name)
	if scope != "" {
		rest = escapePath(scope) + "/" + rest
	}
	q := url.Values{"env": {env}}
	return fmt.Sprintf("%s/v1/kms/orgs/%s/secrets/%s?%s",
		NormaliseHost(host), url.PathEscape(org), rest, q.Encode()), nil
}

// escapePath URL-escapes each `/`-separated segment but preserves the
// segment separator. net/url.PathEscape would mangle slashes inside.
func escapePath(p string) string {
	if p == "" {
		return ""
	}
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}

func parseSecretValue(raw map[string]json.RawMessage) (string, error) {
	if secMsg, ok := raw["secret"]; ok {
		var sec map[string]json.RawMessage
		if err := json.Unmarshal(secMsg, &sec); err == nil {
			if v, ok := sec["value"]; ok {
				return decodeJSONString(v)
			}
			if v, ok := sec["secretValue"]; ok {
				return decodeJSONString(v)
			}
		}
	}
	if v, ok := raw["value"]; ok {
		return decodeJSONString(v)
	}
	return "", fmt.Errorf("kmsapi: unrecognised KMS response shape")
}

func decodeJSONString(raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("kmsapi: secret value is not a JSON string: %w", err)
	}
	return s, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && cut < len(s) {
		// Keep us on a UTF-8 boundary.
		if (s[cut] & 0xC0) != 0x80 {
			break
		}
		cut--
	}
	return s[:cut] + "...[truncated]"
}
