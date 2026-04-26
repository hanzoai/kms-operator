package kmsapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── Pure helpers ─────────────────────────────────────────────────────────

func TestNormaliseHost(t *testing.T) {
	cases := map[string]string{
		"https://kms.hanzo.ai/":     "https://kms.hanzo.ai",
		"https://kms.hanzo.ai/api":  "https://kms.hanzo.ai",
		"https://kms.hanzo.ai/api/": "https://kms.hanzo.ai",
		"https://kms.hanzo.ai":      "https://kms.hanzo.ai",
		"  https://x  ":             "https://x",
	}
	for in, want := range cases {
		if got := NormaliseHost(in); got != want {
			t.Errorf("NormaliseHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormaliseScopePath(t *testing.T) {
	cases := map[string]string{
		"/foo/bar/": "foo/bar",
		"foo/bar":   "foo/bar",
		"/":         "",
		"":          "",
		"  ///  ":   "",
	}
	for in, want := range cases {
		if got := NormaliseScopePath(in); got != want {
			t.Errorf("NormaliseScopePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestContainsUnsafeControl_RejectsNUL(t *testing.T) {
	if !ContainsUnsafeControl("a\x00b") {
		t.Fatal("expected NUL to be rejected")
	}
}

func TestContainsUnsafeControl_RejectsC0(t *testing.T) {
	for _, b := range []byte{0x01, 0x07, 0x08, 0x0B, 0x0C, 0x1B, 0x1F} {
		if !ContainsUnsafeControl("a" + string(rune(b)) + "b") {
			t.Fatalf("expected control byte 0x%02x to be rejected", b)
		}
	}
}

func TestContainsUnsafeControl_AllowsWhitespaceAndPEM(t *testing.T) {
	allowed := []string{
		"plain",
		"a\tb",
		"a\nb",
		"a\rb",
		"a\r\nb",
		"-----BEGIN CERTIFICATE-----\nMIIBIjAN\n-----END CERTIFICATE-----\n",
	}
	for _, s := range allowed {
		if ContainsUnsafeControl(s) {
			t.Fatalf("did not expect %q to be flagged", s)
		}
	}
}

func TestTokenCacheKey_HostBound(t *testing.T) {
	a := tokenCacheKey("https://kms-a", "id", "sec")
	b := tokenCacheKey("https://kms-b", "id", "sec")
	if a == b {
		t.Fatal("cache keys must differ when host differs")
	}
	if len(a) != 64 {
		t.Fatalf("cache key not hex SHA-256: len=%d", len(a))
	}
}

func TestTokenCacheKey_CredentialBound(t *testing.T) {
	a := tokenCacheKey("h", "id1", "sec")
	b := tokenCacheKey("h", "id2", "sec")
	c := tokenCacheKey("h", "id1", "sec2")
	if a == b || a == c {
		t.Fatal("cache keys must differ when credentials differ")
	}
}

func TestValidateScope(t *testing.T) {
	if err := validateScope("hanzo", "dev", "/foo", "k"); err != nil {
		t.Fatalf("expected ok: %v", err)
	}
	if err := validateScope("", "dev", "/foo", "k"); err == nil {
		t.Fatal("expected empty org to fail")
	}
	if err := validateScope("hanzo", "", "/foo", "k"); err == nil {
		t.Fatal("expected empty env to fail")
	}
	if err := validateScope("hanzo", "dev", "/foo", ""); err == nil {
		t.Fatal("expected empty name to fail")
	}
	long := strings.Repeat("x", MaxSlugLen+1)
	if err := validateScope(long, "dev", "/foo", "k"); err == nil {
		t.Fatal("expected oversize org to fail")
	}
	if err := validateScope("hanzo", long, "/foo", "k"); err == nil {
		t.Fatal("expected oversize env to fail")
	}
	if err := validateScope("hanzo", "dev", strings.Repeat("x", MaxPathLen+1), "k"); err == nil {
		t.Fatal("expected oversize path to fail")
	}
	if err := validateScope("hanzo", "dev", "/foo", strings.Repeat("x", MaxKeyLen+1)); err == nil {
		t.Fatal("expected oversize name to fail")
	}
	if err := validateScope("hanzo\x00", "dev", "/foo", "k"); err == nil {
		t.Fatal("expected control-byte org to fail")
	}
}

func TestBuildSecretURL_WithPath(t *testing.T) {
	u, err := buildSecretURL("https://kms", "lux", "staking/keys", "node1.crt", "mainnet")
	if err != nil {
		t.Fatal(err)
	}
	want := "https://kms/v1/kms/orgs/lux/secrets/staking/keys/node1.crt?env=mainnet"
	if u != want {
		t.Fatalf("got %q want %q", u, want)
	}
}

func TestBuildSecretURL_RootPath(t *testing.T) {
	u, err := buildSecretURL("https://kms", "lux", "", "x", "dev")
	if err != nil {
		t.Fatal(err)
	}
	want := "https://kms/v1/kms/orgs/lux/secrets/x?env=dev"
	if u != want {
		t.Fatalf("got %q want %q", u, want)
	}
}

func TestBuildSecretURL_EscapesOrgEnvSegments(t *testing.T) {
	u, err := buildSecretURL("https://kms", "lux infra", "a b/c", "n d", "main net")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(u, "/orgs/lux%20infra/") {
		t.Fatalf("org not escaped: %s", u)
	}
	if !strings.Contains(u, "/a%20b/c/") {
		t.Fatalf("path segments not escaped: %s", u)
	}
	if !strings.Contains(u, "/n%20d?") {
		t.Fatalf("name segment not escaped: %s", u)
	}
	if !strings.Contains(u, "env=main+net") && !strings.Contains(u, "env=main%20net") {
		t.Fatalf("env not URL-encoded: %s", u)
	}
}

func TestParseSecretValue_CanonicalShape(t *testing.T) {
	body := []byte(`{"secret":{"value":"hello"},"version":3}`)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	v, err := parseSecretValue(raw)
	if err != nil {
		t.Fatal(err)
	}
	if v != "hello" {
		t.Fatalf("got %q want hello", v)
	}
}

func TestParseSecretValue_LegacySecretValue(t *testing.T) {
	body := []byte(`{"secret":{"secretKey":"X","secretValue":"y"}}`)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	v, err := parseSecretValue(raw)
	if err != nil {
		t.Fatal(err)
	}
	if v != "y" {
		t.Fatalf("got %q want y", v)
	}
}

func TestParseSecretValue_BareValue(t *testing.T) {
	body := []byte(`{"value":"bare"}`)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	v, err := parseSecretValue(raw)
	if err != nil {
		t.Fatal(err)
	}
	if v != "bare" {
		t.Fatalf("got %q want bare", v)
	}
}

func TestParseSecretValue_RejectsUnknownShape(t *testing.T) {
	body := []byte(`{"unexpected":"shape"}`)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	if _, err := parseSecretValue(raw); err == nil {
		t.Fatal("expected unknown shape to fail")
	}
}

func TestTruncate_RespectsUTF8Boundary(t *testing.T) {
	s := "abc\xf0\x9f\xa6\x80def" // crab + def
	out := truncate(s, 4)         // would land mid-rune
	if !strings.HasPrefix(out, "abc") {
		t.Fatalf("got %q", out)
	}
}

// ── HTTP integration (httptest) ──────────────────────────────────────────

func newClient(t *testing.T) *Client {
	t.Helper()
	c, err := New(Config{UserAgent: "test-agent"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestLogin_TargetsCanonicalPath(t *testing.T) {
	var hit string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = r.Method + " " + r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]any{
			"accessToken": "tok-1",
			"expiresIn":   60,
			"tokenType":   "Bearer",
		})
	}))
	defer srv.Close()

	c := newClient(t)
	resp, err := c.Login(context.Background(), srv.URL, "id", "sec")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if resp.AccessToken != "tok-1" {
		t.Fatalf("token: %q", resp.AccessToken)
	}
	if hit != "POST /v1/kms/auth/login" {
		t.Fatalf("hit canonical path? got %q", hit)
	}
}

func TestLogin_RejectsControlBytesInCredentials(t *testing.T) {
	c := newClient(t)
	_, err := c.Login(context.Background(), "https://kms.x", "id\x00", "sec")
	if err == nil {
		t.Fatal("expected control-byte rejection")
	}
}

func TestLoginCached_SkipsSecondNetworkCall(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"accessToken": "tok-cache",
			"expiresIn":   3600,
			"tokenType":   "Bearer",
		})
	}))
	defer srv.Close()

	c := newClient(t)
	for i := 0; i < 5; i++ {
		tok, err := c.LoginCached(context.Background(), srv.URL, "id", "sec")
		if err != nil {
			t.Fatalf("LoginCached: %v", err)
		}
		if tok != "tok-cache" {
			t.Fatalf("token: %q", tok)
		}
	}
	if calls != 1 {
		t.Fatalf("expected one network call, got %d", calls)
	}
}

func TestLoginCached_NotShared_AcrossHosts(t *testing.T) {
	var aHits, bHits int
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		aHits++
		_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": "tok-a", "expiresIn": 3600})
	}))
	defer srvA.Close()
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bHits++
		_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": "tok-b", "expiresIn": 3600})
	}))
	defer srvB.Close()

	c := newClient(t)
	if _, err := c.LoginCached(context.Background(), srvA.URL, "id", "sec"); err != nil {
		t.Fatal(err)
	}
	tok, err := c.LoginCached(context.Background(), srvB.URL, "id", "sec")
	if err != nil {
		t.Fatal(err)
	}
	if tok != "tok-b" {
		t.Fatalf("got %q, expected tok-b — token must be host-bound", tok)
	}
	if aHits != 1 || bHits != 1 {
		t.Fatalf("expected one hit per host: aHits=%d bHits=%d", aHits, bHits)
	}
}

func TestInvalidateToken_ForcesFreshLogin(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": "tok", "expiresIn": 3600})
	}))
	defer srv.Close()

	c := newClient(t)
	if _, err := c.LoginCached(context.Background(), srv.URL, "id", "sec"); err != nil {
		t.Fatal(err)
	}
	c.InvalidateToken(srv.URL, "id", "sec")
	if _, err := c.LoginCached(context.Background(), srv.URL, "id", "sec"); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("expected re-login after invalidate, calls=%d", calls)
	}
}

func TestGetSecret_TargetsCanonicalPathAndSendsBearer(t *testing.T) {
	var hit, auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = r.Method + " " + r.URL.Path + "?" + r.URL.RawQuery
		auth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"secret":  map[string]any{"value": "hello"},
			"version": 7,
		})
	}))
	defer srv.Close()

	c := newClient(t)
	resp, err := c.GetSecret(context.Background(), srv.URL, "tok-x", "hanzo", "dev", "/staking", "node-key")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if resp.Value != "hello" || resp.Version != 7 {
		t.Fatalf("resp = %+v", resp)
	}
	if hit != "GET /v1/kms/orgs/hanzo/secrets/staking/node-key?env=dev" {
		t.Fatalf("canonical surface? got %q", hit)
	}
	if auth != "Bearer tok-x" {
		t.Fatalf("Authorization header: %q", auth)
	}
}

func TestGetSecret_404IsErrNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := newClient(t)
	_, err := c.GetSecret(context.Background(), srv.URL, "tok", "hanzo", "dev", "", "missing")
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestGetSecret_RejectsControlBytesInResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"secret": map[string]any{"value": "real\x00evil"},
		})
	}))
	defer srv.Close()
	c := newClient(t)
	_, err := c.GetSecret(context.Background(), srv.URL, "tok", "hanzo", "dev", "", "k")
	if err == nil {
		t.Fatal("expected control-byte rejection in response value")
	}
}

func TestCreateSecret_PostsCanonicalBody(t *testing.T) {
	var got map[string]any
	var hit string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = r.Method + " " + r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "version": 1})
	}))
	defer srv.Close()
	c := newClient(t)
	ver, err := c.CreateSecret(context.Background(), srv.URL, "tok", "hanzo", "dev", "/auth", "tok", "v")
	if err != nil {
		t.Fatal(err)
	}
	if ver != 1 {
		t.Fatalf("version=%d", ver)
	}
	if hit != "POST /v1/kms/orgs/hanzo/secrets" {
		t.Fatalf("canonical create path? %s", hit)
	}
	if got["path"] != "/auth" || got["name"] != "tok" || got["env"] != "dev" || got["value"] != "v" {
		t.Fatalf("body = %+v", got)
	}
}

func TestCreateSecret_RejectsControlBytesInValue(t *testing.T) {
	c := newClient(t)
	_, err := c.CreateSecret(context.Background(), "https://nope", "tok", "hanzo", "dev", "/p", "k", "ev\x00il")
	if err == nil {
		t.Fatal("expected control-byte rejection")
	}
}

func TestUpdateSecret_PatchSetsIfMatchOnCAS(t *testing.T) {
	var hit, ifMatch string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = r.Method + " " + r.URL.Path
		ifMatch = r.Header.Get("If-Match")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "version": 2})
	}))
	defer srv.Close()
	c := newClient(t)
	ver, err := c.UpdateSecret(context.Background(), srv.URL, "tok", "hanzo", "dev", "/p", "k", "v2", 1)
	if err != nil {
		t.Fatal(err)
	}
	if ver != 2 {
		t.Fatalf("version=%d", ver)
	}
	if hit != "PATCH /v1/kms/orgs/hanzo/secrets/p/k" {
		t.Fatalf("canonical patch path? %s", hit)
	}
	if ifMatch != "1" {
		t.Fatalf("If-Match: %q", ifMatch)
	}
}

func TestUpdateSecret_409IsErrVersionConflict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	defer srv.Close()
	c := newClient(t)
	_, err := c.UpdateSecret(context.Background(), srv.URL, "tok", "hanzo", "dev", "", "k", "v", 0)
	if err != ErrVersionConflict {
		t.Fatalf("expected ErrVersionConflict, got %v", err)
	}
}

func TestDeleteSecret_TargetsCanonicalPath(t *testing.T) {
	var hit string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = r.Method + " " + r.URL.Path + "?" + r.URL.RawQuery
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer srv.Close()
	c := newClient(t)
	if err := c.DeleteSecret(context.Background(), srv.URL, "tok", "hanzo", "dev", "/p", "k"); err != nil {
		t.Fatal(err)
	}
	if hit != "DELETE /v1/kms/orgs/hanzo/secrets/p/k?env=dev" {
		t.Fatalf("canonical delete path? %s", hit)
	}
}

func TestDeleteSecret_404IsErrNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := newClient(t)
	if err := c.DeleteSecret(context.Background(), srv.URL, "tok", "hanzo", "dev", "", "k"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// Sanity: the client respects the per-request context deadline.
func TestRequest_RespectsContextDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	defer srv.Close()
	c := newClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := c.Login(ctx, srv.URL, "id", "sec")
	if err == nil {
		t.Fatal("expected ctx deadline error")
	}
}
