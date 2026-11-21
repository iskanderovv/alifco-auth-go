package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/iskanderovv/alifco-auth-go/internal/apperr"
	"github.com/iskanderovv/alifco-auth-go/internal/config"
	"github.com/iskanderovv/alifco-auth-go/internal/identity"
	"github.com/iskanderovv/alifco-auth-go/internal/oauthtx"
	"github.com/iskanderovv/alifco-auth-go/internal/provider"
	"github.com/iskanderovv/alifco-auth-go/internal/store"
	"github.com/iskanderovv/alifco-auth-go/internal/testutil"
	"github.com/iskanderovv/alifco-auth-go/internal/token"
)

const frontend = "http://localhost:5173"

type fakeProvider struct {
	name    string
	profile provider.Profile
	err     error
}

func (f *fakeProvider) Name() string { return f.name }
func (f *fakeProvider) AuthorizationURL(state, challenge string) string {
	return "https://provider.example/auth?" + url.Values{"state": {state}, "code_challenge": {challenge}}.Encode()
}
func (f *fakeProvider) Authenticate(context.Context, string, string) (provider.Profile, error) {
	return f.profile, f.err
}

type app struct {
	t       *testing.T
	handler http.Handler
	google  *fakeProvider
	tg      *fakeProvider
	st      *store.Store
}

func newApp(t *testing.T, mutate func(*config.Config)) *app {
	t.Helper()
	st := testutil.NewStore(t)
	cfg := config.Config{
		APIBaseURL: "http://localhost:3000", FrontendURL: frontend, CookieSameSite: "lax",
		BodyLimit: 10240, JWTSecret: "http-test-secret-http-test-secret-1", JWTIssuer: "iss", JWTAudience: "aud",
	}
	if mutate != nil {
		mutate(&cfg)
	}
	google := &fakeProvider{name: store.Google, profile: provider.Profile{ProviderUserID: "g-1", Name: "Ali", Email: "ali@example.com", EmailVerified: true}}
	tg := &fakeProvider{name: store.Telegram, profile: provider.Profile{ProviderUserID: "t-1", Name: "Ali TG"}}
	handler := New(Deps{
		Config: cfg, Store: st,
		Tokens: token.NewService(st, token.Options{Secret: cfg.JWTSecret, Issuer: "iss", Audience: "aud",
			AccessTTL: 15 * time.Minute, RefreshTTL: time.Hour}),
		Identities: identity.NewService(st), Txs: oauthtx.NewService(st),
		Providers: provider.NewRegistryOf(google, tg),
	}).Handler()
	return &app{t: t, handler: handler, google: google, tg: tg, st: st}
}

type reply struct {
	*httptest.ResponseRecorder
}

func (a *app) do(method, path string, headers map[string]string, cookies ...*http.Cookie) reply {
	a.t.Helper()
	req := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	a.handler.ServeHTTP(rec, req)
	return reply{rec}
}

func (r reply) cookie(name string) *http.Cookie {
	for _, c := range r.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func (r reply) location() string { return r.Header().Get("Location") }

func (r reply) errorCode() string {
	var body struct {
		Error struct{ Code string } `json:"error"`
	}
	_ = json.Unmarshal(r.Body.Bytes(), &body)
	return body.Error.Code
}

func (a *app) begin(path string) (state string, tx *http.Cookie) {
	a.t.Helper()
	res := a.do(http.MethodGet, path, nil)
	if res.Code != http.StatusFound {
		a.t.Fatalf("start = %d %s", res.Code, res.Body.String())
	}
	u, _ := url.Parse(res.location())
	tx = res.cookie(oauthtx.CookieName)
	if tx == nil {
		a.t.Fatal("no oauth_tx cookie")
	}
	return u.Query().Get("state"), tx
}

func (a *app) login() (refresh *http.Cookie) {
	a.t.Helper()
	state, tx := a.begin("/auth/google")
	res := a.do(http.MethodGet, "/auth/google/callback?code=c&state="+url.QueryEscape(state), nil, tx)
	if res.location() != frontend+"/auth/callback" {
		a.t.Fatalf("callback redirected to %s", res.location())
	}
	refresh = res.cookie(RefreshCookie)
	if refresh == nil {
		a.t.Fatal("no refresh cookie")
	}
	return refresh
}

func (a *app) access(refresh *http.Cookie) (string, *http.Cookie) {
	a.t.Helper()
	res := a.do(http.MethodPost, "/auth/refresh", map[string]string{"X-Requested-With": "fetch"}, refresh)
	if res.Code != http.StatusOK {
		a.t.Fatalf("refresh = %d %s", res.Code, res.Body.String())
	}
	var body struct{ AccessToken string }
	_ = json.Unmarshal(res.Body.Bytes(), &body)
	return body.AccessToken, res.cookie(RefreshCookie)
}

func bearer(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

func TestLoginRefreshMeLogout(t *testing.T) {
	a := newApp(t, nil)

	state, tx := a.begin("/auth/google")
	if tx.Value == "" || !tx.HttpOnly || tx.Path != "/auth" || tx.Domain != "" {
		t.Fatalf("oauth_tx cookie = %+v", tx)
	}
	if state == "" {
		t.Fatal("the redirect has no state")
	}

	res := a.do(http.MethodGet, "/auth/google/callback?code=c&state="+url.QueryEscape(state), nil, tx)
	if strings.Contains(res.location(), "token") || strings.Contains(res.location(), "?") {
		t.Fatalf("the redirect must carry nothing, got %s", res.location())
	}
	refresh := res.cookie(RefreshCookie)
	if refresh == nil || !refresh.HttpOnly || refresh.SameSite != http.SameSiteLaxMode || refresh.Path != "/auth" || refresh.Domain != "" {
		t.Fatalf("refresh cookie = %+v", refresh)
	}
	if cleared := res.cookie(oauthtx.CookieName); cleared == nil || cleared.MaxAge >= 0 {
		t.Fatal("the transaction cookie must be cleared")
	}

	accessToken, rotated := a.access(refresh)
	if rotated == nil || rotated.Value == refresh.Value {
		t.Fatal("refresh must set a new cookie")
	}

	me := a.do(http.MethodGet, "/me", bearer(accessToken))
	if me.Code != http.StatusOK {
		t.Fatalf("/me = %d %s", me.Code, me.Body.String())
	}
	var profile struct {
		Name      string
		Email     *string
		Providers []string
	}
	_ = json.Unmarshal(me.Body.Bytes(), &profile)
	if profile.Name != "Ali" || profile.Email == nil || len(profile.Providers) != 1 || profile.Providers[0] != "google" {
		t.Fatalf("profile = %+v", profile)
	}

	out := a.do(http.MethodPost, "/auth/logout", map[string]string{"X-Requested-With": "fetch"}, rotated)
	if out.Code != http.StatusNoContent {
		t.Fatalf("logout = %d", out.Code)
	}
	after := a.do(http.MethodPost, "/auth/refresh", map[string]string{"X-Requested-With": "fetch"}, rotated)
	if after.Code != http.StatusUnauthorized {
		t.Fatalf("refresh after logout = %d", after.Code)
	}
}

func TestRefreshReuseIsDetected(t *testing.T) {
	a := newApp(t, nil)
	first := a.login()
	_, second := a.access(first)

	res := a.do(http.MethodPost, "/auth/refresh", map[string]string{"X-Requested-With": "fetch"}, first)
	if res.Code != http.StatusUnauthorized || res.errorCode() != apperr.CodeRefreshReused {
		t.Fatalf("reuse = %d %s", res.Code, res.errorCode())
	}
	if c := res.cookie(RefreshCookie); c == nil || c.MaxAge >= 0 {
		t.Fatal("the cookie must be cleared on a refresh failure")
	}
	again := a.do(http.MethodPost, "/auth/refresh", map[string]string{"X-Requested-With": "fetch"}, second)
	if again.Code != http.StatusUnauthorized {
		t.Fatal("the whole family must be revoked")
	}
}

func TestCSRFProtection(t *testing.T) {
	a := newApp(t, nil)
	refresh := a.login()

	cases := map[string]struct {
		headers map[string]string
		code    string
	}{
		"no custom header": {nil, apperr.CodeCSRFHeaderMissing},
		"wrong header":     {map[string]string{"X-Requested-With": "xhr"}, apperr.CodeCSRFHeaderMissing},
		"other origin":     {map[string]string{"X-Requested-With": "fetch", "Origin": "https://evil.example"}, apperr.CodeCSRFOriginInvalid},
	}
	for name, tc := range cases {
		for _, path := range []string{"/auth/refresh", "/auth/logout"} {
			t.Run(name+" "+path, func(t *testing.T) {
				res := a.do(http.MethodPost, path, tc.headers, refresh)
				if res.Code != http.StatusForbidden || res.errorCode() != tc.code {
					t.Fatalf("= %d %s", res.Code, res.errorCode())
				}
			})
		}
	}

	t.Run("a missing cookie", func(t *testing.T) {
		res := a.do(http.MethodPost, "/auth/refresh", map[string]string{"X-Requested-With": "fetch"})
		if res.Code != http.StatusUnauthorized || res.errorCode() != apperr.CodeRefreshMissing {
			t.Fatalf("= %d %s", res.Code, res.errorCode())
		}
	})
}

func TestCORS(t *testing.T) {
	a := newApp(t, nil)
	allowed := a.do(http.MethodOptions, "/auth/refresh", map[string]string{"Origin": frontend})
	if allowed.Header().Get("Access-Control-Allow-Origin") != frontend || allowed.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("headers = %v", allowed.Header())
	}
	other := a.do(http.MethodOptions, "/auth/refresh", map[string]string{"Origin": "https://evil.example"})
	if other.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("another origin must not be allowed")
	}
}

func TestCallbackAlwaysRedirectsWithASafeCode(t *testing.T) {
	a := newApp(t, nil)

	t.Run("the user denied access", func(t *testing.T) {
		res := a.do(http.MethodGet, "/auth/google/callback?error=access_denied&error_description=SECRET", nil)
		if res.location() != frontend+"/auth/callback?error=access_denied" {
			t.Fatalf("location = %s", res.location())
		}
	})
	t.Run("any other provider error", func(t *testing.T) {
		res := a.do(http.MethodGet, "/auth/google/callback?error=server_error&error_description=SECRET", nil)
		if res.location() != frontend+"/auth/callback?error=provider_error" {
			t.Fatalf("location = %s", res.location())
		}
	})
	t.Run("forged state and a missing cookie", func(t *testing.T) {
		_, tx := a.begin("/auth/google")
		forged := a.do(http.MethodGet, "/auth/google/callback?code=c&state=forged", nil, tx)
		missing := a.do(http.MethodGet, "/auth/google/callback?code=c&state=x", nil)
		for _, res := range []reply{forged, missing} {
			if res.location() != frontend+"/auth/callback?error=invalid_state" {
				t.Fatalf("location = %s", res.location())
			}
		}
	})
	t.Run("a replayed callback", func(t *testing.T) {
		state, tx := a.begin("/auth/google")
		path := "/auth/google/callback?code=c&state=" + url.QueryEscape(state)
		a.do(http.MethodGet, path, nil, tx)
		replay := a.do(http.MethodGet, path, nil, tx)
		if replay.location() != frontend+"/auth/callback?error=invalid_state" {
			t.Fatalf("location = %s", replay.location())
		}
	})
	t.Run("a provider failure never leaks its message", func(t *testing.T) {
		a.google.err = apperr.Provider("Google token endpoint returned 400 (invalid_grant) SECRET")
		defer func() { a.google.err = nil }()
		state, tx := a.begin("/auth/google")
		res := a.do(http.MethodGet, "/auth/google/callback?code=c&state="+url.QueryEscape(state), nil, tx)
		if res.location() != frontend+"/auth/callback?error=provider_error" {
			t.Fatalf("location = %s", res.location())
		}
		if res.cookie(RefreshCookie) != nil {
			t.Fatal("no session on a failed login")
		}
	})
	t.Run("an unexpected failure is internal_error", func(t *testing.T) {
		a.google.err = context.DeadlineExceeded
		defer func() { a.google.err = nil }()
		state, tx := a.begin("/auth/google")
		res := a.do(http.MethodGet, "/auth/google/callback?code=c&state="+url.QueryEscape(state), nil, tx)
		if res.location() != frontend+"/auth/callback?error=internal_error" {
			t.Fatalf("location = %s", res.location())
		}
	})
}

func TestLinkingFlow(t *testing.T) {
	a := newApp(t, nil)
	accessToken, _ := a.access(a.login())

	t.Run("link needs an access token", func(t *testing.T) {
		res := a.do(http.MethodPost, "/auth/link/telegram", nil)
		if res.Code != http.StatusUnauthorized || res.errorCode() != apperr.CodeTokenMissing {
			t.Fatalf("= %d %s", res.Code, res.errorCode())
		}
	})

	t.Run("link, callback, then two providers", func(t *testing.T) {
		start := a.do(http.MethodPost, "/auth/link/telegram", bearer(accessToken))
		if start.Code != http.StatusOK {
			t.Fatalf("link = %d %s", start.Code, start.Body.String())
		}
		var body struct{ URL string }
		_ = json.Unmarshal(start.Body.Bytes(), &body)
		u, _ := url.Parse(body.URL)

		res := a.do(http.MethodGet, "/auth/telegram/callback?code=c&state="+url.QueryEscape(u.Query().Get("state")), nil, start.cookie(oauthtx.CookieName))
		if res.location() != frontend+"/settings/accounts?linked=telegram" {
			t.Fatalf("location = %s", res.location())
		}
		if res.cookie(RefreshCookie) != nil {
			t.Fatal("linking must not issue a session")
		}
		me := a.do(http.MethodGet, "/me", bearer(accessToken))
		var profile struct{ Providers []string }
		_ = json.Unmarshal(me.Body.Bytes(), &profile)
		if len(profile.Providers) != 2 {
			t.Fatalf("providers = %v", profile.Providers)
		}
	})

	t.Run("linking a provider the user already has", func(t *testing.T) {
		login := a.do(http.MethodPost, "/auth/link/telegram", bearer(accessToken))
		var body struct{ URL string }
		_ = json.Unmarshal(login.Body.Bytes(), &body)
		u, _ := url.Parse(body.URL)
		res := a.do(http.MethodGet, "/auth/telegram/callback?code=c&state="+url.QueryEscape(u.Query().Get("state")), nil, login.cookie(oauthtx.CookieName))
		if res.location() != frontend+"/settings/accounts?error=already_linked" {
			t.Fatalf("location = %s", res.location())
		}
	})

	t.Run("unlink, then the last provider is protected", func(t *testing.T) {
		del := a.do(http.MethodDelete, "/auth/link/telegram", bearer(accessToken))
		if del.Code != http.StatusNoContent {
			t.Fatalf("unlink = %d %s", del.Code, del.Body.String())
		}
		last := a.do(http.MethodDelete, "/auth/link/google", bearer(accessToken))
		if last.Code != http.StatusConflict || last.errorCode() != apperr.CodeLastIdentity {
			t.Fatalf("= %d %s", last.Code, last.errorCode())
		}
		again := a.do(http.MethodDelete, "/auth/link/telegram", bearer(accessToken))
		if again.Code != http.StatusNotFound || again.errorCode() != apperr.CodeNotLinked {
			t.Fatalf("= %d %s", again.Code, again.errorCode())
		}
		unknown := a.do(http.MethodDelete, "/auth/link/github", bearer(accessToken))
		if unknown.errorCode() != apperr.CodeProviderNotFound {
			t.Fatalf("= %d %s", unknown.Code, unknown.errorCode())
		}
	})
}

func TestLinkingAnAccountThatHasItsOwnProfile(t *testing.T) {
	a := newApp(t, nil)
	accessToken, _ := a.access(a.login())

	state, tx := a.begin("/auth/telegram")
	res := a.do(http.MethodGet, "/auth/telegram/callback?code=c&state="+url.QueryEscape(state), nil, tx)
	if res.cookie(RefreshCookie) == nil {
		t.Fatal("the second person could not sign in")
	}

	start := a.do(http.MethodPost, "/auth/link/telegram", bearer(accessToken))
	var body struct{ URL string }
	_ = json.Unmarshal(start.Body.Bytes(), &body)
	u, _ := url.Parse(body.URL)
	linked := a.do(http.MethodGet, "/auth/telegram/callback?code=c&state="+url.QueryEscape(u.Query().Get("state")), nil, start.cookie(oauthtx.CookieName))
	if linked.location() != frontend+"/settings/accounts?error=identity_taken" {
		t.Fatalf("location = %s", linked.location())
	}
}

func TestProtectedEndpoints(t *testing.T) {
	a := newApp(t, nil)
	for name, headers := range map[string]map[string]string{
		"missing":      nil,
		"not a bearer": {"Authorization": "Basic abc"},
		"garbage":      bearer("not.a.jwt"),
		"empty bearer": {"Authorization": "Bearer "},
	} {
		res := a.do(http.MethodGet, "/me", headers)
		if res.Code != http.StatusUnauthorized {
			t.Errorf("%s: = %d", name, res.Code)
		}
	}
}

func TestErrorShapeAndRouting(t *testing.T) {
	a := newApp(t, nil)

	if res := a.do(http.MethodGet, "/nope", nil); res.Code != http.StatusNotFound || res.errorCode() != apperr.CodeNotFound {
		t.Fatalf("unknown route = %d %s", res.Code, res.errorCode())
	}
	if res := a.do(http.MethodGet, "/auth/github", nil); res.Code != http.StatusNotFound || res.errorCode() != apperr.CodeProviderNotFound {
		t.Fatalf("unknown provider = %d %s", res.Code, res.errorCode())
	}
	if res := a.do(http.MethodGet, "/health", nil); res.Code != http.StatusOK || strings.TrimSpace(res.Body.String()) != `{"status":"ok"}` {
		t.Fatalf("health = %d %s", res.Code, res.Body.String())
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", strings.NewReader(strings.Repeat("x", 20000)))
	req.ContentLength = 20000
	rec := httptest.NewRecorder()
	a.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large body = %d", rec.Code)
	}
}

func TestDocsLogin(t *testing.T) {
	a := newApp(t, func(c *config.Config) { c.DocsUser, c.DocsPassword = "alifco", "test-password-1" })

	for _, path := range []string{"/docs", "/docs-json"} {
		if res := a.do(http.MethodGet, path, nil); res.Code != http.StatusUnauthorized || res.Header().Get("WWW-Authenticate") == "" {
			t.Fatalf("%s without login = %d", path, res.Code)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/docs-json", nil)
	req.SetBasicAuth("alifco", "wrong")
	rec := httptest.NewRecorder()
	a.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password = %d", rec.Code)
	}
	req.SetBasicAuth("alifco", "test-password-1")
	rec = httptest.NewRecorder()
	a.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("right login = %d", rec.Code)
	}
	var doc struct{ Paths map[string]any }
	_ = json.Unmarshal(rec.Body.Bytes(), &doc)
	for _, path := range []string{"/health", "/me", "/auth/{provider}", "/auth/{provider}/callback", "/auth/refresh", "/auth/logout", "/auth/link/{provider}"} {
		if _, ok := doc.Paths[path]; !ok {
			t.Errorf("the OpenAPI document is missing %s", path)
		}
	}
	if res := a.do(http.MethodGet, "/health", nil); res.Code != http.StatusOK {
		t.Fatal("the API itself must not need the docs login")
	}
}

func TestRateLimiting(t *testing.T) {
	st := testutil.NewStore(t)
	cfg := config.Config{FrontendURL: frontend, CookieSameSite: "lax", BodyLimit: 10240, JWTSecret: strings.Repeat("s", 32)}
	handler := New(Deps{
		Config: cfg, Store: st,
		Tokens:     token.NewService(st, token.Options{Secret: cfg.JWTSecret, AccessTTL: time.Minute, RefreshTTL: time.Hour}),
		Identities: identity.NewService(st), Txs: oauthtx.NewService(st),
		Providers: provider.NewRegistryOf(&fakeProvider{name: store.Google}), Limits: true,
	}).Handler()

	statuses := map[int]int{}
	for range 25 {
		req := httptest.NewRequest(http.MethodGet, "/auth/google", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		statuses[rec.Code]++
	}
	if statuses[http.StatusFound] != 20 || statuses[http.StatusTooManyRequests] != 5 {
		t.Fatalf("statuses = %v, want 20 redirects then 5 limited", statuses)
	}

	for range 200 {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("health must never be limited, got %d", rec.Code)
		}
	}
}

func TestForwardedClientIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:5555"
	req.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.9")
	if got := clientIP(req); got != "203.0.113.9" {
		t.Fatalf("clientIP = %s, want the entry added by the proxy", got)
	}
	req.Header.Del("X-Forwarded-For")
	if got := clientIP(req); got != "10.0.0.1" {
		t.Fatalf("clientIP = %s", got)
	}
}

func TestAccessLogLeaksNothing(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	defer slog.SetDefault(previous)

	a := newApp(t, nil)
	refresh := a.login()
	access, _ := a.access(refresh)
	a.do(http.MethodGet, "/me", bearer(access))
	a.do(http.MethodGet, "/auth/google/callback?code=SECRET-CODE&state=SECRET-STATE&error_description=SECRET-DESC", nil)

	secrets := []string{access, refresh.Value, "SECRET-CODE", "SECRET-STATE", "SECRET-DESC", "Bearer", "refresh_token", "oauth_tx"}
	for _, secret := range secrets {
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("the log contains %q", secret)
		}
	}
	if !strings.Contains(logs.String(), `"path":"/me"`) {
		t.Fatal("the access log should still record the path")
	}
}

func TestDevSPAServesThePageAndTheLogo(t *testing.T) {
	a := newApp(t, func(c *config.Config) { c.DevSPA = true })

	for _, path := range []string{"/", "/auth/callback", "/settings/accounts"} {
		res := a.do(http.MethodGet, path, nil)
		if res.Code != http.StatusOK || !strings.Contains(res.Header().Get("Content-Type"), "text/html") {
			t.Fatalf("%s = %d %s", path, res.Code, res.Header().Get("Content-Type"))
		}
		if strings.Contains(res.Body.String(), "%API%") {
			t.Fatalf("%s still has the API placeholder", path)
		}
	}

	logo := a.do(http.MethodGet, "/logo.png", nil)
	if logo.Code != http.StatusOK || logo.Header().Get("Content-Type") != "image/png" ||
		!strings.HasPrefix(logo.Body.String(), "\x89PNG") {
		t.Fatalf("logo = %d %s", logo.Code, logo.Header().Get("Content-Type"))
	}
	if res := a.do(http.MethodGet, "/favicon.ico", nil); res.Code != http.StatusNoContent {
		t.Fatalf("favicon = %d", res.Code)
	}

	off := newApp(t, nil)
	if res := off.do(http.MethodGet, "/logo.png", nil); res.Code != http.StatusNotFound {
		t.Fatalf("the logo must not be served without DEV_SPA, got %d", res.Code)
	}
}
