package provider

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/iskanderovv/alifco-auth-go/internal/apperr"
)

type signer struct {
	key *rsa.PrivateKey
	kid string
}

func newSigner(t *testing.T, kid string) signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return signer{key: key, kid: kid}
}

func (s signer) jwk() map[string]string {
	return map[string]string{
		"kty": "RSA", "kid": s.kid, "alg": "RS256", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(s.key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(s.key.E)).Bytes()),
	}
}

func (s signer) sign(t *testing.T, method jwt.SigningMethod, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = s.kid
	var key any = s.key
	if method == jwt.SigningMethodHS256 {
		key = []byte("any-shared-secret-any-shared-secret")
	}
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func claims(issuer, audience string, extra jwt.MapClaims) jwt.MapClaims {
	c := jwt.MapClaims{
		"iss": issuer, "aud": audience, "sub": "subject-1",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	}
	for k, v := range extra {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

func jwksServer(t *testing.T, signers ...signer) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		keys := make([]map[string]string, 0, len(signers))
		for _, s := range signers {
			keys = append(keys, s.jwk())
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func tokenServer(t *testing.T, idToken string, check func(*http.Request)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if check != nil {
			check(r)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": idToken})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func wantProviderError(t *testing.T, err error, contains string) {
	t.Helper()
	appErr, ok := apperr.As(err)
	if !ok || appErr.Code != apperr.CodeProviderError {
		t.Fatalf("want provider_error, got %v", err)
	}
	if contains != "" && !strings.Contains(appErr.Message, contains) {
		t.Fatalf("message %q does not contain %q", appErr.Message, contains)
	}
}

func TestGoogle(t *testing.T) {
	ctx := context.Background()
	good := newSigner(t, "k1")
	jwks, _ := jwksServer(t, good)
	const clientID = "client-id"
	const issuer = "https://accounts.google.com"

	build := func(idToken string, check func(*http.Request)) Provider {
		tokens := tokenServer(t, idToken, check)
		return NewGoogle(GoogleOptions{
			ClientID: clientID, ClientSecret: "secret", RedirectURI: "https://app/auth/google/callback",
			Client: http.DefaultClient, TokenURL: tokens.URL, Keys: NewJWKS(jwks.URL, http.DefaultClient),
		})
	}

	t.Run("authorization url has PKCE and state", func(t *testing.T) {
		u, _ := url.Parse(build("x", nil).AuthorizationURL("st", "ch"))
		q := u.Query()
		if q.Get("code_challenge") != "ch" || q.Get("code_challenge_method") != "S256" || q.Get("state") != "st" ||
			q.Get("response_type") != "code" || q.Get("redirect_uri") != "https://app/auth/google/callback" {
			t.Fatalf("query = %v", q)
		}
	})

	t.Run("a valid token gives a profile, and the token request carries the verifier", func(t *testing.T) {
		idToken := good.sign(t, jwt.SigningMethodRS256, claims(issuer, clientID, jwt.MapClaims{
			"email": "ali@example.com", "email_verified": "true", "name": "Ali", "picture": "https://img/a.png",
		}))
		p := build(idToken, func(r *http.Request) {
			_ = r.ParseForm()
			if r.Form.Get("code_verifier") != "ver" || r.Form.Get("code") != "the-code" || r.Form.Get("grant_type") != "authorization_code" {
				t.Errorf("token request form = %v", r.Form)
			}
		})
		profile, err := p.Authenticate(ctx, "the-code", "ver")
		if err != nil {
			t.Fatal(err)
		}
		if profile.ProviderUserID != "subject-1" || profile.Email != "ali@example.com" || !profile.EmailVerified || profile.Name != "Ali" {
			t.Fatalf("profile = %+v", profile)
		}
	})

	t.Run("the other issuer spelling is accepted", func(t *testing.T) {
		idToken := good.sign(t, jwt.SigningMethodRS256, claims("accounts.google.com", clientID, nil))
		if _, err := build(idToken, nil).Authenticate(ctx, "c", "v"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("an unverified email is reported as unverified", func(t *testing.T) {
		idToken := good.sign(t, jwt.SigningMethodRS256, claims(issuer, clientID, jwt.MapClaims{"email": "a@b.c", "email_verified": false}))
		profile, err := build(idToken, nil).Authenticate(ctx, "c", "v")
		if err != nil || profile.EmailVerified {
			t.Fatalf("profile = %+v, err = %v", profile, err)
		}
	})

	other := newSigner(t, "k1")
	rejected := map[string]string{
		"wrong audience": good.sign(t, jwt.SigningMethodRS256, claims(issuer, "someone-else", nil)),
		"wrong issuer":   good.sign(t, jwt.SigningMethodRS256, claims("https://evil.example", clientID, nil)),
		"expired":        good.sign(t, jwt.SigningMethodRS256, claims(issuer, clientID, jwt.MapClaims{"exp": time.Now().Add(-time.Hour).Unix()})),
		"no subject":     good.sign(t, jwt.SigningMethodRS256, claims(issuer, clientID, jwt.MapClaims{"sub": ""})),
		"signed by another key with the same kid": other.sign(t, jwt.SigningMethodRS256, claims(issuer, clientID, nil)),
		"unknown kid":   newSigner(t, "unknown").sign(t, jwt.SigningMethodRS256, claims(issuer, clientID, nil)),
		"hs256 forgery": good.sign(t, jwt.SigningMethodHS256, claims(issuer, clientID, nil)),
		"alg none": func() string {
			raw, _ := jwt.NewWithClaims(jwt.SigningMethodNone, claims(issuer, clientID, nil)).SignedString(jwt.UnsafeAllowNoneSignatureType)
			return raw
		}(),
	}
	for name, idToken := range rejected {
		t.Run("rejects "+name, func(t *testing.T) {
			_, err := build(idToken, nil).Authenticate(ctx, "c", "v")
			wantProviderError(t, err, "")
		})
	}

	t.Run("a token endpoint failure does not echo the response body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"SECRET-DETAIL"}`))
		}))
		defer srv.Close()
		p := NewGoogle(GoogleOptions{ClientID: clientID, ClientSecret: "s", Client: http.DefaultClient, TokenURL: srv.URL,
			Keys: NewJWKS(jwks.URL, http.DefaultClient)})
		_, err := p.Authenticate(ctx, "c", "v")
		wantProviderError(t, err, "invalid_grant")
		if strings.Contains(err.Error(), "SECRET-DETAIL") {
			t.Fatal("the provider's error_description leaked into the error")
		}
	})

	t.Run("a network failure is a provider error", func(t *testing.T) {
		p := NewGoogle(GoogleOptions{ClientID: clientID, Client: http.DefaultClient, TokenURL: "http://127.0.0.1:1",
			Keys: NewJWKS(jwks.URL, http.DefaultClient)})
		_, err := p.Authenticate(ctx, "c", "v")
		wantProviderError(t, err, "token request failed")
	})
}

func TestTelegram(t *testing.T) {
	ctx := context.Background()
	good := newSigner(t, "tg1")
	jwks, _ := jwksServer(t, good)
	const clientID = "123456"
	const issuer = "https://oauth.telegram.org"

	build := func(idToken string, check func(*http.Request)) Provider {
		tokens := tokenServer(t, idToken, check)
		return NewTelegram(TelegramOptions{
			ClientID: clientID, ClientSecret: "tg-secret", RedirectURI: "https://app/auth/telegram/callback",
			Client: http.DefaultClient, TokenURL: tokens.URL, Keys: NewJWKS(jwks.URL, http.DefaultClient),
		})
	}

	t.Run("uses HTTP Basic client authentication and never sends the secret in the body", func(t *testing.T) {
		idToken := good.sign(t, jwt.SigningMethodRS256, claims(issuer, clientID, jwt.MapClaims{
			"name": "Ali", "preferred_username": "ali", "picture": "https://t.me/i/a.jpg",
		}))
		p := build(idToken, func(r *http.Request) {
			user, pass, ok := r.BasicAuth()
			if !ok || user != clientID || pass != "tg-secret" {
				t.Errorf("basic auth = %q %q %v", user, pass, ok)
			}
			_ = r.ParseForm()
			if r.Form.Get("client_secret") != "" {
				t.Error("the secret must not be in the body")
			}
		})
		profile, err := p.Authenticate(ctx, "c", "v")
		if err != nil {
			t.Fatal(err)
		}
		if profile.Email != "" || profile.EmailVerified {
			t.Fatal("telegram has no email")
		}
		if profile.Name != "Ali" || profile.Username != "ali" || profile.AvatarURL == "" {
			t.Fatalf("profile = %+v", profile)
		}
	})

	t.Run("rejects another audience, issuer and algorithm", func(t *testing.T) {
		for name, idToken := range map[string]string{
			"audience":  good.sign(t, jwt.SigningMethodRS256, claims(issuer, "other", nil)),
			"issuer":    good.sign(t, jwt.SigningMethodRS256, claims("https://evil", clientID, nil)),
			"algorithm": good.sign(t, jwt.SigningMethodHS256, claims(issuer, clientID, nil)),
		} {
			if _, err := build(idToken, nil).Authenticate(ctx, "c", "v"); err == nil {
				t.Errorf("%s was accepted", name)
			}
		}
	})
}

func TestFacebook(t *testing.T) {
	ctx := context.Background()
	var seenProof, seenToken string

	graph := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth/access_token"):
			_ = r.ParseForm()
			if r.URL.RawQuery != "" {
				t.Error("the secret and code must not be in the URL")
			}
			if r.Form.Get("client_secret") != "app-secret" || r.Form.Get("code_verifier") != "ver" {
				t.Errorf("exchange form = %v", r.Form)
			}
			_, _ = w.Write([]byte(`{"access_token":"user-token"}`))
		case strings.HasSuffix(r.URL.Path, "/me"):
			seenToken = r.URL.Query().Get("access_token")
			seenProof = r.URL.Query().Get("appsecret_proof")
			_, _ = w.Write([]byte(`{"id":"fb-1","name":"Ali","email":"ali@example.com","picture":{"data":{"url":"https://img/f.png"}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer graph.Close()

	p := NewFacebook(FacebookOptions{AppID: "app", AppSecret: "app-secret", GraphVersion: "v25.0",
		RedirectURI: "https://app/auth/facebook/callback", Client: http.DefaultClient, GraphBase: graph.URL})

	t.Run("authorization url", func(t *testing.T) {
		u, _ := url.Parse(p.AuthorizationURL("st", "ch"))
		if !strings.Contains(u.Path, "/v25.0/dialog/oauth") || u.Query().Get("code_challenge_method") != "S256" {
			t.Fatalf("url = %s", u)
		}
	})

	t.Run("profile, appsecret_proof, and the email is never trusted", func(t *testing.T) {
		profile, err := p.Authenticate(ctx, "code", "ver")
		if err != nil {
			t.Fatal(err)
		}
		if profile.ProviderUserID != "fb-1" || profile.Email != "ali@example.com" || profile.EmailVerified {
			t.Fatalf("profile = %+v", profile)
		}
		if seenToken != "user-token" || len(seenProof) != 64 {
			t.Fatalf("token=%q proof=%q", seenToken, seenProof)
		}
	})

	t.Run("a failing endpoint is a provider error without the body", func(t *testing.T) {
		bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("SECRET-DETAIL"))
		}))
		defer bad.Close()
		q := NewFacebook(FacebookOptions{AppID: "a", AppSecret: "s", GraphVersion: "v25.0", Client: http.DefaultClient, GraphBase: bad.URL})
		_, err := q.Authenticate(ctx, "c", "v")
		wantProviderError(t, err, "token request returned 400")
		if strings.Contains(err.Error(), "SECRET-DETAIL") {
			t.Fatal("the body leaked")
		}
	})
}

func TestJWKS(t *testing.T) {
	ctx := context.Background()
	first := newSigner(t, "a")

	t.Run("reads a gzip answer, which Telegram sends even when none is asked for", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Type", "application/json")
			zw := gzip.NewWriter(w)
			_ = json.NewEncoder(zw).Encode(map[string]any{"keys": []map[string]string{first.jwk()}})
			_ = zw.Close()
		}))
		defer srv.Close()
		if _, err := NewJWKS(srv.URL, http.DefaultClient).Key(ctx, "a"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("caches keys", func(t *testing.T) {
		srv, hits := jwksServer(t, first)
		set := NewJWKS(srv.URL, http.DefaultClient)
		for range 5 {
			if _, err := set.Key(ctx, "a"); err != nil {
				t.Fatal(err)
			}
		}
		if hits.Load() != 1 {
			t.Fatalf("fetches = %d, want 1", hits.Load())
		}
	})

	t.Run("an unknown key id does not refetch inside the cooldown", func(t *testing.T) {
		srv, hits := jwksServer(t, first)
		set := NewJWKS(srv.URL, http.DefaultClient)
		_, _ = set.Key(ctx, "a")
		for range 5 {
			if _, err := set.Key(ctx, "missing"); err == nil {
				t.Fatal("an unknown key id must fail")
			}
		}
		if hits.Load() != 1 {
			t.Fatalf("fetches = %d, want 1", hits.Load())
		}
	})

	t.Run("picks up a newly published key after the cooldown", func(t *testing.T) {
		second := newSigner(t, "b")
		var published atomic.Bool
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			keys := []map[string]string{first.jwk()}
			if published.Load() {
				keys = append(keys, second.jwk())
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
		}))
		defer srv.Close()

		clock := time.Now()
		set := NewJWKS(srv.URL, http.DefaultClient)
		set.now = func() time.Time { return clock }
		if _, err := set.Key(ctx, "a"); err != nil {
			t.Fatal(err)
		}
		published.Store(true)
		clock = clock.Add(time.Minute)
		if _, err := set.Key(ctx, "b"); err != nil {
			t.Fatalf("the new key was not picked up: %v", err)
		}
	})

	t.Run("a malformed or failing response is a provider error", func(t *testing.T) {
		for name, handler := range map[string]http.HandlerFunc{
			"malformed": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) },
			"500":       func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) },
		} {
			srv := httptest.NewServer(handler)
			_, err := NewJWKS(srv.URL, http.DefaultClient).Key(ctx, "a")
			srv.Close()
			if appErr, ok := apperr.As(err); !ok || appErr.Code != apperr.CodeProviderError {
				t.Errorf("%s: got %v", name, err)
			}
		}
	})
}

func TestRegistry(t *testing.T) {
	r := NewRegistryOf(NewGoogle(GoogleOptions{ClientID: "x", Client: http.DefaultClient}))
	if p, err := r.Get("GOOGLE"); err != nil || p.Name() != "google" {
		t.Fatalf("Get = %v, %v", p, err)
	}
	_, err := r.Get("facebook")
	if appErr, ok := apperr.As(err); !ok || appErr.Code != apperr.CodeProviderNotFound {
		t.Fatalf("an unconfigured provider must be provider_not_found, got %v", err)
	}
	if !Known("telegram") || Known("github") {
		t.Fatal("Known is wrong")
	}
}
