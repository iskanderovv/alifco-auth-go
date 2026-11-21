package provider

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/iskanderovv/alifco-auth-go/internal/apperr"
)

const (
	clockTolerance = 30 * time.Second
	jwksTTL        = 10 * time.Minute
	jwksCooldown   = 30 * time.Second
	maxBody        = 1 << 20
)

var oauthErrorCode = regexp.MustCompile(`^[a-z_]{1,40}$`)

type tokenRequest struct {
	client       HTTPClient
	endpoint     string
	form         url.Values
	basicID      string
	basicSecret  string
	providerName string
}

// requestIDToken posts the code exchange. Errors name the failed step only: the
// provider's body can hold secrets or personal data, so it never reaches an error or a log.
func requestIDToken(ctx context.Context, r tokenRequest) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, strings.NewReader(r.form.Encode()))
	if err != nil {
		return "", apperr.Provider(r.providerName + " token request could not be built")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if r.basicID != "" {
		req.SetBasicAuth(r.basicID, r.basicSecret)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return "", apperr.Provider(r.providerName + " token request failed")
	}
	defer closeBody(resp)

	var body struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	_ = json.NewDecoder(limited(resp)).Decode(&body)

	if resp.StatusCode != http.StatusOK {
		detail := ""
		if oauthErrorCode.MatchString(body.Error) {
			detail = " (" + body.Error + ")"
		}
		return "", apperr.Provider(fmt.Sprintf("%s token endpoint returned %d%s", r.providerName, resp.StatusCode, detail))
	}
	if body.IDToken == "" {
		return "", apperr.Provider(r.providerName + " response has no id_token")
	}
	return body.IDToken, nil
}

type idTokenCheck struct {
	raw          string
	keys         *JWKS
	issuers      []string
	audience     string
	providerName string
}

type idClaims struct {
	jwt.RegisteredClaims
	Email         string `json:"email"`
	EmailVerified any    `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	Username      string `json:"preferred_username"`
}

func verifyIDToken(ctx context.Context, c idTokenCheck) (*idClaims, error) {
	claims := &idClaims{}
	_, err := jwt.ParseWithClaims(c.raw, claims,
		func(t *jwt.Token) (any, error) {
			kid, _ := t.Header["kid"].(string)
			return c.keys.Key(ctx, kid)
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithAudience(audienceOrNever(c.audience)),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(clockTolerance),
	)
	if err != nil {
		var appErr *apperr.Error
		if errors.As(err, &appErr) {
			return nil, appErr
		}
		return nil, apperr.Provider(fmt.Sprintf("%s id_token failed verification (%s)", c.providerName, reason(err)))
	}
	issuer, err := claims.GetIssuer()
	if err != nil || !contains(c.issuers, issuer) {
		return nil, apperr.Provider(c.providerName + " id_token failed verification (issuer)")
	}
	if claims.Subject == "" {
		return nil, apperr.Provider(c.providerName + " id_token has no subject")
	}
	return claims, nil
}

func audienceOrNever(audience string) string {
	if audience == "" {
		return "\x00never-matches"
	}
	return audience
}

func reason(err error) string {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return "expired"
	case errors.Is(err, jwt.ErrTokenInvalidAudience):
		return "audience"
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return "signature"
	case errors.Is(err, jwt.ErrTokenUnverifiable):
		return "unknown key or algorithm"
	default:
		return "malformed or invalid"
	}
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// JWKS is a cached set of a provider's RSA signing keys, fetched over HTTP.
// The standard library client decompresses gzip itself, which matters because
// Telegram answers the key request with gzip even when none is asked for.
type JWKS struct {
	url    string
	client HTTPClient
	now    func() time.Time

	mu       sync.Mutex
	keys     map[string]*rsa.PublicKey
	loadedAt time.Time
}

func NewJWKS(url string, client HTTPClient) *JWKS {
	return &JWKS{url: url, client: client, now: time.Now}
}

func (j *JWKS) Key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.keys == nil || j.now().Sub(j.loadedAt) > jwksTTL {
		if err := j.load(ctx); err != nil {
			return nil, err
		}
	}
	if key, ok := j.keys[kid]; ok {
		return key, nil
	}
	// A new key may have been published: look again, but not on every bad token.
	if j.now().Sub(j.loadedAt) > jwksCooldown {
		if err := j.load(ctx); err != nil {
			return nil, err
		}
		if key, ok := j.keys[kid]; ok {
			return key, nil
		}
	}
	return nil, errors.New("no key with that id")
}

func (j *JWKS) load(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.url, nil)
	if err != nil {
		return apperr.Provider("Signing keys request could not be built")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := j.client.Do(req)
	if err != nil {
		return apperr.Provider("Signing keys request failed")
	}
	defer closeBody(resp)
	if resp.StatusCode != http.StatusOK {
		return apperr.Provider(fmt.Sprintf("Signing keys request returned %d", resp.StatusCode))
	}

	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(limited(resp)).Decode(&doc); err != nil || doc.Keys == nil {
		return apperr.Provider("Signing keys response is malformed")
	}

	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		n, errN := base64.RawURLEncoding.DecodeString(k.N)
		e, errE := base64.RawURLEncoding.DecodeString(k.E)
		if errN != nil || errE != nil || len(n) == 0 || len(e) == 0 {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	j.keys, j.loadedAt = keys, j.now()
	return nil
}
