package token

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/iskanderovv/alifco-auth-go/internal/apperr"
	"github.com/iskanderovv/alifco-auth-go/internal/secure"
	"github.com/iskanderovv/alifco-auth-go/internal/testutil"
)

const (
	secret = "unit-test-secret-unit-test-secret!!"
	userID = "3f0c1c9e-6f0d-4c37-8d4e-0d7a9e2b1a11"
)

func options() Options {
	return Options{Secret: secret, Issuer: "iss", Audience: "aud", AccessTTL: 15 * time.Minute, RefreshTTL: time.Hour}
}

func code(t *testing.T, err error) string {
	t.Helper()
	appErr, ok := apperr.As(err)
	if !ok {
		t.Fatalf("expected an app error, got %v", err)
	}
	return appErr.Code
}

func TestAccessTokenRoundTrip(t *testing.T) {
	svc := NewService(nil, options())
	access, err := svc.IssueAccess(userID)
	if err != nil {
		t.Fatal(err)
	}
	if access.ExpiresIn != 900 {
		t.Fatalf("expiresIn = %d, want 900", access.ExpiresIn)
	}
	got, err := svc.VerifyAccess(access.Token)
	if err != nil || got != userID {
		t.Fatalf("VerifyAccess = %q, %v", got, err)
	}
}

func TestVerifyAccessRejects(t *testing.T) {
	svc := NewService(nil, options())
	now := time.Now()
	good := jwt.RegisteredClaims{
		Subject: userID, Issuer: "iss", Audience: jwt.ClaimStrings{"aud"},
		IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
	}
	sign := func(method jwt.SigningMethod, claims jwt.RegisteredClaims, key any) string {
		s, err := jwt.NewWithClaims(method, claims).SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	with := func(edit func(*jwt.RegisteredClaims)) jwt.RegisteredClaims {
		c := good
		edit(&c)
		return c
	}
	none := func() string {
		s, err := jwt.NewWithClaims(jwt.SigningMethodNone, good).SignedString(jwt.UnsafeAllowNoneSignatureType)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	tests := []struct {
		name, token, want string
	}{
		{"alg none", none(), apperr.CodeTokenInvalid},
		{"other algorithm", sign(jwt.SigningMethodHS512, good, []byte(secret)), apperr.CodeTokenInvalid},
		{"other secret", sign(jwt.SigningMethodHS256, good, []byte("another-secret-another-secret-123")), apperr.CodeTokenInvalid},
		{"wrong issuer", sign(jwt.SigningMethodHS256, with(func(c *jwt.RegisteredClaims) { c.Issuer = "x" }), []byte(secret)), apperr.CodeTokenInvalid},
		{"wrong audience", sign(jwt.SigningMethodHS256, with(func(c *jwt.RegisteredClaims) { c.Audience = jwt.ClaimStrings{"x"} }), []byte(secret)), apperr.CodeTokenInvalid},
		{"no expiry", sign(jwt.SigningMethodHS256, with(func(c *jwt.RegisteredClaims) { c.ExpiresAt = nil }), []byte(secret)), apperr.CodeTokenInvalid},
		{"expired", sign(jwt.SigningMethodHS256, with(func(c *jwt.RegisteredClaims) { c.ExpiresAt = jwt.NewNumericDate(now.Add(-time.Minute)) }), []byte(secret)), apperr.CodeTokenExpired},
		{"subject not a uuid", sign(jwt.SigningMethodHS256, with(func(c *jwt.RegisteredClaims) { c.Subject = "1 OR 1=1" }), []byte(secret)), apperr.CodeTokenInvalid},
		{"garbage", "not.a.jwt", apperr.CodeTokenInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.VerifyAccess(tc.token)
			if got := code(t, err); got != tc.want {
				t.Fatalf("code = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestRefreshRotation(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewStore(t)
	svc := NewService(st, options())
	user := testutil.NewUser(t, st, "Ali")

	t.Run("rotates and stores only the hash", func(t *testing.T) {
		first, err := svc.IssueRefresh(ctx, user, RequestMeta{UserAgent: "ua", IP: "203.0.113.7"})
		if err != nil {
			t.Fatal(err)
		}
		var stored int
		_ = st.Pool.QueryRow(ctx, `SELECT count(*) FROM refresh_tokens WHERE token_hash = $1`, first.Token).Scan(&stored)
		if stored != 0 {
			t.Fatal("the raw token is stored")
		}
		got, next, err := svc.Rotate(ctx, first.Token, RequestMeta{})
		if err != nil || got != user {
			t.Fatalf("Rotate = %q, %v", got, err)
		}
		if next.FamilyID != first.FamilyID || next.Token == first.Token {
			t.Fatal("the new token must be new and stay in the same family")
		}
	})

	t.Run("reuse revokes the whole family", func(t *testing.T) {
		first, _ := svc.IssueRefresh(ctx, user, RequestMeta{})
		_, second, err := svc.Rotate(ctx, first.Token, RequestMeta{})
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = svc.Rotate(ctx, first.Token, RequestMeta{})
		if got := code(t, err); got != apperr.CodeRefreshReused {
			t.Fatalf("code = %s", got)
		}
		_, _, err = svc.Rotate(ctx, second.Token, RequestMeta{})
		if got := code(t, err); got != apperr.CodeRefreshReused {
			t.Fatalf("the descendant must be revoked too, got %s", got)
		}
	})

	t.Run("unknown token is invalid", func(t *testing.T) {
		_, _, err := svc.Rotate(ctx, "nope", RequestMeta{})
		if got := code(t, err); got != apperr.CodeRefreshInvalid {
			t.Fatalf("code = %s", got)
		}
	})

	t.Run("expired token is refused", func(t *testing.T) {
		raw, _ := secure.RandomToken(32)
		_, err := st.Pool.Exec(ctx, `INSERT INTO refresh_tokens (user_id, family_id, token_hash, expires_at)
			VALUES ($1, gen_random_uuid(), $2, now() - interval '1 minute')`, user, secure.SHA256Hex(raw))
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = svc.Rotate(ctx, raw, RequestMeta{})
		if got := code(t, err); got != apperr.CodeRefreshExpired {
			t.Fatalf("code = %s", got)
		}
	})

	t.Run("a bad ip is not stored", func(t *testing.T) {
		if _, err := svc.IssueRefresh(ctx, user, RequestMeta{IP: "not-an-ip"}); err != nil {
			t.Fatalf("a malformed address must not break issuing: %v", err)
		}
	})

	t.Run("logout revokes the session", func(t *testing.T) {
		first, _ := svc.IssueRefresh(ctx, user, RequestMeta{})
		if err := svc.Revoke(ctx, first.Token); err != nil {
			t.Fatal(err)
		}
		_, _, err := svc.Rotate(ctx, first.Token, RequestMeta{})
		if got := code(t, err); got != apperr.CodeRefreshReused {
			t.Fatalf("code = %s", got)
		}
		if err := svc.Revoke(ctx, "unknown"); err != nil {
			t.Fatalf("an unknown token is not an error: %v", err)
		}
	})
}

func TestParallelRefreshHasExactlyOneWinner(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewStore(t)
	svc := NewService(st, options())
	user := testutil.NewUser(t, st, "Ali")
	first, err := svc.IssueRefresh(ctx, user, RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}

	const callers = 30
	var wins, reused atomic.Int32
	var ready, done sync.WaitGroup
	start := make(chan struct{})
	ready.Add(callers)
	done.Add(callers)
	for range callers {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			_, _, err := svc.Rotate(ctx, first.Token, RequestMeta{})
			switch {
			case err == nil:
				wins.Add(1)
			case code(t, err) == apperr.CodeRefreshReused:
				reused.Add(1)
			}
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()

	if wins.Load() != 1 {
		t.Fatalf("winners = %d, want exactly 1", wins.Load())
	}
	var active int
	_ = st.Pool.QueryRow(ctx, `SELECT count(*) FROM refresh_tokens WHERE revoked_at IS NULL`).Scan(&active)
	if active > 1 {
		t.Fatalf("%d tokens are still active", active)
	}
}
