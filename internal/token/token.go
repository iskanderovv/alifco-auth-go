package token

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/iskanderovv/alifco-auth-go/internal/apperr"
	"github.com/iskanderovv/alifco-auth-go/internal/secure"
	"github.com/iskanderovv/alifco-auth-go/internal/store"
)

type Options struct {
	Secret     string
	Issuer     string
	Audience   string
	AccessTTL  time.Duration
	RefreshTTL time.Duration
	Now        func() time.Time
}

type Service struct {
	store *store.Store
	opts  Options
}

func NewService(s *store.Store, opts Options) *Service {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Service{store: s, opts: opts}
}

type RequestMeta struct {
	UserAgent string
	IP        string
}

type Refresh struct {
	Token     string
	FamilyID  string
	ExpiresAt time.Time
}

type Access struct {
	Token     string `json:"accessToken"`
	ExpiresIn int    `json:"expiresIn"`
}

func (s *Service) IssueAccess(userID string) (Access, error) {
	now := s.opts.Now()
	claims := jwt.RegisteredClaims{
		Subject:   userID,
		Issuer:    s.opts.Issuer,
		Audience:  jwt.ClaimStrings{s.opts.Audience},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(s.opts.AccessTTL)),
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(s.opts.Secret))
	if err != nil {
		return Access{}, fmt.Errorf("sign access token: %w", err)
	}
	return Access{Token: signed, ExpiresIn: int(s.opts.AccessTTL.Seconds())}, nil
}

func (s *Service) VerifyAccess(raw string) (string, error) {
	claims := &jwt.RegisteredClaims{}
	_, err := jwt.ParseWithClaims(raw, claims,
		func(*jwt.Token) (any, error) { return []byte(s.opts.Secret), nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(s.opts.Issuer),
		jwt.WithAudience(s.opts.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(s.opts.Now),
	)
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return "", apperr.Unauthorized(apperr.CodeTokenExpired)
	case err != nil:
		return "", apperr.Unauthorized(apperr.CodeTokenInvalid)
	case claims.Subject == "" || !secure.IsUUID(claims.Subject):
		return "", apperr.Unauthorized(apperr.CodeTokenInvalid)
	}
	return claims.Subject, nil
}

func (s *Service) IssueRefresh(ctx context.Context, userID string, meta RequestMeta) (Refresh, error) {
	return s.insertRefresh(ctx, s.store.Pool, userID, uuid.NewString(), meta)
}

type rotation int

const (
	rotated rotation = iota
	rotationInvalid
	rotationExpired
	rotationReused
)

func (s *Service) Rotate(ctx context.Context, raw string, meta RequestMeta) (string, Refresh, error) {
	hash := secure.SHA256Hex(raw)
	now := s.opts.Now()

	var (
		outcome rotation
		userID  string
		next    Refresh
	)
	err := s.store.InTx(ctx, func(tx pgx.Tx) error {
		var familyID string
		// One conditional UPDATE: of any number of concurrent callers only one matches.
		err := tx.QueryRow(ctx, `
			UPDATE refresh_tokens SET revoked_at = $2
			WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > $2
			RETURNING user_id::text, family_id::text`, hash, now).Scan(&userID, &familyID)
		if err == nil {
			next, err = s.insertRefresh(ctx, tx, userID, familyID, meta)
			outcome = rotated
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}

		var revoked *time.Time
		err = tx.QueryRow(ctx, `SELECT family_id::text, revoked_at FROM refresh_tokens WHERE token_hash = $1`, hash).
			Scan(&familyID, &revoked)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			outcome = rotationInvalid
			return nil
		case err != nil:
			return err
		case revoked != nil:
			outcome = rotationReused
			_, err = tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = $2 WHERE family_id = $1 AND revoked_at IS NULL`,
				familyID, now)
			return err
		}
		outcome = rotationExpired
		return nil
	})
	if err != nil {
		return "", Refresh{}, fmt.Errorf("rotate refresh token: %w", err)
	}

	switch outcome {
	case rotated:
		return userID, next, nil
	case rotationReused:
		return "", Refresh{}, apperr.Unauthorized(apperr.CodeRefreshReused)
	case rotationExpired:
		return "", Refresh{}, apperr.Unauthorized(apperr.CodeRefreshExpired)
	default:
		return "", Refresh{}, apperr.Unauthorized(apperr.CodeRefreshInvalid)
	}
}

func (s *Service) Revoke(ctx context.Context, raw string) error {
	if raw == "" {
		return nil
	}
	_, err := s.store.Pool.Exec(ctx, `
		UPDATE refresh_tokens SET revoked_at = $2
		WHERE revoked_at IS NULL AND family_id = (SELECT family_id FROM refresh_tokens WHERE token_hash = $1)`,
		secure.SHA256Hex(raw), s.opts.Now())
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

func (s *Service) insertRefresh(ctx context.Context, q store.Querier, userID, familyID string, meta RequestMeta) (Refresh, error) {
	raw, err := secure.RandomToken(32)
	if err != nil {
		return Refresh{}, err
	}
	expires := s.opts.Now().Add(s.opts.RefreshTTL)

	var ip *string
	if addr, err := netip.ParseAddr(meta.IP); err == nil {
		text := addr.String()
		ip = &text
	}
	agent := meta.UserAgent
	if len(agent) > 512 {
		agent = agent[:512]
	}
	_, err = q.Exec(ctx, `
		INSERT INTO refresh_tokens (user_id, family_id, token_hash, expires_at, user_agent, ip)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6::inet)`,
		userID, familyID, secure.SHA256Hex(raw), expires, agent, ip)
	if err != nil {
		return Refresh{}, fmt.Errorf("store refresh token: %w", err)
	}
	return Refresh{Token: raw, FamilyID: familyID, ExpiresAt: expires}, nil
}
