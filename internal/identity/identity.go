package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/iskanderovv/alifco-auth-go/internal/apperr"
	"github.com/iskanderovv/alifco-auth-go/internal/provider"
	"github.com/iskanderovv/alifco-auth-go/internal/store"
)

type Service struct {
	store *store.Store
}

func NewService(s *store.Store) *Service { return &Service{store: s} }

func (s *Service) Login(ctx context.Context, providerName string, p provider.Profile) (store.User, bool, error) {
	if user, found, err := s.loginExisting(ctx, providerName, p); err != nil || found {
		return user, false, err
	}
	return s.create(ctx, providerName, p)
}

func (s *Service) create(ctx context.Context, providerName string, p provider.Profile) (store.User, bool, error) {
	email := normalizeEmail(p.Email)
	var user store.User
	err := s.store.InTx(ctx, func(tx pgx.Tx) error {
		var verified *string
		if p.EmailVerified {
			verified = nullable(email)
		}
		var err error
		user, err = scanCreatedUser(tx.QueryRow(ctx, `
			INSERT INTO users (email, name, avatar_url) VALUES ($1, $2, $3)
			RETURNING id::text, email, name, avatar_url, created_at`,
			verified, displayName(p), nullable(safeAvatarURL(p.AvatarURL))))
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO oauth_identities (user_id, provider, provider_user_id, email, last_login_at)
			VALUES ($1, $2::oauth_provider, $3, $4, now())`,
			user.ID, providerName, p.ProviderUserID, nullable(email))
		return err
	})
	if err == nil {
		return user, true, nil
	}
	// Another request created it first. The unique index decides, so log in its user.
	// The transaction rolled back, so no half-made user is left behind.
	if store.IsUniqueViolation(err) {
		if winner, found, lookupErr := s.loginExisting(ctx, providerName, p); lookupErr == nil && found {
			return winner, false, nil
		}
	}
	return store.User{}, false, fmt.Errorf("create user: %w", err)
}

func (s *Service) Link(ctx context.Context, userID, providerName string, p provider.Profile) error {
	if _, err := s.store.UserByID(ctx, userID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return apperr.New(apperr.CodeInvalidState, 400)
		}
		return err
	}

	_, err := s.store.Pool.Exec(ctx, `
		INSERT INTO oauth_identities (user_id, provider, provider_user_id, email, last_login_at)
		VALUES ($1, $2::oauth_provider, $3, $4, now())`,
		userID, providerName, p.ProviderUserID, nullable(normalizeEmail(p.Email)))
	if err == nil {
		return nil
	}
	if !store.IsUniqueViolation(err) {
		return fmt.Errorf("link identity: %w", err)
	}
	var owner string
	lookup := s.store.Pool.QueryRow(ctx, `
		SELECT user_id::text FROM oauth_identities WHERE provider = $1::oauth_provider AND provider_user_id = $2`,
		providerName, p.ProviderUserID).Scan(&owner)
	if lookup == nil && owner != userID {
		return apperr.Conflict(apperr.CodeIdentityTaken)
	}
	return apperr.Conflict(apperr.CodeAlreadyLinked)
}

func (s *Service) Unlink(ctx context.Context, userID, providerName string) error {
	return s.store.InTx(ctx, func(tx pgx.Tx) error {
		// Lock the user row so two concurrent unlinks cannot remove every login method.
		if _, err := tx.Exec(ctx, `SELECT id FROM users WHERE id = $1 FOR UPDATE`, userID); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT provider::text FROM oauth_identities WHERE user_id = $1`, userID)
		if err != nil {
			return err
		}
		providers, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		linked := false
		for _, name := range providers {
			linked = linked || name == providerName
		}
		switch {
		case !linked:
			return apperr.NotFound(apperr.CodeNotLinked)
		case len(providers) <= 1:
			return apperr.Conflict(apperr.CodeLastIdentity)
		}
		_, err = tx.Exec(ctx, `DELETE FROM oauth_identities WHERE user_id = $1 AND provider = $2::oauth_provider`,
			userID, providerName)
		return err
	})
}

func (s *Service) loginExisting(ctx context.Context, providerName string, p provider.Profile) (store.User, bool, error) {
	var user store.User
	err := s.store.Pool.QueryRow(ctx, `
		SELECT u.id::text, u.email, u.name, u.avatar_url, u.created_at, i.id::text
		FROM oauth_identities i JOIN users u ON u.id = i.user_id
		WHERE i.provider = $1::oauth_provider AND i.provider_user_id = $2`,
		providerName, p.ProviderUserID).Scan(&user.ID, &user.Email, &user.Name, &user.AvatarURL, &user.CreatedAt, new(string))
	if errors.Is(err, pgx.ErrNoRows) {
		return store.User{}, false, nil
	}
	if err != nil {
		return store.User{}, false, fmt.Errorf("find identity: %w", err)
	}

	_, err = s.store.Pool.Exec(ctx, `
		UPDATE oauth_identities SET last_login_at = $3, email = COALESCE($4, email)
		WHERE provider = $1::oauth_provider AND provider_user_id = $2`,
		providerName, p.ProviderUserID, time.Now(), nullable(normalizeEmail(p.Email)))
	if err != nil {
		return store.User{}, false, fmt.Errorf("touch identity: %w", err)
	}

	// Provider picture links expire, so the avatar follows the latest login. The name does not.
	if avatar := safeAvatarURL(p.AvatarURL); avatar != "" && (user.AvatarURL == nil || *user.AvatarURL != avatar) {
		if _, err := s.store.Pool.Exec(ctx, `UPDATE users SET avatar_url = $2, updated_at = now() WHERE id = $1`,
			user.ID, avatar); err != nil {
			return store.User{}, false, fmt.Errorf("refresh avatar: %w", err)
		}
		user.AvatarURL = &avatar
	}
	return user, true, nil
}

func scanCreatedUser(row pgx.Row) (store.User, error) {
	var u store.User
	err := row.Scan(&u.ID, &u.Email, &u.Name, &u.AvatarURL, &u.CreatedAt)
	return u, err
}
