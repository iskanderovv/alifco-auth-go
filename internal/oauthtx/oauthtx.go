package oauthtx

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/iskanderovv/alifco-auth-go/internal/apperr"
	"github.com/iskanderovv/alifco-auth-go/internal/secure"
	"github.com/iskanderovv/alifco-auth-go/internal/store"
)

const CookieName = "oauth_tx"

const TTL = 10 * time.Minute

type Service struct {
	store *store.Store
	now   func() time.Time
}

func NewService(s *store.Store) *Service { return &Service{store: s, now: time.Now} }

type Started struct {
	TransactionID string
	State         string
	CodeChallenge string
}

func (s *Service) Start(ctx context.Context, provider, mode, userID string) (Started, error) {
	state, err := secure.RandomToken(32)
	if err != nil {
		return Started{}, err
	}
	verifier, err := secure.RandomToken(32)
	if err != nil {
		return Started{}, err
	}
	var uid *string
	if userID != "" {
		uid = &userID
	}
	var id string
	err = s.store.Pool.QueryRow(ctx, `
		INSERT INTO oauth_transactions (state_hash, code_verifier, provider, mode, user_id, expires_at)
		VALUES ($1, $2, $3::oauth_provider, $4::oauth_mode, $5, $6)
		RETURNING id::text`,
		secure.SHA256Hex(state), verifier, provider, mode, uid, s.now().Add(TTL)).Scan(&id)
	if err != nil {
		return Started{}, fmt.Errorf("start oauth transaction: %w", err)
	}
	return Started{TransactionID: id, State: state, CodeChallenge: secure.PKCEChallenge(verifier)}, nil
}

type Consumed struct {
	CodeVerifier string
	Mode         string
	UserID       string
}

func (s *Service) Consume(ctx context.Context, transactionID, state, provider string) (Consumed, error) {
	invalid := apperr.New(apperr.CodeInvalidState, 400)
	if !secure.IsUUID(transactionID) || state == "" {
		return Consumed{}, invalid
	}
	var (
		out    Consumed
		userID *string
	)
	err := s.store.Pool.QueryRow(ctx, `
		UPDATE oauth_transactions SET consumed_at = $4
		WHERE id = $1 AND state_hash = $2 AND provider = $3::oauth_provider
		  AND consumed_at IS NULL AND expires_at > $4
		RETURNING code_verifier, mode::text, user_id::text`,
		transactionID, secure.SHA256Hex(state), provider, s.now()).Scan(&out.CodeVerifier, &out.Mode, &userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Consumed{}, invalid
	}
	if err != nil {
		return Consumed{}, fmt.Errorf("consume oauth transaction: %w", err)
	}
	if userID != nil {
		out.UserID = *userID
	}
	return out, nil
}
