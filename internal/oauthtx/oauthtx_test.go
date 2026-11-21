package oauthtx

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iskanderovv/alifco-auth-go/internal/apperr"
	"github.com/iskanderovv/alifco-auth-go/internal/secure"
	"github.com/iskanderovv/alifco-auth-go/internal/store"
	"github.com/iskanderovv/alifco-auth-go/internal/testutil"
)

func invalid(t *testing.T, err error) {
	t.Helper()
	appErr, ok := apperr.As(err)
	if !ok || appErr.Code != apperr.CodeInvalidState {
		t.Fatalf("want invalid_state, got %v", err)
	}
}

func TestStartAndConsume(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewStore(t)
	svc := NewService(st)

	started, err := svc.Start(ctx, store.Google, store.ModeLogin, "")
	if err != nil {
		t.Fatal(err)
	}

	var storedState, verifier string
	_ = st.Pool.QueryRow(ctx, `SELECT state_hash, code_verifier FROM oauth_transactions WHERE id = $1`,
		started.TransactionID).Scan(&storedState, &verifier)
	if storedState == started.State {
		t.Fatal("the state must be stored hashed")
	}
	if started.CodeChallenge != secure.PKCEChallenge(verifier) {
		t.Fatal("the challenge must be the S256 of the stored verifier")
	}

	got, err := svc.Consume(ctx, started.TransactionID, started.State, store.Google)
	if err != nil || got.CodeVerifier != verifier || got.Mode != store.ModeLogin {
		t.Fatalf("Consume = %+v, %v", got, err)
	}

	_, err = svc.Consume(ctx, started.TransactionID, started.State, store.Google)
	invalid(t, err)
}

func TestConsumeRejects(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewStore(t)
	svc := NewService(st)
	started, _ := svc.Start(ctx, store.Google, store.ModeLogin, "")

	cases := map[string]func() error{
		"forged state": func() error {
			_, err := svc.Consume(ctx, started.TransactionID, "forged", store.Google)
			return err
		},
		"other provider": func() error {
			_, err := svc.Consume(ctx, started.TransactionID, started.State, store.Telegram)
			return err
		},
		"missing cookie": func() error {
			_, err := svc.Consume(ctx, "", started.State, store.Google)
			return err
		},
		"missing state": func() error {
			_, err := svc.Consume(ctx, started.TransactionID, "", store.Google)
			return err
		},
		"sql injection in the id": func() error {
			_, err := svc.Consume(ctx, "' OR 1=1 --", started.State, store.Google)
			return err
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) { invalid(t, run()) })
	}

	t.Run("the failed attempts did not use the flow up", func(t *testing.T) {
		if _, err := svc.Consume(ctx, started.TransactionID, started.State, store.Google); err != nil {
			t.Fatalf("the genuine callback must still work: %v", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		old, _ := svc.Start(ctx, store.Google, store.ModeLogin, "")
		_, _ = st.Pool.Exec(ctx, `UPDATE oauth_transactions SET expires_at = now() - interval '1 second' WHERE id = $1`,
			old.TransactionID)
		_, err := svc.Consume(ctx, old.TransactionID, old.State, store.Google)
		invalid(t, err)
	})
}

func TestLinkTransactionCarriesTheUser(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewStore(t)
	svc := NewService(st)
	user := testutil.NewUser(t, st, "Ali")

	started, err := svc.Start(ctx, store.Facebook, store.ModeLink, user)
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.Consume(ctx, started.TransactionID, started.State, store.Facebook)
	if err != nil || got.Mode != store.ModeLink || got.UserID != user {
		t.Fatalf("Consume = %+v, %v", got, err)
	}
}

func TestConcurrentCallbacksHaveOneWinner(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewStore(t)
	svc := NewService(st)
	started, _ := svc.Start(ctx, store.Google, store.ModeLogin, "")

	const callers = 20
	var wins atomic.Int32
	var wg sync.WaitGroup
	gate := make(chan struct{})
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-gate
			if _, err := svc.Consume(ctx, started.TransactionID, started.State, store.Google); err == nil {
				wins.Add(1)
			}
		}()
	}
	close(gate)
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("winners = %d, want exactly 1", wins.Load())
	}
}

func TestTTL(t *testing.T) {
	if TTL != 10*time.Minute {
		t.Fatalf("TTL = %v", TTL)
	}
}
