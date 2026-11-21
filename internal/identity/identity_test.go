package identity

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iskanderovv/alifco-auth-go/internal/apperr"
	"github.com/iskanderovv/alifco-auth-go/internal/provider"
	"github.com/iskanderovv/alifco-auth-go/internal/store"
	"github.com/iskanderovv/alifco-auth-go/internal/testutil"
)

func wantCode(t *testing.T, err error, want string) {
	t.Helper()
	appErr, ok := apperr.As(err)
	if !ok || appErr.Code != want {
		t.Fatalf("want %s, got %v", want, err)
	}
}

func count(t *testing.T, st *store.Store, query string, args ...any) int {
	t.Helper()
	var n int
	if err := st.Pool.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func googleProfile(sub string) provider.Profile {
	return provider.Profile{ProviderUserID: sub, Email: "Ali@Example.com", EmailVerified: true, Name: "Ali", AvatarURL: "https://img/a.png"}
}

func TestLoginCreatesThenReusesTheUser(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewStore(t)
	svc := NewService(st)

	user, isNew, err := svc.Login(ctx, store.Google, googleProfile("g-1"))
	if err != nil || !isNew {
		t.Fatalf("first login: new=%v err=%v", isNew, err)
	}
	if user.Email == nil || *user.Email != "ali@example.com" {
		t.Fatalf("a verified email must be stored lowercase, got %v", user.Email)
	}

	again, isNew, err := svc.Login(ctx, store.Google, googleProfile("g-1"))
	if err != nil || isNew || again.ID != user.ID {
		t.Fatalf("second login: id=%s new=%v err=%v", again.ID, isNew, err)
	}
	if n := count(t, st, `SELECT count(*) FROM users`); n != 1 {
		t.Fatalf("users = %d", n)
	}
}

func TestUnverifiedEmailIsNotStoredOnTheUser(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewStore(t)
	svc := NewService(st)

	user, _, err := svc.Login(ctx, store.Facebook, provider.Profile{
		ProviderUserID: "fb-1", Email: "victim@example.com", EmailVerified: false, Name: "Mallory",
	})
	if err != nil {
		t.Fatal(err)
	}
	if user.Email != nil {
		t.Fatal("an unverified email must not reach users.email")
	}
}

func TestNoMergeByEmail(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewStore(t)
	svc := NewService(st)

	attacker, _, _ := svc.Login(ctx, store.Facebook, provider.Profile{
		ProviderUserID: "fb-attacker", Email: "victim@example.com", EmailVerified: false, Name: "Mallory",
	})
	victim, isNew, err := svc.Login(ctx, store.Google, googleProfile("g-victim"))
	if err != nil || !isNew {
		t.Fatalf("victim login: new=%v err=%v", isNew, err)
	}
	if victim.ID == attacker.ID {
		t.Fatal("pre-account takeover: accounts were merged by email")
	}
}

func TestAvatarFollowsLatestLoginButNameDoesNot(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewStore(t)
	svc := NewService(st)

	first := provider.Profile{ProviderUserID: "t-1", Name: "Ali", AvatarURL: "https://img/old.png"}
	user, _, _ := svc.Login(ctx, store.Telegram, first)

	renamed := provider.Profile{ProviderUserID: "t-1", Name: "Someone Else", AvatarURL: "https://img/new.png"}
	got, _, err := svc.Login(ctx, store.Telegram, renamed)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != user.ID || got.Name != "Ali" {
		t.Fatalf("the name must not change: %+v", got)
	}
	if got.AvatarURL == nil || *got.AvatarURL != "https://img/new.png" {
		t.Fatalf("avatar = %v", got.AvatarURL)
	}

	insecure := provider.Profile{ProviderUserID: "t-1", AvatarURL: "http://img/plain.png"}
	got, _, _ = svc.Login(ctx, store.Telegram, insecure)
	if got.AvatarURL == nil || *got.AvatarURL != "https://img/new.png" {
		t.Fatal("an http picture link must be ignored")
	}
}

func TestConcurrentFirstLoginCreatesOneUser(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewStore(t)
	svc := NewService(st)

	const callers = 15
	var failures atomic.Int32
	ids := make(chan string, callers)
	var wg sync.WaitGroup
	gate := make(chan struct{})
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-gate
			user, _, err := svc.Login(ctx, store.Google, googleProfile("g-race"))
			if err != nil {
				failures.Add(1)
				return
			}
			ids <- user.ID
		}()
	}
	close(gate)
	wg.Wait()
	close(ids)

	if failures.Load() != 0 {
		t.Fatalf("%d logins failed", failures.Load())
	}
	seen := map[string]bool{}
	for id := range ids {
		seen[id] = true
	}
	if len(seen) != 1 {
		t.Fatalf("callers got %d different users", len(seen))
	}
	if n := count(t, st, `SELECT count(*) FROM users`); n != 1 {
		t.Fatalf("users = %d, want 1 (no orphan from the losers)", n)
	}
}

func TestLosingTheFirstLoginRaceLogsInTheWinner(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewStore(t)
	svc := NewService(st)

	winner, _, err := svc.Login(ctx, store.Google, googleProfile("g-late"))
	if err != nil {
		t.Fatal(err)
	}

	loser, isNew, err := svc.create(ctx, store.Google, googleProfile("g-late"))
	if err != nil || isNew || loser.ID != winner.ID {
		t.Fatalf("create = id %s new %v err %v, want the winner %s", loser.ID, isNew, err, winner.ID)
	}
	if n := count(t, st, `SELECT count(*) FROM users`); n != 1 {
		t.Fatalf("users = %d, the failed attempt left a half-made user behind", n)
	}
}

func TestLinkAndUnlink(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewStore(t)
	svc := NewService(st)

	ali, _, _ := svc.Login(ctx, store.Google, googleProfile("g-ali"))

	if err := svc.Link(ctx, ali.ID, store.Telegram, provider.Profile{ProviderUserID: "t-ali"}); err != nil {
		t.Fatal(err)
	}
	providers, _ := st.ProvidersOf(ctx, ali.ID)
	if len(providers) != 2 {
		t.Fatalf("providers = %v", providers)
	}

	t.Run("already linked", func(t *testing.T) {
		err := svc.Link(ctx, ali.ID, store.Telegram, provider.Profile{ProviderUserID: "t-other"})
		wantCode(t, err, apperr.CodeAlreadyLinked)
	})

	t.Run("account of someone else", func(t *testing.T) {
		vali, _, _ := svc.Login(ctx, store.Facebook, provider.Profile{ProviderUserID: "fb-vali", Name: "Vali"})
		err := svc.Link(ctx, ali.ID, store.Facebook, provider.Profile{ProviderUserID: "fb-vali"})
		wantCode(t, err, apperr.CodeIdentityTaken)
		if n := count(t, st, `SELECT count(*) FROM oauth_identities WHERE user_id = $1`, vali.ID); n != 1 {
			t.Fatal("the refused link must not touch the other user")
		}
	})

	t.Run("unknown user", func(t *testing.T) {
		err := svc.Link(ctx, "3f0c1c9e-6f0d-4c37-8d4e-0d7a9e2b1a11", store.Facebook, provider.Profile{ProviderUserID: "fb-x"})
		wantCode(t, err, apperr.CodeInvalidState)
	})

	t.Run("unlink", func(t *testing.T) {
		if err := svc.Unlink(ctx, ali.ID, store.Telegram); err != nil {
			t.Fatal(err)
		}
		wantCode(t, svc.Unlink(ctx, ali.ID, store.Telegram), apperr.CodeNotLinked)
	})

	t.Run("the last provider cannot be removed", func(t *testing.T) {
		wantCode(t, svc.Unlink(ctx, ali.ID, store.Google), apperr.CodeLastIdentity)
	})
}

func TestConcurrentUnlinksKeepOneLoginMethod(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewStore(t)
	svc := NewService(st)

	user, _, _ := svc.Login(ctx, store.Google, googleProfile("g-lock"))
	_ = svc.Link(ctx, user.ID, store.Telegram, provider.Profile{ProviderUserID: "t-lock"})

	var wg sync.WaitGroup
	gate := make(chan struct{})
	for _, name := range []string{store.Google, store.Telegram} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-gate
			_ = svc.Unlink(ctx, user.ID, name)
		}()
	}
	close(gate)
	wg.Wait()

	if n := count(t, st, `SELECT count(*) FROM oauth_identities WHERE user_id = $1`, user.ID); n != 1 {
		t.Fatalf("%d identities left, want exactly 1", n)
	}
}

func TestUnlinkHoldsTheUserLock(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewStore(t)
	svc := NewService(st)

	user, _, _ := svc.Login(ctx, store.Google, googleProfile("g-held"))
	_ = svc.Link(ctx, user.ID, store.Telegram, provider.Profile{ProviderUserID: "t-held"})

	holder, err := st.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(ctx) }()
	if _, err := holder.Exec(ctx, `SELECT id FROM users WHERE id = $1 FOR UPDATE`, user.ID); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- svc.Unlink(ctx, user.ID, store.Telegram) }()

	waitUntilBlocked(t, st)
	select {
	case err := <-done:
		_ = holder.Rollback(ctx)
		t.Fatalf("unlink did not wait for the row lock (returned %v)", err)
	default:
	}
	if err := holder.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func waitUntilBlocked(t *testing.T, st *store.Store) {
	t.Helper()
	ctx := context.Background()
	for range 200 {
		var waiting int
		err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()`).Scan(&waiting)
		if err == nil && waiting > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("unlink never blocked on the lock")
}
