package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/iskanderovv/alifco-auth-go/internal/db"
	"github.com/iskanderovv/alifco-auth-go/internal/store"
	"github.com/iskanderovv/alifco-auth-go/internal/token"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "stress:", err)
		os.Exit(1)
	}
}

func run() error {
	base := flag.String("url", "http://localhost:3000", "running instance")
	dsn := flag.String("db", os.Getenv("STRESS_DATABASE_URL"), "test database (its name must end in _test)")
	secret := flag.String("jwt-secret", os.Getenv("JWT_SECRET"), "must match the server")
	issuer := flag.String("jwt-issuer", envOr("JWT_ISSUER", "oauth-service"), "")
	audience := flag.String("jwt-audience", envOr("JWT_AUDIENCE", "oauth-service-api"), "")
	conns := flag.Int("c", 50, "connections")
	duration := flag.Duration("d", 10*time.Second, "time per scenario")
	sessions := flag.Int("sessions", 300, "refresh sessions to seed")
	flag.Parse()

	u, err := url.Parse(*dsn)
	if err != nil || *dsn == "" || !strings.HasSuffix(strings.TrimPrefix(u.Path, "/"), "_test") {
		return fmt.Errorf("refusing to seed: the database name must end in _test (set STRESS_DATABASE_URL)")
	}
	if len(*secret) < 32 {
		return fmt.Errorf("JWT_SECRET must match the server and be at least 32 characters")
	}

	ctx := context.Background()
	if err := db.EnsureSchema(ctx, *dsn); err != nil {
		return err
	}
	pool, err := pgxpool.New(ctx, *dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool); err != nil {
		return err
	}
	st := store.New(pool)
	tokens := token.NewService(st, token.Options{
		Secret: *secret, Issuer: *issuer, Audience: *audience, AccessTTL: time.Hour, RefreshTTL: time.Hour,
	})

	var userID string
	if err := pool.QueryRow(ctx, `INSERT INTO users (name) VALUES ('Stress') RETURNING id::text`).Scan(&userID); err != nil {
		return err
	}
	access, err := tokens.IssueAccess(userID)
	if err != nil {
		return err
	}
	refresh := make([]string, *sessions)
	for i := range refresh {
		issued, err := tokens.IssueRefresh(ctx, userID, token.RequestMeta{})
		if err != nil {
			return err
		}
		refresh[i] = issued.Token
	}

	client := &http.Client{
		Timeout:       10 * time.Second,
		Transport:     &http.Transport{MaxIdleConnsPerHost: *conns * 2},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	get := func(path string, header http.Header) func(int) (int, error) {
		return func(int) (int, error) { return do(client, http.MethodGet, *base+path, header) }
	}
	refreshCall := func(i int) (int, error) {
		h := http.Header{"X-Requested-With": {"fetch"}, "Cookie": {"refresh_token=" + refresh[i%len(refresh)]}}
		return do(client, http.MethodPost, *base+"/auth/refresh", h)
	}

	fmt.Printf("%-44s %9s %8s %8s %8s  %s\n", "scenario", "req/s", "p50", "p99", "max", "status codes")
	bench("GET /health", *conns, *duration, get("/health", nil))
	bench("GET /me", *conns, *duration, get("/me", http.Header{"Authorization": {"Bearer " + access.Token}}))
	bench("GET /auth/google (writes a row, needs the provider)", *conns, *duration, get("/auth/google", nil))
	bench("GET callback with a wrong state", *conns, *duration, get("/auth/google/callback?code=x&state=wrong", nil))
	bench(fmt.Sprintf("POST /auth/refresh, %d sessions, once each", len(refresh)), *conns, 0, refreshCall)

	return parallelRefresh(ctx, tokens, userID, client, *base, pool)
}

func parallelRefresh(ctx context.Context, tokens *token.Service, userID string, client *http.Client, base string, pool *pgxpool.Pool) error {
	issued, err := tokens.IssueRefresh(ctx, userID, token.RequestMeta{})
	if err != nil {
		return err
	}
	const callers = 100
	var ok, rejected, other atomic.Int32
	var wg sync.WaitGroup
	gate := make(chan struct{})
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-gate
			h := http.Header{"X-Requested-With": {"fetch"}, "Cookie": {"refresh_token=" + issued.Token}}
			switch status, _ := do(client, http.MethodPost, base+"/auth/refresh", h); status {
			case http.StatusOK:
				ok.Add(1)
			case http.StatusUnauthorized:
				rejected.Add(1)
			default:
				other.Add(1)
			}
		}()
	}
	close(gate)
	wg.Wait()

	var active int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM refresh_tokens WHERE family_id = $1 AND revoked_at IS NULL`, issued.FamilyID).Scan(&active); err != nil {
		return err
	}
	fmt.Printf("\n%d parallel refreshes of one token: %d x 200, %d x 401, %d other, %d token(s) left active\n",
		callers, ok.Load(), rejected.Load(), other.Load(), active)
	if ok.Load() != 1 || active > 1 || other.Load() != 0 {
		return fmt.Errorf("the parallel refresh guarantee is broken")
	}
	return nil
}

func do(client *http.Client, method, target string, header http.Header) (int, error) {
	req, err := http.NewRequestWithContext(context.Background(), method, target, nil)
	if err != nil {
		return 0, err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, nil
}

func bench(name string, conns int, duration time.Duration, fn func(int) (int, error)) {
	var (
		mu        sync.Mutex
		latencies []time.Duration
		statuses  = map[int]int{}
		errs      int
		next      atomic.Int64
	)
	started := time.Now()
	deadline := started.Add(duration)
	limit := int64(300)

	var wg sync.WaitGroup
	for range conns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := next.Add(1) - 1
				if duration == 0 && i >= limit || duration > 0 && time.Now().After(deadline) {
					return
				}
				t0 := time.Now()
				status, err := fn(int(i))
				took := time.Since(t0)
				mu.Lock()
				latencies = append(latencies, took)
				if err != nil {
					errs++
				} else {
					statuses[status]++
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	elapsed := time.Since(started)
	slices.Sort(latencies)
	pct := func(p float64) time.Duration {
		if len(latencies) == 0 {
			return 0
		}
		return latencies[min(len(latencies)-1, int(float64(len(latencies))*p))]
	}
	codes := make([]string, 0, len(statuses))
	for code, n := range statuses {
		codes = append(codes, fmt.Sprintf("%d x%d", code, n))
	}
	slices.Sort(codes)
	if errs > 0 {
		codes = append(codes, fmt.Sprintf("errors x%d", errs))
	}
	fmt.Printf("%-44s %9.0f %8s %8s %8s  %s\n", name, float64(len(latencies))/elapsed.Seconds(),
		pct(0.50).Round(10*time.Microsecond), pct(0.99).Round(10*time.Microsecond),
		pct(1).Round(10*time.Microsecond), strings.Join(codes, ", "))
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
