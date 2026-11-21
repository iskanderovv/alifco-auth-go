package testutil

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/iskanderovv/alifco-auth-go/internal/db"
	"github.com/iskanderovv/alifco-auth-go/internal/store"
)

const defaultURL = "postgresql://oauth:oauth@localhost:5432/oauth_test"

// NewStore returns a store on a fresh, migrated schema that is dropped when the
// test ends. Each call gets its own schema, so tests and packages never share rows.
// The test is skipped when no database is reachable.
func NewStore(t *testing.T) *store.Store {
	t.Helper()
	ctx := context.Background()

	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		base = defaultURL
	}
	admin, err := pgxpool.New(ctx, base)
	if err != nil {
		t.Skipf("database not available: %v", err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Skipf("database not available: %v", err)
	}

	schema := "go_test_" + uuid.NewString()[:8]
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		admin.Close()
		t.Fatalf("create schema: %v", err)
	}

	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse database url: %v", err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()

	cfg, err := pgxpool.ParseConfig(u.String())
	if err != nil {
		t.Fatalf("parse pool config: %v", err)
	}
	cfg.MaxConns = 40
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(ctx, fmt.Sprintf("DROP SCHEMA %s CASCADE", schema))
		admin.Close()
	})
	return store.New(pool)
}

// NewUser inserts a user and returns its id.
func NewUser(t *testing.T, s *store.Store, name string) string {
	t.Helper()
	var id string
	err := s.Pool.QueryRow(context.Background(),
		`INSERT INTO users (name) VALUES ($1) RETURNING id::text`, name).Scan(&id)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	return id
}
