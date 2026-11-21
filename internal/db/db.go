package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"net/url"
	"regexp"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

var schemaName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

//go:embed migrations/*.sql
var migrations embed.FS

func Connect(ctx context.Context, url string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("open pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return pool, nil
}

func EnsureSchema(ctx context.Context, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse database url: %w", err)
	}
	schema := u.Query().Get("search_path")
	if schema == "" || !schemaName.MatchString(schema) {
		return nil
	}
	q := u.Query()
	q.Del("search_path")
	u.RawQuery = q.Encode()

	pool, err := Connect(ctx, u.String())
	if err != nil {
		return err
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS "+schema); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}
	return nil
}

func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	goose.SetBaseFS(migrations)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("set dialect: %w", err)
	}
	conn := stdlib.OpenDBFromPool(pool)
	defer closeQuietly(conn)
	if err := goose.UpContext(ctx, conn, "migrations"); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}

func closeQuietly(conn *sql.DB) { _ = conn.Close() }
