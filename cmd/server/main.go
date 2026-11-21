package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"

	"github.com/iskanderovv/alifco-auth-go/internal/config"
	"github.com/iskanderovv/alifco-auth-go/internal/db"
	"github.com/iskanderovv/alifco-auth-go/internal/httpapi"
	"github.com/iskanderovv/alifco-auth-go/internal/identity"
	"github.com/iskanderovv/alifco-auth-go/internal/oauthtx"
	"github.com/iskanderovv/alifco-auth-go/internal/provider"
	"github.com/iskanderovv/alifco-auth-go/internal/store"
	"github.com/iskanderovv/alifco-auth-go/internal/token"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	_ = godotenv.Load()

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	configureLogger(cfg.LogLevel)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.MigrateOnStart {
		if err := db.EnsureSchema(ctx, cfg.DatabaseURL); err != nil {
			return err
		}
	}
	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if cfg.MigrateOnStart {
		if err := db.Migrate(ctx, pool); err != nil {
			return err
		}
	}

	st := store.New(pool)
	handler := httpapi.New(httpapi.Deps{
		Config: cfg,
		Store:  st,
		Tokens: token.NewService(st, token.Options{
			Secret: cfg.JWTSecret, Issuer: cfg.JWTIssuer, Audience: cfg.JWTAudience,
			AccessTTL: cfg.AccessTTL, RefreshTTL: cfg.RefreshTTL,
		}),
		Identities: identity.NewService(st),
		Txs:        oauthtx.NewService(st),
		Providers:  provider.NewRegistry(cfg, provider.NewHTTPClient(cfg.HTTPTimeout)),
		Limits:     !cfg.RateLimitOff,
	}).Handler()

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	failed := make(chan error, 1)
	go func() {
		slog.Info("listening", "addr", srv.Addr, "providers", cfg.Providers())
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			failed <- err
		}
	}()

	select {
	case err := <-failed:
		return err
	case <-ctx.Done():
	}

	slog.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func configureLogger(level string) {
	var lv slog.Level
	if err := lv.UnmarshalText([]byte(level)); err != nil {
		lv = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lv})))
}
