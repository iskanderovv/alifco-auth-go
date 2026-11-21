package config

import (
	"strings"
	"testing"
	"time"
)

func env(values map[string]string) func(string) string {
	base := map[string]string{
		"DATABASE_URL": "postgresql://u:p@localhost:5432/db",
		"JWT_SECRET":   strings.Repeat("x", 32),
	}
	for k, v := range values {
		base[k] = v
	}
	return func(key string) string { return base[key] }
}

func TestDefaults(t *testing.T) {
	cfg, err := parse(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 3000 || cfg.AccessTTL != 15*time.Minute || cfg.RefreshTTL != 30*24*time.Hour || cfg.CookieSecure {
		t.Fatalf("defaults = %+v", cfg)
	}
	if len(cfg.Providers()) != 0 {
		t.Fatalf("providers = %v", cfg.Providers())
	}
}

func TestTrailingSlashIsStripped(t *testing.T) {
	cfg, err := parse(env(map[string]string{"API_BASE_URL": "https://api.example.com/", "FRONTEND_URL": "https://app.example.com//"}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIBaseURL != "https://api.example.com" || cfg.FrontendURL != "https://app.example.com" {
		t.Fatalf("urls = %s %s", cfg.APIBaseURL, cfg.FrontendURL)
	}
}

func TestErrorsNameTheVariableButNeverItsValue(t *testing.T) {
	const secret = "short-secret-value"
	_, err := parse(env(map[string]string{"JWT_SECRET": secret, "DATABASE_URL": "", "PORT": "99999"}))
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"JWT_SECRET", "DATABASE_URL", "PORT"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not name %s: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("the error printed a secret")
	}
}

func TestProviderPairsMustBeComplete(t *testing.T) {
	if _, err := parse(env(map[string]string{"GOOGLE_CLIENT_ID": "id"})); err == nil {
		t.Fatal("half a pair must be rejected")
	}
	cfg, err := parse(env(map[string]string{"GOOGLE_CLIENT_ID": "id", "GOOGLE_CLIENT_SECRET": "s", "TELEGRAM_CLIENT_ID": " ", "TELEGRAM_CLIENT_SECRET": ""}))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Providers(); len(got) != 1 || got[0] != "google" {
		t.Fatalf("providers = %v, blank values mean not configured", got)
	}
}

func TestDocsLoginMustBeComplete(t *testing.T) {
	if _, err := parse(env(map[string]string{"SWAGGER_USER": "alifco"})); err == nil {
		t.Fatal("a user without a password must be rejected")
	}
	if _, err := parse(env(map[string]string{"SWAGGER_USER": "a", "SWAGGER_PASSWORD": "b"})); err != nil {
		t.Fatal(err)
	}
}

func TestCookieRules(t *testing.T) {
	if _, err := parse(env(map[string]string{"COOKIE_SAME_SITE": "none"})); err == nil {
		t.Fatal("SameSite=None needs Secure")
	}
	if _, err := parse(env(map[string]string{"COOKIE_SAME_SITE": "none", "COOKIE_SECURE": "true"})); err != nil {
		t.Fatal(err)
	}
	if _, err := parse(env(map[string]string{"COOKIE_SAME_SITE": "strict"})); err == nil {
		t.Fatal("an unknown SameSite value must be rejected")
	}
}

func TestProductionIsStrict(t *testing.T) {
	prod := map[string]string{"NODE_ENV": "production"}
	if _, err := parse(env(prod)); err == nil {
		t.Fatal("production without secure cookies must fail")
	}
	prod["COOKIE_SECURE"] = "true"
	if _, err := parse(env(prod)); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("production over http must fail, got %v", err)
	}
	prod["API_BASE_URL"], prod["FRONTEND_URL"] = "https://api.example.com", "https://app.example.com"
	if _, err := parse(env(prod)); err != nil {
		t.Fatal(err)
	}
}

func TestParseTTL(t *testing.T) {
	good := map[string]time.Duration{"30s": 30 * time.Second, "15m": 15 * time.Minute, "12h": 12 * time.Hour, "7d": 7 * 24 * time.Hour}
	for in, want := range good {
		if got, err := parseTTL(in); err != nil || got != want {
			t.Errorf("parseTTL(%q) = %v, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "m", "15", "0m", "-5m", "5w", "abc"} {
		if _, err := parseTTL(in); err == nil {
			t.Errorf("parseTTL(%q) must fail", in)
		}
	}
}
