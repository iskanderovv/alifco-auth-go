package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Credentials struct {
	ID     string
	Secret string
}

type Config struct {
	Env         string
	Port        int
	APIBaseURL  string
	FrontendURL string
	DatabaseURL string

	JWTSecret      string
	JWTIssuer      string
	JWTAudience    string
	AccessTTL      time.Duration
	RefreshTTL     time.Duration
	CookieSecure   bool
	CookieSameSite string

	Google               Credentials
	Facebook             Credentials
	Telegram             Credentials
	FacebookGraphVersion string

	DocsUser     string
	DocsPassword string

	LogLevel       string
	HTTPTimeout    time.Duration
	BodyLimit      int64
	MigrateOnStart bool
	RateLimitOff   bool
}

func (c Config) Production() bool { return c.Env == "production" }

func Load() (Config, error) { return parse(os.Getenv) }

func parse(get func(string) string) (Config, error) {
	var problems []string
	fail := func(key, message string) { problems = append(problems, fmt.Sprintf("  - %s: %s", key, message)) }

	str := func(key, fallback string) string {
		if v := strings.TrimSpace(get(key)); v != "" {
			return v
		}
		return fallback
	}
	integer := func(key string, fallback, min, max int) int {
		raw := str(key, "")
		if raw == "" {
			return fallback
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < min || n > max {
			fail(key, fmt.Sprintf("must be an integer from %d to %d", min, max))
			return fallback
		}
		return n
	}
	boolean := func(key string) bool {
		switch strings.ToLower(str(key, "false")) {
		case "true":
			return true
		case "false":
			return false
		default:
			fail(key, "must be true or false")
			return false
		}
	}
	httpURL := func(key, fallback string) string {
		raw := strings.TrimRight(str(key, fallback), "/")
		parsed, err := url.Parse(raw)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			fail(key, "must be an http or https URL")
		}
		return raw
	}
	pair := func(idKey, secretKey string) Credentials {
		id, secret := str(idKey, ""), str(secretKey, "")
		if (id == "") != (secret == "") {
			fail(idKey, fmt.Sprintf("%s and %s must be set together", idKey, secretKey))
		}
		return Credentials{ID: id, Secret: secret}
	}

	cfg := Config{
		Env:         str("NODE_ENV", str("APP_ENV", "development")),
		Port:        integer("PORT", 3000, 1, 65535),
		APIBaseURL:  httpURL("API_BASE_URL", "http://localhost:3000"),
		FrontendURL: httpURL("FRONTEND_URL", "http://localhost:5173"),
		DatabaseURL: str("DATABASE_URL", ""),

		JWTSecret:      str("JWT_SECRET", ""),
		JWTIssuer:      str("JWT_ISSUER", "oauth-service"),
		JWTAudience:    str("JWT_AUDIENCE", "oauth-service-api"),
		CookieSecure:   boolean("COOKIE_SECURE"),
		CookieSameSite: strings.ToLower(str("COOKIE_SAME_SITE", "lax")),

		Google:               pair("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"),
		Facebook:             pair("FACEBOOK_APP_ID", "FACEBOOK_APP_SECRET"),
		Telegram:             pair("TELEGRAM_CLIENT_ID", "TELEGRAM_CLIENT_SECRET"),
		FacebookGraphVersion: str("FACEBOOK_GRAPH_VERSION", "v25.0"),

		DocsUser:     str("SWAGGER_USER", ""),
		DocsPassword: str("SWAGGER_PASSWORD", ""),

		LogLevel:       strings.ToLower(str("LOG_LEVEL", "info")),
		HTTPTimeout:    time.Duration(integer("HTTP_TIMEOUT_MS", 5000, 100, 60000)) * time.Millisecond,
		BodyLimit:      int64(integer("BODY_LIMIT_BYTES", 10240, 256, 10<<20)),
		MigrateOnStart: boolean("MIGRATE_ON_START"),
		RateLimitOff:   boolean("RATE_LIMIT_OFF"),
	}

	accessTTL, err := parseTTL(str("JWT_ACCESS_TTL", "15m"))
	if err != nil {
		fail("JWT_ACCESS_TTL", "use a form like 15m, 1h or 7d")
	}
	cfg.AccessTTL = accessTTL
	cfg.RefreshTTL = time.Duration(integer("REFRESH_TTL_DAYS", 30, 1, 365)) * 24 * time.Hour

	if cfg.DatabaseURL == "" {
		fail("DATABASE_URL", "is required")
	}
	if len(cfg.JWTSecret) < 32 {
		fail("JWT_SECRET", "must be at least 32 characters")
	}
	if cfg.CookieSameSite != "lax" && cfg.CookieSameSite != "none" {
		fail("COOKIE_SAME_SITE", "must be lax or none")
	}
	if cfg.CookieSameSite == "none" && !cfg.CookieSecure {
		fail("COOKIE_SECURE", "must be true when COOKIE_SAME_SITE is none")
	}
	if (cfg.DocsUser == "") != (cfg.DocsPassword == "") {
		fail("SWAGGER_USER", "SWAGGER_USER and SWAGGER_PASSWORD must be set together")
	}
	if cfg.Production() {
		if cfg.RateLimitOff {
			fail("RATE_LIMIT_OFF", "must be false in production")
		}
		if !cfg.CookieSecure {
			fail("COOKIE_SECURE", "must be true in production")
		}
		for key, value := range map[string]string{"API_BASE_URL": cfg.APIBaseURL, "FRONTEND_URL": cfg.FrontendURL} {
			if !strings.HasPrefix(value, "https://") {
				fail(key, "must be https in production")
			}
		}
	}

	if len(problems) > 0 {
		return Config{}, errors.New("invalid environment configuration:\n" + strings.Join(problems, "\n"))
	}
	return cfg, nil
}

func parseTTL(value string) (time.Duration, error) {
	if len(value) < 2 {
		return 0, errors.New("too short")
	}
	n, err := strconv.Atoi(value[:len(value)-1])
	if err != nil || n <= 0 {
		return 0, errors.New("bad number")
	}
	units := map[byte]time.Duration{'s': time.Second, 'm': time.Minute, 'h': time.Hour, 'd': 24 * time.Hour}
	unit, ok := units[value[len(value)-1]]
	if !ok {
		return 0, errors.New("bad unit")
	}
	return time.Duration(n) * unit, nil
}

func (c Config) Providers() []string {
	var names []string
	if c.Google.ID != "" {
		names = append(names, "google")
	}
	if c.Facebook.ID != "" {
		names = append(names, "facebook")
	}
	if c.Telegram.ID != "" {
		names = append(names, "telegram")
	}
	return names
}
