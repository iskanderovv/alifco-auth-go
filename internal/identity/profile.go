package identity

import (
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/iskanderovv/alifco-auth-go/internal/provider"
)

const (
	nameMax      = 255
	emailMax     = 320
	fallbackName = "User"
)

func normalizeEmail(email string) string {
	value := strings.ToLower(strings.TrimSpace(email))
	if value == "" || len(value) > emailMax || !strings.Contains(value, "@") {
		return ""
	}
	return value
}

func displayName(p provider.Profile) string {
	for _, candidate := range []string{p.Name, p.Username} {
		if name := strings.TrimSpace(candidate); name != "" {
			return truncate(name, nameMax)
		}
	}
	return fallbackName
}

func safeAvatarURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return ""
	}
	return parsed.String()
}

func truncate(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	return string([]rune(s)[:max])
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
