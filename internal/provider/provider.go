package provider

import (
	"context"
	"net/http"
	"time"
)

type Profile struct {
	ProviderUserID string
	Email          string
	EmailVerified  bool
	Name           string
	Username       string
	AvatarURL      string
}

type Provider interface {
	Name() string
	AuthorizationURL(state, codeChallenge string) string
	Authenticate(ctx context.Context, code, codeVerifier string) (Profile, error)
}

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout}
}
