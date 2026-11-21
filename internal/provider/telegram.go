package provider

import (
	"context"
	"net/url"

	"github.com/iskanderovv/alifco-auth-go/internal/store"
)

const (
	telegramAuthURL  = "https://oauth.telegram.org/auth"
	telegramTokenURL = "https://oauth.telegram.org/token"
	telegramJWKSURL  = "https://oauth.telegram.org/.well-known/jwks.json"
	telegramIssuer   = "https://oauth.telegram.org"
)

type TelegramOptions struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Client       HTTPClient
	TokenURL     string
	Keys         *JWKS
}

type telegram struct{ TelegramOptions }

// NewTelegram returns the Telegram adapter (OpenID Connect with PKCE, HTTP Basic
// client authentication). Telegram gives no email, so none is ever stored for it.
func NewTelegram(o TelegramOptions) Provider {
	if o.TokenURL == "" {
		o.TokenURL = telegramTokenURL
	}
	if o.Keys == nil {
		o.Keys = NewJWKS(telegramJWKSURL, o.Client)
	}
	return &telegram{o}
}

func (t *telegram) Name() string { return store.Telegram }

func (t *telegram) AuthorizationURL(state, codeChallenge string) string {
	return authorizationURL(telegramAuthURL, url.Values{
		"client_id":             {t.ClientID},
		"redirect_uri":          {t.RedirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid profile"},
		"state":                 {state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	})
}

// Authenticate pins RS256, which is the BotFather default.
func (t *telegram) Authenticate(ctx context.Context, code, codeVerifier string) (Profile, error) {
	raw, err := requestIDToken(ctx, tokenRequest{
		client:   t.Client,
		endpoint: t.TokenURL,
		form: url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {t.RedirectURI},
			"client_id":     {t.ClientID},
			"code_verifier": {codeVerifier},
		},
		basicID:      t.ClientID,
		basicSecret:  t.ClientSecret,
		providerName: "Telegram",
	})
	if err != nil {
		return Profile{}, err
	}
	claims, err := verifyIDToken(ctx, idTokenCheck{
		raw:          raw,
		keys:         t.Keys,
		issuers:      []string{telegramIssuer},
		audience:     t.ClientID,
		providerName: "Telegram",
	})
	if err != nil {
		return Profile{}, err
	}
	return Profile{
		ProviderUserID: claims.Subject,
		Name:           claims.Name,
		Username:       claims.Username,
		AvatarURL:      claims.Picture,
	}, nil
}
