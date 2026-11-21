package provider

import (
	"context"
	"net/url"

	"github.com/iskanderovv/alifco-auth-go/internal/store"
)

const (
	googleAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL = "https://oauth2.googleapis.com/token"
	googleJWKSURL  = "https://www.googleapis.com/oauth2/v3/certs"
)

type GoogleOptions struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Client       HTTPClient
	TokenURL     string
	Keys         *JWKS
}

type google struct{ GoogleOptions }

func NewGoogle(o GoogleOptions) Provider {
	if o.TokenURL == "" {
		o.TokenURL = googleTokenURL
	}
	if o.Keys == nil {
		o.Keys = NewJWKS(googleJWKSURL, o.Client)
	}
	return &google{o}
}

func (g *google) Name() string { return store.Google }

func (g *google) AuthorizationURL(state, codeChallenge string) string {
	return authorizationURL(googleAuthURL, url.Values{
		"client_id":             {g.ClientID},
		"redirect_uri":          {g.RedirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid email profile"},
		"state":                 {state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
		"prompt":                {"select_account"},
	})
}

func (g *google) Authenticate(ctx context.Context, code, codeVerifier string) (Profile, error) {
	raw, err := requestIDToken(ctx, tokenRequest{
		client:   g.Client,
		endpoint: g.TokenURL,
		form: url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {g.RedirectURI},
			"client_id":     {g.ClientID},
			"client_secret": {g.ClientSecret},
			"code_verifier": {codeVerifier},
		},
		providerName: "Google",
	})
	if err != nil {
		return Profile{}, err
	}
	claims, err := verifyIDToken(ctx, idTokenCheck{
		raw:          raw,
		keys:         g.Keys,
		issuers:      []string{"https://accounts.google.com", "accounts.google.com"},
		audience:     g.ClientID,
		providerName: "Google",
	})
	if err != nil {
		return Profile{}, err
	}
	return Profile{
		ProviderUserID: claims.Subject,
		Email:          claims.Email,
		EmailVerified:  verifiedEmail(claims.EmailVerified),
		Name:           claims.Name,
		AvatarURL:      claims.Picture,
	}, nil
}
