package provider

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/iskanderovv/alifco-auth-go/internal/apperr"
	"github.com/iskanderovv/alifco-auth-go/internal/store"
)

type FacebookOptions struct {
	AppID        string
	AppSecret    string
	GraphVersion string
	RedirectURI  string
	Client       HTTPClient
	GraphBase    string
}

type facebook struct{ FacebookOptions }

// NewFacebook returns the Facebook adapter. Facebook is OAuth 2, not OpenID Connect,
// so the profile is read from the Graph API with the access token.
func NewFacebook(o FacebookOptions) Provider {
	if o.GraphBase == "" {
		o.GraphBase = "https://graph.facebook.com"
	}
	return &facebook{o}
}

func (f *facebook) Name() string { return store.Facebook }

func (f *facebook) AuthorizationURL(state, codeChallenge string) string {
	return authorizationURL("https://www.facebook.com/"+f.GraphVersion+"/dialog/oauth", url.Values{
		"client_id":             {f.AppID},
		"redirect_uri":          {f.RedirectURI},
		"response_type":         {"code"},
		"scope":                 {"public_profile,email"},
		"state":                 {state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	})
}

func (f *facebook) Authenticate(ctx context.Context, code, codeVerifier string) (Profile, error) {
	accessToken, err := f.exchangeCode(ctx, code, codeVerifier)
	if err != nil {
		return Profile{}, err
	}
	me, err := f.fetchProfile(ctx, accessToken)
	if err != nil {
		return Profile{}, err
	}
	if me.ID == "" {
		return Profile{}, apperr.Provider("Facebook profile has no id")
	}
	return Profile{
		ProviderUserID: me.ID,
		Email:          me.Email,
		// Facebook has no email_verified, so its email is never trusted.
		EmailVerified: false,
		Name:          me.Name,
		AvatarURL:     me.Picture.Data.URL,
	}, nil
}

func (f *facebook) exchangeCode(ctx context.Context, code, codeVerifier string) (string, error) {
	form := url.Values{
		"client_id":     {f.AppID},
		"client_secret": {f.AppSecret}, // in the POST body, never in a URL
		"redirect_uri":  {f.RedirectURI},
		"code":          {code},
		"code_verifier": {codeVerifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		f.GraphBase+"/"+f.GraphVersion+"/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", apperr.Provider("Facebook token request could not be built")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := f.do(req, "token request", &body); err != nil {
		return "", err
	}
	if body.AccessToken == "" {
		return "", apperr.Provider("Facebook response has no access_token")
	}
	return body.AccessToken, nil
}

type facebookMe struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Picture struct {
		Data struct {
			URL string `json:"url"`
		} `json:"data"`
	} `json:"picture"`
}

func (f *facebook) fetchProfile(ctx context.Context, accessToken string) (facebookMe, error) {
	mac := hmac.New(sha256.New, []byte(f.AppSecret))
	mac.Write([]byte(accessToken))
	query := url.Values{
		"fields":          {"id,name,email,picture.type(large)"},
		"access_token":    {accessToken},
		"appsecret_proof": {hex.EncodeToString(mac.Sum(nil))},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		f.GraphBase+"/"+f.GraphVersion+"/me?"+query.Encode(), nil)
	if err != nil {
		return facebookMe{}, apperr.Provider("Facebook profile request could not be built")
	}
	var me facebookMe
	if err := f.do(req, "profile request", &me); err != nil {
		return facebookMe{}, err
	}
	return me, nil
}

func (f *facebook) do(req *http.Request, what string, out any) error {
	req.Header.Set("Accept", "application/json")
	resp, err := f.Client.Do(req)
	if err != nil {
		return apperr.Provider(fmt.Sprintf("Facebook %s failed", what))
	}
	defer closeBody(resp)
	if resp.StatusCode != http.StatusOK {
		return apperr.Provider(fmt.Sprintf("Facebook %s returned %d", what, resp.StatusCode))
	}
	_ = json.NewDecoder(limited(resp)).Decode(out)
	return nil
}
