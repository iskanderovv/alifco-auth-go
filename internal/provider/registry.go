package provider

import (
	"strings"

	"github.com/iskanderovv/alifco-auth-go/internal/apperr"
	"github.com/iskanderovv/alifco-auth-go/internal/config"
)

type Registry struct {
	byName map[string]Provider
}

func NewRegistry(cfg config.Config, client HTTPClient) *Registry {
	r := &Registry{byName: map[string]Provider{}}
	callback := func(name string) string { return cfg.APIBaseURL + "/auth/" + name + "/callback" }

	if cfg.Google.ID != "" {
		r.byName["google"] = NewGoogle(GoogleOptions{
			ClientID: cfg.Google.ID, ClientSecret: cfg.Google.Secret, RedirectURI: callback("google"), Client: client,
		})
	}
	if cfg.Facebook.ID != "" {
		r.byName["facebook"] = NewFacebook(FacebookOptions{
			AppID: cfg.Facebook.ID, AppSecret: cfg.Facebook.Secret, GraphVersion: cfg.FacebookGraphVersion,
			RedirectURI: callback("facebook"), Client: client,
		})
	}
	if cfg.Telegram.ID != "" {
		r.byName["telegram"] = NewTelegram(TelegramOptions{
			ClientID: cfg.Telegram.ID, ClientSecret: cfg.Telegram.Secret, RedirectURI: callback("telegram"), Client: client,
		})
	}
	return r
}

func NewRegistryOf(providers ...Provider) *Registry {
	r := &Registry{byName: map[string]Provider{}}
	for _, p := range providers {
		r.byName[p.Name()] = p
	}
	return r
}

func (r *Registry) Get(name string) (Provider, error) {
	if p, ok := r.byName[strings.ToLower(name)]; ok {
		return p, nil
	}
	return nil, apperr.NotFound(apperr.CodeProviderNotFound)
}

func Known(name string) bool {
	switch name {
	case "google", "facebook", "telegram":
		return true
	}
	return false
}
