package httpapi

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/iskanderovv/alifco-auth-go/internal/apperr"
	"github.com/iskanderovv/alifco-auth-go/internal/config"
	"github.com/iskanderovv/alifco-auth-go/internal/identity"
	"github.com/iskanderovv/alifco-auth-go/internal/oauthtx"
	"github.com/iskanderovv/alifco-auth-go/internal/provider"
	"github.com/iskanderovv/alifco-auth-go/internal/store"
	"github.com/iskanderovv/alifco-auth-go/internal/token"
)

type Deps struct {
	Config     config.Config
	Store      *store.Store
	Tokens     *token.Service
	Identities *identity.Service
	Txs        *oauthtx.Service
	Providers  *provider.Registry
	Limits     bool
}

type Server struct {
	cfg        config.Config
	store      *store.Store
	tokens     *token.Service
	identities *identity.Service
	txs        *oauthtx.Service
	providers  *provider.Registry
	cookies    cookieJar
	limits     bool
}

func New(d Deps) *Server {
	return &Server{
		cfg: d.Config, store: d.Store, tokens: d.Tokens, identities: d.Identities,
		txs: d.Txs, providers: d.Providers, limits: d.Limits,
		cookies: newCookieJar(d.Config.CookieSecure, d.Config.CookieSameSite),
	}
}

func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(recoverer, accessLog, cors(s.cfg.FrontendURL), bodyLimit(s.cfg.BodyLimit))

	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, r, apperr.NotFound(apperr.CodeNotFound))
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, r, apperr.NotFound(apperr.CodeNotFound))
	})

	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	s.mountDocs(r)

	r.Group(func(r chi.Router) {
		if s.limits {
			r.Use(limit(60, time.Minute))
		}
		r.With(s.requireAccess).Get("/me", s.me)

		r.Route("/auth", func(r chi.Router) {
			if s.limits {
				r.Use(limit(20, time.Minute))
			}
			if s.cfg.DevSPA {
				r.Get("/callback", s.spa)
			}
			r.Get("/{provider}", s.start)
			r.Get("/{provider}/callback", s.callback)

			refresh := r.With(csrf(s.cfg.FrontendURL))
			if s.limits {
				refresh = refresh.With(limit(10, time.Minute))
			}
			refresh.Post("/refresh", s.refresh)
			r.With(csrf(s.cfg.FrontendURL)).Post("/logout", s.logout)

			r.With(s.requireAccess).Post("/link/{provider}", s.link)
			r.With(s.requireAccess).Delete("/link/{provider}", s.unlink)
		})
	})

	if s.cfg.DevSPA {
		r.Get("/", s.spa)
		r.Get("/logo.png", s.logo)
		r.Get("/favicon.ico", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
		r.Get("/settings/accounts", s.spa)
	}
	return r
}
