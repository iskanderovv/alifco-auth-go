package httpapi

import (
	"log/slog"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"

	"github.com/iskanderovv/alifco-auth-go/internal/apperr"
	"github.com/iskanderovv/alifco-auth-go/internal/oauthtx"
	"github.com/iskanderovv/alifco-auth-go/internal/provider"
	"github.com/iskanderovv/alifco-auth-go/internal/store"
	"github.com/iskanderovv/alifco-auth-go/internal/token"
)

var redirectErrors = map[string]bool{
	apperr.CodeAccessDenied:  true,
	apperr.CodeInvalidState:  true,
	apperr.CodeProviderError: true,
	apperr.CodeInternal:      true,
	apperr.CodeIdentityTaken: true,
	apperr.CodeAlreadyLinked: true,
}

func meta(r *http.Request) token.RequestMeta {
	return token.RequestMeta{UserAgent: r.UserAgent(), IP: clientIP(r)}
}

func (s *Server) start(w http.ResponseWriter, r *http.Request) {
	p, err := s.providers.Get(chi.URLParam(r, "provider"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	tx, err := s.txs.Start(r.Context(), p.Name(), store.ModeLogin, "")
	if err != nil {
		writeError(w, r, err)
		return
	}
	s.cookies.setTransaction(w, tx.TransactionID)
	http.Redirect(w, r, p.AuthorizationURL(tx.State, tx.CodeChallenge), http.StatusFound)
}

// callback finishes a login or a link. It is a browser navigation, not an API call,
// so every outcome is a redirect to the frontend.
func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	p, err := s.providers.Get(chi.URLParam(r, "provider"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	mode := store.ModeLogin

	target, err := s.finishCallback(w, r, p, &mode)
	s.cookies.clearTransaction(w)
	if err != nil {
		code := s.redirectErrorCode(r, err)
		if mode == store.ModeLink {
			target = s.settingsURL(url.Values{"error": {code}})
		} else {
			target = s.callbackURL(code)
		}
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func (s *Server) finishCallback(w http.ResponseWriter, r *http.Request, p provider.Provider, mode *string) (string, error) {
	query := r.URL.Query()
	if query.Has("error") {
		code := apperr.CodeProviderError
		if query.Get("error") == "access_denied" {
			code = apperr.CodeAccessDenied
		}
		return "", apperr.New(code, http.StatusUnauthorized)
	}

	var txID string
	if c, err := r.Cookie(oauthtx.CookieName); err == nil {
		txID = c.Value
	}
	tx, err := s.txs.Consume(r.Context(), txID, query.Get("state"), p.Name())
	if err != nil {
		return "", err
	}
	*mode = tx.Mode

	code := query.Get("code")
	if code == "" {
		return "", apperr.New(apperr.CodeProviderError, http.StatusBadRequest)
	}
	profile, err := p.Authenticate(r.Context(), code, tx.CodeVerifier)
	if err != nil {
		return "", err
	}

	// Linking never touches the session: no refresh cookie is issued.
	if tx.Mode == store.ModeLink {
		if tx.UserID == "" {
			return "", apperr.New(apperr.CodeInvalidState, http.StatusBadRequest)
		}
		if err := s.identities.Link(r.Context(), tx.UserID, p.Name(), profile); err != nil {
			return "", err
		}
		return s.settingsURL(url.Values{"linked": {p.Name()}}), nil
	}

	user, _, err := s.identities.Login(r.Context(), p.Name(), profile)
	if err != nil {
		return "", err
	}
	refresh, err := s.tokens.IssueRefresh(r.Context(), user.ID, meta(r))
	if err != nil {
		return "", err
	}
	s.cookies.setRefresh(w, refresh.Token, refresh.ExpiresAt)
	return s.callbackURL(""), nil
}

func (s *Server) refresh(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(RefreshCookie)
	if err != nil || c.Value == "" {
		writeError(w, r, apperr.Unauthorized(apperr.CodeRefreshMissing))
		return
	}
	userID, next, err := s.tokens.Rotate(r.Context(), c.Value, meta(r))
	if err != nil {
		if _, known := apperr.As(err); known {
			s.cookies.clearRefresh(w)
		}
		writeError(w, r, err)
		return
	}
	access, err := s.tokens.IssueAccess(userID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	s.cookies.setRefresh(w, next.Token, next.ExpiresAt)
	writeJSON(w, http.StatusOK, access)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(RefreshCookie); err == nil {
		if err := s.tokens.Revoke(r.Context(), c.Value); err != nil {
			writeError(w, r, err)
			return
		}
	}
	s.cookies.clearRefresh(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) link(w http.ResponseWriter, r *http.Request) {
	p, err := s.providers.Get(chi.URLParam(r, "provider"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	tx, err := s.txs.Start(r.Context(), p.Name(), store.ModeLink, userID(r))
	if err != nil {
		writeError(w, r, err)
		return
	}
	s.cookies.setTransaction(w, tx.TransactionID)
	writeJSON(w, http.StatusOK, map[string]string{"url": p.AuthorizationURL(tx.State, tx.CodeChallenge)})
}

func (s *Server) unlink(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "provider")
	if !provider.Known(name) {
		writeError(w, r, apperr.NotFound(apperr.CodeProviderNotFound))
		return
	}
	if err := s.identities.Unlink(r.Context(), userID(r), name); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	user, err := s.store.UserByID(r.Context(), userID(r))
	if err != nil {
		writeError(w, r, apperr.Unauthorized(apperr.CodeTokenInvalid))
		return
	}
	providers, err := s.store.ProvidersOf(r.Context(), user.ID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": user.ID, "name": user.Name, "email": user.Email, "avatarUrl": user.AvatarURL,
		"providers": providers, "createdAt": user.CreatedAt,
	})
}

func (s *Server) settingsURL(params url.Values) string {
	return s.cfg.FrontendURL + "/settings/accounts?" + params.Encode()
}

func (s *Server) callbackURL(errorCode string) string {
	if errorCode == "" {
		return s.cfg.FrontendURL + "/auth/callback"
	}
	return s.cfg.FrontendURL + "/auth/callback?" + url.Values{"error": {errorCode}}.Encode()
}

func (s *Server) redirectErrorCode(r *http.Request, err error) string {
	appErr, ok := apperr.As(err)
	if !ok {
		slog.ErrorContext(r.Context(), "login failed", "error", err)
		return apperr.CodeInternal
	}
	slog.WarnContext(r.Context(), "login failed", "code", appErr.Code, "detail", appErr.Message)
	if redirectErrors[appErr.Code] {
		return appErr.Code
	}
	return apperr.CodeProviderError
}
