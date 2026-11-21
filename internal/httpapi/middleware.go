package httpapi

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/httprate"

	"github.com/iskanderovv/alifco-auth-go/internal/apperr"
	"github.com/iskanderovv/alifco-auth-go/internal/secure"
)

type ctxKey string

const userIDKey ctxKey = "userID"

func userID(r *http.Request) string {
	id, _ := r.Context().Value(userIDKey).(string)
	return id
}

func clientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func limit(requests int, window time.Duration) func(http.Handler) http.Handler {
	return httprate.LimitBy(requests, window,
		func(r *http.Request) (string, error) { return clientIP(r), nil },
		httprate.WithLimitHandler(func(w http.ResponseWriter, r *http.Request) {
			writeError(w, r, apperr.New(apperr.CodeRateLimited, http.StatusTooManyRequests))
		}),
	)
}

func recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.ErrorContext(r.Context(), "panic", "value", rec, "path", r.URL.Path)
				writeError(w, r, apperr.New(apperr.CodeInternal, http.StatusInternalServerError))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		slog.InfoContext(r.Context(), "request",
			"method", r.Method, "path", r.URL.Path, "status", sw.status,
			"ms", time.Since(started).Milliseconds())
	})
}

func bodyLimit(max int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > max {
				writeError(w, r, apperr.New(apperr.CodePayloadTooLarge, http.StatusRequestEntityTooLarge))
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, max)
			next.ServeHTTP(w, r)
		})
	}
}

func cors(origin string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Origin") == origin {
				h := w.Header()
				h.Set("Access-Control-Allow-Origin", origin)
				h.Set("Access-Control-Allow-Credentials", "true")
				h.Add("Vary", "Origin")
				if r.Method == http.MethodOptions {
					h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Requested-With")
					h.Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
					w.WriteHeader(http.StatusNoContent)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func csrf(frontendURL string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Requested-With") != "fetch" {
				writeError(w, r, apperr.Forbidden(apperr.CodeCSRFHeaderMissing))
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" && origin != frontendURL {
				writeError(w, r, apperr.Forbidden(apperr.CodeCSRFOriginInvalid))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (s *Server) requireAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || raw == "" {
			writeError(w, r, apperr.Unauthorized(apperr.CodeTokenMissing))
			return
		}
		id, err := s.tokens.VerifyAccess(raw)
		if err != nil {
			writeError(w, r, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userIDKey, id)))
	})
}

func basicAuth(user, password string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotUser, gotPassword, ok := r.BasicAuth()
			userOK := secure.Equal(gotUser, user)
			passwordOK := secure.Equal(gotPassword, password)
			if !ok || !userOK || !passwordOK {
				w.Header().Set("WWW-Authenticate", `Basic realm="API docs", charset="UTF-8"`)
				http.Error(w, "Authentication required", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
