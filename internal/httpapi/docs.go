package httpapi

import (
	_ "embed"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

//go:embed web/openapi.json
var openAPIDocument []byte

//go:embed web/spa.html
var spaPage string

//go:embed web/docs.html
var docsPage []byte

func (s *Server) mountDocs(r chi.Router) {
	r.Group(func(r chi.Router) {
		if s.cfg.DocsUser != "" {
			r.Use(basicAuth(s.cfg.DocsUser, s.cfg.DocsPassword))
		}
		r.Get("/docs", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(docsPage)
		})
		r.Get("/docs-json", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, _ = w.Write(openAPIDocument)
		})
	})
}

func (s *Server) spa(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(strings.Replace(spaPage, "%API%", "", 1)))
}
