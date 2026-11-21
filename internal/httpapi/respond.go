package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/iskanderovv/alifco-auth-go/internal/apperr"
)

type errorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, r *http.Request, err error) {
	appErr, ok := apperr.As(err)
	if !ok {
		slog.ErrorContext(r.Context(), "unexpected error", "error", err, "path", r.URL.Path)
		appErr = apperr.New(apperr.CodeInternal, http.StatusInternalServerError)
	}
	var body errorBody
	body.Error.Code = appErr.Code
	body.Error.Message = appErr.Code
	writeJSON(w, appErr.Status, body)
}
