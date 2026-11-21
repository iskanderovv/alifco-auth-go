package apperr

import (
	"errors"
	"net/http"
)

type Error struct {
	Code    string
	Status  int
	Message string
}

func (e *Error) Error() string { return e.Message }

func New(code string, status int) *Error {
	return &Error{Code: code, Status: status, Message: code}
}

func (e *Error) WithMessage(message string) *Error {
	return &Error{Code: e.Code, Status: e.Status, Message: message}
}

func Unauthorized(code string) *Error { return New(code, http.StatusUnauthorized) }
func Forbidden(code string) *Error    { return New(code, http.StatusForbidden) }
func NotFound(code string) *Error     { return New(code, http.StatusNotFound) }
func Conflict(code string) *Error     { return New(code, http.StatusConflict) }

func Provider(message string) *Error {
	return &Error{Code: CodeProviderError, Status: http.StatusBadGateway, Message: message}
}

func As(err error) (*Error, bool) {
	var target *Error
	if errors.As(err, &target) {
		return target, true
	}
	return nil, false
}

const (
	CodeTokenMissing      = "token_missing"
	CodeTokenInvalid      = "token_invalid"
	CodeTokenExpired      = "token_expired"
	CodeRefreshMissing    = "refresh_missing"
	CodeRefreshInvalid    = "refresh_invalid"
	CodeRefreshExpired    = "refresh_expired"
	CodeRefreshReused     = "refresh_reused"
	CodeCSRFHeaderMissing = "csrf_header_missing"
	CodeCSRFOriginInvalid = "csrf_origin_invalid"
	CodeRateLimited       = "rate_limited"
	CodeNotFound          = "not_found"
	CodePayloadTooLarge   = "payload_too_large"
	CodeInvalidState      = "invalid_state"
	CodeProviderNotFound  = "provider_not_found"
	CodeProviderError     = "provider_error"
	CodeAccessDenied      = "access_denied"
	CodeIdentityTaken     = "identity_taken"
	CodeAlreadyLinked     = "already_linked"
	CodeNotLinked         = "not_linked"
	CodeLastIdentity      = "last_identity"
	CodeInternal          = "internal_error"
)
