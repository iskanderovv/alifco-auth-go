package httpapi

import (
	"net/http"
	"time"

	"github.com/iskanderovv/alifco-auth-go/internal/oauthtx"
)

const RefreshCookie = "refresh_token"

type cookieJar struct {
	secure   bool
	sameSite http.SameSite
}

func newCookieJar(secure bool, sameSite string) cookieJar {
	mode := http.SameSiteLaxMode
	if sameSite == "none" {
		mode = http.SameSiteNoneMode
	}
	return cookieJar{secure: secure, sameSite: mode}
}

func (j cookieJar) base(name string) *http.Cookie {
	return &http.Cookie{Name: name, Path: "/auth", HttpOnly: true, Secure: j.secure, SameSite: j.sameSite}
}

func (j cookieJar) setRefresh(w http.ResponseWriter, token string, expires time.Time) {
	c := j.base(RefreshCookie)
	c.Value, c.Expires = token, expires
	http.SetCookie(w, c)
}

func (j cookieJar) clearRefresh(w http.ResponseWriter) { j.clear(w, RefreshCookie) }

func (j cookieJar) setTransaction(w http.ResponseWriter, id string) {
	c := j.base(oauthtx.CookieName)
	c.Value, c.MaxAge = id, int(oauthtx.TTL.Seconds())
	http.SetCookie(w, c)
}

func (j cookieJar) clearTransaction(w http.ResponseWriter) { j.clear(w, oauthtx.CookieName) }

func (j cookieJar) clear(w http.ResponseWriter, name string) {
	c := j.base(name)
	c.MaxAge = -1
	http.SetCookie(w, c)
}
