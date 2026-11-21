package provider

import (
	"io"
	"net/http"
	"net/url"
)

func limited(resp *http.Response) io.Reader { return io.LimitReader(resp.Body, maxBody) }

func closeBody(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
	_ = resp.Body.Close()
}

func authorizationURL(base string, query url.Values) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	u.RawQuery = query.Encode()
	return u.String()
}

func verifiedEmail(v any) bool {
	switch value := v.(type) {
	case bool:
		return value
	case string:
		return value == "true"
	default:
		return false
	}
}
