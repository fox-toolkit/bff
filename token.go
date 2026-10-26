// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"context"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// AccessToken returns the access token of a request authenticated by [Frontend.Middleware]. It reports false for an
// anonymous request and for a request not handled by the middleware. The returned token has no refresh token.
func AccessToken(ctx context.Context) (*oauth2.Token, bool) {
	st, ok := ctx.Value(sessionKey{}).(*requestState)
	if !ok || st.session == nil || st.session.AccessToken == "" {
		return nil, false
	}
	s := st.session
	token := &oauth2.Token{AccessToken: s.AccessToken, TokenType: s.TokenType}
	if s.Expiry != 0 {
		token.Expiry = time.Unix(s.Expiry, 0)
	}
	return token, true
}

// Transport returns an [http.RoundTripper] that sets the Authorization header from the access token of the request
// context, as returned by [AccessToken]. A request without access token is sent unchanged. A nil base uses
// [http.DefaultTransport].
func Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &transport{base: base}
}

type transport struct {
	base http.RoundTripper
}

func (t *transport) RoundTrip(r *http.Request) (*http.Response, error) {
	if token, ok := AccessToken(r.Context()); ok && !crossHostRedirect(r) {
		// A RoundTripper must not modify the request it is given.
		r = r.Clone(r.Context())
		token.SetAuthHeader(r)
	}
	resp, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	// The middleware cannot filter the response of a protocol upgrade, which the reverse proxy writes after hijacking
	// the connection.
	removeOwnSetCookies(resp.Header)
	return resp, nil
}

// crossHostRedirect reports whether r follows a redirect to another host than the original request. The access token
// is not sent there, as http.Client does not send the Authorization header there either.
func crossHostRedirect(r *http.Request) bool {
	origin := r
	for origin.Response != nil && origin.Response.Request != nil {
		origin = origin.Response.Request
	}
	return origin != r && !strings.EqualFold(origin.URL.Host, r.URL.Host)
}

// Claims returns the claims of the user of a request authenticated by [Frontend.Middleware], as returned by
// [Frontend.UserHandler]. It reports false for an anonymous request and for a request not handled by the middleware.
func Claims(ctx context.Context) (map[string]any, bool) {
	st, ok := ctx.Value(sessionKey{}).(*requestState)
	if !ok || st.session == nil {
		return nil, false
	}
	claims, err := st.session.claims()
	if err != nil {
		return nil, false
	}
	return claims, true
}
