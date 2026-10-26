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
// anonymous request and for a request not handled by the middleware. The returned token has no refresh token. A
// DPoP-bound access token must be sent with [Transport].
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
// context, as returned by [AccessToken], and the DPoP proof of a DPoP-bound access token. A request without access
// token is sent unchanged. A nil base uses [http.DefaultTransport].
func Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &transport{base: base, nonces: newNonceCache()}
}

type transport struct {
	base   http.RoundTripper
	nonces *nonceCache
}

func (t *transport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.send(r)
	if err != nil {
		return nil, err
	}
	// The middleware cannot filter the response of a protocol upgrade, which the reverse proxy writes after hijacking
	// the connection.
	removeOwnSetCookies(resp.Header)
	return resp, nil
}

func (t *transport) send(r *http.Request) (*http.Response, error) {
	st, ok := r.Context().Value(sessionKey{}).(*requestState)
	if !ok || st.session == nil || st.session.AccessToken == "" || crossHostRedirect(r) {
		return t.base.RoundTrip(r)
	}
	s := st.session
	if s.DPoPKey != nil {
		key, err := parseDPoPKey(s.DPoPKey)
		if err != nil {
			return nil, err
		}
		return sendDPoP(t.base, t.nonces, key, r, s.AccessToken, time.Now())
	}
	// A RoundTripper must not modify the request it is given.
	r = r.Clone(r.Context())
	(&oauth2.Token{AccessToken: s.AccessToken, TokenType: s.TokenType}).SetAuthHeader(r)
	return t.base.RoundTrip(r)
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

// UserClaims returns the claims about the user of a request authenticated by [Frontend.Middleware], as returned by
// [Frontend.UserHandler]. It reports false for an anonymous request and for a request not handled by the middleware.
func UserClaims(ctx context.Context) (map[string]any, bool) {
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
