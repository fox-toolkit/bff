// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"context"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

// Token returns the access token of a request authenticated by [Frontend.Middleware]. It reports false for an
// anonymous request and for a request not handled by the middleware. The returned token has no refresh token.
func Token(ctx context.Context) (*oauth2.Token, bool) {
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
// context, as returned by [Token]. A request without access token is sent unchanged. A nil base uses
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
	token, ok := Token(r.Context())
	if !ok {
		return t.base.RoundTrip(r)
	}
	// A RoundTripper must not modify the request it is given.
	r = r.Clone(r.Context())
	token.SetAuthHeader(r)
	return t.base.RoundTrip(r)
}
