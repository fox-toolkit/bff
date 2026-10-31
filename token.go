// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.

package bff

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

var errRouteResource = errors.New("resource not declared on the route")

// AccessToken returns the access token of a request authenticated by [Frontend.Authenticate]. It reports false for an
// anonymous request and for a request not handled by the middleware. A DPoP-bound access token must be sent with
// [Transport].
func AccessToken(ctx context.Context) (*oauth2.Token, bool) {
	rs, ok := ctx.Value(sessionKey{}).(*requestState)
	if !ok {
		return nil, false
	}
	t, ok := rs.accessToken()
	if !ok {
		return nil, false
	}
	return t.token(), true
}

// ResourceAccessToken returns the access token of the resource for a request authenticated by [Frontend.Authenticate],
// as defined by RFC 8707. It reports false for an anonymous request, for a request not handled by the middleware and
// for a resource that the route does not declare with [ForResource]. A DPoP-bound access token must be sent with
// [ResourceTransport].
func ResourceAccessToken(ctx context.Context, resource string) (*oauth2.Token, bool) {
	rs, ok := ctx.Value(sessionKey{}).(*requestState)
	if !ok {
		return nil, false
	}
	t, ok := rs.resourceToken(resource)
	if !ok {
		return nil, false
	}
	return t.token(), true
}

// Transport returns an [http.RoundTripper] that sets the Authorization header with the access token of the request, as
// returned by [AccessToken]. For a DPoP-bound access token, it also adds a DPoP proof. It does not add an access token
// to an anonymous request. A nil base uses [http.DefaultTransport].
func Transport(base http.RoundTripper) http.RoundTripper {
	return newTransport(base, "", false)
}

// ResourceTransport returns an [http.RoundTripper] that sets the Authorization header with the access token of the
// resource, as returned by [ResourceAccessToken]. For a DPoP-bound access token, it also adds a DPoP proof. It does not
// add an access token to an anonymous request or to a request for a resource that the route does not declare with
// [ForResource]. A nil base uses [http.DefaultTransport].
func ResourceTransport(base http.RoundTripper, resource string) http.RoundTripper {
	return newTransport(base, resource, true)
}

func newTransport(base http.RoundTripper, resource string, scoped bool) *transport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &transport{base: base, nonces: newNonceCache(), resource: resource, scoped: scoped}
}

type transport struct {
	base     http.RoundTripper
	nonces   *nonceCache
	resource string
	scoped   bool
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
	rs, ok := r.Context().Value(sessionKey{}).(*requestState)
	if !ok || rs.session == nil || crossHostRedirect(r) {
		return t.base.RoundTrip(r)
	}
	var token resourceToken
	if t.scoped {
		if token, ok = rs.resourceToken(t.resource); !ok {
			rs.fe.logFailed(rs.request, "resource access token", fmt.Errorf("%w: %q", errRouteResource, t.resource))
			return t.base.RoundTrip(r)
		}
	} else if token, ok = rs.accessToken(); !ok {
		return t.base.RoundTrip(r)
	}
	if dpopKey := rs.session.DPoPKey; dpopKey != nil {
		key, err := parseDPoPKey(dpopKey)
		if err != nil {
			return nil, err
		}
		return sendDPoP(t.base, t.nonces, key, r, token.AccessToken, time.Now())
	}
	// A RoundTripper must not modify the request it is given.
	r = r.Clone(r.Context())
	(&oauth2.Token{AccessToken: token.AccessToken, TokenType: token.TokenType}).SetAuthHeader(r)
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

// accessToken returns the access token of the session.
func (rs *requestState) accessToken() (resourceToken, bool) {
	s := rs.session
	if s == nil || s.AccessToken == "" {
		return resourceToken{}, false
	}
	return resourceToken{AccessToken: s.AccessToken, TokenType: s.TokenType, Expiry: s.Expiry}, true
}

// resourceToken returns the access token of a resource of the route, which the middleware obtained.
func (rs *requestState) resourceToken(resource string) (resourceToken, bool) {
	if rs.session == nil || !slices.Contains(rs.resources, resource) {
		return resourceToken{}, false
	}
	t, ok := rs.session.Resources[resource]
	return t, ok
}

// UserClaims returns the claims about the user of a request authenticated by [Frontend.Authenticate], as returned by
// [Frontend.UserHandler]. It reports false for an anonymous request and for a request not handled by the middleware.
func UserClaims(ctx context.Context) (map[string]any, bool) {
	rs, ok := ctx.Value(sessionKey{}).(*requestState)
	if !ok {
		return nil, false
	}
	if rs.session == nil {
		return nil, false
	}
	claims, err := rs.session.claims()
	if err != nil {
		return nil, false
	}
	return claims, true
}
