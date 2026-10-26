// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

var (
	errUndeclaredResource = errors.New("undeclared resource")
	errResponseStarted    = errors.New("response already started")
)

// AccessToken returns the access token of a request authenticated by [Frontend.Authenticate]. It reports false for an
// anonymous request and for a request not handled by the middleware. The returned token has no refresh token. A
// DPoP-bound access token must be sent with [Transport].
func AccessToken(ctx context.Context) (*oauth2.Token, bool) {
	rs, ok := ctx.Value(sessionKey{}).(*requestState)
	if !ok {
		return nil, false
	}
	t, _, err := rs.accessToken(ctx, "")
	if err != nil {
		return nil, false
	}
	return t.token(), true
}

// ResourceAccessToken returns the access token of the resource for a request authenticated by [Frontend.Authenticate],
// as defined by RFC 8707. The resource must be declared with [WithResources]. The token is requested from the provider
// when the session has none or when it expires. It returns [ErrNoSession] for an anonymous request, for a request not
// handled by the middleware and when the provider ends the session. The returned token has no refresh token. A
// DPoP-bound access token must be sent with [ResourceTransport].
//
// With a session kept in the cookie, the token must be requested before the response is written, so the new cookie can
// be set.
func ResourceAccessToken(ctx context.Context, resource string) (*oauth2.Token, error) {
	rs, ok := ctx.Value(sessionKey{}).(*requestState)
	if !ok {
		return nil, ErrNoSession
	}
	t, _, err := rs.accessToken(ctx, resource)
	if err != nil {
		return nil, err
	}
	return t.token(), nil
}

// Transport returns an [http.RoundTripper] that sets the Authorization header from the access token of the request
// context, as returned by [AccessToken], and the DPoP proof of a DPoP-bound access token. A request without access
// token is sent unchanged. A nil base uses [http.DefaultTransport].
func Transport(base http.RoundTripper) http.RoundTripper {
	return newTransport(base, "")
}

// ResourceTransport returns an [http.RoundTripper] like [Transport], with the access token of the resource as returned
// by [ResourceAccessToken]. A request without session on a route with [AllowAnonymous] and a request for a resource
// that is not declared are sent unchanged. A request fails without being sent when the access token cannot be
// obtained, with [ErrNoSession] when the provider ends the session. The reverse proxy should use [ProxyErrorHandler].
func ResourceTransport(base http.RoundTripper, resource string) http.RoundTripper {
	return newTransport(base, resource)
}

// ProxyErrorHandler is an ErrorHandler for an [httputil.ReverseProxy] that uses [Transport] or [ResourceTransport]. A
// request whose session ended gets the response of the unauthorized handler. The other errors are logged and respond
// with 502 Bad Gateway, or 500 Internal Server Error for a failure of the session store. It must only be called by the
// reverse proxy.
func ProxyErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	rs, ok := r.Context().Value(sessionKey{}).(*requestState)
	if !ok || rs.c == nil {
		log.Printf("bff: proxy error: %v", err)
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}
	switch {
	case errors.Is(err, ErrNoSession):
		rs.fe.cfg.unauthorized(rs.c)
	case errors.Is(err, errStore):
		rs.fe.logFailed(rs.request, "session store", err)
		internalError(w)
	default:
		rs.fe.logFailed(rs.request, "proxy", err)
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
	}
}

func newTransport(base http.RoundTripper, resource string) *transport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &transport{base: base, nonces: newNonceCache(), resource: resource}
}

type transport struct {
	base     http.RoundTripper
	nonces   *nonceCache
	resource string
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
	if !ok || crossHostRedirect(r) {
		return t.base.RoundTrip(r)
	}
	token, dpopKey, err := rs.accessToken(r.Context(), t.resource)
	switch {
	case errors.Is(err, ErrNoSession) && rs.anonymous:
		return t.base.RoundTrip(r)
	case errors.Is(err, errUndeclaredResource):
		rs.fe.logFailed(rs.request, "resource access token", err)
		return t.base.RoundTrip(r)
	case err != nil:
		return nil, err
	}
	if dpopKey != nil {
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

// accessToken returns the access token of the resource, or the access token of the session when the resource is empty,
// with the DPoP key of the session.
func (rs *requestState) accessToken(ctx context.Context, resource string) (resourceToken, []byte, error) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	s := rs.session
	if s == nil {
		return resourceToken{}, nil, ErrNoSession
	}
	if resource == "" {
		if s.AccessToken == "" {
			return resourceToken{}, nil, ErrNoSession
		}
		return resourceToken{AccessToken: s.AccessToken, TokenType: s.TokenType, Expiry: s.Expiry}, s.DPoPKey, nil
	}

	fe := rs.fe
	if !slices.Contains(fe.cfg.resources, resource) {
		return resourceToken{}, nil, fmt.Errorf("%w: %q", errUndeclaredResource, resource)
	}
	if t, ok := s.Resources[resource]; ok && !t.stale(fe.now()) {
		return t, s.DPoPKey, nil
	}
	if fe.cfg.store == nil && rs.cookies.started() {
		return rs.validToken(resource, errResponseStarted)
	}

	var tr tokenRequest
	defer tr.stop()
	changed, err := fe.updateTokens(ctx, s, rs.st, &tr, func() (bool, error) {
		if t, ok := s.Resources[resource]; ok && !t.stale(fe.now()) {
			return false, nil
		}
		if s.RefreshToken == "" {
			return false, errNoRefreshToken
		}
		res, err := fe.redeem(tr.ctx, s, resource)
		if err != nil {
			return keepRefreshToken(s, res, err)
		}
		s.setResourceToken(resource, res.token, res.at)
		if res.idToken != "" {
			s.IDToken = res.idToken
		}
		return true, nil
	})
	if errors.Is(err, errSessionEnded) {
		fe.logger.InfoContext(ctx, "session ended", "path", rs.request.URL.Path, "error", err)
		rs.end(tr.ctx)
		return resourceToken{}, nil, fmt.Errorf("%w: %w", ErrNoSession, err)
	}
	if changed {
		// A failed request can still replace the refresh token, so the session is saved before the error is returned.
		werr := rs.write(tr.ctx)
		if errors.Is(werr, ErrNoSession) {
			// The session was ended by another request, such as a back-channel logout, while this one was running.
			fe.logger.InfoContext(ctx, "session ended during the request", "path", rs.request.URL.Path)
			_ = fe.revoke(tr.ctx, s.RefreshToken)
			rs.end(tr.ctx)
			return resourceToken{}, nil, ErrNoSession
		}
		if err == nil {
			err = werr
		}
	}
	if err != nil {
		return rs.validToken(resource, err)
	}
	return s.Resources[resource], s.DPoPKey, nil
}

// validToken returns the access token of the resource when it has not expired, as the middleware keeps using the
// access token of the session while it cannot be renewed. It returns err otherwise.
func (rs *requestState) validToken(resource string, err error) (resourceToken, []byte, error) {
	s := rs.session
	t, ok := s.Resources[resource]
	if !ok || t.Expiry != 0 && !rs.fe.now().Before(time.Unix(t.Expiry, 0)) {
		return resourceToken{}, nil, err
	}
	rs.fe.logFailed(rs.request, "resource access token", err)
	return t, s.DPoPKey, nil
}

// write saves the session after the middleware wrote it, and replaces the session cookie of the response.
func (rs *requestState) write(ctx context.Context) error {
	if rs.fe.cfg.store != nil {
		return rs.fe.writeSession(ctx, make(http.Header), rs.session, rs.st)
	}
	c := &rs.cookies
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sent {
		return errResponseStarted
	}
	h := http.Header{"Set-Cookie": c.lines}
	removeSessionSetCookies(h)
	err := rs.fe.writeSession(ctx, h, rs.session, rs.st)
	c.lines = h["Set-Cookie"]
	return err
}

// end deletes the session, which the request no longer has.
func (rs *requestState) end(ctx context.Context) {
	// The token request may have used up the time of ctx.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), endSessionTimeout)
	defer cancel()
	rs.fe.tokens.Forget(rs.session.LogoutCSRFToken)
	rs.session = nil
	c := &rs.cookies
	c.mu.Lock()
	defer c.mu.Unlock()
	h := http.Header{"Set-Cookie": c.lines}
	removeSessionSetCookies(h)
	_ = rs.fe.deleteSession(ctx, h, rs.st)
	if !c.sent {
		c.lines = h["Set-Cookie"]
	}
}

// UserClaims returns the claims about the user of a request authenticated by [Frontend.Authenticate], as returned by
// [Frontend.UserHandler]. It reports false for an anonymous request and for a request not handled by the middleware.
func UserClaims(ctx context.Context) (map[string]any, bool) {
	rs, ok := ctx.Value(sessionKey{}).(*requestState)
	if !ok {
		return nil, false
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.session == nil {
		return nil, false
	}
	claims, err := rs.session.claims()
	if err != nil {
		return nil, false
	}
	return claims, true
}
