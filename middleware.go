// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.

package bff

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/fox-toolkit/fox"
)

var (
	errProvider           = errors.New("provider unavailable")
	errUndeclaredResource = errors.New("undeclared resource")
)

type (
	anonymousKey struct{}
	resourcesKey struct{}
	sessionKey   struct{}
)

// AllowAnonymous returns a [fox.RouteOption] that lets [Frontend.Authenticate] and [Proxy.Authenticate] pass the
// requests without a session to the next handler. For these requests, [AccessToken] and [ResourceAccessToken] return
// false, and [Transport] and [ResourceTransport] do not add an access token.
func AllowAnonymous() fox.RouteOption {
	return fox.WithAnnotation(anonymousKey{}, true)
}

// ForResource returns a [fox.RouteOption] that lets [Frontend.Authenticate] and [Proxy.Authenticate] obtain the access
// tokens of the resources for the next handler, as defined by RFC 8707. The resources must be declared with
// [WithResources].
func ForResource(resources ...string) fox.RouteOption {
	return fox.WithAnnotation(resourcesKey{}, slices.Clone(resources))
}

// requestState is attached to the request context by the middleware. A nil session is an anonymous request. It does
// not change once the next handler runs.
type requestState struct {
	rp      *relyingParty
	session *session
	// request is the request handled by the middleware.
	request *http.Request
	// resources are the resources of the route, whose access tokens the middleware obtained.
	resources []string
}

// Authenticate returns a middleware that authenticates the requests with the session cookie and refreshes the access
// tokens before they expire, including the tokens of the route resources (see [ForResource]). A request without a valid
// session is handled by the unauthorized handler (see [WithUnauthorizedHandler]), unless the route has
// [AllowAnonymous]. Use [AccessToken] or [ResourceAccessToken] to retrieve the tokens in the next handler.
//
// To prevent cross-site request forgery, the middleware responds with 403 Forbidden to a cross-origin request with an
// unsafe method, except from the trusted origins (see [WithTrustedOrigins]), and to a request without the header
// configured with [WithCSRFHeader].
func (fe *Frontend) Authenticate() fox.MiddlewareFunc {
	return func(next fox.HandlerFunc) fox.HandlerFunc {
		return func(c *fox.Context) {
			fe.serve(c, next)
		}
	}
}

func (fe *Frontend) serve(c *fox.Context, next fox.HandlerFunc) {
	rp := fe.rp
	r := c.Request()
	if err := rp.checkCSRF(r); err != nil {
		rp.logRejected(r, "cross-site request", err)
		http.Error(c.Writer(), http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	route := c.Route()
	s, resources, pending, ok := rp.authenticate(c, route)
	if !ok {
		return
	}
	if s == nil && !allowAnonymous(route) {
		addSetCookies(c.Writer().Header(), pending)
		rp.cfg.unauthorized(c)
		return
	}
	forward(c, next, rp.authenticatedRequest(r, s, resources), pending)
}

// authenticate returns the session of the request, or nil, with the resources of the route and the cookies to set on
// the response. When it returns false, it already responded with an error.
func (rp *relyingParty) authenticate(c *fox.Context, route *fox.Route) (*session, []string, http.Header, bool) {
	r := c.Request()
	resources := routeResources(route)
	for _, resource := range resources {
		if !slices.Contains(rp.cfg.resources, resource) {
			rp.logFailed(r, "route resource", fmt.Errorf("%w: %q", errUndeclaredResource, resource))
			internalError(c.Writer())
			return nil, nil, nil, false
		}
	}

	pending := make(http.Header)
	s, err := rp.currentSession(r, pending, resources)
	if err != nil {
		addSetCookies(c.Writer().Header(), pending)
		rp.sessionError(c.Writer(), r, err)
		return nil, nil, nil, false
	}
	return s, resources, pending, true
}

// authenticatedRequest returns the request passed to the next handler, with the state of the middleware and without
// the BFF cookies.
func (rp *relyingParty) authenticatedRequest(r *http.Request, s *session, resources []string) *http.Request {
	rs := &requestState{rp: rp, session: s, request: r, resources: resources}
	req := r.WithContext(context.WithValue(r.Context(), sessionKey{}, rs))
	req.Header = r.Header.Clone()
	removeOwnCookies(req.Header)
	return req
}

// forward calls next with req, and adds the pending cookies to the response.
func forward(c *fox.Context, next fox.HandlerFunc, req *http.Request, pending http.Header) {
	r := c.Request()
	w := &cookieWriter{ResponseWriter: c.Writer(), cookies: pending["Set-Cookie"]}
	c.SetRequest(req)
	c.SetWriter(w)
	next(c)
	w.commit()
	c.SetWriter(w.ResponseWriter)
	c.SetRequest(r)
}

func allowAnonymous(route *fox.Route) bool {
	return route != nil && route.Annotation(anonymousKey{}) != nil
}

func routeResources(route *fox.Route) []string {
	if route == nil {
		return nil
	}
	resources, _ := route.Annotation(resourcesKey{}).([]string)
	return resources
}

func addSetCookies(dst, src http.Header) {
	for _, line := range src.Values("Set-Cookie") {
		dst.Add("Set-Cookie", line)
	}
}

var errCSRFHeader = errors.New("missing or invalid csrf header")

func (rp *relyingParty) checkCSRF(r *http.Request) error {
	if err := rp.cop.Check(r); err != nil {
		return err
	}
	if rp.cfg.csrfHeader != "" && r.Header.Get(rp.cfg.csrfHeader) != rp.cfg.csrfValue {
		return errCSRFHeader
	}
	return nil
}

// sessionError responds to a failure to load or save the session.
func (rp *relyingParty) sessionError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, errProvider) {
		rp.logFailed(r, "provider unavailable", err)
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}
	rp.logFailed(r, "session store", err)
	internalError(w)
}

// currentSession returns the valid session of the request, or nil. It renews the access tokens of the session and of
// the resources when they expire. The cookies to set on the response are added to h.
func (rp *relyingParty) currentSession(r *http.Request, h http.Header, resources []string) (*session, error) {
	ctx := r.Context()
	s, st, err := rp.readSession(ctx, r.Cookies())
	if errors.Is(err, errNoSession) {
		if st.chunks > 0 {
			rp.logger.InfoContext(ctx, "invalid or ended session", "path", r.URL.Path)
		}
		rp.cookie.clear(h, st.chunks)
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	now := rp.now()
	if !now.Before(s.expires(rp.cfg)) {
		return nil, rp.deleteSession(ctx, h, st)
	}
	if (s.DPoPKey != nil) != rp.cfg.dpop {
		// Do not revoke the refresh token. The provider session goes on, and the user can log in again silently.
		rp.logger.InfoContext(ctx, "session ended by a dpop configuration change", "path", r.URL.Path)
		rp.tokens.Forget(s.LogoutCSRFToken)
		return nil, rp.deleteSession(ctx, h, st)
	}

	// The idle timeout slides by steps of half its duration, so a session is not rewritten on every request.
	dirty := false
	if now.Sub(time.Unix(s.LastSeen, 0)) >= rp.cfg.idleTimeout/2 {
		s.LastSeen = now.Unix()
		dirty = true
	}

	// Each token request restarts tr, and so does the write of the renewed tokens.
	var tr tokenRequest
	defer tr.stop()
	renewed := false
	var failed error
	if s.stale(now) {
		changed, err := rp.refreshToken(ctx, s, st, &tr)
		// The token request may have taken long enough for the access token to expire.
		expired := !rp.now().Before(time.Unix(s.Expiry, 0))
		if errors.Is(err, errSessionEnded) || err != nil && expired && s.RefreshToken == "" {
			return nil, rp.deleteEndedSession(ctx, r, h, s, st, err)
		}
		renewed = changed
		// A failed refresh can still replace the refresh token, so the session is saved before the error is returned.
		if err != nil && expired {
			failed = err
		}
	}
	for _, resource := range resources {
		if failed != nil {
			break
		}
		if t, ok := s.Resources[resource]; ok && !t.stale(rp.now()) {
			continue
		}
		changed, err := rp.refreshResource(ctx, s, st, resource, &tr)
		if errors.Is(err, errSessionEnded) {
			return nil, rp.deleteEndedSession(ctx, r, h, s, st, err)
		}
		renewed = renewed || changed
		if err == nil {
			continue
		}
		// Like the access token of the session, the access token of a resource is used while it cannot be renewed.
		if t, ok := s.Resources[resource]; ok && (t.Expiry == 0 || rp.now().Before(time.Unix(t.Expiry, 0))) {
			rp.logFailed(r, "resource access token", err)
			continue
		}
		failed = err
	}

	writeCtx := ctx
	if renewed {
		// The session may hold a new refresh token, and the wait for the lock may have used up the time of the last
		// token request.
		tr.start(ctx)
		dirty, writeCtx = true, tr.ctx
	}
	if dirty {
		err := rp.writeSession(writeCtx, h, s, st)
		if errors.Is(err, errNoSession) {
			// The session was ended by another request, such as a back-channel logout, while this one was running. Do not
			// revoke the refresh token. A login in the same provider session may have replaced this session.
			rp.logger.InfoContext(ctx, "session ended during the request", "path", r.URL.Path)
			rp.cookie.clear(h, st.chunks)
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
	}
	switch {
	case failed == nil:
		return s, nil
	case errors.Is(failed, errStore):
		return nil, failed
	default:
		return nil, fmt.Errorf("%w: %w", errProvider, failed)
	}
}

// deleteEndedSession deletes the session that the provider ended.
func (rp *relyingParty) deleteEndedSession(ctx context.Context, r *http.Request, h http.Header, s *session, st sessionState, err error) error {
	rp.logger.InfoContext(ctx, "session ended", "path", r.URL.Path, "error", err)
	rp.tokens.Forget(s.LogoutCSRFToken)
	// The token request may have used up the time of ctx.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), endSessionTimeout)
	defer cancel()
	return rp.deleteSession(ctx, h, st)
}

var errNoRefreshToken = errors.New("no refresh token")

func (rp *relyingParty) refreshToken(ctx context.Context, s *session, st sessionState, tr *tokenRequest) (bool, error) {
	if s.RefreshToken == "" {
		return false, errNoRefreshToken
	}
	return rp.refresh(ctx, s, st, tr)
}

// isOwnCookie reports whether name is a cookie of a [Frontend] or a [Proxy], whichever serves the request, since both
// can share a host.
func isOwnCookie(name string) bool {
	name = strings.TrimSpace(name)
	return strings.HasPrefix(name, frontendCookie) || strings.HasPrefix(name, proxyCookie) || strings.HasPrefix(name, sharedCookie)
}

func removeOwnCookies(h http.Header) {
	lines := h["Cookie"]
	if len(lines) == 0 {
		return
	}
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		var pairs []string
		for pair := range strings.SplitSeq(line, ";") {
			name, _, _ := strings.Cut(pair, "=")
			if !isOwnCookie(name) {
				pairs = append(pairs, strings.TrimSpace(pair))
			}
		}
		if len(pairs) > 0 {
			kept = append(kept, strings.Join(pairs, "; "))
		}
	}
	if len(kept) == 0 {
		delete(h, "Cookie")
		return
	}
	h["Cookie"] = kept
}

// cookieWriter removes the BFF cookies set by the handler from the response and adds the cookies of the middleware,
// when the header is written.
type cookieWriter struct {
	fox.ResponseWriter
	cookies []string
	done    bool
}

func (w *cookieWriter) commit() {
	if w.done {
		return
	}
	w.done = true
	w.removeOwnCookies()
	if len(w.cookies) > 0 {
		h := w.Header()
		h["Set-Cookie"] = append(h["Set-Cookie"], w.cookies...)
	}
}

func (w *cookieWriter) removeOwnCookies() {
	removeOwnSetCookies(w.Header())
}

// removeOwnSetCookies removes the Set-Cookie lines of the BFF cookies from h.
func removeOwnSetCookies(h http.Header) {
	removeSetCookies(h, isOwnCookie)
}

func removeSetCookies(h http.Header, remove func(name string) bool) {
	lines := h["Set-Cookie"]
	if len(lines) == 0 {
		return
	}
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		name, _, _ := strings.Cut(line, "=")
		if !remove(name) {
			kept = append(kept, line)
		}
	}
	if len(kept) == 0 {
		delete(h, "Set-Cookie")
		return
	}
	h["Set-Cookie"] = kept
}

func (w *cookieWriter) WriteHeader(code int) {
	if code < http.StatusOK {
		w.removeOwnCookies()
	} else {
		w.commit()
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *cookieWriter) Write(b []byte) (int, error) {
	w.commit()
	return w.ResponseWriter.Write(b)
}

func (w *cookieWriter) WriteString(s string) (int, error) {
	w.commit()
	return w.ResponseWriter.WriteString(s)
}

func (w *cookieWriter) ReadFrom(src io.Reader) (int64, error) {
	w.commit()
	return w.ResponseWriter.ReadFrom(src)
}

func (w *cookieWriter) FlushError() error {
	w.commit()
	return w.ResponseWriter.FlushError()
}

// Hijack commits the cookies first, since the reverse proxy writes the header of a protocol upgrade itself.
func (w *cookieWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.commit()
	return w.ResponseWriter.Hijack()
}
