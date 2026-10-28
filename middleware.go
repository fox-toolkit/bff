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
	"strings"
	"sync"
	"time"

	"github.com/fox-toolkit/fox"
)

var errProvider = errors.New("provider unavailable")

type (
	anonymousKey struct{}
	sessionKey   struct{}
)

// AllowAnonymous returns a route option that lets the requests without a session through [Frontend.Authenticate]. These
// requests have no access token.
func AllowAnonymous() fox.RouteOption {
	return fox.WithAnnotation(anonymousKey{}, true)
}

// requestState is attached to the request context by the middleware. A nil session is an anonymous request. The
// session is changed when the access token of a resource is requested, so it is read and changed with mu.
type requestState struct {
	fe      *Frontend
	c       *fox.Context
	session *session
	// request is the request handled by the middleware.
	request *http.Request
	st      sessionState
	cookies pendingCookies
	mu      sync.Mutex
	// anonymous reports whether the route lets the requests without session through. The route is read by the
	// middleware, since c is only valid while the handler runs.
	anonymous bool
}

// pendingCookies are the Set-Cookie lines the middleware adds to the response when its header is written.
type pendingCookies struct {
	lines []string
	mu    sync.Mutex
	sent  bool
}

func (c *pendingCookies) started() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sent
}

// Authenticate returns a middleware that authenticates the requests with the session cookie. It rejects cross-origin
// requests with an unsafe method, except from the trusted origins (see [WithTrustedOrigins]), refreshes the access
// token before it expires, and makes it available with [AccessToken]. Requests without a valid session are handled by
// the unauthorized handler, unless the route has [AllowAnonymous]. The session cookies are removed from the request
// passed to the next handler and from its response.
func (fe *Frontend) Authenticate() fox.MiddlewareFunc {
	return func(next fox.HandlerFunc) fox.HandlerFunc {
		return func(c *fox.Context) {
			fe.serve(c, next)
		}
	}
}

func (fe *Frontend) serve(c *fox.Context, next fox.HandlerFunc) {
	r := c.Request()
	if err := fe.checkCSRF(r); err != nil {
		fe.logRejected(r, "cross-site request", err)
		http.Error(c.Writer(), http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	pending := make(http.Header)
	s, st, err := fe.currentSession(r, pending)
	if err != nil {
		addSetCookies(c.Writer().Header(), pending)
		fe.sessionError(c.Writer(), r, err)
		return
	}
	if s == nil && !allowAnonymous(c) {
		addSetCookies(c.Writer().Header(), pending)
		fe.cfg.unauthorized(c)
		return
	}

	rs := &requestState{fe: fe, c: c, session: s, request: r, st: st, anonymous: allowAnonymous(c)}
	rs.cookies.lines = pending["Set-Cookie"]
	req := r.WithContext(context.WithValue(r.Context(), sessionKey{}, rs))
	req.Header = r.Header.Clone()
	removeOwnCookies(req.Header)
	w := &cookieWriter{ResponseWriter: c.Writer(), cookies: &rs.cookies}
	c.SetRequest(req)
	c.SetWriter(w)
	next(c)
	w.commit()
	c.SetWriter(w.ResponseWriter)
	c.SetRequest(r)
}

// Unauthorized responds with the unauthorized handler of the frontend, such as in a handler when [ResourceAccessToken]
// returns [ErrNoSession].
func (fe *Frontend) Unauthorized(c *fox.Context) {
	fe.cfg.unauthorized(c)
}

func allowAnonymous(c *fox.Context) bool {
	route := c.Route()
	return route != nil && route.Annotation(anonymousKey{}) != nil
}

func addSetCookies(dst, src http.Header) {
	for _, line := range src.Values("Set-Cookie") {
		dst.Add("Set-Cookie", line)
	}
}

var errCSRFHeader = errors.New("missing or invalid csrf header")

func (fe *Frontend) checkCSRF(r *http.Request) error {
	if err := fe.cop.Check(r); err != nil {
		return err
	}
	if fe.cfg.csrfHeader != "" && r.Header.Get(fe.cfg.csrfHeader) != fe.cfg.csrfValue {
		return errCSRFHeader
	}
	return nil
}

// sessionError responds to a failure to load or save the session.
func (fe *Frontend) sessionError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, errProvider) {
		fe.logFailed(r, "provider unavailable", err)
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}
	fe.logFailed(r, "session store", err)
	internalError(w)
}

// currentSession returns the valid session of the request with the state of its cookie, or nil. The cookies to set on
// the response are added to h.
func (fe *Frontend) currentSession(r *http.Request, h http.Header) (*session, sessionState, error) {
	ctx := r.Context()
	s, st, err := fe.readSession(ctx, r.Cookies())
	if errors.Is(err, ErrNoSession) {
		if st.chunks > 0 {
			fe.logger.InfoContext(ctx, "invalid or ended session", "path", r.URL.Path)
		}
		sessionCookie.clear(h, st.chunks)
		return nil, st, nil
	}
	if err != nil {
		return nil, st, err
	}

	now := fe.now()
	if !now.Before(s.expires(fe.cfg)) {
		return nil, st, fe.deleteSession(ctx, h, st)
	}
	if (s.DPoPKey != nil) != fe.cfg.dpop {
		// Do not revoke the refresh token. The provider session goes on, and the user can log in again silently.
		fe.logger.InfoContext(ctx, "session ended by a dpop configuration change", "path", r.URL.Path)
		fe.tokens.Forget(s.LogoutCSRFToken)
		return nil, st, fe.deleteSession(ctx, h, st)
	}

	// The idle timeout slides by steps of half its duration, so a session is not rewritten on every request.
	dirty := false
	if now.Sub(time.Unix(s.LastSeen, 0)) >= fe.cfg.idleTimeout/2 {
		s.LastSeen = now.Unix()
		dirty = true
	}

	writeCtx := ctx
	var failed error
	if s.stale(now) {
		expired := !now.Before(time.Unix(s.Expiry, 0))
		var tr tokenRequest
		defer tr.stop()
		changed, err := fe.refreshToken(ctx, s, st, &tr)
		if errors.Is(err, errSessionEnded) || err != nil && expired && s.RefreshToken == "" {
			fe.logger.InfoContext(ctx, "session ended", "path", r.URL.Path, "error", err)
			fe.tokens.Forget(s.LogoutCSRFToken)
			return nil, st, fe.deleteSession(ctx, h, st)
		}
		if changed {
			dirty, writeCtx = true, tr.ctx
		}
		// A failed refresh can still replace the refresh token, so the session is saved before the error is returned.
		if err != nil && expired {
			failed = err
		}
	}

	if dirty {
		err := fe.writeSession(writeCtx, h, s, st)
		if errors.Is(err, ErrNoSession) {
			// The session was ended by another request, such as a back-channel logout, while this one was running. Do not
			// revoke the refresh token. A login in the same provider session may have replaced this session.
			fe.logger.InfoContext(ctx, "session ended during the request", "path", r.URL.Path)
			sessionCookie.clear(h, st.chunks)
			return nil, st, nil
		}
		if err != nil {
			return nil, st, err
		}
	}
	switch {
	case failed == nil:
		return s, st, nil
	case errors.Is(failed, errStore):
		return nil, st, failed
	default:
		return nil, st, fmt.Errorf("%w: %w", errProvider, failed)
	}
}

var errNoRefreshToken = errors.New("no refresh token")

func (fe *Frontend) refreshToken(ctx context.Context, s *session, st sessionState, tr *tokenRequest) (bool, error) {
	if s.RefreshToken == "" {
		return false, errNoRefreshToken
	}
	return fe.refresh(ctx, s, st, tr)
}

func isOwnCookie(name string) bool {
	return strings.HasPrefix(strings.TrimSpace(name), cookiePrefix+"bff")
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
	cookies *pendingCookies
	done    bool
}

func (w *cookieWriter) commit() {
	if w.done {
		return
	}
	w.done = true
	w.removeOwnCookies()
	w.cookies.mu.Lock()
	w.cookies.sent = true
	lines := w.cookies.lines
	w.cookies.mu.Unlock()
	if len(lines) > 0 {
		h := w.Header()
		h["Set-Cookie"] = append(h["Set-Cookie"], lines...)
	}
}

func (w *cookieWriter) removeOwnCookies() {
	removeOwnSetCookies(w.Header())
}

// removeOwnSetCookies removes the Set-Cookie lines of the BFF cookies from h.
func removeOwnSetCookies(h http.Header) {
	removeSetCookies(h, isOwnCookie)
}

// removeSessionSetCookies removes the Set-Cookie lines of the session cookie from h.
func removeSessionSetCookies(h http.Header) {
	removeSetCookies(h, func(name string) bool { return strings.HasPrefix(name, sessionCookie.name+".") })
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
