// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

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
	"time"

	"github.com/fox-toolkit/fox"
)

var errProvider = errors.New("provider unavailable")

type (
	anonymousKey struct{}
	sessionKey   struct{}
)

// AllowAnonymous returns a route option that lets the requests without a session through [Frontend.Middleware]. These
// requests have no access token.
func AllowAnonymous() fox.RouteOption {
	return fox.WithAnnotation(anonymousKey{}, true)
}

// requestState is attached to the request context by the middleware. A nil session is an anonymous request.
type requestState struct {
	session *session
}

// Middleware returns a middleware that authenticates the requests with the session cookie. It rejects cross-origin
// requests, refreshes the access token before it expires, and makes it available with [AccessToken]. Requests without a
// valid session are handled by the unauthorized handler, unless the route has [AllowAnonymous]. The session cookies are
// removed from the request passed to the next handler and from its response.
func (fe *Frontend) Middleware() fox.MiddlewareFunc {
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
	s, err := fe.currentSession(r, pending)
	if err != nil {
		fe.sessionError(c.Writer(), r, err)
		return
	}
	if s == nil {
		if route := c.Route(); route == nil || route.Annotation(anonymousKey{}) == nil {
			for _, line := range pending.Values("Set-Cookie") {
				c.Writer().Header().Add("Set-Cookie", line)
			}
			fe.cfg.unauthorized(c)
			return
		}
	}

	req := r.WithContext(context.WithValue(r.Context(), sessionKey{}, &requestState{session: s}))
	req.Header = r.Header.Clone()
	removeOwnCookies(req.Header)
	w := &cookieWriter{ResponseWriter: c.Writer(), cookies: pending.Values("Set-Cookie")}
	c.SetRequest(req)
	c.SetWriter(w)
	next(c)
	w.commit()
	c.SetWriter(w.ResponseWriter)
	c.SetRequest(r)
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

// currentSession returns the valid session of the request, or nil. The cookies to set on the response are added to h.
func (fe *Frontend) currentSession(r *http.Request, h http.Header) (*session, error) {
	ctx := r.Context()
	s, st, err := fe.readSession(ctx, r.Cookies())
	if errors.Is(err, errNoSession) {
		if st.chunks > 0 {
			fe.logger.InfoContext(ctx, "invalid or ended session", "path", r.URL.Path)
		}
		sessionCookie.clear(h, st.chunks)
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	now := fe.now()
	if !now.Before(s.expires(fe.cfg)) {
		return nil, fe.deleteSession(ctx, h, st)
	}

	// The idle timeout slides by steps of half its duration, so a session is not rewritten on every request.
	dirty := false
	if now.Sub(time.Unix(s.LastSeen, 0)) >= fe.cfg.idleTimeout/2 {
		s.LastSeen = now.Unix()
		dirty = true
	}

	refreshed := false
	if s.Expiry != 0 && !now.Add(s.refreshSkew()).Before(time.Unix(s.Expiry, 0)) {
		expired := !now.Before(time.Unix(s.Expiry, 0))
		switch err := fe.refreshToken(ctx, s); {
		case err == nil:
			dirty, refreshed = true, true
		case errors.Is(err, errSessionEnded) || expired && s.RefreshToken == "":
			fe.logger.InfoContext(ctx, "session ended", "path", r.URL.Path, "error", err)
			return nil, fe.deleteSession(ctx, h, st)
		case expired:
			return nil, fmt.Errorf("%w: %w", errProvider, err)
		}
	}

	if dirty {
		err := fe.writeSession(ctx, h, s, st)
		if errors.Is(err, errNoSession) {
			// The session was ended by another request, such as a back-channel logout, while this one was running.
			fe.logger.InfoContext(ctx, "session ended during the request", "path", r.URL.Path)
			sessionCookie.clear(h, st.chunks)
			if refreshed {
				_ = fe.revoke(ctx, s.RefreshToken)
			}
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

var errNoRefreshToken = errors.New("no refresh token")

func (fe *Frontend) refreshToken(ctx context.Context, s *session) error {
	if s.RefreshToken == "" {
		return errNoRefreshToken
	}
	return fe.refresh(ctx, s)
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
	lines := h["Set-Cookie"]
	if len(lines) == 0 {
		return
	}
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		name, _, _ := strings.Cut(line, "=")
		if !isOwnCookie(name) {
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
