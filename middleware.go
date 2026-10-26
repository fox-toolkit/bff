// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"context"
	"errors"
	"fmt"
	"io"
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
// requests, refreshes the access token before it expires, and makes it available with [Token]. Requests without a
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
	if !fe.checkCSRF(r) {
		http.Error(c.Writer(), http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	pending := make(http.Header)
	s, err := fe.currentSession(r, pending)
	if err != nil {
		if errors.Is(err, errProvider) {
			http.Error(c.Writer(), http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		} else {
			internalError(c.Writer())
		}
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

func (fe *Frontend) checkCSRF(r *http.Request) bool {
	return fe.cop.Check(r) == nil && (fe.cfg.csrfHeader == "" || r.Header.Get(fe.cfg.csrfHeader) == fe.cfg.csrfValue)
}

// currentSession returns the valid session of the request, or nil. The cookies to set on the response are added to h.
func (fe *Frontend) currentSession(r *http.Request, h http.Header) (*session, error) {
	ctx := r.Context()
	s, st, err := fe.readSession(ctx, r.Cookies())
	if errors.Is(err, errNoSession) {
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

	if s.Expiry != 0 && !now.Add(refreshSkew).Before(time.Unix(s.Expiry, 0)) {
		expired := !now.Before(time.Unix(s.Expiry, 0))
		switch err := fe.refreshToken(ctx, s); {
		case err == nil:
			dirty = true
		case errors.Is(err, errSessionEnded) || expired && s.RefreshToken == "":
			return nil, fe.deleteSession(ctx, h, st)
		case expired:
			return nil, fmt.Errorf("%w: %w", errProvider, err)
		}
	}

	if dirty {
		if err := fe.writeSession(ctx, h, s, st); err != nil {
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
	h := w.Header()
	lines := h["Set-Cookie"]
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
