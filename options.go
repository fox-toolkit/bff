// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/fox-toolkit/bff/store"
	"github.com/fox-toolkit/fox"
	"golang.org/x/net/http/httpguts"
)

var ErrInvalidConfig = errors.New("invalid config")

const (
	// DefaultIdleTimeout is the default idle timeout of a session.
	DefaultIdleTimeout = 30 * time.Minute
	// DefaultAbsoluteTimeout is the default absolute timeout of a session.
	DefaultAbsoluteTimeout = 8 * time.Hour
)

// Option configures a [Frontend].
type Option interface {
	apply(*config) error
}

type optionFunc func(*config) error

func (f optionFunc) apply(c *config) error {
	return f(c)
}

type config struct {
	logHandler      slog.Handler
	store           store.Store
	unauthorized    fox.HandlerFunc
	csrfHeader      string
	csrfValue       string
	idleTimeout     time.Duration
	absoluteTimeout time.Duration
	userInfo        bool
}

func defaultConfig() *config {
	return &config{
		logHandler:      slog.DiscardHandler,
		unauthorized:    DefaultUnauthorized,
		idleTimeout:     DefaultIdleTimeout,
		absoluteTimeout: DefaultAbsoluteTimeout,
	}
}

// WithStore keeps the sessions in the store, and the session cookie only contains a key to its session. By default,
// the session is kept in the cookie.
func WithStore(s store.Store) Option {
	return optionFunc(func(c *config) error {
		if s == nil {
			return fmt.Errorf("%w: nil store", ErrInvalidConfig)
		}
		c.store = s
		return nil
	})
}

// WithLogHandler sets the handler of the logs written when a request is rejected or fails. By default, nothing is
// logged.
func WithLogHandler(h slog.Handler) Option {
	return optionFunc(func(c *config) error {
		if h == nil {
			return fmt.Errorf("%w: nil log handler", ErrInvalidConfig)
		}
		c.logHandler = h
		return nil
	})
}

// WithIdleTimeout sets the duration of inactivity after which a session ends. The default is [DefaultIdleTimeout].
func WithIdleTimeout(d time.Duration) Option {
	return optionFunc(func(c *config) error {
		if d <= 0 {
			return fmt.Errorf("%w: idle timeout must be positive", ErrInvalidConfig)
		}
		c.idleTimeout = d
		return nil
	})
}

// WithAbsoluteTimeout sets the maximum lifetime of a session. The default is [DefaultAbsoluteTimeout].
func WithAbsoluteTimeout(d time.Duration) Option {
	return optionFunc(func(c *config) error {
		if d <= 0 {
			return fmt.Errorf("%w: absolute timeout must be positive", ErrInvalidConfig)
		}
		c.absoluteTimeout = d
		return nil
	})
}

// WithUserInfo requests the UserInfo endpoint at login and adds its claims to the ID token claims.
func WithUserInfo() Option {
	return optionFunc(func(c *config) error {
		c.userInfo = true
		return nil
	})
}

// WithCSRFHeader requires the header with the given value on the requests handled by [Frontend.Middleware] and
// [Frontend.UserHandler].
func WithCSRFHeader(name, value string) Option {
	return optionFunc(func(c *config) error {
		if !httpguts.ValidHeaderFieldName(name) {
			return fmt.Errorf("%w: invalid csrf header name", ErrInvalidConfig)
		}
		if value == "" || !httpguts.ValidHeaderFieldValue(value) {
			return fmt.Errorf("%w: invalid csrf header value", ErrInvalidConfig)
		}
		c.csrfHeader = http.CanonicalHeaderKey(name)
		c.csrfValue = value
		return nil
	})
}

// WithUnauthorizedHandler sets the handler called for the requests without a valid session. The default is
// [DefaultUnauthorized].
func WithUnauthorizedHandler(handler fox.HandlerFunc) Option {
	return optionFunc(func(c *config) error {
		if handler == nil {
			return fmt.Errorf("%w: nil unauthorized handler", ErrInvalidConfig)
		}
		c.unauthorized = handler
		return nil
	})
}

// DefaultUnauthorized responds with 401 Unauthorized.
func DefaultUnauthorized(c *fox.Context) {
	http.Error(c.Writer(), http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}
