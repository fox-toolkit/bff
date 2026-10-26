// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"fmt"
	"slices"
)

// Client is the configuration of an OpenID Connect Relying Party, a confidential OAuth 2.0 client registered with
// the provider. Its URLs must use https, except for a loopback host.
type Client struct {
	// Provider is the OpenID Provider the client is registered with.
	Provider *Provider
	// ClientID is the client identifier.
	ClientID string
	// ClientSecret is the client secret.
	ClientSecret string
	// RedirectURL is the URL the provider redirects the user to after login, where [Frontend.CallbackHandler] is served.
	RedirectURL string
	// PostLogoutRedirectURL is the optional URL the provider redirects the user to after logout.
	PostLogoutRedirectURL string
	// Scopes specifies the requested scopes. It must include openid.
	Scopes []string
}

func (c *Client) validate() error {
	if c.Provider == nil {
		return fmt.Errorf("%w: nil provider", ErrInvalidConfig)
	}
	if c.ClientID == "" {
		return fmt.Errorf("%w: empty client id", ErrInvalidConfig)
	}
	if c.ClientSecret == "" {
		return fmt.Errorf("%w: empty client secret", ErrInvalidConfig)
	}
	if err := checkURL(c.RedirectURL); err != nil {
		return fmt.Errorf("%w: redirect url %w", ErrInvalidConfig, err)
	}
	if c.PostLogoutRedirectURL != "" {
		if err := checkURL(c.PostLogoutRedirectURL); err != nil {
			return fmt.Errorf("%w: post logout redirect url %w", ErrInvalidConfig, err)
		}
	}
	if !slices.Contains(c.Scopes, "openid") {
		return fmt.Errorf("%w: scopes must include openid", ErrInvalidConfig)
	}
	if slices.ContainsFunc(c.Scopes, func(s string) bool { return !validScope(s) }) {
		return fmt.Errorf("%w: invalid scope", ErrInvalidConfig)
	}
	return nil
}

// validScope reports whether s is a scope token as defined by RFC 6749, section 3.3.
func validScope(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if b := s[i]; b < 0x21 || b > 0x7e || b == '"' || b == '\\' {
			return false
		}
	}
	return true
}
