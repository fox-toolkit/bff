// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.

package bff

import (
	"crypto"
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
	// ClientSecret is the client secret, sent with client_secret_basic.
	ClientSecret string
	// ClientKey is the private key that authenticates the client with private_key_jwt. It must be an ECDSA P-256 key,
	// an RSA key of at least 2048 bits or an Ed25519 key. A client has either a secret or a key.
	ClientKey crypto.Signer
	// ClientKeyID is the optional ID of the client key, sent in the assertions.
	ClientKeyID string
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
	if (c.ClientSecret == "") == (c.ClientKey == nil) {
		return fmt.Errorf("%w: client must have either a secret or a key", ErrInvalidConfig)
	}
	if c.ClientKey != nil && len(clientKeyAlgs(c.ClientKey.Public())) == 0 {
		return fmt.Errorf("%w: unsupported client key", ErrInvalidConfig)
	}
	if c.ClientKey == nil && c.ClientKeyID != "" {
		return fmt.Errorf("%w: client key id without client key", ErrInvalidConfig)
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
