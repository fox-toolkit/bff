// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/rp/blob/main/LICENSE.

package oidctest

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

const redirectURL = "https://app.example.com/callback"

type client struct {
	srv      *Server
	ctx      context.Context
	provider *oidc.Provider
	config   oauth2.Config
}

func newClient(t *testing.T, opts Options) *client {
	t.Helper()
	srv := NewServer(opts)
	t.Cleanup(srv.Close)
	ctx := oidc.ClientContext(t.Context(), srv.Client())
	p, err := oidc.NewProvider(ctx, srv.URL)
	require.NoError(t, err)
	return &client{
		srv:      srv,
		ctx:      ctx,
		provider: p,
		config: oauth2.Config{
			ClientID:     "app",
			ClientSecret: ClientSecret,
			Endpoint:     p.Endpoint(),
			RedirectURL:  redirectURL,
			Scopes:       []string{oidc.ScopeOpenID},
		},
	}
}

func (c *client) authorize(t *testing.T, verifier string, opts ...oauth2.AuthCodeOption) url.Values {
	t.Helper()
	opts = append(opts, oidc.Nonce("n-0S6_WzA2Mj"), oauth2.S256ChallengeOption(verifier))
	hc := c.srv.Client()
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := hc.Get(c.config.AuthCodeURL("xyz", opts...))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	return loc.Query()
}

func (c *client) login(t *testing.T) *oauth2.Token {
	t.Helper()
	verifier := oauth2.GenerateVerifier()
	q := c.authorize(t, verifier)
	token, err := c.config.Exchange(c.ctx, q.Get("code"), oauth2.VerifierOption(verifier))
	require.NoError(t, err)
	return token
}

func TestCodeFlow(t *testing.T) {
	c := newClient(t, Options{Subject: "alice", SID: "s1", UserInfo: map[string]any{"email": "alice@example.com"}})
	verifier := oauth2.GenerateVerifier()
	q := c.authorize(t, verifier)
	assert.Equal(t, "xyz", q.Get("state"))
	assert.Empty(t, q.Get("iss"))

	token, err := c.config.Exchange(c.ctx, q.Get("code"), oauth2.VerifierOption(verifier))
	require.NoError(t, err)
	assert.NotEmpty(t, token.RefreshToken)

	idToken, err := c.provider.Verifier(&oidc.Config{ClientID: "app"}).Verify(c.ctx, token.Extra("id_token").(string))
	require.NoError(t, err)
	assert.Equal(t, "alice", idToken.Subject)
	assert.Equal(t, "n-0S6_WzA2Mj", idToken.Nonce)
	var claims struct {
		SID string `json:"sid"`
	}
	require.NoError(t, idToken.Claims(&claims))
	assert.Equal(t, "s1", claims.SID)

	info, err := c.provider.UserInfo(c.ctx, oauth2.StaticTokenSource(token))
	require.NoError(t, err)
	assert.Equal(t, "alice", info.Subject)
	assert.Equal(t, "alice@example.com", info.Email)

	_, err = c.config.Exchange(c.ctx, q.Get("code"), oauth2.VerifierOption(verifier))
	assert.Error(t, err)
}

func TestCodeFlowWrongVerifier(t *testing.T) {
	c := newClient(t, Options{Subject: "alice"})
	q := c.authorize(t, oauth2.GenerateVerifier())
	_, err := c.config.Exchange(c.ctx, q.Get("code"), oauth2.VerifierOption(oauth2.GenerateVerifier()))
	assert.Error(t, err)
}

func TestAuthorizeResponse(t *testing.T) {
	c := newClient(t, Options{
		Subject:   "alice",
		LoggedOut: true,
		Metadata:  map[string]any{"authorization_response_iss_parameter_supported": true},
	})
	q := c.authorize(t, oauth2.GenerateVerifier(), oauth2.SetAuthURLParam("prompt", "none"))
	assert.Equal(t, "login_required", q.Get("error"))
	assert.Equal(t, "xyz", q.Get("state"))
	assert.Equal(t, c.srv.URL, q.Get("iss"))

	c.srv.Update(func(o *Options) { o.ISS = "https://evil.example.com" })
	q = c.authorize(t, oauth2.GenerateVerifier())
	assert.NotEmpty(t, q.Get("code"))
	assert.Equal(t, "https://evil.example.com", q.Get("iss"))
}

func TestRefresh(t *testing.T) {
	t.Run("without rotation", func(t *testing.T) {
		c := newClient(t, Options{Subject: "alice"})
		token := c.login(t)
		for range 2 {
			refreshed, err := c.config.TokenSource(c.ctx, &oauth2.Token{RefreshToken: token.RefreshToken}).Token()
			require.NoError(t, err)
			assert.Equal(t, token.RefreshToken, refreshed.RefreshToken)
			assert.NotEqual(t, token.AccessToken, refreshed.AccessToken)
		}
	})

	t.Run("rotation and reuse", func(t *testing.T) {
		c := newClient(t, Options{Subject: "alice", RotateRefreshTokens: true})
		token := c.login(t)
		refreshed, err := c.config.TokenSource(c.ctx, &oauth2.Token{RefreshToken: token.RefreshToken}).Token()
		require.NoError(t, err)
		assert.NotEqual(t, token.RefreshToken, refreshed.RefreshToken)

		_, err = c.config.TokenSource(c.ctx, &oauth2.Token{RefreshToken: token.RefreshToken}).Token()
		assert.Error(t, err)
		_, err = c.config.TokenSource(c.ctx, &oauth2.Token{RefreshToken: refreshed.RefreshToken}).Token()
		assert.Error(t, err)
	})
}

func TestRevoke(t *testing.T) {
	c := newClient(t, Options{Subject: "alice"})
	token := c.login(t)

	resp, err := c.srv.Client().PostForm(c.srv.URL+"/revoke", url.Values{
		"token":         {token.RefreshToken},
		"client_id":     {"app"},
		"client_secret": {ClientSecret},
	})
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, []string{token.RefreshToken}, c.srv.Revoked())

	_, err = c.config.TokenSource(c.ctx, &oauth2.Token{RefreshToken: token.RefreshToken}).Token()
	assert.Error(t, err)
}

func TestEndSession(t *testing.T) {
	c := newClient(t, Options{Subject: "alice"})
	hc := c.srv.Client()
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := hc.Get(c.srv.URL + "/end_session?" + url.Values{
		"id_token_hint":            {"hint"},
		"post_logout_redirect_uri": {"https://app.example.com/"},
	}.Encode())
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, "https://app.example.com/", resp.Header.Get("Location"))
	assert.Equal(t, []EndSession{{IDTokenHint: "hint", PostLogoutRedirectURI: "https://app.example.com/"}}, c.srv.EndSessions())

	q := c.authorize(t, oauth2.GenerateVerifier(), oauth2.SetAuthURLParam("prompt", "none"))
	assert.Equal(t, "login_required", q.Get("error"))
}

func TestLogoutToken(t *testing.T) {
	c := newClient(t, Options{})
	raw := c.srv.LogoutToken("app", "alice", "s1")

	jws, err := jose.ParseSignedCompact(raw, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)
	assert.Equal(t, "logout+jwt", jws.Signatures[0].Header.ExtraHeaders[jose.HeaderType])

	token, err := c.provider.Verifier(&oidc.Config{ClientID: "app"}).Verify(c.ctx, raw)
	require.NoError(t, err)
	var claims struct {
		Events map[string]any `json:"events"`
		SID    string         `json:"sid"`
		JTI    string         `json:"jti"`
	}
	require.NoError(t, token.Claims(&claims))
	assert.Equal(t, "alice", token.Subject)
	assert.Equal(t, "s1", claims.SID)
	assert.NotEmpty(t, claims.JTI)
	assert.Contains(t, claims.Events, "http://schemas.openid.net/event/backchannel-logout")
}
