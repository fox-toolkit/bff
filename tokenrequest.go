// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"
)

const maxTokenResponseSize = 1 << 20

// tokenError is an error response of the token endpoint (RFC 6749 5.2).
type tokenError struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
	status      int
}

func (e *tokenError) Error() string {
	return fmt.Sprintf("token endpoint: status %d: %s %s", e.status, e.Code, e.Description)
}

// requestToken sends the token request to the provider with the client, and returns the token of a successful response
// (RFC 6749 5.1) with its other members as extra values.
func (fe *Frontend) requestToken(ctx context.Context, client *http.Client, form url.Values) (*oauth2.Token, error) {
	req, err := fe.auth.newRequest(ctx, fe.oauth2.Endpoint.TokenURL, form, fe.now())
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseSize))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		e := &tokenError{status: resp.StatusCode}
		_ = json.Unmarshal(body, e)
		return nil, e
	}

	var res struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
		// Some providers send expires_in as a string.
		ExpiresIn json.Number `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, err
	}
	if res.AccessToken == "" {
		return nil, errors.New("token endpoint: no access token")
	}
	var extra map[string]any
	if err := json.Unmarshal(body, &extra); err != nil {
		return nil, err
	}
	token := &oauth2.Token{AccessToken: res.AccessToken, TokenType: res.TokenType, RefreshToken: res.RefreshToken}
	if n, err := res.ExpiresIn.Int64(); err == nil && n > 0 {
		token.Expiry = fe.now().Add(time.Duration(n) * time.Second)
	}
	return token.WithExtra(extra), nil
}
