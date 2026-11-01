// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.

package bff

import (
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fox-toolkit/bff/internal/oidctest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type countingTransport struct {
	base  http.RoundTripper
	paths map[string]*atomic.Int32
}

func (c countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if n, ok := c.paths[r.URL.Path]; ok {
		n.Add(1)
	}
	return c.base.RoundTrip(r)
}

func TestTokenRequestSingleAttempt(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{})
	var n atomic.Int32
	e.fe.rp.provider.client = &http.Client{Transport: countingTransport{
		base:  e.idp.Client().Transport,
		paths: map[string]*atomic.Int32{"/token": &n},
	}}
	rec, callback := e.startLogin(t, "")
	u, err := url.Parse(callback)
	require.NoError(t, err)
	q := u.Query()
	q.Set("code", "invalid")
	u.RawQuery = q.Encode()

	assert.Equal(t, http.StatusBadRequest, e.serve(u.RequestURI(), requestCookies(t, rec.Header())).Code)
	assert.Equal(t, int32(1), n.Load())
}

func TestRequestToken(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{})
	cases := []struct {
		name   string
		status int
		body   string
		check  func(t *testing.T, err error, expiry time.Time)
	}{
		{name: "expires_in as string", status: http.StatusOK, body: `{"access_token":"a","token_type":"Bearer","expires_in":"3600"}`,
			check: func(t *testing.T, err error, expiry time.Time) {
				require.NoError(t, err)
				assert.WithinDuration(t, time.Now().Add(time.Hour), expiry, time.Minute)
			}},
		{name: "expires_in overflow", status: http.StatusOK, body: `{"access_token":"a","token_type":"Bearer","expires_in":10000000000}`,
			check: func(t *testing.T, err error, expiry time.Time) {
				require.NoError(t, err)
				assert.WithinDuration(t, time.Now().Add(math.MaxInt32*time.Second), expiry, time.Minute)
			}},
		{name: "error", status: http.StatusBadRequest, body: `{"error":"invalid_grant","error_description":"expired"}`,
			check: func(t *testing.T, err error, _ time.Time) {
				te, ok := err.(*tokenError)
				require.True(t, ok)
				assert.Equal(t, "invalid_grant", te.Code)
			}},
		{name: "no access token", status: http.StatusOK, body: `{"token_type":"Bearer"}`,
			check: func(t *testing.T, err error, _ time.Time) { assert.Error(t, err) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			e.fe.rp.oauth2.Endpoint.TokenURL = srv.URL
			token, err := e.fe.rp.requestToken(t.Context(), srv.Client(), url.Values{"grant_type": {"refresh_token"}})
			var expiry time.Time
			if token != nil {
				expiry = token.Expiry
			}
			tc.check(t, err, expiry)
		})
	}
}
