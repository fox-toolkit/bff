// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"bytes"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fox-toolkit/bff/internal/oidctest"
	"github.com/fox-toolkit/bff/store"
	"github.com/fox-toolkit/fox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newBackchannelEnv(t *testing.T) (*testEnv, *mapStore) {
	t.Helper()
	ms := &mapStore{records: make(map[string]store.Record)}
	e := newTestEnv(t, oidctest.Options{Subject: "alice", SID: "s1"}, WithStore(ms))
	_, err := e.router.Add(fox.MethodPost, "/bff/backchannel", e.fe.BackchannelHandler())
	require.NoError(t, err)
	return e, ms
}

func (e *testEnv) backchannel(token string) *httptest.ResponseRecorder {
	return e.doForm(http.MethodPost, "/bff/backchannel", nil, nil, url.Values{"logout_token": {token}})
}

func (e *testEnv) loginAs(t *testing.T, subject, sid string) []*http.Cookie {
	t.Helper()
	e.idp.Update(func(o *oidctest.Options) {
		o.Subject = subject
		o.SID = sid
	})
	return e.loggedIn(t)
}

func TestBackchannel(t *testing.T) {
	cases := []struct {
		name    string
		sub     string
		sid     string
		deleted []string
	}{
		{name: "sid", sid: "s1", deleted: []string{"alice/s1"}},
		{name: "subject", sub: "alice", deleted: []string{"alice/s1", "alice/s2"}},
		{name: "subject and sid", sub: "alice", sid: "s2", deleted: []string{"alice/s2"}},
		{name: "unknown session", sub: "alice", sid: "s3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := newBackchannelEnv(t)
			sessions := map[string][]*http.Cookie{
				"alice/s1": e.loginAs(t, "alice", "s1"),
				"alice/s2": e.loginAs(t, "alice", "s2"),
				"bob/s3":   e.loginAs(t, "bob", "s3"),
			}
			refreshTokens := make(map[string]string)
			for name, cookies := range sessions {
				s, _, err := e.fe.readSession(t.Context(), cookies)
				require.NoError(t, err)
				refreshTokens[name] = s.RefreshToken
			}

			rec := e.backchannel(e.idp.LogoutToken("app", tc.sub, tc.sid))
			require.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

			var revoked []string
			for _, name := range tc.deleted {
				revoked = append(revoked, refreshTokens[name])
			}
			assert.ElementsMatch(t, revoked, e.idp.Revoked())
			for name, cookies := range sessions {
				_, _, err := e.fe.readSession(t.Context(), cookies)
				if slices.Contains(tc.deleted, name) {
					assert.ErrorIs(t, err, errNoSession)
				} else {
					assert.NoError(t, err)
				}
			}
		})
	}
}

func TestBackchannelInvalidToken(t *testing.T) {
	e, ms := newBackchannelEnv(t)
	e.loggedIn(t)
	now := time.Now()
	valid := func() map[string]any {
		return map[string]any{
			"iss":    e.idp.URL,
			"aud":    "app",
			"sub":    "alice",
			"sid":    "s1",
			"iat":    now.Unix(),
			"exp":    now.Add(time.Minute).Unix(),
			"jti":    "id-1",
			"events": map[string]any{backchannelLogoutEvent: map[string]any{}},
		}
	}
	with := func(edit func(c map[string]any)) string {
		c := valid()
		edit(c)
		return e.idp.Sign("logout+jwt", c)
	}

	cases := map[string]string{
		"missing":           "",
		"malformed":         "not-a-jwt",
		"other audience":    with(func(c map[string]any) { c["aud"] = "other" }),
		"other issuer":      with(func(c map[string]any) { c["iss"] = "https://evil.example.com" }),
		"expired":           with(func(c map[string]any) { c["exp"] = now.Add(-time.Minute).Unix() }),
		"no sub nor sid":    with(func(c map[string]any) { delete(c, "sub"); delete(c, "sid") }),
		"no events":         with(func(c map[string]any) { delete(c, "events") }),
		"other event":       with(func(c map[string]any) { c["events"] = map[string]any{"other": map[string]any{}} }),
		"event not object":  with(func(c map[string]any) { c["events"] = map[string]any{backchannelLogoutEvent: "x"} }),
		"nonce":             with(func(c map[string]any) { c["nonce"] = "n" }),
		"null nonce":        with(func(c map[string]any) { c["nonce"] = nil }),
		"no jti":            with(func(c map[string]any) { delete(c, "jti") }),
		"no iat":            with(func(c map[string]any) { delete(c, "iat") }),
		"unsigned id token": "eyJhbGciOiJub25lIn0." + "e30.",
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			before := maps.Clone(ms.records)
			assert.Equal(t, http.StatusBadRequest, e.backchannel(token).Code)
			assert.Equal(t, before, ms.records)
		})
	}

	t.Run("valid", func(t *testing.T) {
		assert.Equal(t, http.StatusOK, e.backchannel(e.idp.Sign("logout+jwt", valid())).Code)
		assert.Empty(t, ms.records)
	})
}

type keySetRequests struct {
	base http.RoundTripper
	n    *atomic.Int32
}

func (c keySetRequests) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path == "/jwks" {
		c.n.Add(1)
	}
	return c.base.RoundTrip(r)
}

func TestBackchannelUnknownKeyID(t *testing.T) {
	e, _ := newBackchannelEnv(t)
	e.loggedIn(t)
	var n atomic.Int32
	client := e.fe.provider.client
	client.Transport = keySetRequests{base: client.Transport, n: &n}

	e.idp.RotateKey()
	for range 20 {
		assert.Equal(t, http.StatusBadRequest, e.backchannel(e.idp.LogoutToken("app", "alice", "")).Code)
	}
	assert.Equal(t, int32(0), n.Load())
}

func TestBackchannelRequiresStore(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{})
	assert.PanicsWithValue(t, "bff: back-channel logout requires a store", func() { e.fe.BackchannelHandler() })
}

func FuzzVerifyLogoutToken(f *testing.F) {
	e := newTestEnv(f, oidctest.Options{})
	f.Add("eyJhbGciOiJub25lIn0.e30.")
	f.Add(e.idp.Sign("JWT", map[string]any{"iss": e.idp.URL, "aud": "other", "sub": "alice"}))
	f.Fuzz(func(t *testing.T, raw string) {
		_, _, err := e.fe.verifyLogoutToken(t.Context(), raw)
		assert.Error(t, err)
	})
}

func TestBackchannelLog(t *testing.T) {
	var buf bytes.Buffer
	ms := &mapStore{records: make(map[string]store.Record)}
	e := newTestEnv(t, oidctest.Options{}, WithStore(ms), WithLogHandler(slog.NewTextHandler(&buf, nil)))
	_, err := e.router.Add(fox.MethodPost, "/bff/backchannel", e.fe.BackchannelHandler())
	require.NoError(t, err)

	token := e.idp.Sign("logout+jwt", map[string]any{"iss": e.idp.URL, "aud": "app", "sid": "s1", "iat": time.Now().Unix(),
		"jti": "id-1", "events": map[string]any{backchannelLogoutEvent: map[string]any{}}})
	assert.Equal(t, http.StatusBadRequest, e.backchannel(token).Code)
	assert.Contains(t, buf.String(), "level=WARN")
	assert.Contains(t, buf.String(), `msg="invalid back-channel logout"`)
	assert.Contains(t, buf.String(), "client_id=app")
}
