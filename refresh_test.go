// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fox-toolkit/bff/internal/oidctest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenGroupSerializes(t *testing.T) {
	g := newTokenGroup(time.Now)
	var running, maxRunning atomic.Int32
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			err := g.Do(t.Context(), "id", func(*session) (*session, error) {
				n := running.Add(1)
				for {
					m := maxRunning.Load()
					if n <= m || maxRunning.CompareAndSwap(m, n) {
						break
					}
				}
				time.Sleep(time.Millisecond)
				running.Add(-1)
				return nil, nil
			})
			assert.NoError(t, err)
		})
	}
	wg.Wait()
	assert.Equal(t, int32(1), maxRunning.Load())
	assert.Empty(t, g.sessions)
}

func TestTokenGroupLatest(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	g := newTokenGroup(func() time.Time { return now })
	keep := &session{RefreshToken: "rt2", Generation: 2}
	require.NoError(t, g.Do(t.Context(), "id", func(latest *session) (*session, error) {
		assert.Nil(t, latest)
		return keep, nil
	}))

	now = now.Add(refreshReuse - time.Second)
	require.NoError(t, g.Do(t.Context(), "id", func(latest *session) (*session, error) {
		assert.Same(t, keep, latest)
		return nil, nil
	}))
	assert.Error(t, g.Do(t.Context(), "other", func(latest *session) (*session, error) {
		assert.Nil(t, latest)
		return nil, errors.New("unavailable")
	}))

	now = now.Add(time.Second)
	require.NoError(t, g.Do(t.Context(), "id", func(latest *session) (*session, error) {
		assert.Nil(t, latest)
		return nil, nil
	}))
	assert.Empty(t, g.sessions)
}

func TestTokenGroupCanceled(t *testing.T) {
	g := newTokenGroup(time.Now)
	release := make(chan struct{})
	started := make(chan struct{})
	go func() {
		_ = g.Do(t.Context(), "id", func(*session) (*session, error) {
			close(started)
			<-release
			return nil, nil
		})
	}()
	<-started

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := g.Do(ctx, "id", func(*session) (*session, error) {
		t.Error("ran without the lock")
		return nil, nil
	})
	assert.ErrorIs(t, err, context.Canceled)
	close(release)
}

func TestTokenGroupForgetDuringDo(t *testing.T) {
	g := newTokenGroup(time.Now)
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = g.Do(t.Context(), "id", func(*session) (*session, error) {
			close(started)
			<-release
			return &session{RefreshToken: "rt2", Generation: 2}, nil
		})
	}()
	<-started
	g.Forget("id")
	close(release)
	<-done

	require.NoError(t, g.Do(t.Context(), "id", func(latest *session) (*session, error) {
		assert.Nil(t, latest)
		return nil, nil
	}))
	assert.Empty(t, g.sessions)
}

func TestRefreshedIDToken(t *testing.T) {
	cases := []struct {
		name    string
		login   map[string]any
		refresh map[string]any
		code    int
	}{
		{name: "same authentication", login: map[string]any{"auth_time": 1000}, refresh: map[string]any{"auth_time": 1000}, code: http.StatusOK},
		{name: "aud changed", refresh: map[string]any{"aud": []string{"app", "other"}, "azp": "app"}, code: http.StatusUnauthorized},
		{name: "auth_time changed", login: map[string]any{"auth_time": 1000}, refresh: map[string]any{"auth_time": 2000}, code: http.StatusUnauthorized},
		{name: "nonce changed", refresh: map[string]any{"nonce": "other"}, code: http.StatusUnauthorized},
		{name: "sub changed", refresh: map[string]any{"sub": "other"}, code: http.StatusUnauthorized},
		{name: "aud as an array", refresh: map[string]any{"aud": []string{"app"}}, code: http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnv(t, oidctest.Options{Claims: tc.login})
			e.mount(t, "/api")
			cookies := e.loggedIn(t)
			e.idp.Update(func(o *oidctest.Options) { o.Claims = tc.refresh })
			e.skipAhead(5 * time.Minute)

			assert.Equal(t, tc.code, e.do(http.MethodGet, "/api", cookies, nil).Code)
			assert.Empty(t, e.idp.Revoked())
		})
	}
}

func TestRefreshedIDTokenComparedWithLogin(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{Claims: map[string]any{"auth_time": 1000}})
	e.mount(t, "/api")
	cookies := e.loggedIn(t)

	e.idp.Update(func(o *oidctest.Options) { o.Claims = map[string]any{"auth_time": nil} })
	e.skipAhead(5 * time.Minute)
	rec := e.do(http.MethodGet, "/api", cookies, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	cookies = requestCookies(t, rec.Header())

	e.idp.Update(func(o *oidctest.Options) { o.Claims = map[string]any{"auth_time": 2000} })
	e.skipAhead(10 * time.Minute)
	assert.Equal(t, http.StatusUnauthorized, e.do(http.MethodGet, "/api", cookies, nil).Code)
}

func TestAudience(t *testing.T) {
	cases := []struct {
		data    string
		want    audience
		invalid bool
	}{
		{data: `null`},
		{data: `"app"`, want: audience{"app"}},
		{data: `["app","other"]`, want: audience{"app", "other"}},
		{data: `1`, invalid: true},
	}
	for _, tc := range cases {
		var a audience
		err := json.Unmarshal([]byte(tc.data), &a)
		assert.Equal(t, tc.invalid, err != nil)
		assert.Equal(t, tc.want, a)
	}
}
