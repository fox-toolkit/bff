// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.

package bff

import (
	"context"
	"crypto/sha256"
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

func TestTokenGroupSharesFailure(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		shared bool
	}{
		{name: "token request", err: &sharedError{errors.New("unavailable")}, shared: true},
		{name: "other", err: errors.New("store")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newTokenGroup(time.Now)
			started := make(chan struct{})
			release := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				done <- g.Request(t.Context(), "id", "", func(*session, error) (*session, error) {
					close(started)
					<-release
					return nil, tc.err
				})
			}()
			<-started

			var ran atomic.Int32
			run := func(_ *session, shared error) (*session, error) {
				if shared != nil {
					return nil, shared
				}
				ran.Add(1)
				return nil, nil
			}
			errs := make(chan error, 3)
			go func() { errs <- g.Request(t.Context(), "id", "", run) }()
			go func() { errs <- g.Request(t.Context(), "id", billing, run) }()
			go func() {
				errs <- g.Do(t.Context(), "id", func(s *session) (*session, error) { return run(s, nil) })
			}()
			key := sha256.Sum256([]byte("id"))
			require.Eventually(t, func() bool {
				g.mu.Lock()
				defer g.mu.Unlock()
				return g.sessions[key].refs == 4
			}, time.Second, time.Millisecond)
			close(release)

			assert.Error(t, <-done)
			failures := 0
			for range 3 {
				if <-errs != nil {
					failures++
				}
			}
			if tc.shared {
				assert.Equal(t, 1, failures)
				assert.Equal(t, int32(2), ran.Load())
			} else {
				assert.Zero(t, failures)
				assert.Equal(t, int32(3), ran.Load())
			}

			require.NoError(t, g.Request(t.Context(), "id", "", run))
			assert.Empty(t, g.sessions)
		})
	}
}

func TestRefreshedIDToken(t *testing.T) {
	cases := []struct {
		name    string
		refresh map[string]any
	}{
		{name: "sub changed", refresh: map[string]any{"sub": "other"}},
		{name: "azp mismatch", refresh: map[string]any{"azp": "other"}},
		{name: "several audiences without azp", refresh: map[string]any{"aud": []string{"app", "other"}}},
		{name: "missing iat", refresh: map[string]any{"iat": nil}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnv(t, oidctest.Options{})
			e.mount(t, "/api")
			cookies := e.loggedIn(t)
			e.idp.Update(func(o *oidctest.Options) { o.Claims = tc.refresh })
			e.skipAhead(5 * time.Minute)

			assert.Equal(t, http.StatusUnauthorized, e.do(http.MethodGet, "/api", cookies, nil).Code)
			assert.Empty(t, e.idp.Revoked())
		})
	}
}
