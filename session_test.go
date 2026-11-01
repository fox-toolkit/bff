// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/rp/blob/main/LICENSE.

package rp

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/fox-toolkit/rp/internal/oidctest"
	"github.com/fox-toolkit/rp/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestFrontend(t testing.TB, opts ...FrontendOption) *Frontend {
	t.Helper()
	fe, err := NewFrontend(Client{
		Provider:     newTestProvider(t, nil),
		ClientID:     "app",
		ClientSecret: "secret",
		RedirectURL:  "https://app.example.com/bff/callback",
		Scopes:       []string{"openid"},
	}, newGCMAEAD(t), opts...)
	require.NoError(t, err)
	return fe
}

func testSession() *session {
	s := newSession(time.Unix(1_000_000, 0))
	s.Subject = "alice"
	s.SID = "s1"
	s.AccessToken = "access-token"
	s.RefreshToken = "refresh-token"
	s.Expiry = 1_000_300
	return s
}

func TestSessionStateless(t *testing.T) {
	fe := newTestFrontend(t)
	s := testSession()

	h := make(http.Header)
	require.NoError(t, fe.rp.writeSession(t.Context(), h, s, sessionState{}))
	got, st, err := fe.rp.readSession(t.Context(), requestCookies(t, h))
	require.NoError(t, err)
	assert.Equal(t, s, got)
	assert.Equal(t, sessionState{chunks: 1}, st)

	h = make(http.Header)
	require.NoError(t, fe.rp.deleteSession(t.Context(), h, st))
	assert.Equal(t, []string{"__Host-Http-BFF.0=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict"}, h.Values("Set-Cookie"))
}

type mapStore struct {
	records map[string]store.Record
	mu      sync.Mutex
}

func (s *mapStore) Load(_ context.Context, id string) (store.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[id]
	if !ok {
		return store.Record{}, store.ErrNotFound
	}
	return r, nil
}

func (s *mapStore) Create(_ context.Context, id string, r store.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[id] = r
	return nil
}

func (s *mapStore) Update(_ context.Context, id string, r store.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, ok := s.records[id]
	if !ok {
		return store.ErrNotFound
	}
	if prev.Generation > r.Generation {
		return store.ErrConflict
	}
	s.records[id] = r
	return nil
}

func (s *mapStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, id)
	return nil
}

func (s *mapStore) DeleteBy(_ context.Context, partition, subject, sid string) (map[string]store.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	deleted := make(map[string]store.Record)
	for k, r := range s.records {
		if r.Partition == partition && (subject == "" || r.Subject == subject) && (sid == "" || r.SID == sid) {
			deleted[k] = r
			delete(s.records, k)
		}
	}
	return deleted, nil
}

func TestSessionStateful(t *testing.T) {
	ms := &mapStore{records: make(map[string]store.Record)}
	fe := newTestFrontend(t, WithStore(ms))
	s := testSession()
	ctx := t.Context()

	h := make(http.Header)
	require.NoError(t, fe.rp.writeSession(ctx, h, s, sessionState{}))
	require.Len(t, ms.records, 1)
	for _, r := range ms.records {
		assert.Equal(t, "alice", r.Subject)
		assert.Equal(t, "s1", r.SID)
		assert.Equal(t, time.Unix(1_000_000, 0).Add(DefaultIdleTimeout), r.Expires)
		assert.NotContains(t, string(r.Data), "access-token")
	}

	cookies := requestCookies(t, h)
	got, st, err := fe.rp.readSession(ctx, cookies)
	require.NoError(t, err)
	assert.Equal(t, s, got)
	assert.NotEmpty(t, st.id)
	assert.NotContains(t, cookies[0].Value, st.id)

	t.Run("update keeps the cookie", func(t *testing.T) {
		got.AccessToken = "new-access-token"
		h := make(http.Header)
		require.NoError(t, fe.rp.writeSession(ctx, h, got, st))
		assert.Empty(t, h.Values("Set-Cookie"))
		updated, _, err := fe.rp.readSession(ctx, cookies)
		require.NoError(t, err)
		assert.Equal(t, "new-access-token", updated.AccessToken)
	})

	t.Run("new session gets a new key", func(t *testing.T) {
		h := make(http.Header)
		require.NoError(t, fe.rp.writeSession(ctx, h, testSession(), sessionState{chunks: st.chunks}))
		_, other, err := fe.rp.readSession(ctx, requestCookies(t, h))
		require.NoError(t, err)
		assert.NotEqual(t, st.id, other.id)
	})

	t.Run("record bound to its id", func(t *testing.T) {
		r, err := ms.Load(ctx, st.id)
		require.NoError(t, err)
		h := make(http.Header)
		require.NoError(t, fe.rp.writeSession(ctx, h, testSession(), sessionState{}))
		_, other, err := fe.rp.readSession(ctx, requestCookies(t, h))
		require.NoError(t, err)
		require.NoError(t, ms.Update(ctx, other.id, r))
		_, _, err = fe.rp.readSession(ctx, requestCookies(t, h))
		assert.ErrorIs(t, err, errNoSession)
	})

	t.Run("deleted", func(t *testing.T) {
		h := make(http.Header)
		require.NoError(t, fe.rp.deleteSession(ctx, h, st))
		assert.Len(t, h.Values("Set-Cookie"), 1)
		_, st, err := fe.rp.readSession(ctx, cookies)
		assert.ErrorIs(t, err, errNoSession)
		assert.Equal(t, 1, st.chunks)
	})
}

func TestSessionVersion(t *testing.T) {
	fe := newTestFrontend(t)
	s := testSession()
	s.Version = sessionVersion + 1
	data, err := json.Marshal(s)
	require.NoError(t, err)
	h := make(http.Header)
	require.NoError(t, sessionCookie.write(h, fe.rp.aead, data, 0, 0))
	_, _, err = fe.rp.readSession(t.Context(), requestCookies(t, h))
	assert.ErrorIs(t, err, errNoSession)
}

func TestSessionExpires(t *testing.T) {
	cfg := defaultConfig()
	s := newSession(time.Unix(1_000_000, 0))
	assert.Equal(t, time.Unix(1_000_000, 0).Add(cfg.idleTimeout), s.expires(cfg))

	s.LastSeen = s.Created + int64((cfg.absoluteTimeout - time.Minute).Seconds())
	assert.Equal(t, time.Unix(s.Created, 0).Add(cfg.absoluteTimeout), s.expires(cfg))
}

func FuzzDecodeSession(f *testing.F) {
	f.Add([]byte(`{"v":1,"sub":"alice","lt":"x","iat":1,"seen":1}`))
	f.Add([]byte(`{"v":1,"ui":{"email":1}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := decodeSession(data)
		if err == nil {
			assert.Equal(t, sessionVersion, s.Version)
		}
	})
}

func TestSessionRefreshSkew(t *testing.T) {
	for lifetime, want := range map[int64]time.Duration{
		0:    refreshSkew,
		3600: refreshSkew,
		60:   30 * time.Second,
		10:   5 * time.Second,
	} {
		s := &session{Lifetime: lifetime}
		assert.Equal(t, want, s.refreshSkew())
	}
}

func TestSessionBoundToFrontend(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{})
	cookies := e.loggedIn(t)
	admin, err := NewFrontend(Client{
		Provider:     e.fe.rp.provider,
		ClientID:     "admin",
		ClientSecret: oidctest.ClientSecret,
		RedirectURL:  appOrigin + "/bff/callback",
		Scopes:       []string{"openid"},
	}, newGCMAEAD(t))
	require.NoError(t, err)

	_, _, err = e.fe.rp.readSession(t.Context(), cookies)
	require.NoError(t, err)
	_, _, err = admin.rp.readSession(t.Context(), cookies)
	assert.ErrorIs(t, err, errNoSession)
}

// slowStore stores the sessions late, so a concurrent request reads the session before it is stored.
type slowStore struct {
	*mapStore
}

func (s slowStore) Update(ctx context.Context, id string, r store.Record) error {
	time.Sleep(20 * time.Millisecond)
	return s.mapStore.Update(ctx, id, r)
}

func TestSessionPrune(t *testing.T) {
	fe := newTestFrontend(t, WithResources(billing, orders))
	now := fe.rp.now()
	s := testSession()
	s.Resources = map[string]resourceToken{
		billing:                       {AccessToken: "expired", Expiry: now.Add(-time.Second).Unix()},
		orders:                        {AccessToken: "valid", Expiry: now.Add(time.Hour).Unix()},
		"https://removed.example.com": {AccessToken: "removed"},
	}

	h := make(http.Header)
	require.NoError(t, fe.rp.writeSession(t.Context(), h, s, sessionState{}))
	got, _, err := fe.rp.readSession(t.Context(), requestCookies(t, h))
	require.NoError(t, err)
	assert.Equal(t, map[string]resourceToken{orders: s.Resources[orders]}, got.Resources)
}
