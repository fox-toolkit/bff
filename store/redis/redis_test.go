// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.

package redis

import (
	"context"
	"errors"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/fox-toolkit/bff/store"
	"github.com/fox-toolkit/bff/store/storetest"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type clock struct {
	now time.Time
	m   *miniredis.Miniredis
}

func (c *clock) Now() time.Time { return c.now }

func (c *clock) Advance(d time.Duration) {
	c.now = c.now.Add(d)
	if c.m != nil {
		c.m.SetTime(c.now)
		c.m.FastForward(d)
	}
}

func newMiniStore(t *testing.T, opts ...Option) (*Store, *clock, *miniredis.Miniredis) {
	m := miniredis.RunT(t)
	c := &clock{now: time.UnixMilli(time.Now().UnixMilli()), m: m}
	m.SetTime(c.now)
	client := goredis.NewClient(&goredis.Options{Addr: m.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	s, err := NewStore(client, opts...)
	require.NoError(t, err)
	s.now = c.Now
	return s, c, m
}

func TestStore(t *testing.T) {
	storetest.TestStore(t, func(t *testing.T) (store.Store, storetest.Clock) {
		s, c, _ := newMiniStore(t)
		return s, c
	})
}

func redisClient(t *testing.T) *goredis.Client {
	addr := os.Getenv("BFF_REDIS_ADDR")
	if addr == "" {
		t.Skip("BFF_REDIS_ADDR not set")
	}
	client := goredis.NewClient(&goredis.Options{Addr: addr})
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func newRedisStore(t *testing.T, client *goredis.Client) *Store {
	prefix := "bfftest:" + t.Name() + ":"
	s, err := NewStore(client, WithKeyPrefix(prefix))
	require.NoError(t, err)
	t.Cleanup(func() {
		keys, _ := client.Keys(context.Background(), prefix+"*").Result()
		if len(keys) > 0 {
			client.Del(context.Background(), keys...)
		}
	})
	return s
}

// TestStoreRedis runs against the Redis server at BFF_REDIS_ADDR. Its keys expire on the server clock, so the tests
// only rely on the expiry checked by the store.
func TestStoreRedis(t *testing.T) {
	client := redisClient(t)
	storetest.TestStore(t, func(t *testing.T) (store.Store, storetest.Clock) {
		s := newRedisStore(t, client)
		c := &clock{now: time.UnixMilli(time.Now().UnixMilli())}
		s.now = c.Now
		return s, c
	})
}

// TestStoreRedisMaxmemory sets maxmemory on the server at BFF_REDIS_ADDR, which must use the noeviction policy.
func TestStoreRedisMaxmemory(t *testing.T) {
	client := redisClient(t)
	s := newRedisStore(t, client)
	ctx := t.Context()
	r := store.Record{Expires: time.Now().Add(time.Hour), Subject: "alice", SID: "s1"}
	require.NoError(t, s.Create(ctx, "1", r))

	prev, err := client.ConfigGet(ctx, "maxmemory").Result()
	require.NoError(t, err)
	require.NoError(t, client.ConfigSet(ctx, "maxmemory", "1").Err())
	t.Cleanup(func() { client.ConfigSet(context.Background(), "maxmemory", prev["maxmemory"]) })

	assert.ErrorContains(t, s.Create(ctx, "2", r), "OOM")
	assert.ErrorIs(t, client.ZScore(ctx, s.indexKey("i:", "", "s1"), "2").Err(), goredis.Nil)
	assert.ErrorContains(t, s.Update(ctx, "1", r), "OOM")
	assert.ErrorContains(t, s.Create(ctx, "3", store.Record{Expires: r.Expires}), "OOM")
	deleted, err := s.DeleteBy(ctx, "", "alice", "")
	require.NoError(t, err)
	assert.Len(t, deleted, 1)
}

func TestNewStore(t *testing.T) {
	_, err := NewStore(nil)
	assert.ErrorIs(t, err, ErrInvalidConfig)
	_, err = NewStore(goredis.NewClient(&goredis.Options{}), WithKeyPrefix(""))
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

func TestStoreKeys(t *testing.T) {
	s, c, m := newMiniStore(t, WithKeyPrefix("app:"))
	ctx := t.Context()

	r := store.Record{Expires: c.now.Add(time.Hour), Partition: "a:b", Subject: "c", SID: "s1", Data: []byte("x")}
	require.NoError(t, s.Create(ctx, "1", r))
	require.NoError(t, s.Create(ctx, "2", store.Record{Expires: c.now.Add(time.Hour), Partition: "a", Subject: "b:c"}))
	assert.ElementsMatch(t, []string{"app:s:1", "app:s:2", "app:u:YTpi:Yw", "app:i:YTpi:czE", "app:u:YQ:Yjpj"}, m.Keys())
	assert.Equal(t, time.Hour, m.TTL("app:s:1"))
	assert.Equal(t, time.Hour, m.TTL("app:u:YTpi:Yw"))

	// The index lives as long as its last session.
	require.NoError(t, s.Create(ctx, "3", store.Record{Expires: c.now.Add(2 * time.Hour), Partition: "a:b", Subject: "c"}))
	assert.Equal(t, 2*time.Hour, m.TTL("app:u:YTpi:Yw"))

	require.NoError(t, s.Delete(ctx, "1"))
	assert.ElementsMatch(t, []string{"app:s:2", "app:s:3", "app:u:YTpi:Yw", "app:u:YQ:Yjpj"}, m.Keys())
	members, err := m.ZMembers("app:u:YTpi:Yw")
	require.NoError(t, err)
	assert.Equal(t, []string{"3"}, members)
}

func TestStoreIndexPrune(t *testing.T) {
	s, c, m := newMiniStore(t)
	ctx := t.Context()

	require.NoError(t, s.Create(ctx, "1", store.Record{Expires: c.now.Add(time.Minute), Subject: "alice"}))
	require.NoError(t, s.Create(ctx, "2", store.Record{Expires: c.now.Add(time.Hour), Subject: "alice"}))
	c.Advance(time.Minute)
	require.NoError(t, s.Create(ctx, "3", store.Record{Expires: c.now.Add(time.Hour), Subject: "alice"}))
	members, err := m.ZMembers(s.indexKey("u:", "", "alice"))
	require.NoError(t, err)
	assert.Equal(t, []string{"2", "3"}, members)
}

func TestStoreIndexPruneServerTime(t *testing.T) {
	s, c, _ := newMiniStore(t)
	ctx := t.Context()

	require.NoError(t, s.Create(ctx, "1", store.Record{Expires: c.now.Add(time.Minute), SID: "s1"}))
	s.now = func() time.Time { return c.now.Add(2 * time.Minute) }
	require.NoError(t, s.Create(ctx, "2", store.Record{Expires: c.now.Add(time.Hour), SID: "s1"}))
	s.now = c.Now
	deleted, err := s.DeleteBy(ctx, "", "", "s1")
	require.NoError(t, err)
	assert.Len(t, deleted, 2)
}

// failTake fails the n-th take.
type failTake struct {
	n     int
	calls int
}

func (h *failTake) DialHook(next goredis.DialHook) goredis.DialHook { return next }

func (h *failTake) ProcessPipelineHook(next goredis.ProcessPipelineHook) goredis.ProcessPipelineHook {
	return next
}

func (h *failTake) ProcessHook(next goredis.ProcessHook) goredis.ProcessHook {
	return func(ctx context.Context, cmd goredis.Cmder) error {
		if cmd.Name() == "evalsha" && cmd.Args()[1] == takeScript.Hash() {
			h.calls++
			if h.calls == h.n {
				cmd.SetErr(errTake)
				return errTake
			}
		}
		return next(ctx, cmd)
	}
}

var errTake = errors.New("take failed")

func TestStoreDeleteByError(t *testing.T) {
	s, c, m := newMiniStore(t)
	ctx := t.Context()
	client := goredis.NewClient(&goredis.Options{Addr: m.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	require.NoError(t, takeScript.Load(ctx, client).Err())
	client.AddHook(&failTake{n: 2})
	s.client = client

	for i := range 4 {
		r := store.Record{Expires: c.now.Add(time.Duration(i+1) * time.Hour), SID: "s1"}
		require.NoError(t, s.Create(ctx, strconv.Itoa(i), r))
	}
	deleted, err := s.DeleteBy(ctx, "", "", "s1")
	assert.ErrorIs(t, err, errTake)
	assert.Len(t, deleted, 3)
	assert.True(t, m.Exists(s.sessionKey("1")))
}

func TestStoreConflictKeepsIndex(t *testing.T) {
	s, c, m := newMiniStore(t)
	ctx := t.Context()

	require.NoError(t, s.Create(ctx, "1", store.Record{Expires: c.now.Add(2 * time.Hour), Subject: "alice", Generation: 2}))
	assert.ErrorIs(t, s.Update(ctx, "1", store.Record{Expires: c.now.Add(time.Hour), Subject: "alice", Generation: 1}), store.ErrConflict)
	score, err := m.ZScore(s.indexKey("u:", "", "alice"), "1")
	require.NoError(t, err)
	assert.InDelta(t, float64(c.now.Add(2*time.Hour).UnixMilli()), score, 0)
}

func TestStoreInvalidRecord(t *testing.T) {
	s, _, m := newMiniStore(t)
	ctx := t.Context()

	m.HSet(s.sessionKey("1"), "d", "x", "g", "x", "p", "", "u", "", "i", "", "e", "1")
	_, err := s.Load(ctx, "1")
	assert.ErrorIs(t, err, errInvalidRecord)
	m.HSet(s.sessionKey("2"), "d", "x", "g", "1", "p", "", "u", "", "i", "", "e", "x")
	_, err = s.Load(ctx, "2")
	assert.ErrorIs(t, err, errInvalidRecord)
	m.HSet(s.sessionKey("3"), "e", "1")
	assert.ErrorIs(t, s.Delete(ctx, "3"), errInvalidRecord)
}

func TestStoreCanceled(t *testing.T) {
	s, c, _ := newMiniStore(t)
	require.NoError(t, s.Create(t.Context(), "1", store.Record{Expires: c.now.Add(time.Hour), Subject: "alice", SID: "s1"}))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	r := store.Record{Expires: c.now.Add(time.Hour), Subject: "alice", SID: "s1"}
	_, err := s.Load(ctx, "1")
	assert.Error(t, err)
	assert.Error(t, s.Create(ctx, "2", r))
	assert.Error(t, s.Update(ctx, "1", r))
	assert.Error(t, s.Delete(ctx, "1"))
	_, err = s.DeleteBy(ctx, "", "alice", "")
	assert.Error(t, err)
}
