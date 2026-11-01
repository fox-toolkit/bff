// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/rp/blob/main/LICENSE.

// Package storetest tests implementations of [store.Store].
package storetest

import (
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/fox-toolkit/rp/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Clock is the time seen by a store under test.
type Clock interface {
	// Now returns the current time of the store.
	Now() time.Time
	// Advance moves the time of the store forward by d.
	Advance(d time.Duration)
}

// TestStore runs the tests of a [store.Store]. newStore returns an empty store and the clock it uses to expire the
// sessions. The clock starts at a time truncated to the millisecond.
func TestStore(t *testing.T, newStore func(t *testing.T) (store.Store, Clock)) {
	t.Run("crud", func(t *testing.T) { testCRUD(t, newStore) })
	t.Run("expiry", func(t *testing.T) { testExpiry(t, newStore) })
	t.Run("delete by", func(t *testing.T) { testDeleteBy(t, newStore) })
}

func testCRUD(t *testing.T, newStore func(t *testing.T) (store.Store, Clock)) {
	s, clock := newStore(t)
	ctx := t.Context()
	now := clock.Now()

	_, err := s.Load(ctx, "a")
	assert.ErrorIs(t, err, store.ErrNotFound)

	r := store.Record{Expires: now.Add(time.Hour), Partition: "app", Subject: "alice", SID: "s1", Data: []byte("x")}
	require.NoError(t, s.Create(ctx, "a", r))
	got, err := s.Load(ctx, "a")
	require.NoError(t, err)
	assertRecord(t, r, got)

	r.Data = []byte("y")
	require.NoError(t, s.Update(ctx, "a", r))
	got, err = s.Load(ctx, "a")
	require.NoError(t, err)
	assert.Equal(t, []byte("y"), got.Data)

	r.Generation = 2
	require.NoError(t, s.Update(ctx, "a", r))
	assert.ErrorIs(t, s.Update(ctx, "a", store.Record{Expires: r.Expires, Generation: 1}), store.ErrConflict)
	require.NoError(t, s.Update(ctx, "a", r))
	got, err = s.Load(ctx, "a")
	require.NoError(t, err)
	assertRecord(t, r, got)

	require.NoError(t, s.Delete(ctx, "a"))
	_, err = s.Load(ctx, "a")
	assert.ErrorIs(t, err, store.ErrNotFound)
	assert.NoError(t, s.Delete(ctx, "a"))
	assert.ErrorIs(t, s.Update(ctx, "a", r), store.ErrNotFound)
}

func testExpiry(t *testing.T, newStore func(t *testing.T) (store.Store, Clock)) {
	s, clock := newStore(t)
	ctx := t.Context()
	now := clock.Now()

	require.NoError(t, s.Create(ctx, "a", store.Record{Expires: now.Add(time.Minute), Partition: "app", Subject: "alice"}))
	require.NoError(t, s.Create(ctx, "b", store.Record{Expires: now.Add(time.Hour), Partition: "app", Subject: "alice"}))

	clock.Advance(time.Minute)
	_, err := s.Load(ctx, "a")
	assert.ErrorIs(t, err, store.ErrNotFound)
	_, err = s.Load(ctx, "b")
	assert.NoError(t, err)
	assert.ErrorIs(t, s.Update(ctx, "a", store.Record{Expires: now.Add(2 * time.Hour), Partition: "app", Subject: "alice"}), store.ErrNotFound)

	// An update that extends a session keeps it reachable by subject after its first expiry.
	require.NoError(t, s.Update(ctx, "b", store.Record{Expires: now.Add(3 * time.Hour), Partition: "app", Subject: "alice"}))
	clock.Advance(2 * time.Hour)
	deleted, err := s.DeleteBy(ctx, "app", "alice", "")
	require.NoError(t, err)
	assert.Contains(t, deleted, "b")
}

func testDeleteBy(t *testing.T, newStore func(t *testing.T) (store.Store, Clock)) {
	ctx := t.Context()
	populate := func(t *testing.T) (store.Store, map[string]store.Record) {
		s, clock := newStore(t)
		exp := clock.Now().Add(time.Hour)
		records := map[string]store.Record{
			"1": {Expires: exp, Partition: "app", Subject: "alice", SID: "s1", Data: []byte("1"), Generation: 1},
			"2": {Expires: exp, Partition: "app", Subject: "alice", SID: "s2", Data: []byte("2")},
			"3": {Expires: exp, Partition: "app", Subject: "bob", SID: "s3", Data: []byte("3")},
			"4": {Expires: exp, Partition: "admin", Subject: "alice", SID: "s1", Data: []byte("4")},
			"5": {Expires: exp, Partition: "app", Subject: "carol", Data: []byte("5")},
		}
		for id, r := range records {
			require.NoError(t, s.Create(ctx, id, r))
		}
		return s, records
	}

	cases := []struct {
		name    string
		subject string
		sid     string
		deleted []string
	}{
		{name: "subject", subject: "alice", deleted: []string{"1", "2"}},
		{name: "subject without sid", subject: "carol", deleted: []string{"5"}},
		{name: "sid", sid: "s3", deleted: []string{"3"}},
		{name: "subject and sid", subject: "alice", sid: "s2", deleted: []string{"2"}},
		{name: "subject and other sid", subject: "alice", sid: "s3"},
		{name: "nothing", subject: "", sid: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, records := populate(t)
			deleted, err := s.DeleteBy(ctx, "app", tc.subject, tc.sid)
			require.NoError(t, err)
			assert.ElementsMatch(t, tc.deleted, slices.Collect(maps.Keys(deleted)))
			for id, r := range deleted {
				assertRecord(t, records[id], r)
			}
			for id := range records {
				_, err := s.Load(ctx, id)
				if slices.Contains(tc.deleted, id) {
					assert.ErrorIs(t, err, store.ErrNotFound)
				} else {
					assert.NoError(t, err)
				}
			}
		})
	}

	t.Run("other partition after update", func(t *testing.T) {
		s, clock := newStore(t)
		exp := clock.Now().Add(time.Hour)
		require.NoError(t, s.Create(ctx, "1", store.Record{Expires: exp, Subject: "alice"}))
		require.NoError(t, s.Update(ctx, "1", store.Record{Expires: exp, Partition: "admin", Subject: "alice"}))
		deleted, err := s.DeleteBy(ctx, "", "alice", "")
		require.NoError(t, err)
		assert.Empty(t, deleted)
		_, err = s.Load(ctx, "1")
		assert.NoError(t, err)
	})
}

func assertRecord(t *testing.T, want, got store.Record) {
	t.Helper()
	assert.True(t, want.Expires.Equal(got.Expires))
	want.Expires, got.Expires = time.Time{}, time.Time{}
	assert.Equal(t, want, got)
}
