// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package memory

import (
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/fox-toolkit/bff/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryStore(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := NewStore()
	s.now = func() time.Time { return now }
	ctx := t.Context()

	_, err := s.Load(ctx, "a")
	assert.ErrorIs(t, err, store.ErrNotFound)

	r := store.Record{Expires: now.Add(time.Hour), Subject: "alice", SID: "s1", Data: []byte("x")}
	require.NoError(t, s.Create(ctx, "a", r))
	got, err := s.Load(ctx, "a")
	require.NoError(t, err)
	assert.Equal(t, r, got)

	r.Data = []byte("y")
	require.NoError(t, s.Update(ctx, "a", r))
	got, err = s.Load(ctx, "a")
	require.NoError(t, err)
	assert.Equal(t, []byte("y"), got.Data)

	require.NoError(t, s.Delete(ctx, "a"))
	_, err = s.Load(ctx, "a")
	assert.ErrorIs(t, err, store.ErrNotFound)
	assert.NoError(t, s.Delete(ctx, "a"))
	assert.ErrorIs(t, s.Update(ctx, "a", r), store.ErrNotFound)
}

func TestMemoryStoreExpiry(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := NewStore()
	s.now = func() time.Time { return now }
	ctx := t.Context()

	require.NoError(t, s.Create(ctx, "a", store.Record{Expires: now.Add(time.Minute)}))
	require.NoError(t, s.Create(ctx, "b", store.Record{Expires: now.Add(time.Hour)}))

	now = now.Add(time.Minute)
	_, err := s.Load(ctx, "a")
	assert.ErrorIs(t, err, store.ErrNotFound)
	_, err = s.Load(ctx, "b")
	assert.NoError(t, err)
	assert.ErrorIs(t, s.Update(ctx, "a", store.Record{Expires: now.Add(time.Hour)}), store.ErrNotFound)

	require.NoError(t, s.Create(ctx, "c", store.Record{Expires: now.Add(time.Hour)}))
	assert.Len(t, s.records, 2)
}

func TestMemoryStoreDeleteBy(t *testing.T) {
	ctx := t.Context()
	newStore := func(t *testing.T) *Store {
		s := NewStore()
		exp := time.Now().Add(time.Hour)
		require.NoError(t, s.Create(ctx, "1", store.Record{Expires: exp, Partition: "app", Subject: "alice", SID: "s1"}))
		require.NoError(t, s.Create(ctx, "2", store.Record{Expires: exp, Partition: "app", Subject: "alice", SID: "s2"}))
		require.NoError(t, s.Create(ctx, "3", store.Record{Expires: exp, Partition: "app", Subject: "bob", SID: "s3"}))
		require.NoError(t, s.Create(ctx, "4", store.Record{Expires: exp, Partition: "admin", Subject: "alice", SID: "s1"}))
		return s
	}

	cases := []struct {
		name    string
		subject string
		sid     string
		deleted []string
	}{
		{name: "subject", subject: "alice", deleted: []string{"1", "2"}},
		{name: "sid", sid: "s3", deleted: []string{"3"}},
		{name: "subject and sid", subject: "alice", sid: "s2", deleted: []string{"2"}},
		{name: "subject and other sid", subject: "alice", sid: "s3"},
		{name: "nothing", subject: "", sid: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t)
			deleted, err := s.DeleteBy(ctx, "app", tc.subject, tc.sid)
			require.NoError(t, err)
			assert.ElementsMatch(t, tc.deleted, slices.Collect(maps.Keys(deleted)))
			for _, id := range []string{"1", "2", "3", "4"} {
				_, err := s.Load(ctx, id)
				if slices.Contains(tc.deleted, id) {
					assert.ErrorIs(t, err, store.ErrNotFound)
				} else {
					assert.NoError(t, err)
				}
			}
		})
	}
}
