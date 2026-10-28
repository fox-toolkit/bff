// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.

package memory

import (
	"testing"
	"time"

	"github.com/fox-toolkit/bff/store"
	"github.com/fox-toolkit/bff/store/storetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type clock struct {
	now time.Time
}

func (c *clock) Now() time.Time          { return c.now }
func (c *clock) Advance(d time.Duration) { c.now = c.now.Add(d) }

func newTestStore() (*Store, *clock) {
	c := &clock{now: time.UnixMilli(time.Now().UnixMilli())}
	s := NewStore()
	s.now = c.Now
	return s, c
}

func TestMemoryStore(t *testing.T) {
	storetest.TestStore(t, func(t *testing.T) (store.Store, storetest.Clock) {
		return newTestStore()
	})
}

func TestMemoryStoreSweep(t *testing.T) {
	s, c := newTestStore()
	ctx := t.Context()

	require.NoError(t, s.Create(ctx, "a", store.Record{Expires: c.now.Add(time.Minute)}))
	require.NoError(t, s.Create(ctx, "b", store.Record{Expires: c.now.Add(time.Hour)}))

	c.Advance(time.Minute)
	require.NoError(t, s.Create(ctx, "c", store.Record{Expires: c.now.Add(time.Hour)}))
	assert.Len(t, s.records, 2)
}
