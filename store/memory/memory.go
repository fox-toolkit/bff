// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

// Package memory provides a [store.Store] that keeps the sessions in memory.
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/fox-toolkit/bff/store"
)

const sweepInterval = time.Minute

// Store is a [store.Store] that keeps the sessions in memory. The sessions are neither shared nor persisted, so it is
// only suited to a single instance.
type Store struct {
	now       func() time.Time
	records   map[string]store.Record
	lastSweep time.Time
	mu        sync.Mutex
}

// NewStore returns an empty [Store].
func NewStore() *Store {
	return &Store{now: time.Now, records: make(map[string]store.Record)}
}

// Load implements [store.Store].
func (s *Store) Load(_ context.Context, id string) (store.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[id]
	if !ok || !s.now().Before(r.Expires) {
		return store.Record{}, store.ErrNotFound
	}
	return r, nil
}

// Create implements [store.Store].
func (s *Store) Create(_ context.Context, id string, r store.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if now.Sub(s.lastSweep) >= sweepInterval {
		for k, v := range s.records {
			if !now.Before(v.Expires) {
				delete(s.records, k)
			}
		}
		s.lastSweep = now
	}
	s.records[id] = r
	return nil
}

// Update implements [store.Store].
func (s *Store) Update(_ context.Context, id string, r store.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, ok := s.records[id]
	if !ok || !s.now().Before(prev.Expires) {
		return store.ErrNotFound
	}
	if prev.Generation > r.Generation {
		return store.ErrConflict
	}
	s.records[id] = r
	return nil
}

// Delete implements [store.Store].
func (s *Store) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, id)
	return nil
}

// DeleteBy implements [store.Store].
func (s *Store) DeleteBy(_ context.Context, partition, subject, sid string) (map[string]store.Record, error) {
	if subject == "" && sid == "" {
		return nil, nil
	}
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
