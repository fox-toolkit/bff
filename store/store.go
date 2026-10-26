// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

// Package store defines the interface between stateful frontends and their session storage.
package store

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound = errors.New("session not found")
	ErrConflict = errors.New("session changed")
)

// Record is a session kept by a [Store].
type Record struct {
	// Expires is the time after which the session is no longer valid.
	Expires time.Time
	// Partition identifies the frontend of the session.
	Partition string
	// Subject is the sub claim of the user.
	Subject string
	// SID is the sid claim of the provider session. It may be empty.
	SID string
	// Data is the session, encrypted by the frontend.
	Data []byte
	// Generation counts the changes of the session tokens. A record never replaces a record with a greater
	// generation.
	Generation int64
}

// Store keeps the sessions of stateful frontends. A Store must be safe for concurrent use.
type Store interface {
	// Load returns the record of the session, or [ErrNotFound] if it does not exist or has expired.
	Load(ctx context.Context, id string) (Record, error)
	// Create stores the record of a new session.
	Create(ctx context.Context, id string, r Record) error
	// Update replaces the record of an existing session, or returns [ErrNotFound] if it does not exist or has
	// expired. It returns [ErrConflict] without replacing the record if the stored record has a greater generation.
	Update(ctx context.Context, id string, r Record) error
	// Delete deletes the session. Deleting a session that does not exist is not an error.
	Delete(ctx context.Context, id string) error
	// DeleteBy deletes the sessions of the partition that belong to the subject, restricted to the sid when it is not
	// empty, and returns them by id. An empty subject matches any subject. DeleteBy deletes nothing when both are
	// empty.
	DeleteBy(ctx context.Context, partition, subject, sid string) (map[string]Record, error)
}
