// Package vaultsync syncs the local records with the server. Local changes
// are pushed first, one by one, and conflicts are resolved on the way; then
// the changes of other devices are pulled page by page.
package vaultsync

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"uuid"

	"github.com/AVZotov/gophkeeper/internal/client/records"
	"github.com/AVZotov/gophkeeper/internal/client/remote"
	"github.com/AVZotov/gophkeeper/internal/client/storage"
	"github.com/AVZotov/gophkeeper/internal/client/vaultcrypto"
)

// ConflictSuffix ends the name of the copy that keeps a local change which
// conflicted with a change on the server.
const ConflictSuffix = " (conflict)"

// maxPushAttempts bounds the pushes of one record while it keeps changing
// on the server.
const maxPushAttempts = 3

// Result counts what a sync did.
type Result struct {
	// Pushed is the number of local changes the server accepted.
	Pushed int
	// Conflicts is the number of conflict copies made.
	Conflicts int
	// Pulled is the number of records received from the server.
	Pulled int
}

// ErrBadPage means the server returned a page that breaks the Pull
// contract: an empty page with more records left, or revisions that do not grow.
var ErrBadPage = errors.New("server returned an invalid page")

// checkPage returns [ErrBadPage] if the page is empty but hasMore is set,
// or if its revisions do not grow strictly starting after since.
func checkPage(since int64, page []storage.Record, hasMore bool) error {
	if len(page) == 0 && hasMore {
		return fmt.Errorf("%w: empty page, but more records are left", ErrBadPage)
	}
	prev := since
	for _, r := range page {
		if r.Revision <= prev {
			return fmt.Errorf("%w: revision %d after %d", ErrBadPage, r.Revision, prev)
		}
		prev = r.Revision
	}
	return nil
}

// Sync pushes the dirty records and pulls the changes from the server,
// saving the pull position after every page. key decrypts a local change to
// make a conflict copy. Returns the errors of [remote.Client], [ErrBadPage]
// if the server returns an invalid page, an error if a conflict copy cannot
// be made and an error if the storage fails. What was done before an error
// is kept.
func Sync(ctx context.Context, store *storage.Store, client *remote.Client, key vaultcrypto.DataKey) (Result, error) {
	s := syncer{store: store, client: client, key: key}
	dirty, err := store.Dirty(ctx)
	if err != nil {
		return s.result, err
	}
	for _, r := range dirty {
		if err := s.push(ctx, r); err != nil {
			return s.result, err
		}
	}
	err = s.pull(ctx)
	return s.result, err
}

type syncer struct {
	store  *storage.Store
	client *remote.Client
	key    vaultcrypto.DataKey
	result Result
}

// push sends the local change r and resolves a conflict with the server.
func (s *syncer) push(ctx context.Context, r storage.Record) error {
	pushed := r
	for range maxPushAttempts {
		revision, err := s.client.Push(ctx, r)
		if err == nil {
			s.result.Pushed++
			r.Revision = revision
			return s.store.MarkPushed(ctx, pushed, r)
		}
		if errors.Is(err, remote.ErrRecordNotFound) {
			// The server lost the record, for example restored from an older
			// backup: the local change brings it back as a new one.
			r.Revision = 0
			continue
		}
		conflict, ok := errors.AsType[*remote.ConflictError](err)
		if !ok {
			return err
		}

		current := conflict.Current
		switch {
		case current.Deleted == r.Deleted && bytes.Equal(current.Ciphertext, r.Ciphertext):
			// The server has this change already: the answer to an earlier
			// push was lost.
			s.result.Pushed++
			return s.store.MarkPushed(ctx, pushed, current)
		case r.Deleted:
			// A change on another device wins over the local delete.
			return s.store.MarkPushed(ctx, pushed, current)
		case current.Deleted:
			// The local change wins over a delete and brings the record
			// back.
			r.Revision = current.Revision
		default:
			return s.copyConflict(ctx, pushed, current)
		}
	}
	return fmt.Errorf("record %s keeps changing on the server, sync again later", r.ID)
}

// copyConflict takes the server version of the record and keeps the local
// change as a new record named with [ConflictSuffix], then pushes it. The
// copy is saved before the local change is replaced, so the change is not
// lost if the sync stops between the two.
func (s *syncer) copyConflict(ctx context.Context, pushed, current storage.Record) error {
	rec, err := records.Open(s.key, pushed.ID, pushed.Ciphertext)
	if err != nil {
		return fmt.Errorf("conflict copy: %w", err)
	}
	rec.SetName(rec.GetName() + ConflictSuffix)
	// The record ID is bound to the ciphertext, so the copy is encrypted
	// anew for its own ID.
	id := uuid.New()
	ciphertext, err := records.Seal(s.key, id, rec)
	if err != nil {
		return fmt.Errorf("conflict copy of record %s: %w", pushed.ID, err)
	}
	if err := s.store.SaveLocal(ctx, id, false, ciphertext); err != nil {
		return err
	}
	if err := s.store.MarkPushed(ctx, pushed, current); err != nil {
		return err
	}
	s.result.Conflicts++
	return s.push(ctx, storage.Record{ID: id, Ciphertext: ciphertext})
}

// pull saves the records changed on the server after the last revision
// received, page by page, and saves the revision after every page.
func (s *syncer) pull(ctx context.Context) error {
	st, err := s.store.State(ctx)
	if err != nil {
		return err
	}
	since := st.LastRevision
	for {
		page, hasMore, err := s.client.Pull(ctx, since)
		if err != nil {
			return err
		}
		if err := checkPage(since, page, hasMore); err != nil {
			return err
		}
		for _, r := range page {
			if err := s.store.ApplyRemote(ctx, r); err != nil {
				return err
			}
		}
		if len(page) == 0 {
			return nil
		}
		s.result.Pulled += len(page)
		since = page[len(page)-1].Revision
		if err := s.store.UpdateState(ctx, func(st *storage.State) { st.LastRevision = since }); err != nil {
			return err
		}
		if !hasMore {
			return nil
		}
	}
}
