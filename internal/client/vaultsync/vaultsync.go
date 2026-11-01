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

	"google.golang.org/protobuf/proto"

	"github.com/AVZotov/gophkeeper/internal/client/recordpb"
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

// Sync pushes the dirty records and pulls the changes from the server,
// saving the pull position after every page. key decrypts a local change to
// make a conflict copy. Returns the errors of [remote.Client], an error if a
// conflict copy cannot be made and an error if the storage fails. What was
// done before an error is kept.
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
	return s.result, s.pull(ctx)
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
	plain, err := vaultcrypto.DecryptRecord(s.key, pushed.ID, pushed.Ciphertext)
	if err != nil {
		return fmt.Errorf("conflict copy: %w", err)
	}
	var rec recordpb.Record
	if err := proto.Unmarshal(plain, &rec); err != nil {
		return fmt.Errorf("conflict copy of record %s: %w", pushed.ID, err)
	}
	rec.SetName(rec.GetName() + ConflictSuffix)
	plain, err = proto.Marshal(&rec)
	if err != nil {
		return fmt.Errorf("conflict copy of record %s: %w", pushed.ID, err)
	}

	// The record ID is bound to the ciphertext, so the copy is encrypted
	// anew for its own ID.
	cp := storage.Record{ID: uuid.New()}
	cp.Ciphertext = vaultcrypto.EncryptRecord(s.key, cp.ID, plain)
	if err := s.store.SaveLocal(ctx, cp.ID, false, cp.Ciphertext); err != nil {
		return err
	}
	if err := s.store.MarkPushed(ctx, pushed, current); err != nil {
		return err
	}
	s.result.Conflicts++
	return s.push(ctx, cp)
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
		records, hasMore, err := s.client.Pull(ctx, since)
		if err != nil {
			return err
		}
		for _, r := range records {
			if err := s.store.ApplyRemote(ctx, r); err != nil {
				return err
			}
		}
		if len(records) == 0 {
			return nil
		}
		s.result.Pulled += len(records)
		since = records[len(records)-1].Revision
		if err := s.store.UpdateState(ctx, func(st *storage.State) { st.LastRevision = since }); err != nil {
			return err
		}
		if !hasMore {
			return nil
		}
	}
}
