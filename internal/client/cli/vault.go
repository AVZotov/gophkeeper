package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/AVZotov/gophkeeper/internal/client/recordpb"
	"github.com/AVZotov/gophkeeper/internal/client/records"
	"github.com/AVZotov/gophkeeper/internal/client/remote"
	"github.com/AVZotov/gophkeeper/internal/client/session"
	"github.com/AVZotov/gophkeeper/internal/client/storage"
	"github.com/AVZotov/gophkeeper/internal/client/vaultsync"
)

var (
	// errSavedLocally replaces the error of a sync when the server is
	// unavailable: the details from gRPC tell the user nothing.
	errSavedLocally = fmt.Errorf("%w, changes are saved locally", remote.ErrUnavailable)
	errNoRecord     = errors.New("no record")
	errAmbiguousID  = errors.New("ambiguous record ID")
	errEmptyID      = errors.New("record ID is empty")
)

// vault is an unlocked vault: the local database, the state and the keys of
// the session.
type vault struct {
	app         app
	cfg         config
	store       *storage.Store
	state       storage.State
	sessionPath string
	keys        session.Keys
}

// openVault opens the local database and the session. Returns
// [storage.ErrNoState] with a hint if the user has not logged in and
// [session.ErrLocked] if there is no usable session.
func (a app) openVault(ctx context.Context) (*vault, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	store, err := a.openStore(ctx)
	if err != nil {
		return nil, err
	}
	st, err := loggedIn(ctx, store)
	if err != nil {
		store.Close()
		return nil, err
	}
	path, keys, err := a.openSession(cfg)
	if err != nil {
		store.Close()
		return nil, err
	}
	return &vault{app: a, cfg: cfg, store: store, state: st, sessionPath: path, keys: keys}, nil
}

// Close closes the local database.
func (v *vault) Close() error {
	return v.store.Close()
}

// sync syncs the local records with the server and saves a new token.
func (v *vault) sync(ctx context.Context) (vaultsync.Result, error) {
	client, err := v.app.dialSaved(v.cfg, v.state)
	if err != nil {
		return vaultsync.Result{}, err
	}
	defer client.Close()
	client.Resume(v.state.Login, v.keys.Login, v.state.Token)

	res, err := vaultsync.Sync(ctx, v.store, client, v.keys.Data)
	return res, errors.Join(err, saveToken(ctx, v.store, client, v.state.Token))
}

// syncChange syncs right after a local change. If the server is
// unavailable, it tells the user that the change syncs later and returns
// nil: the change is saved.
func (v *vault) syncChange(cmd *cobra.Command) error {
	_, err := v.sync(cmd.Context())
	if errors.Is(err, remote.ErrUnavailable) {
		_, err = fmt.Fprintln(cmd.OutOrStdout(), "Saved locally, will sync later: the server is unavailable.")
		return err
	}
	if err != nil {
		return fmt.Errorf("saved locally, but sync failed: %w", err)
	}
	return nil
}

// undecryptable stands for the type and the name of a record that does not
// decrypt.
const undecryptable = "?"

// undecryptableName is shown instead of the name of a record that does not
// decrypt: one damaged record must not hide the others or stop its delete.
const undecryptableName = "(cannot decrypt)"

// find returns the record, not deleted, whose ID starts with prefix, and its
// content. Returns the errors of [vault.match] and an error if the record
// does not decrypt.
func (v *vault) find(ctx context.Context, prefix string) (storage.Record, *recordpb.Record, error) {
	r, err := v.match(ctx, prefix)
	if err != nil {
		return storage.Record{}, nil, err
	}
	rec, err := records.Open(v.keys.Data, r.ID, r.Ciphertext)
	return r, rec, err
}

// match returns the record, not deleted, whose ID starts with prefix,
// without decrypting it. Returns [errEmptyID] if prefix is empty,
// [errNoRecord] if there is no such record and [errAmbiguousID] listing the
// records if there are several.
func (v *vault) match(ctx context.Context, prefix string) (storage.Record, error) {
	if prefix == "" {
		return storage.Record{}, errEmptyID
	}
	list, err := v.store.List(ctx)
	if err != nil {
		return storage.Record{}, err
	}
	prefix = strings.ToLower(prefix)
	var matches []storage.Record
	for _, r := range list {
		if strings.HasPrefix(r.ID.String(), prefix) {
			matches = append(matches, r)
		}
	}

	switch len(matches) {
	case 0:
		return storage.Record{}, fmt.Errorf("%w with ID %s", errNoRecord, prefix)
	case 1:
		return matches[0], nil
	}
	var b strings.Builder
	for _, r := range matches {
		recordType, name := v.describe(r)
		fmt.Fprintf(&b, "\n  %s  %s  %s", r.ID, recordType, name)
	}
	return storage.Record{}, fmt.Errorf("%w %s matches %d records:%s", errAmbiguousID, prefix, len(matches), b.String())
}

// describe returns the type and the name of the record, or
// [undecryptable] and [undecryptableName] if it does not decrypt.
func (v *vault) describe(r storage.Record) (recordType, name string) {
	rec, err := records.Open(v.keys.Data, r.ID, r.Ciphertext)
	if err != nil {
		return undecryptable, undecryptableName
	}
	return records.Type(rec), rec.GetName()
}
