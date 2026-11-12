package cli

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/AVZotov/gophkeeper/internal/client/remote"
	"github.com/AVZotov/gophkeeper/internal/client/session"
	"github.com/AVZotov/gophkeeper/internal/client/storage"
)

// Files of the client, in the gophkeeper directory under the user config
// directory.
const (
	dirName     = "gophkeeper"
	dbFile      = "gophkeeper.db"
	sessionFile = "session"
)

// dirMode keeps the client directory private to its owner.
const dirMode = 0o700

// NewRootCmd returns the gophkeeper command tree. The version command prints
// version and buildDate.
func NewRootCmd(version, buildDate string) *cobra.Command {
	return newRootCmd(version, buildDate, app{dir: defaultDir})
}

// newRootCmd is [NewRootCmd] with the files and the connection of a.
func newRootCmd(version, buildDate string, a app) *cobra.Command {
	root := &cobra.Command{
		Use:   "gophkeeper",
		Short: "GophKeeper password manager client",
		// An error of a command is not a usage mistake.
		SilenceUsage: true,
	}
	root.AddCommand(
		newVersionCmd(version, buildDate),
		newRegisterCmd(a),
		newLoginCmd(a),
		newUnlockCmd(a),
		newChangePasswordCmd(a),
		newSyncCmd(a),
		newAddCmd(a),
		newListCmd(a),
		newShowCmd(a),
		newEditCmd(a),
		newDeleteCmd(a),
		newLockCmd(a),
		newLogoutCmd(a),
	)
	return root
}

// defaultDir returns the gophkeeper directory under the user config
// directory. Returns an error if the config directory is unknown.
func defaultDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("find config directory: %w", err)
	}
	return filepath.Join(dir, dirName), nil
}

// app finds the files of the client in the directory returned by dir and
// connects to the server with dialOptions added.
type app struct {
	dir         func() (string, error)
	dialOptions []grpc.DialOption
}

// path returns the path of the named file, creating the client directory if
// it does not exist and making it readable only by its owner.
func (a app) path(name string) (string, error) {
	dir, err := a.dir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return "", fmt.Errorf("create client directory: %w", err)
	}
	// MkdirAll keeps the mode of an existing directory.
	if err := os.Chmod(dir, dirMode); err != nil {
		return "", fmt.Errorf("make client directory private: %w", err)
	}
	return filepath.Join(dir, name), nil
}

// openStore opens the local database.
func (a app) openStore(ctx context.Context) (*storage.Store, error) {
	path, err := a.path(dbFile)
	if err != nil {
		return nil, err
	}
	store, err := storage.Open(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("open local database: %w", err)
	}
	return store, nil
}

// dial returns a client of the server at address that trusts the CA in
// caPath.
func (a app) dial(address, caPath string) (*remote.Client, error) {
	return remote.Dial(address, caPath, a.dialOptions...)
}

// dialSaved returns a client of the saved server, unless the environment
// sets another one.
func (a app) dialSaved(cfg config, st storage.State) (*remote.Client, error) {
	return a.dial(cmp.Or(cfg.Server, st.ServerAddress), cmp.Or(cfg.CA, st.CAPath))
}

// openSession returns the path of the session file and the keys of the
// session opened with the key from the environment. Returns
// [session.ErrLocked] if there is no usable session.
func (a app) openSession(cfg config) (string, session.Keys, error) {
	path, err := a.path(sessionFile)
	if err != nil {
		return "", session.Keys{}, err
	}
	if cfg.Session == "" {
		return "", session.Keys{}, fmt.Errorf("%s is not set: %w", sessionEnv, session.ErrLocked)
	}
	keys, err := session.Load(path, cfg.Session, time.Now())
	return path, keys, err
}

// loggedIn returns the saved state. Returns [storage.ErrNoState] with a hint
// to log in if the user has not logged in.
func loggedIn(ctx context.Context, store *storage.Store) (storage.State, error) {
	st, err := store.State(ctx)
	if errors.Is(err, storage.ErrNoState) {
		return storage.State{}, fmt.Errorf("%w, run gophkeeper login first", err)
	}
	return st, err
}

// saveToken saves the token of the client if it differs from old: the
// client got a new one by a silent login.
func saveToken(ctx context.Context, store *storage.Store, client *remote.Client, old string) error {
	if client.Token() == old {
		return nil
	}
	return store.UpdateState(ctx, func(st *storage.State) { st.Token = client.Token() })
}
