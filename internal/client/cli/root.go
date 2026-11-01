package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

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
	return newRootCmd(version, buildDate, defaultDir)
}

// newRootCmd is [NewRootCmd] with the client directory returned by dir.
func newRootCmd(version, buildDate string, dir func() (string, error)) *cobra.Command {
	root := &cobra.Command{
		Use:   "gophkeeper",
		Short: "GophKeeper password manager client",
		// An error of a command is not a usage mistake.
		SilenceUsage: true,
	}
	f := files{dir: dir}
	root.AddCommand(
		newVersionCmd(version, buildDate),
		newUnlockCmd(f),
		newLockCmd(f),
		newLogoutCmd(f),
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

// files finds the files of the client in the directory returned by dir.
type files struct {
	dir func() (string, error)
}

// path returns the path of the named file, creating the client directory if
// it does not exist.
func (f files) path(name string) (string, error) {
	dir, err := f.dir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return "", fmt.Errorf("create client directory: %w", err)
	}
	return filepath.Join(dir, name), nil
}

// openStore opens the local database.
func (f files) openStore(ctx context.Context) (*storage.Store, error) {
	path, err := f.path(dbFile)
	if err != nil {
		return nil, err
	}
	store, err := storage.Open(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("open local database: %w", err)
	}
	return store, nil
}
