package storage

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

// fileMode keeps the database readable only by its owner: the envelope in it
// lets one guess the password offline.
const fileMode = 0o600

// busyTimeout is how long a query waits, in milliseconds, for another
// gophkeeper process to release the database.
const busyTimeout = 5000

// Store is the local storage backed by an SQLite file. It is safe for
// concurrent use.
type Store struct {
	db *sql.DB
}

// Open opens the SQLite database at path, creating the file if it does not
// exist, and applies pending migrations. An existing file is made readable
// only by its owner. Returns an error if the file cannot be created, opened
// or made private, or a migration fails.
func Open(ctx context.Context, path string) (*Store, error) {
	// SQLite creates its journal with the mode of the database file, so the
	// file gets the right mode before SQLite opens it.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, fileMode)
	if err != nil {
		return nil, fmt.Errorf("create database: %w", err)
	}
	if err := errors.Join(f.Chmod(fileMode), f.Close()); err != nil {
		return nil, fmt.Errorf("create database: %w", err)
	}

	name, err := dataSourceName(path)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", name)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := migrate(ctx, db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// dataSourceName returns the SQLite URI of the database at path. A URI,
// unlike a plain file name, keeps the characters ? and # of the path.
func dataSourceName(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("database path: %w", err)
	}
	// A Windows path starts with the drive letter: file:///C:/...
	p := filepath.ToSlash(abs)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	u := url.URL{
		Scheme: "file",
		Path:   p,
		// secure_delete overwrites deleted rows with zeros, so cleared data
		// does not stay in free pages of the file. Immediate transactions
		// take the write lock at the start, so a read-modify-write waits for
		// another process instead of failing halfway.
		RawQuery: "_pragma=secure_delete(1)&_txlock=immediate&_busy_timeout=" + strconv.Itoa(busyTimeout),
	}
	return u.String(), nil
}

// Close closes the database. Returns an error if closing fails.
func (s *Store) Close() error {
	return s.db.Close()
}

// inTx runs fn in a transaction and commits it if fn returns nil.
func (s *Store) inTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback()

	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// migrate applies pending migrations.
func migrate(ctx context.Context, db *sql.DB) error {
	fsys, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return err
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, db, fsys)
	if err != nil {
		return err
	}
	_, err = provider.Up(ctx)
	return err
}
