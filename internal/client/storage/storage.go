package storage

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"strconv"

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
// exist, and applies pending migrations. Returns an error if the file cannot
// be created or opened or a migration fails.
func Open(ctx context.Context, path string) (*Store, error) {
	// SQLite creates its journal with the mode of the database file, so the
	// file is created here with the right mode before SQLite opens it.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, fileMode)
	if err != nil {
		return nil, fmt.Errorf("create database: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("create database: %w", err)
	}

	// secure_delete overwrites deleted rows with zeros, so cleared data does
	// not stay in free pages of the file.
	dsn := path + "?_pragma=secure_delete(1)&_busy_timeout=" + strconv.Itoa(busyTimeout)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := migrate(ctx, db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the database. Returns an error if closing fails.
func (s *Store) Close() error {
	return s.db.Close()
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
