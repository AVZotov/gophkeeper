package storage

import (
	"context"
	"embed"
	"fmt"
	"io/fs"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Store is the server storage backed by a PostgreSQL connection pool. It is
// safe for concurrent use.
type Store struct {
	pool *pgxpool.Pool
}

// Open connects to PostgreSQL at dsn and applies pending migrations. Returns
// an error if dsn is malformed, the database is unreachable or a migration
// fails.
func Open(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}
	if err := migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close waits for queries in progress and closes all connections.
func (s *Store) Close() {
	s.pool.Close()
}

// migrate applies pending migrations. goose works with database/sql, so it
// gets a *sql.DB on top of the pool; closing it does not close the pool.
func migrate(ctx context.Context, pool *pgxpool.Pool) error {
	fsys, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return err
	}
	db := stdlib.OpenDBFromPool(pool)
	defer db.Close()

	provider, err := goose.NewProvider(goose.DialectPostgres, db, fsys)
	if err != nil {
		return err
	}
	_, err = provider.Up(ctx)
	return err
}
