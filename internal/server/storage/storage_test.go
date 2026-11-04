package storage

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AVZotov/gophkeeper/internal/pgtest"
)

// testDSN and testStore point to one PostgreSQL container shared by all tests
// of the package.
var (
	testDSN   string
	testStore *Store
)

func TestMain(m *testing.M) {
	os.Exit(pgtest.Run(m, func(dsn string) (func(), error) {
		testDSN = dsn
		var err error
		testStore, err = Open(context.Background(), dsn)
		if err != nil {
			return nil, fmt.Errorf("open store: %w", err)
		}
		return testStore.Close, nil
	}))
}

// newStore returns the shared store with all tables emptied.
func newStore(t *testing.T) *Store {
	t.Helper()
	_, err := testStore.pool.Exec(t.Context(), `TRUNCATE users, records`)
	require.NoError(t, err)
	return testStore
}

func TestOpenAppliedMigrationsTwice(t *testing.T) {
	s, err := Open(t.Context(), testDSN)
	require.NoError(t, err)
	s.Close()
}

func TestOpenFails(t *testing.T) {
	tests := []struct {
		name string
		dsn  string
	}{
		{"malformed DSN", "postgres://%zz"},
		{"unreachable database", "postgres://user:pass@127.0.0.1:1/db?connect_timeout=1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := Open(t.Context(), tt.dsn)
			assert.Error(t, err)
			assert.Nil(t, s)
		})
	}
}
