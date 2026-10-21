package storage

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

// postgresImage matches the image in compose.yaml.
const postgresImage = "postgres:18-alpine"

// testDSN and testStore point to one PostgreSQL container shared by all tests
// of the package.
var (
	testDSN   string
	testStore *Store
)

func TestMain(m *testing.M) {
	code, err := runTests(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(code)
}

// runTests starts the container, runs the tests and removes the container.
// Without Docker it returns an error, so the tests fail instead of being
// skipped.
func runTests(m *testing.M) (int, error) {
	ctx := context.Background()
	ctr, err := postgres.Run(ctx, postgresImage, postgres.BasicWaitStrategies())
	if err != nil {
		return 0, fmt.Errorf("start PostgreSQL container (is Docker running?): %w", err)
	}
	defer func() {
		if err := testcontainers.TerminateContainer(ctr); err != nil {
			fmt.Fprintln(os.Stderr, "terminate container:", err)
		}
	}()

	testDSN, err = ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return 0, fmt.Errorf("container DSN: %w", err)
	}
	testStore, err = Open(ctx, testDSN)
	if err != nil {
		return 0, fmt.Errorf("open store: %w", err)
	}
	defer testStore.Close()

	return m.Run(), nil
}

// newStore returns the shared store with all tables emptied.
func newStore(t *testing.T) *Store {
	t.Helper()
	_, err := testStore.pool.Exec(t.Context(), `TRUNCATE users`)
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
