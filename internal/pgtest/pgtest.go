// Package pgtest runs PostgreSQL in a Docker container for tests.
package pgtest

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

// image matches the image in compose.yaml.
const image = "postgres:18-alpine"

// Run starts PostgreSQL in a container, calls setup with its DSN, runs the
// tests and removes the container. The cleanup returned by setup, if not
// nil, runs after the tests. Run returns the exit code for os.Exit in
// TestMain: if Docker is not available or setup fails, it prints the error
// and returns 1, so tests fail instead of being skipped.
func Run(m *testing.M, setup func(dsn string) (cleanup func(), err error)) int {
	code, err := run(m, setup)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return code
}

// run is [Run] that returns the error instead of printing it.
func run(m *testing.M, setup func(dsn string) (func(), error)) (int, error) {
	ctx := context.Background()
	ctr, err := postgres.Run(ctx, image, postgres.BasicWaitStrategies())
	if err != nil {
		return 0, fmt.Errorf("start PostgreSQL container (is Docker running?): %w", err)
	}
	defer func() {
		if err := testcontainers.TerminateContainer(ctr); err != nil {
			fmt.Fprintln(os.Stderr, "remove container:", err)
		}
	}()

	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return 0, fmt.Errorf("container DSN: %w", err)
	}
	cleanup, err := setup(dsn)
	if err != nil {
		return 0, fmt.Errorf("set up tests: %w", err)
	}
	if cleanup != nil {
		defer cleanup()
	}
	return m.Run(), nil
}
