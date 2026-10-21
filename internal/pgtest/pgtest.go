// Package pgtest runs PostgreSQL in a Docker container for tests.
package pgtest

import (
	"context"
	"errors"
	"fmt"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

// image matches the image in compose.yaml.
const image = "postgres:18-alpine"

// Start runs PostgreSQL in a container and returns its DSN and a function
// that removes the container. Returns an error if Docker is not available,
// so tests fail instead of being skipped.
func Start(ctx context.Context) (dsn string, stop func() error, err error) {
	ctr, err := postgres.Run(ctx, image, postgres.BasicWaitStrategies())
	if err != nil {
		return "", nil, fmt.Errorf("start PostgreSQL container (is Docker running?): %w", err)
	}
	stop = func() error { return testcontainers.TerminateContainer(ctr) }

	dsn, err = ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return "", nil, errors.Join(fmt.Errorf("container DSN: %w", err), stop())
	}
	return dsn, stop, nil
}
