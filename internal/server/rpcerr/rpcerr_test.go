package rpcerr

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestInternal(t *testing.T) {
	errStoreDown := errors.New("store is down")
	tests := []struct {
		name    string
		err     error
		want    codes.Code
		wantLog bool
	}{
		{"failure", fmt.Errorf("select: %w", errStoreDown), codes.Internal, true},
		{"canceled call", fmt.Errorf("select: %w", context.Canceled), codes.Canceled, false},
		{"expired call", fmt.Errorf("select: %w", context.DeadlineExceeded), codes.DeadlineExceeded, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			err := Internal(t.Context(), slog.New(slog.NewTextHandler(&logs, nil)), "pull", tt.err)

			assert.Equal(t, tt.want, status.Code(err))
			assert.NotContains(t, err.Error(), "select", "the client must not see the details")
			if tt.wantLog {
				assert.Contains(t, logs.String(), "pull failed")
				assert.Contains(t, logs.String(), errStoreDown.Error())
			} else {
				assert.Empty(t, logs.String())
			}
		})
	}
}

func TestInvalidArgument(t *testing.T) {
	assert.NoError(t, InvalidArgument(nil, nil))

	err := InvalidArgument(nil, errors.New("login is empty"), errors.New("salt is short"))
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, err.Error(), "login is empty")
	assert.Contains(t, err.Error(), "salt is short")
}
