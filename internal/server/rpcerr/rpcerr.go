// Package rpcerr builds the gRPC errors the server services return to
// clients.
package rpcerr

import (
	"context"
	"errors"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Internal logs the failure of op and returns Internal that tells the
// client nothing about it. An error of a canceled or expired call gives
// Canceled or DeadlineExceeded and is not logged: the client gave up,
// nothing failed.
func Internal(ctx context.Context, log *slog.Logger, op string, err error) error {
	// The context error alone: the wrapping error has storage details.
	switch {
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, context.Canceled.Error())
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, context.DeadlineExceeded.Error())
	}
	log.ErrorContext(ctx, op+" failed", "error", err)
	return status.Error(codes.Internal, "internal error")
}

// InvalidArgument returns InvalidArgument listing the failed checks, or nil
// if all passed.
func InvalidArgument(checks ...error) error {
	if err := errors.Join(checks...); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return nil
}
