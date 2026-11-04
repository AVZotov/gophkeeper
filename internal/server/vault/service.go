// Package vault is the Vault gRPC service: it stores the users' encrypted
// records and gives out their changes page by page. The server sees only the
// service fields of a record, never its content.
package vault

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"uuid"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/AVZotov/gophkeeper/api/gophkeeper/v1"
	"github.com/AVZotov/gophkeeper/internal/server/auth"
	"github.com/AVZotov/gophkeeper/internal/server/rpcerr"
	"github.com/AVZotov/gophkeeper/internal/server/storage"
)

// idSize is the size of a record UUID in bytes.
const idSize = len(uuid.UUID{})

// RecordStore is the record storage the service needs.
type RecordStore interface {
	PushRecord(
		ctx context.Context, ownerID int64, id uuid.UUID, baseRevision int64, deleted bool, ciphertext []byte,
	) (int64, error)
	PullRecords(ctx context.Context, ownerID, since int64, maxRecords, maxBytes int) ([]storage.Record, bool, error)
}

// Service implements the Vault gRPC service. It takes the user ID from the
// context, so calls must go through [auth.Service.TapHandle], which rejects
// calls without a valid token before their message is read, and
// [auth.Service.UnaryInterceptor], which rejects revoked tokens and puts the
// user ID into the context. It is safe for concurrent use.
type Service struct {
	pb.UnimplementedVaultServer

	records RecordStore
	log     *slog.Logger
}

// NewService returns the service.
func NewService(records RecordStore, log *slog.Logger) *Service {
	return &Service{records: records, log: log}
}

// Pull returns a page of the user's records changed after req.since.
// Returns Unauthenticated if the context has no user ID, InvalidArgument if
// since is negative and Internal if the storage fails.
func (s *Service) Pull(ctx context.Context, req *pb.PullRequest) (*pb.PullResponse, error) {
	owner, err := auth.RequireUserID(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetSince() < 0 {
		return nil, status.Error(codes.InvalidArgument, "since is negative")
	}

	records, hasMore, err := s.records.PullRecords(ctx, owner, req.GetSince(), pb.MaxPageRecords, pb.MaxPageBytes)
	if err != nil {
		return nil, rpcerr.Internal(ctx, s.log, "pull", err)
	}
	page := make([]*pb.Record, len(records))
	for i, r := range records {
		page[i] = toProto(r)
	}
	return pb.PullResponse_builder{Records: page, HasMore: hasMore}.Build(), nil
}

// Push creates, updates or deletes the user's record and returns the
// revision given to the change. Returns Unauthenticated if the context has no
// user ID, InvalidArgument if a field is invalid, NotFound if there is no
// record and base_revision is not 0, Aborted with the current Record in the
// status details if base_revision is not the current revision, and Internal
// if the storage fails.
func (s *Service) Push(ctx context.Context, req *pb.PushRequest) (*pb.PushResponse, error) {
	owner, err := auth.RequireUserID(ctx)
	if err != nil {
		return nil, err
	}
	if err := rpcerr.InvalidArgument(checkPush(req)); err != nil {
		return nil, err
	}

	revision, err := s.records.PushRecord(
		ctx, owner, uuid.UUID(req.GetId()),
		req.GetBaseRevision(), req.GetDeleted(), req.GetCiphertext(),
	)
	if conflict, ok := errors.AsType[*storage.ConflictError](err); ok {
		return nil, s.conflict(ctx, conflict.Current)
	}
	if errors.Is(err, storage.ErrRecordNotFound) {
		return nil, status.Error(codes.NotFound, "record not found")
	}
	if err != nil {
		return nil, rpcerr.Internal(ctx, s.log, "push", err)
	}
	return pb.PushResponse_builder{Revision: revision}.Build(), nil
}

// conflict returns Aborted with the current record in the status details.
func (s *Service) conflict(ctx context.Context, current storage.Record) error {
	st, err := status.New(codes.Aborted, "record changed after the base revision").WithDetails(toProto(current))
	if err != nil {
		return rpcerr.Internal(ctx, s.log, "add conflict details", err)
	}
	return st.Err()
}

// checkPush returns the errors of the invalid fields of req joined, or nil
// if all are valid.
func checkPush(req *pb.PushRequest) error {
	var errs []error
	if n := len(req.GetId()); n != idSize {
		errs = append(errs, fmt.Errorf("id is %d bytes, want %d", n, idSize))
	}
	if req.GetBaseRevision() < 0 {
		errs = append(errs, errors.New("base revision is negative"))
	}
	n := len(req.GetCiphertext())
	switch {
	case req.GetDeleted() && n != 0:
		errs = append(errs, errors.New("ciphertext of a deleted record must be empty"))
	case !req.GetDeleted() && n == 0:
		errs = append(errs, errors.New("ciphertext is empty"))
	case n > pb.MaxCiphertextSize:
		errs = append(errs, fmt.Errorf("ciphertext is %d bytes, more than %d", n, pb.MaxCiphertextSize))
	}
	return errors.Join(errs...)
}

func toProto(r storage.Record) *pb.Record {
	return pb.Record_builder{
		Id:         r.ID[:],
		Revision:   r.Revision,
		Deleted:    r.Deleted,
		Ciphertext: r.Ciphertext,
	}.Build()
}
