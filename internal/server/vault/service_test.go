package vault

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/AVZotov/gophkeeper/api/gophkeeper/v1"
	"github.com/AVZotov/gophkeeper/internal/server/auth"
	"github.com/AVZotov/gophkeeper/internal/server/storage"
)

const testOwner = 7

var errStoreDown = errors.New("store is down")

// pushCall is the arguments of one PushRecord call.
type pushCall struct {
	owner      int64
	id         uuid.UUID
	base       int64
	deleted    bool
	ciphertext []byte
}

// pullCall is the arguments of one PullRecords call.
type pullCall struct {
	owner, since         int64
	maxRecords, maxBytes int
}

// fakeStore records the calls and answers with the preset values.
type fakeStore struct {
	pushes   []pushCall
	pulls    []pullCall
	revision int64
	records  []storage.Record
	hasMore  bool
	err      error
}

func (f *fakeStore) PushRecord(_ context.Context, owner int64, id uuid.UUID, base int64, deleted bool, ciphertext []byte) (int64, error) {
	f.pushes = append(f.pushes, pushCall{owner, id, base, deleted, ciphertext})
	return f.revision, f.err
}

func (f *fakeStore) PullRecords(_ context.Context, owner, since int64, maxRecords, maxBytes int) ([]storage.Record, bool, error) {
	f.pulls = append(f.pulls, pullCall{owner, since, maxRecords, maxBytes})
	return f.records, f.hasMore, f.err
}

func newTestService(store RecordStore) *Service {
	return NewService(store, slog.New(slog.DiscardHandler))
}

// ownerContext returns a context of a call made by testOwner.
func ownerContext(t *testing.T) context.Context {
	return auth.WithUserID(t.Context(), testOwner)
}

func filled(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }

func pushRequest(base int64, ciphertext []byte) *pb.PushRequest {
	return pb.PushRequest_builder{Id: filled(1, idSize), BaseRevision: base, Ciphertext: ciphertext}.Build()
}

func TestPush(t *testing.T) {
	tests := []struct {
		name string
		req  *pb.PushRequest
	}{
		{"new record", pushRequest(0, []byte("ciphertext"))},
		{"largest ciphertext", pushRequest(3, filled(2, pb.MaxCiphertextSize))},
		{"tombstone", pb.PushRequest_builder{Id: filled(1, idSize), BaseRevision: 3, Deleted: true}.Build()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &fakeStore{revision: 5}
			resp, err := newTestService(store).Push(ownerContext(t), tt.req)
			require.NoError(t, err)
			assert.Equal(t, int64(5), resp.GetRevision())
			assert.Equal(t, []pushCall{{
				owner:      testOwner,
				id:         uuid.UUID(filled(1, idSize)),
				base:       tt.req.GetBaseRevision(),
				deleted:    tt.req.GetDeleted(),
				ciphertext: tt.req.GetCiphertext(),
			}}, store.pushes)
		})
	}
}

func TestPushInvalidArgument(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*pb.PushRequest)
	}{
		{"no id", func(r *pb.PushRequest) { r.SetId(nil) }},
		{"short id", func(r *pb.PushRequest) { r.SetId(filled(1, idSize-1)) }},
		{"long id", func(r *pb.PushRequest) { r.SetId(filled(1, idSize+1)) }},
		{"negative base revision", func(r *pb.PushRequest) { r.SetBaseRevision(-1) }},
		{"empty ciphertext", func(r *pb.PushRequest) { r.SetCiphertext(nil) }},
		{"ciphertext too large", func(r *pb.PushRequest) { r.SetCiphertext(filled(1, pb.MaxCiphertextSize+1)) }},
		{"tombstone with ciphertext", func(r *pb.PushRequest) { r.SetDeleted(true) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := pushRequest(1, []byte("ciphertext"))
			tt.modify(req)
			store := &fakeStore{}

			_, err := newTestService(store).Push(ownerContext(t), req)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			assert.Empty(t, store.pushes)
		})
	}
}

func TestPushConflict(t *testing.T) {
	current := storage.Record{ID: uuid.UUID(filled(1, idSize)), Revision: 4, Ciphertext: []byte("theirs")}
	store := &fakeStore{err: &storage.ConflictError{Current: current}}

	_, err := newTestService(store).Push(ownerContext(t), pushRequest(3, []byte("mine")))
	st := status.Convert(err)
	require.Equal(t, codes.Aborted, st.Code())
	require.Len(t, st.Details(), 1)
	got, ok := st.Details()[0].(*pb.Record)
	require.True(t, ok, "got %T", st.Details()[0])
	assert.True(t, proto.Equal(toProto(current), got), "got %v", got)
}

func TestPushNotFound(t *testing.T) {
	_, err := newTestService(&fakeStore{err: storage.ErrRecordNotFound}).Push(ownerContext(t), pushRequest(3, []byte("mine")))
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestPull(t *testing.T) {
	records := []storage.Record{
		{ID: uuid.UUID(filled(1, idSize)), Revision: 4, Ciphertext: []byte("one")},
		{ID: uuid.UUID(filled(2, idSize)), Revision: 6, Deleted: true},
	}
	store := &fakeStore{records: records, hasMore: true}

	resp, err := newTestService(store).Pull(ownerContext(t), pb.PullRequest_builder{Since: 3}.Build())
	require.NoError(t, err)
	assert.True(t, resp.GetHasMore())
	require.Len(t, resp.GetRecords(), len(records))
	for i, r := range records {
		assert.True(t, proto.Equal(toProto(r), resp.GetRecords()[i]), "record %d: got %v", i, resp.GetRecords()[i])
	}
	assert.Equal(t, []pullCall{{testOwner, 3, pb.MaxPageRecords, pb.MaxPageBytes}}, store.pulls)
}

func TestPullInvalidArgument(t *testing.T) {
	store := &fakeStore{}
	_, err := newTestService(store).Pull(ownerContext(t), pb.PullRequest_builder{Since: -1}.Build())
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Empty(t, store.pulls)
}

func TestNoUserID(t *testing.T) {
	s := newTestService(&fakeStore{})
	_, err := s.Push(t.Context(), pushRequest(0, []byte("ciphertext")))
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	_, err = s.Pull(t.Context(), pb.PullRequest_builder{}.Build())
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

// TestStoreError checks that a storage failure gives Internal without
// details and is logged.
func TestStoreError(t *testing.T) {
	tests := []struct {
		name string
		call func(*Service) error
	}{
		{"Push", func(s *Service) error {
			_, err := s.Push(ownerContext(t), pushRequest(0, []byte("ciphertext")))
			return err
		}},
		{"Pull", func(s *Service) error {
			_, err := s.Pull(ownerContext(t), pb.PullRequest_builder{}.Build())
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			s := NewService(&fakeStore{err: errStoreDown}, slog.New(slog.NewTextHandler(&logs, nil)))

			err := tt.call(s)
			assert.Equal(t, codes.Internal, status.Code(err))
			assert.NotContains(t, err.Error(), errStoreDown.Error(), "the client must not see storage details")
			assert.Contains(t, logs.String(), errStoreDown.Error())
		})
	}
}
