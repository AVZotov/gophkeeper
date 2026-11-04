package vaultsync

import (
	"context"
	"crypto/tls"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/AVZotov/gophkeeper/api/gophkeeper/v1"
	"github.com/AVZotov/gophkeeper/internal/client/remote"
	"github.com/AVZotov/gophkeeper/internal/client/storage"
	"github.com/AVZotov/gophkeeper/internal/client/vaultcrypto"
	"github.com/AVZotov/gophkeeper/internal/tlstest"
)

const (
	// bufSize is the buffer of the in-memory connection.
	bufSize = 1 << 20
	// syncTimeout stops a sync that keeps asking for the same page.
	syncTimeout = 10 * time.Second
	// startRevision is the pull position saved before a sync.
	startRevision = 5
)

func TestCheckPage(t *testing.T) {
	tests := []struct {
		name      string
		revisions []int64
		hasMore   bool
		wantErr   error
	}{
		{name: "empty with more left", hasMore: true, wantErr: ErrBadPage},
		{name: "empty, nothing left"},
		{name: "growing revisions", revisions: []int64{6, 7, 9}},
		{name: "growing revisions with more left", revisions: []int64{6, 7, 9}, hasMore: true},
		{name: "first revision is since", revisions: []int64{5, 6}, wantErr: ErrBadPage},
		{name: "first revision below since", revisions: []int64{4, 6}, wantErr: ErrBadPage},
		{name: "equal revisions in a row", revisions: []int64{6, 7, 7}, wantErr: ErrBadPage},
		{name: "falling revisions", revisions: []int64{7, 6}, wantErr: ErrBadPage},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page := make([]storage.Record, len(tt.revisions))
			for i, revision := range tt.revisions {
				page[i] = storage.Record{ID: uuid.New(), Revision: revision}
			}

			err := checkPage(startRevision, page, tt.hasMore)

			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

// fakeVault answers Pull with pages in order, repeating the last one, as a
// faulty server that does not move on.
type fakeVault struct {
	pb.UnimplementedVaultServer
	pages []*pb.PullResponse
	calls atomic.Int32
}

func (f *fakeVault) Pull(context.Context, *pb.PullRequest) (*pb.PullResponse, error) {
	i := min(int(f.calls.Add(1)), len(f.pages)) - 1
	return f.pages[i], nil
}

// serve returns a client of a server with vault.
func serve(t *testing.T, vault pb.VaultServer) *remote.Client {
	t.Helper()
	cert := tlstest.New(t)
	creds := credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert.TLS}, MinVersion: tls.VersionTLS13})
	srv := grpc.NewServer(grpc.Creds(creds))
	pb.RegisterVaultServer(srv, vault)
	lis := bufconn.Listen(bufSize)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)

	client, err := remote.Dial("passthrough:///localhost:8443", cert.CertFile,
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
	)
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	return client
}

// page returns a response with a new record for each of the revisions.
func page(hasMore bool, revisions ...int64) *pb.PullResponse {
	records := make([]*pb.Record, len(revisions))
	for i, revision := range revisions {
		id := uuid.New()
		records[i] = pb.Record_builder{Id: id[:], Revision: revision, Ciphertext: []byte("ciphertext")}.Build()
	}
	return pb.PullResponse_builder{Records: records, HasMore: hasMore}.Build()
}

// TestSyncRejectsBadPage checks that nothing of a bad page reaches the local
// vault, even the records before the broken one. The pages before it are
// kept.
func TestSyncRejectsBadPage(t *testing.T) {
	tests := []struct {
		name         string
		pages        []*pb.PullResponse
		wantRecords  int
		wantRevision int64
	}{
		{
			name:         "empty with more left",
			pages:        []*pb.PullResponse{page(true)},
			wantRevision: startRevision,
		},
		{
			name:         "first revision is since",
			pages:        []*pb.PullResponse{page(false, startRevision, 6)},
			wantRevision: startRevision,
		},
		{
			name:         "equal revisions in a row",
			pages:        []*pb.PullResponse{page(false, 6, 7, 7)},
			wantRevision: startRevision,
		},
		{
			// The page ends at since: a client without the check asks for it
			// again and again.
			name:         "falling revisions, the same page again",
			pages:        []*pb.PullResponse{page(true, 6, startRevision)},
			wantRevision: startRevision,
		},
		{
			name:         "bad page after a good one",
			pages:        []*pb.PullResponse{page(true, 6, 7), page(false, 7, 8)},
			wantRecords:  2,
			wantRevision: 7,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), syncTimeout)
			defer cancel()
			store, err := storage.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
			require.NoError(t, err)
			defer store.Close()
			require.NoError(t, store.SaveState(ctx, storage.State{
				Salt: []byte("salt"), Envelope: []byte("envelope"), LastRevision: startRevision,
			}))

			_, err = Sync(ctx, store, serve(t, &fakeVault{pages: tt.pages}), vaultcrypto.DataKey{})

			require.ErrorIs(t, err, ErrBadPage)
			local, err := store.List(ctx)
			require.NoError(t, err)
			assert.Len(t, local, tt.wantRecords)
			st, err := store.State(ctx)
			require.NoError(t, err)
			assert.Equal(t, tt.wantRevision, st.LastRevision)
		})
	}
}
