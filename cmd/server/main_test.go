package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"log/slog"
	"math"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	pb "github.com/AVZotov/gophkeeper/api/gophkeeper/v1"
	"github.com/AVZotov/gophkeeper/internal/client/vaultcrypto"
	"github.com/AVZotov/gophkeeper/internal/clocktest"
	"github.com/AVZotov/gophkeeper/internal/pgtest"
	"github.com/AVZotov/gophkeeper/internal/server/auth"
	"github.com/AVZotov/gophkeeper/internal/server/rpcserver"
	"github.com/AVZotov/gophkeeper/internal/server/storage"
	"github.com/AVZotov/gophkeeper/internal/server/vault"
	"github.com/AVZotov/gophkeeper/internal/tlstest"
)

// bufSize is the buffer of the in-memory connection.
const bufSize = 1 << 20

// waitTimeout bounds waiting for the server to start or stop.
const waitTimeout = 10 * time.Second

// testDSN points to one PostgreSQL container shared by all tests of the
// package.
var testDSN string

func TestMain(m *testing.M) {
	os.Exit(pgtest.Run(m, func(dsn string) (func(), error) {
		testDSN = dsn
		return nil, nil
	}))
}

// startServer serves the real server with the test storage and the clock now
// on an in-memory listener.
func startServer(t *testing.T, tc tlstest.Cert, now func() time.Time) *bufconn.Listener {
	t.Helper()
	store, err := storage.Open(t.Context(), testDSN)
	require.NoError(t, err)
	t.Cleanup(store.Close)
	log := slog.New(slog.DiscardHandler)
	authSvc, err := auth.NewService(store, mustHexSecret(t, testSecretHex), log, now)
	require.NoError(t, err)

	srv := rpcserver.New(tc.TLS, authSvc, vault.NewService(store, log))
	lis := bufconn.Listen(bufSize)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	return lis
}

// dial connects to the server on lis, accepting messages as large as the
// server does.
func dial(t *testing.T, lis *bufconn.Listener, creds credentials.TransportCredentials) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///localhost",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(pb.MaxMessageSize),
			grpc.MaxCallSendMsgSize(pb.MaxMessageSize),
		))
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return conn
}

func clientTLS(tc tlstest.Cert) credentials.TransportCredentials {
	return credentials.NewTLS(&tls.Config{RootCAs: tc.Roots, ServerName: "localhost", MinVersion: tls.VersionTLS13})
}

func withToken(ctx context.Context, token string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
}

// clientCredentials are what a real client sends for one password.
type clientCredentials struct {
	salt     []byte
	loginKey []byte
	envelope []byte
}

// newClientCredentials makes credentials of the real client format. The
// login key is random instead of derived: the server cannot tell.
func newClientCredentials() clientCredentials {
	loginKey := make([]byte, vaultcrypto.KeySize)
	rand.Read(loginKey)
	var wrap vaultcrypto.WrapKey
	rand.Read(wrap[:])
	return clientCredentials{
		salt:     vaultcrypto.NewSalt(),
		loginKey: loginKey,
		envelope: vaultcrypto.SealEnvelope(wrap, vaultcrypto.NewDataKey()),
	}
}

func TestAuthEndToEnd(t *testing.T) {
	tc := tlstest.New(t)
	clock := clocktest.New(time.Now())
	client := pb.NewAuthClient(dial(t, startServer(t, tc, clock.Now), clientTLS(tc)))
	ctx := t.Context()
	login := "alice-" + rand.Text()
	first, second, third := newClientCredentials(), newClientCredentials(), newClientCredentials()

	fake, err := client.GetSalt(ctx, pb.GetSaltRequest_builder{Login: login}.Build())
	require.NoError(t, err)
	assert.Len(t, fake.GetSalt(), vaultcrypto.SaltSize, "an unknown login gets a fake salt")

	register := pb.RegisterRequest_builder{
		Login: login, Salt: first.salt, LoginKey: first.loginKey, Envelope: first.envelope,
	}.Build()
	_, err = client.Register(ctx, register)
	require.NoError(t, err)
	_, err = client.Register(ctx, register)
	assert.Equal(t, codes.AlreadyExists, status.Code(err))

	salt, err := client.GetSalt(ctx, pb.GetSaltRequest_builder{Login: login}.Build())
	require.NoError(t, err)
	assert.Equal(t, first.salt, salt.GetSalt())

	resp, err := client.Login(ctx, pb.LoginRequest_builder{Login: login, LoginKey: first.loginKey}.Build())
	require.NoError(t, err)
	assert.Equal(t, first.envelope, resp.GetEnvelope())
	oldToken := resp.GetToken()

	change := pb.ChangePasswordRequest_builder{
		OldLoginKey: first.loginKey,
		NewSalt:     second.salt,
		NewLoginKey: second.loginKey,
		NewEnvelope: second.envelope,
	}.Build()
	_, err = client.ChangePassword(ctx, change)
	assert.Equal(t, codes.Unauthenticated, status.Code(err), "no token")

	// Token issue times have whole seconds: the old token must be a second
	// older than the change to be revoked.
	clock.Advance(time.Second)
	_, err = client.ChangePassword(withToken(ctx, oldToken), change)
	require.NoError(t, err)

	// The login key is right, so only the token can be the reason to refuse.
	toThird := pb.ChangePasswordRequest_builder{
		OldLoginKey: second.loginKey,
		NewSalt:     third.salt,
		NewLoginKey: third.loginKey,
		NewEnvelope: third.envelope,
	}.Build()
	_, err = client.ChangePassword(withToken(ctx, oldToken), toThird)
	assert.Equal(t, codes.Unauthenticated, status.Code(err), "the token from before the change must be revoked")
	_, err = client.Login(ctx, pb.LoginRequest_builder{Login: login, LoginKey: first.loginKey}.Build())
	assert.Equal(t, codes.Unauthenticated, status.Code(err), "the old login key must not work")

	// The silent login right after the change, in the same second.
	resp, err = client.Login(ctx, pb.LoginRequest_builder{Login: login, LoginKey: second.loginKey}.Build())
	require.NoError(t, err)
	assert.Equal(t, second.envelope, resp.GetEnvelope())
	salt, err = client.GetSalt(ctx, pb.GetSaltRequest_builder{Login: login}.Build())
	require.NoError(t, err)
	assert.Equal(t, second.salt, salt.GetSalt())

	_, err = client.ChangePassword(withToken(ctx, resp.GetToken()), toThird)
	assert.NoError(t, err, "the new token must work")
}

// signIn registers a new user and returns the context of its calls with the
// access token.
func signIn(t *testing.T, client pb.AuthClient) context.Context {
	t.Helper()
	login := "alice-" + rand.Text()
	c := newClientCredentials()
	_, err := client.Register(t.Context(), pb.RegisterRequest_builder{
		Login: login, Salt: c.salt, LoginKey: c.loginKey, Envelope: c.envelope,
	}.Build())
	require.NoError(t, err)
	resp, err := client.Login(t.Context(), pb.LoginRequest_builder{Login: login, LoginKey: c.loginKey}.Build())
	require.NoError(t, err)
	return withToken(t.Context(), resp.GetToken())
}

// newRecord returns a new record with plaintext encrypted as the client
// does it.
func newRecord(plaintext []byte) *pb.Record {
	id := uuid.New()
	return pb.Record_builder{
		Id:         id[:],
		Ciphertext: vaultcrypto.EncryptRecord(vaultcrypto.NewDataKey(), id, plaintext),
	}.Build()
}

// pull calls Vault.Pull and returns the page.
func pull(ctx context.Context, t *testing.T, client pb.VaultClient, since int64) *pb.PullResponse {
	t.Helper()
	resp, err := client.Pull(ctx, pb.PullRequest_builder{Since: since}.Build())
	require.NoError(t, err)
	return resp
}

func TestVaultEndToEnd(t *testing.T) {
	tc := tlstest.New(t)
	conn := dial(t, startServer(t, tc, time.Now), clientTLS(tc))
	ctx := signIn(t, pb.NewAuthClient(conn))
	client := pb.NewVaultClient(conn)

	_, err := client.Pull(t.Context(), pb.PullRequest_builder{}.Build())
	assert.Equal(t, codes.Unauthenticated, status.Code(err), "no token")

	file := newRecord(make([]byte, pb.MaxFileSize))
	note := newRecord([]byte("note"))
	for i, r := range []*pb.Record{file, note} {
		resp, err := client.Push(ctx, pb.PushRequest_builder{Id: r.GetId(), Ciphertext: r.GetCiphertext()}.Build())
		require.NoError(t, err)
		r.SetRevision(int64(i + 1))
		assert.Equal(t, r.GetRevision(), resp.GetRevision())
	}

	page := pull(ctx, t, client, 0)
	require.Len(t, page.GetRecords(), 1, "the file takes a page of its own")
	assert.True(t, proto.Equal(file, page.GetRecords()[0]))
	assert.True(t, page.GetHasMore())
	page = pull(ctx, t, client, file.GetRevision())
	require.Len(t, page.GetRecords(), 1)
	assert.True(t, proto.Equal(note, page.GetRecords()[0]))
	assert.False(t, page.GetHasMore())

	// Another device did not see the file and creates a record with the same
	// ID: the conflict brings the whole file back in the status details.
	other := newRecord([]byte("other note"))
	_, err = client.Push(ctx, pb.PushRequest_builder{Id: file.GetId(), Ciphertext: other.GetCiphertext()}.Build())
	st := status.Convert(err)
	require.Equal(t, codes.Aborted, st.Code(), "got %v", err)
	require.Len(t, st.Details(), 1)
	current, ok := st.Details()[0].(*pb.Record)
	require.True(t, ok, "got %T", st.Details()[0])
	assert.True(t, proto.Equal(file, current), "the details must hold the current record")

	resp, err := client.Push(ctx, pb.PushRequest_builder{Id: file.GetId(), BaseRevision: file.GetRevision(), Deleted: true}.Build())
	require.NoError(t, err)
	assert.Equal(t, int64(3), resp.GetRevision())

	page = pull(ctx, t, client, note.GetRevision())
	require.Len(t, page.GetRecords(), 1)
	tombstone := pb.Record_builder{Id: file.GetId(), Revision: 3, Deleted: true}.Build()
	assert.True(t, proto.Equal(tombstone, page.GetRecords()[0]), "got %v", page.GetRecords()[0])
	assert.False(t, page.GetHasMore())
}

// TestVaultMessageTooLarge sends a message just over the limit. Without a
// token it is rejected before its message is read: once read, it would be
// rejected for its size.
func TestVaultMessageTooLarge(t *testing.T) {
	tc := tlstest.New(t)
	conn := dial(t, startServer(t, tc, time.Now), clientTLS(tc))
	client := pb.NewVaultClient(conn)
	id := uuid.New()
	req := pb.PushRequest_builder{Id: id[:], Ciphertext: make([]byte, pb.MaxMessageSize)}.Build()
	// The client checks the size too; here the server has to.
	noClientLimit := grpc.MaxCallSendMsgSize(math.MaxInt32)

	_, err := client.Push(t.Context(), req, noClientLimit)
	assert.Equal(t, codes.Unauthenticated, status.Code(err), "got %v", err)

	_, err = client.Push(signIn(t, pb.NewAuthClient(conn)), req, noClientLimit)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err), "got %v", err)
}

// TestServerRejectsLargeMetadata sends metadata far over the limit to a
// public method, which the token check does not guard.
func TestServerRejectsLargeMetadata(t *testing.T) {
	const largeMetadata = 1 << 20
	tc := tlstest.New(t)
	client := pb.NewAuthClient(dial(t, startServer(t, tc, time.Now), clientTLS(tc)))
	req := pb.GetSaltRequest_builder{Login: "alice"}.Build()

	_, err := client.GetSalt(metadata.AppendToOutgoingContext(t.Context(), "x-small", "value"), req)
	require.NoError(t, err)

	ctx := metadata.AppendToOutgoingContext(t.Context(), "x-large", strings.Repeat("a", largeMetadata))
	_, err = client.GetSalt(ctx, req)
	assert.Error(t, err)
}

func TestServerRejectsPlaintext(t *testing.T) {
	tc := tlstest.New(t)
	lis := startServer(t, tc, time.Now)
	req := pb.GetSaltRequest_builder{Login: "alice"}.Build()

	_, err := pb.NewAuthClient(dial(t, lis, clientTLS(tc))).GetSalt(t.Context(), req)
	require.NoError(t, err, "the same call over TLS must work")

	_, err = pb.NewAuthClient(dial(t, lis, insecure.NewCredentials())).GetSalt(t.Context(), req)
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

// syncBuffer is a bytes.Buffer safe for a logger in one goroutine and a
// reader in another.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// runArgs returns arguments for run with the test database and tc, and
// sets the secret in the environment.
func runArgs(t *testing.T, tc tlstest.Cert) []string {
	t.Helper()
	clearEnv(t)
	t.Setenv("SERVER_SECRET", testSecretHex)
	return []string{"-a", "127.0.0.1:0", "-d", testDSN, "-tls-cert", tc.CertFile, "-tls-key", tc.KeyFile}
}

func TestRunStopsGracefully(t *testing.T) {
	args := runArgs(t, tlstest.New(t))
	var logs syncBuffer
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- run(ctx, slog.New(slog.NewJSONHandler(&logs, nil)), args) }()

	require.Eventually(t, func() bool { return strings.Contains(logs.String(), "server started") },
		waitTimeout, 10*time.Millisecond, "logs: %s", &logs)
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(waitTimeout):
		t.Fatal("run did not stop")
	}
	assert.Contains(t, logs.String(), "server stopped")
	assert.NotContains(t, logs.String(), testSecretHex)
}

func TestRunFails(t *testing.T) {
	tc := tlstest.New(t)
	// Each case overrides one of the working arguments: a later flag wins.
	tests := []struct {
		name     string
		override []string
		wantErr  string
	}{
		{"missing certificate", []string{"-tls-cert", "missing.crt"}, "load TLS certificate"},
		{"unreachable database", []string{"-d", "postgres://u:p@127.0.0.1:1/db?connect_timeout=1"}, "open storage"},
		{"bad address", []string{"-a", "127.0.0.1:-1"}, "listen"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append(runArgs(t, tc), tt.override...)
			err := run(t.Context(), slog.New(slog.DiscardHandler), args)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}
