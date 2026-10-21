package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/AVZotov/gophkeeper/api/gophkeeper/v1"
	"github.com/AVZotov/gophkeeper/internal/client/vaultcrypto"
	"github.com/AVZotov/gophkeeper/internal/pgtest"
	"github.com/AVZotov/gophkeeper/internal/server/auth"
	"github.com/AVZotov/gophkeeper/internal/server/storage"
)

// bufSize is the buffer of the in-memory connection.
const bufSize = 1 << 20

// waitTimeout bounds waiting for the server to start or stop.
const waitTimeout = 10 * time.Second

// testDSN points to one PostgreSQL container shared by all tests of the
// package.
var testDSN string

func TestMain(m *testing.M) {
	code, err := runTests(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(code)
}

// runTests starts the container, runs the tests and removes the container.
func runTests(m *testing.M) (int, error) {
	dsn, stop, err := pgtest.Start(context.Background())
	if err != nil {
		return 0, err
	}
	defer func() {
		if err := stop(); err != nil {
			fmt.Fprintln(os.Stderr, "remove container:", err)
		}
	}()

	testDSN = dsn
	return m.Run(), nil
}

// testCert is a self-signed certificate for localhost, in memory and in
// files.
type testCert struct {
	cert     tls.Certificate
	roots    *x509.CertPool
	certFile string
	keyFile  string
}

func newTestCert(t *testing.T) testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(certPEM))

	dir := t.TempDir()
	tc := testCert{
		cert:     cert,
		roots:    roots,
		certFile: filepath.Join(dir, "server.crt"),
		keyFile:  filepath.Join(dir, "server.key"),
	}
	require.NoError(t, os.WriteFile(tc.certFile, certPEM, 0o600))
	require.NoError(t, os.WriteFile(tc.keyFile, keyPEM, 0o600))
	return tc
}

// startServer serves the real server with the test storage on an in-memory
// listener.
func startServer(t *testing.T, tc testCert) *bufconn.Listener {
	t.Helper()
	store, err := storage.Open(t.Context(), testDSN)
	require.NoError(t, err)
	t.Cleanup(store.Close)
	svc, err := auth.NewService(store, mustHexSecret(t, testSecretHex), slog.New(slog.DiscardHandler))
	require.NoError(t, err)

	srv := newGRPCServer(tc.cert, svc)
	lis := bufconn.Listen(bufSize)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	return lis
}

func dial(t *testing.T, lis *bufconn.Listener, creds credentials.TransportCredentials) pb.AuthClient {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///localhost",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(creds))
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return pb.NewAuthClient(conn)
}

func clientTLS(tc testCert) credentials.TransportCredentials {
	return credentials.NewTLS(&tls.Config{RootCAs: tc.roots, ServerName: "localhost", MinVersion: tls.VersionTLS13})
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

// waitNextSecond sleeps past the next whole second. Token issue times have
// whole seconds, so a token issued before the wait is older than a password
// change after it.
func waitNextSecond() {
	const margin = 100 * time.Millisecond
	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second + margin)))
}

func TestAuthEndToEnd(t *testing.T) {
	tc := newTestCert(t)
	client := dial(t, startServer(t, tc), clientTLS(tc))
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

	waitNextSecond()
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

	// The silent login right after the change, usually in the same second.
	resp, err = client.Login(ctx, pb.LoginRequest_builder{Login: login, LoginKey: second.loginKey}.Build())
	require.NoError(t, err)
	assert.Equal(t, second.envelope, resp.GetEnvelope())
	salt, err = client.GetSalt(ctx, pb.GetSaltRequest_builder{Login: login}.Build())
	require.NoError(t, err)
	assert.Equal(t, second.salt, salt.GetSalt())

	_, err = client.ChangePassword(withToken(ctx, resp.GetToken()), toThird)
	assert.NoError(t, err, "the new token must work")
}

func TestServerRejectsPlaintext(t *testing.T) {
	tc := newTestCert(t)
	lis := startServer(t, tc)
	req := pb.GetSaltRequest_builder{Login: "alice"}.Build()

	_, err := dial(t, lis, clientTLS(tc)).GetSalt(t.Context(), req)
	require.NoError(t, err, "the same call over TLS must work")

	_, err = dial(t, lis, insecure.NewCredentials()).GetSalt(t.Context(), req)
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
func runArgs(t *testing.T, tc testCert) []string {
	t.Helper()
	clearEnv(t)
	t.Setenv("SERVER_SECRET", testSecretHex)
	return []string{"-a", "127.0.0.1:0", "-d", testDSN, "-tls-cert", tc.certFile, "-tls-key", tc.keyFile}
}

func TestRunStopsGracefully(t *testing.T) {
	args := runArgs(t, newTestCert(t))
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
	tc := newTestCert(t)
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
