package remote

import (
	"context"
	"crypto/tls"
	"errors"
	"math"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/AVZotov/gophkeeper/api/gophkeeper/v1"
	"github.com/AVZotov/gophkeeper/internal/tlstest"
)

const bufSize = 1 << 20

// connectTimeout bounds a connection to the test server.
const connectTimeout = 5 * time.Second

var testSalt = []byte("0123456789abcdef")

// fakeAuth answers GetSalt with testSalt, or with err if it is set, and
// counts the calls.
type fakeAuth struct {
	pb.UnimplementedAuthServer
	err   error
	calls atomic.Int32
}

func (f *fakeAuth) GetSalt(context.Context, *pb.GetSaltRequest) (*pb.GetSaltResponse, error) {
	f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	return pb.GetSaltResponse_builder{Salt: testSalt}.Build(), nil
}

// serve serves auth on an in-memory listener with creds and returns the
// listener.
func serve(t *testing.T, auth pb.AuthServer, creds credentials.TransportCredentials) *bufconn.Listener {
	t.Helper()
	srv := grpc.NewServer(grpc.Creds(creds))
	pb.RegisterAuthServer(srv, auth)
	lis := bufconn.Listen(bufSize)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	return lis
}

func serverTLS(cert tlstest.Cert) credentials.TransportCredentials {
	return credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert.TLS}, MinVersion: tls.VersionTLS13})
}

// dial returns a client of lis. The first failDials connections fail, as
// when the server is down for a moment; reconnects come at once.
func dial(t *testing.T, lis *bufconn.Listener, ca string, failDials int32) *Client {
	t.Helper()
	var dials atomic.Int32
	// One address, so a failed connection is a failed attempt.
	c, err := Dial("passthrough:///localhost:8443", ca,
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			if dials.Add(1) <= failDials {
				return nil, errors.New("server is down")
			}
			return lis.DialContext(ctx)
		}),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff:           backoff.Config{BaseDelay: time.Millisecond, MaxDelay: time.Millisecond},
			MinConnectTimeout: connectTimeout,
		}),
	)
	require.NoError(t, err)
	t.Cleanup(func() { c.Close() })
	return c
}

func TestGetSalt(t *testing.T) {
	cert := tlstest.New(t)
	lis := serve(t, &fakeAuth{}, serverTLS(cert))

	salt, err := dial(t, lis, cert.CertFile, 0).GetSalt(t.Context(), "alice")

	require.NoError(t, err)
	assert.Equal(t, testSalt, salt)
}

func TestRetriesWhileUnavailable(t *testing.T) {
	cert := tlstest.New(t)
	auth := &fakeAuth{}
	lis := serve(t, auth, serverTLS(cert))

	salt, err := dial(t, lis, cert.CertFile, 1).GetSalt(t.Context(), "alice")

	require.NoError(t, err, "the call is retried after the failed connection")
	assert.Equal(t, testSalt, salt)
}

func TestUnavailableAfterRetries(t *testing.T) {
	cert := tlstest.New(t)
	lis := serve(t, &fakeAuth{}, serverTLS(cert))

	_, err := dial(t, lis, cert.CertFile, math.MaxInt32).GetSalt(t.Context(), "alice")

	assert.ErrorIs(t, err, ErrUnavailable)
}

func TestNoRetryOfOtherErrors(t *testing.T) {
	cert := tlstest.New(t)
	auth := &fakeAuth{err: status.Error(codes.InvalidArgument, "login is empty")}
	lis := serve(t, auth, serverTLS(cert))

	_, err := dial(t, lis, cert.CertFile, 0).GetSalt(t.Context(), "")

	assert.ErrorContains(t, err, "InvalidArgument: login is empty")
	assert.Equal(t, int32(1), auth.calls.Load())
}

// TestRejectsServerWithoutTLS checks that the client does not talk to a
// server without TLS.
func TestRejectsServerWithoutTLS(t *testing.T) {
	cert := tlstest.New(t)
	auth := &fakeAuth{}
	lis := serve(t, auth, insecure.NewCredentials())

	_, err := dial(t, lis, cert.CertFile, 0).GetSalt(t.Context(), "alice")

	assert.ErrorIs(t, err, ErrTLS)
	assert.Zero(t, auth.calls.Load())
}

// TestRejectsUntrustedServer checks that the client trusts only the CA from
// the file.
func TestRejectsUntrustedServer(t *testing.T) {
	auth := &fakeAuth{}
	lis := serve(t, auth, serverTLS(tlstest.New(t)))

	_, err := dial(t, lis, tlstest.New(t).CertFile, 0).GetSalt(t.Context(), "alice")

	assert.ErrorIs(t, err, ErrTLS)
	assert.ErrorContains(t, err, "x509", "the cause is kept")
	assert.Zero(t, auth.calls.Load())
}

func TestDialFails(t *testing.T) {
	notPEM := filepath.Join(t.TempDir(), "ca.crt")
	require.NoError(t, os.WriteFile(notPEM, []byte("not a certificate"), 0o600))
	tests := []struct {
		name    string
		ca      string
		wantMsg string
	}{
		{name: "no CA file", ca: filepath.Join(t.TempDir(), "missing.crt"), wantMsg: "read CA certificate"},
		{name: "CA file without certificates", ca: notPEM, wantMsg: "no certificates"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := Dial("localhost:8443", tt.ca)
			assert.ErrorContains(t, err, tt.wantMsg)
			assert.Nil(t, c)
		})
	}
}

func TestFromStatus(t *testing.T) {
	plain := errors.New("plain")
	tests := []struct {
		name    string
		err     error
		wantErr error
	}{
		{name: "no error", err: nil, wantErr: nil},
		{name: "unavailable", err: status.Error(codes.Unavailable, "down"), wantErr: ErrUnavailable},
		{name: "unauthenticated", err: status.Error(codes.Unauthenticated, "no"), wantErr: ErrWrongCredentials},
		{name: "already exists", err: status.Error(codes.AlreadyExists, "taken"), wantErr: ErrLoginTaken},
		{name: "not found", err: status.Error(codes.NotFound, "record not found"), wantErr: ErrRecordNotFound},
		{name: "canceled", err: status.Error(codes.Canceled, "canceled"), wantErr: context.Canceled},
		{name: "deadline", err: status.Error(codes.DeadlineExceeded, "late"), wantErr: context.DeadlineExceeded},
		{name: "handshake", err: status.Error(codes.Unavailable, "connection error: transport: authentication handshake failed: x509"), wantErr: ErrTLS},
		{name: "not a status", err: plain, wantErr: plain},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorIs(t, fromStatus(tt.err), tt.wantErr)
		})
	}
}
