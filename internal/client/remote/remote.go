// Package remote is the client of the GophKeeper server: gRPC over TLS 1.3
// that trusts only the CA from a file. Calls are retried while the server is
// unavailable, and a rejected token is replaced by a silent login with the
// login key.
package remote

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"
	"uuid"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/AVZotov/gophkeeper/api/gophkeeper/v1"
	"github.com/AVZotov/gophkeeper/internal/client/storage"
	"github.com/AVZotov/gophkeeper/internal/client/vaultcrypto"
)

// Retries of a call while the server is unavailable: up to retryAttempts
// attempts, with a random pause before each retry. The pause limit starts
// at retryInitialBackoff and grows retryBackoffMultiplier times up to
// retryMaxBackoff.
const (
	retryAttempts          = 5
	retryInitialBackoff    = 500 * time.Millisecond
	retryMaxBackoff        = 5 * time.Second
	retryBackoffMultiplier = 2
)

// serviceConfig retries both services on Unavailable only: the other codes
// will not change on a retry.
var serviceConfig = fmt.Sprintf(`{"methodConfig": [{
	"name": [{"service": %q}, {"service": %q}],
	"retryPolicy": {
		"maxAttempts": %d,
		"initialBackoff": "%gs",
		"maxBackoff": "%gs",
		"backoffMultiplier": %d,
		"retryableStatusCodes": ["UNAVAILABLE"]
	}
}]}`,
	pb.Auth_ServiceDesc.ServiceName, pb.Vault_ServiceDesc.ServiceName,
	retryAttempts, retryInitialBackoff.Seconds(), retryMaxBackoff.Seconds(), retryBackoffMultiplier)

var (
	// ErrUnavailable means the server did not answer after all retries.
	ErrUnavailable = errors.New("server is unavailable")
	// ErrWrongCredentials means the server rejected the login and the login
	// key.
	ErrWrongCredentials = errors.New("wrong login or password")
	// ErrLoginTaken means the login is registered already.
	ErrLoginTaken = errors.New("login is taken")
	// ErrPasswordChanged means the server rejected both the token and the
	// login key of the session.
	ErrPasswordChanged = errors.New("password was changed on another device, run gophkeeper unlock")
)

// ConflictError means the record changed on the server after the revision
// the push is based on. Current is the record as the server has it now.
type ConflictError struct {
	Current storage.Record
}

// Error reports the current revision of the record.
func (e *ConflictError) Error() string {
	return fmt.Sprintf("record %s changed on the server: current revision is %d", e.Current.ID, e.Current.Revision)
}

// Client calls the server. It is not safe for concurrent use.
type Client struct {
	conn  *grpc.ClientConn
	auth  pb.AuthClient
	vault pb.VaultClient

	// The credentials of the calls that need a token and of the silent login.
	login    string
	loginKey vaultcrypto.LoginKey
	token    string
}

// Dial returns a client of the server at address that trusts only the CA
// certificate in caPath. It connects on the first call. opts are added to
// the dial options. Returns an error if the CA file cannot be read or has no
// certificates.
func Dial(address, caPath string, opts ...grpc.DialOption) (*Client, error) {
	pem, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates in %s", caPath)
	}

	opts = append([]grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			RootCAs:    roots,
			MinVersion: tls.VersionTLS13,
		})),
		grpc.WithDefaultServiceConfig(serviceConfig),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(pb.MaxMessageSize),
			grpc.MaxCallSendMsgSize(pb.MaxMessageSize),
			// A larger request is not retried at all.
			grpc.MaxRetryRPCBufferSize(pb.MaxMessageSize),
		),
	}, opts...)
	conn, err := grpc.NewClient(address, opts...)
	if err != nil {
		return nil, fmt.Errorf("create client: %w", err)
	}
	return &Client{conn: conn, auth: pb.NewAuthClient(conn), vault: pb.NewVaultClient(conn)}, nil
}

// Close closes the connection. Returns an error if closing fails.
func (c *Client) Close() error {
	return c.conn.Close()
}

// Resume makes the client act for a user logged in before: calls use the
// token, and a rejected token is replaced by a silent login with the login
// key.
func (c *Client) Resume(login string, loginKey vaultcrypto.LoginKey, token string) {
	c.login, c.loginKey, c.token = login, loginKey, token
}

// Token returns the token of the last login.
func (c *Client) Token() string {
	return c.token
}

// GetSalt returns the salt of the login. Returns [ErrUnavailable] if the
// server is unavailable.
func (c *Client) GetSalt(ctx context.Context, login string) ([]byte, error) {
	resp, err := c.auth.GetSalt(ctx, pb.GetSaltRequest_builder{Login: login}.Build())
	if err != nil {
		return nil, fromStatus(err)
	}
	return resp.GetSalt(), nil
}

// Register creates a user. Returns [ErrLoginTaken] if the login is taken and
// [ErrUnavailable] if the server is unavailable.
func (c *Client) Register(ctx context.Context, login string, salt []byte, loginKey vaultcrypto.LoginKey, envelope []byte) error {
	_, err := c.auth.Register(ctx, pb.RegisterRequest_builder{
		Login: login, Salt: salt, LoginKey: loginKey[:], Envelope: envelope,
	}.Build())
	return fromStatus(err)
}

// Login logs in and returns the envelope. The client keeps the token and
// the login key for the next calls, as [Client.Resume] does. Returns
// [ErrWrongCredentials] if the login or the login key is wrong and
// [ErrUnavailable] if the server is unavailable.
func (c *Client) Login(ctx context.Context, login string, loginKey vaultcrypto.LoginKey) ([]byte, error) {
	resp, err := c.auth.Login(ctx, pb.LoginRequest_builder{Login: login, LoginKey: loginKey[:]}.Build())
	if err != nil {
		return nil, fromStatus(err)
	}
	c.Resume(login, loginKey, resp.GetToken())
	return resp.GetEnvelope(), nil
}

// ChangePassword replaces the salt, the login key and the envelope of the
// user. The token stops working, so the next call needs a [Client.Login]
// with the new login key. Returns [ErrWrongCredentials] if the old login key
// is wrong and the errors of the silent login.
func (c *Client) ChangePassword(ctx context.Context, oldLoginKey vaultcrypto.LoginKey, newSalt []byte, newLoginKey vaultcrypto.LoginKey, newEnvelope []byte) error {
	req := pb.ChangePasswordRequest_builder{
		OldLoginKey: oldLoginKey[:], NewSalt: newSalt, NewLoginKey: newLoginKey[:], NewEnvelope: newEnvelope,
	}.Build()
	return c.authorized(ctx, func(ctx context.Context) error {
		_, err := c.auth.ChangePassword(ctx, req)
		return err
	})
}

// Pull returns a page of the records changed on the server after revision
// since and reports whether more are left. Returns the errors of the silent
// login and an error if a record is malformed.
func (c *Client) Pull(ctx context.Context, since int64) ([]storage.Record, bool, error) {
	var resp *pb.PullResponse
	err := c.authorized(ctx, func(ctx context.Context) error {
		var err error
		resp, err = c.vault.Pull(ctx, pb.PullRequest_builder{Since: since}.Build())
		return err
	})
	if err != nil {
		return nil, false, err
	}
	records := make([]storage.Record, len(resp.GetRecords()))
	for i, r := range resp.GetRecords() {
		if records[i], err = fromProto(r); err != nil {
			return nil, false, err
		}
	}
	return records, resp.GetHasMore(), nil
}

// Push sends the record, based on its revision, and returns the revision the
// server gave to the change. Returns [*ConflictError] if the record changed
// on the server after its revision and the errors of the silent login.
func (c *Client) Push(ctx context.Context, r storage.Record) (int64, error) {
	req := pb.PushRequest_builder{
		Id: r.ID[:], BaseRevision: r.Revision, Deleted: r.Deleted, Ciphertext: r.Ciphertext,
	}.Build()
	var resp *pb.PushResponse
	err := c.authorized(ctx, func(ctx context.Context) error {
		var err error
		resp, err = c.vault.Push(ctx, req)
		if status.Code(err) == codes.Aborted {
			return conflict(err)
		}
		return err
	})
	if err != nil {
		return 0, err
	}
	return resp.GetRevision(), nil
}

// authorized makes call with the token. If the server rejects the token,
// it logs in silently with the login key and makes call once more. Returns
// [ErrPasswordChanged] if the server rejects the login key too, and the
// error of call converted by [fromStatus].
func (c *Client) authorized(ctx context.Context, call func(context.Context) error) error {
	err := call(c.withToken(ctx))
	if status.Code(err) == codes.Unauthenticated && c.loginKey != (vaultcrypto.LoginKey{}) {
		if _, err := c.Login(ctx, c.login, c.loginKey); err != nil {
			if errors.Is(err, ErrWrongCredentials) {
				return ErrPasswordChanged
			}
			return err
		}
		err = call(c.withToken(ctx))
	}
	return fromStatus(err)
}

// withToken adds the token to the metadata of the outgoing call.
func (c *Client) withToken(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+c.token)
}

// fromStatus converts a gRPC error into an error of this package. Other
// errors are returned as they are.
func fromStatus(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	switch st.Code() {
	case codes.OK:
		return nil
	case codes.Unavailable:
		return fmt.Errorf("%w: %s", ErrUnavailable, st.Message())
	case codes.Unauthenticated:
		return ErrWrongCredentials
	case codes.AlreadyExists:
		return ErrLoginTaken
	}
	return fmt.Errorf("server: %s: %s", st.Code(), st.Message())
}

// conflict returns the [*ConflictError] of an Aborted push.
func conflict(err error) error {
	for _, d := range status.Convert(err).Details() {
		if r, ok := d.(*pb.Record); ok {
			current, err := fromProto(r)
			if err != nil {
				return err
			}
			return &ConflictError{Current: current}
		}
	}
	return fmt.Errorf("conflict without the current record: %w", err)
}

// fromProto returns the record r received from the server. Returns an error
// if its ID is not a UUID.
func fromProto(r *pb.Record) (storage.Record, error) {
	if len(r.GetId()) != len(uuid.UUID{}) {
		return storage.Record{}, fmt.Errorf("server sent a record ID of %d bytes", len(r.GetId()))
	}
	return storage.Record{
		ID:         uuid.UUID(r.GetId()),
		Revision:   r.GetRevision(),
		Deleted:    r.GetDeleted(),
		Ciphertext: r.GetCiphertext(),
	}, nil
}
