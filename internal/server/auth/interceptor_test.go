package auth

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/AVZotov/gophkeeper/api/gophkeeper/v1"
	"github.com/AVZotov/gophkeeper/internal/server/storage"
)

// protectedMethod is a method that needs a token.
const protectedMethod = pb.Auth_ChangePassword_FullMethodName

// signToken signs claims with the given method and key, bypassing
// [issueToken], to build tokens the server would never issue.
func signToken(t *testing.T, method jwt.SigningMethod, key any, claims jwt.MapClaims) string {
	t.Helper()
	token, err := jwt.NewWithClaims(method, claims).SignedString(key)
	require.NoError(t, err)
	return token
}

// withAuthorization returns a context of a call with the given
// authorization value.
func withAuthorization(ctx context.Context, value string) context.Context {
	return metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", value))
}

// intercept runs the interceptor for method and reports whether the handler
// was called and with which user ID.
func intercept(ctx context.Context, s *Service, method string) (int64, bool, error) {
	var (
		gotID     int64
		gotCalled bool
	)
	handler := func(ctx context.Context, _ any) (any, error) {
		gotCalled = true
		gotID, _ = userIDFrom(ctx)
		return nil, nil
	}
	_, err := s.UnaryInterceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: method}, handler)
	return gotID, gotCalled, err
}

// newInterceptorService returns a service with user 1 whose password changed
// at changedAt.
func newInterceptorService(t *testing.T, changedAt time.Time) *Service {
	t.Helper()
	store := newFakeStore()
	store.users = []storage.User{{ID: 1, Login: "alice"}}
	store.changedAt[1] = changedAt
	return newTestService(t, store)
}

func TestInterceptorPublicMethods(t *testing.T) {
	s := newInterceptorService(t, time.Now())
	public := []string{
		pb.Auth_GetSalt_FullMethodName,
		pb.Auth_Register_FullMethodName,
		pb.Auth_Login_FullMethodName,
	}
	for _, method := range public {
		t.Run(method, func(t *testing.T) {
			_, called, err := intercept(t.Context(), s, method)
			require.NoError(t, err)
			assert.True(t, called)
		})
	}
}

func TestInterceptorRejects(t *testing.T) {
	// The change time has a fraction of a second, like the one from the
	// storage.
	changedAt := time.Now().Add(-time.Hour).Truncate(time.Second).Add(500 * time.Millisecond)
	s := newInterceptorService(t, changedAt)
	now := time.Now()
	claims := func(key string, value any) jwt.MapClaims {
		c := jwt.MapClaims{"sub": "1", "iat": now.Unix(), "exp": now.Add(tokenTTL).Unix()}
		if value == nil {
			delete(c, key)
		} else {
			c[key] = value
		}
		return c
	}
	valid := claims("", nil)
	hs256 := func(c jwt.MapClaims) string {
		return bearerPrefix + signToken(t, jwt.SigningMethodHS256, s.tokenKey, c)
	}
	withHS256 := func(c jwt.MapClaims) context.Context {
		return withAuthorization(context.Background(), hs256(c))
	}

	tests := []struct {
		name   string
		ctx    context.Context
		method string
	}{
		{"no metadata", context.Background(), protectedMethod},
		{"method not in the list", context.Background(), pb.Vault_Pull_FullMethodName},
		{"wrong scheme", withAuthorization(context.Background(), "Basic "+signToken(t, jwt.SigningMethodHS256, s.tokenKey, valid)), protectedMethod},
		{"empty token", withAuthorization(context.Background(), bearerPrefix), protectedMethod},
		{"garbage", withAuthorization(context.Background(), bearerPrefix+"not-a-jwt"), protectedMethod},
		{"other key", withAuthorization(context.Background(), bearerPrefix+signToken(t, jwt.SigningMethodHS256, filled(9, derivedKeySize), valid)), protectedMethod},
		{"HS512", withAuthorization(context.Background(), bearerPrefix+signToken(t, jwt.SigningMethodHS512, s.tokenKey, valid)), protectedMethod},
		{"alg none", withAuthorization(context.Background(), bearerPrefix+signToken(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, valid)), protectedMethod},
		{"expired", withHS256(claims("exp", now.Add(-time.Second).Unix())), protectedMethod},
		{"no expiry", withHS256(claims("exp", nil)), protectedMethod},
		{"no issue time", withHS256(claims("iat", nil)), protectedMethod},
		{"issued in the future", withHS256(claims("iat", now.Add(time.Minute).Unix())), protectedMethod},
		{"bad subject", withHS256(claims("sub", "alice")), protectedMethod},
		{"unknown user", withHS256(claims("sub", "2")), protectedMethod},
		{"issued before password change", withHS256(claims("iat", changedAt.Add(-time.Second).Unix())), protectedMethod},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, called, err := intercept(tt.ctx, s, tt.method)
			assert.Equal(t, codes.Unauthenticated, status.Code(err))
			assert.False(t, called)
		})
	}
}

func TestInterceptorAccepts(t *testing.T) {
	// The token is issued in the same second as the password change, but
	// before it in real time: a silent login right after the change.
	changedAt := time.Now().Add(-time.Minute).Truncate(time.Second).Add(500 * time.Millisecond)
	s := newInterceptorService(t, changedAt)

	tests := []struct {
		name     string
		issuedAt time.Time
	}{
		{"issued by Login", time.Now()},
		{"same second as password change", changedAt.Truncate(time.Second)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := issueToken(s.tokenKey, 1, tt.issuedAt)
			require.NoError(t, err)

			id, called, err := intercept(withAuthorization(t.Context(), bearerPrefix+token), s, protectedMethod)
			require.NoError(t, err)
			assert.True(t, called)
			assert.Equal(t, int64(1), id)
		})
	}
}

func TestInterceptorIPLimit(t *testing.T) {
	s := newInterceptorService(t, time.Now())
	call := func(ip, method string) error {
		_, _, err := intercept(withPeer(t.Context(), ip), s, method)
		return err
	}

	for i := range ipBurst {
		require.NoError(t, call("10.0.0.1", pb.Auth_GetSalt_FullMethodName), "call %d", i+1)
	}
	assert.Equal(t, codes.ResourceExhausted, status.Code(call("10.0.0.1", pb.Auth_GetSalt_FullMethodName)))
	assert.Equal(t, codes.ResourceExhausted, status.Code(call("10.0.0.1", pb.Auth_Register_FullMethodName)),
		"the public methods share the limit")
	assert.NoError(t, call("10.0.0.2", pb.Auth_GetSalt_FullMethodName), "another IP has its own limit")

	for range ipBurst {
		require.NoError(t, call("2001:db8::1", pb.Auth_Login_FullMethodName))
	}
	assert.Equal(t, codes.ResourceExhausted, status.Code(call("2001:db8::2", pb.Auth_Login_FullMethodName)),
		"addresses in one /64 share the limit")
}

func TestInterceptorStoreError(t *testing.T) {
	s := newTestService(t, &fakeStore{err: errStoreDown})
	token, err := issueToken(s.tokenKey, 1, time.Now())
	require.NoError(t, err)

	_, called, err := intercept(withAuthorization(t.Context(), bearerPrefix+token), s, protectedMethod)
	assert.Equal(t, codes.Internal, status.Code(err))
	assert.False(t, called)
}
