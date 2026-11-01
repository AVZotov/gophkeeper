package auth

import (
	"context"
	"errors"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/tap"

	pb "github.com/AVZotov/gophkeeper/api/gophkeeper/v1"
	"github.com/AVZotov/gophkeeper/internal/server/rpcerr"
	"github.com/AVZotov/gophkeeper/internal/server/storage"
)

// publicMethods need no token. Every other method does, including ones
// added later.
var publicMethods = map[string]bool{
	pb.Auth_GetSalt_FullMethodName:  true,
	pb.Auth_Register_FullMethodName: true,
	pb.Auth_Login_FullMethodName:    true,
}

// bearerPrefix starts the authorization metadata value.
const bearerPrefix = "Bearer "

type (
	userIDKey      struct{}
	tokenClaimsKey struct{}
)

// tokenClaims are the claims of a token checked by [Service.TapHandle].
type tokenClaims struct {
	userID   int64
	issuedAt time.Time
}

// TapHandle runs before the server reads the message of a call, so a client
// without a valid token cannot make it read a large one. It limits the
// public methods GetSalt, Register and Login per client IP and checks the
// token signature and expiry of the other methods. It does not block and
// does not use the storage: the token is checked against the password change
// time later, by [Service.UnaryInterceptor]. Returns ResourceExhausted if a
// client calls the public methods too often and Unauthenticated if the
// token is missing or invalid.
func (s *Service) TapHandle(ctx context.Context, info *tap.Info) (context.Context, error) {
	if publicMethods[info.FullMethodName] {
		if !s.ipLimiter.allow(clientIP(ctx), time.Now()) {
			return nil, status.Error(codes.ResourceExhausted, "too many requests, try again later")
		}
		return ctx, nil
	}
	token, ok := bearerToken(info.Header)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing token")
	}
	id, issuedAt, err := parseToken(s.tokenKey, token)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}
	return context.WithValue(ctx, tokenClaimsKey{}, tokenClaims{userID: id, issuedAt: issuedAt}), nil
}

// UnaryInterceptor finishes the token check of [Service.TapHandle] for every
// call except GetSalt, Register and Login and puts the user ID into the
// context. It rejects tokens issued before the last password change. A call
// that did not pass TapHandle is rejected. Returns Unauthenticated if the
// token is missing or revoked and Internal if the storage fails.
func (s *Service) UnaryInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if publicMethods[info.FullMethod] {
		return handler(ctx, req)
	}
	claims, ok := ctx.Value(tokenClaimsKey{}).(tokenClaims)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing token")
	}
	if err := s.checkNotRevoked(ctx, claims); err != nil {
		return nil, err
	}
	return handler(WithUserID(ctx, claims.userID), req)
}

// checkNotRevoked returns an error if the token was issued before the last
// password change or its user is gone.
func (s *Service) checkNotRevoked(ctx context.Context, claims tokenClaims) error {
	changed, err := s.users.PasswordChangedAt(ctx, claims.userID)
	if errors.Is(err, storage.ErrUserNotFound) {
		return status.Error(codes.Unauthenticated, "invalid token")
	}
	if err != nil {
		return rpcerr.Internal(ctx, s.log, "check token", err)
	}
	// The issue time has whole seconds, so the change time is cut to seconds
	// too: a token issued in the same second as the change stays valid.
	if claims.issuedAt.Before(changed.Truncate(time.Second)) {
		return status.Error(codes.Unauthenticated, "token revoked by password change")
	}
	return nil
}

// bearerToken returns the token from the authorization metadata.
func bearerToken(md metadata.MD) (string, bool) {
	values := md.Get("authorization")
	if len(values) != 1 {
		return "", false
	}
	token, ok := strings.CutPrefix(values[0], bearerPrefix)
	return token, ok && token != ""
}

// WithUserID returns a copy of ctx that carries the ID of the user who
// makes the call. See [UserIDFrom].
func WithUserID(ctx context.Context, id int64) context.Context {
	return context.WithValue(ctx, userIDKey{}, id)
}

// UserIDFrom returns the user ID put into the context by
// [Service.UnaryInterceptor] or [WithUserID]. It reports false if there is
// none.
func UserIDFrom(ctx context.Context) (int64, bool) {
	id, ok := ctx.Value(userIDKey{}).(int64)
	return id, ok
}

// RequireUserID returns the user ID from the context, like [UserIDFrom].
// Returns Unauthenticated if there is none: the call did not go through
// [Service.UnaryInterceptor].
func RequireUserID(ctx context.Context) (int64, error) {
	if id, ok := UserIDFrom(ctx); ok {
		return id, nil
	}
	return 0, status.Error(codes.Unauthenticated, "missing token")
}
