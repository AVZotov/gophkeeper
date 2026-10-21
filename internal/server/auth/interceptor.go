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

	pb "github.com/AVZotov/gophkeeper/api/gophkeeper/v1"
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

type userIDKey struct{}

// UnaryInterceptor checks the token of every call except GetSalt, Register
// and Login and puts the user ID into the context. It rejects tokens issued
// before the last password change. The public methods need no token, so
// they are limited per client IP instead. Returns Unauthenticated if the
// token is missing, invalid or revoked, and ResourceExhausted if a client
// calls the public methods too often.
func (s *Service) UnaryInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if publicMethods[info.FullMethod] {
		if !s.ipLimiter.allow(clientIP(ctx), time.Now()) {
			return nil, status.Error(codes.ResourceExhausted, "too many requests, try again later")
		}
		return handler(ctx, req)
	}
	id, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	return handler(context.WithValue(ctx, userIDKey{}, id), req)
}

// authenticate checks the token from the call metadata and returns the user
// ID.
func (s *Service) authenticate(ctx context.Context) (int64, error) {
	token, ok := bearerToken(ctx)
	if !ok {
		return 0, status.Error(codes.Unauthenticated, "missing token")
	}
	id, issuedAt, err := parseToken(s.tokenKey, token)
	if err != nil {
		return 0, status.Error(codes.Unauthenticated, "invalid token")
	}

	changed, err := s.users.PasswordChangedAt(ctx, id)
	if errors.Is(err, storage.ErrUserNotFound) {
		return 0, status.Error(codes.Unauthenticated, "invalid token")
	}
	if err != nil {
		return 0, s.internal(ctx, "check token", err)
	}
	// The issue time has whole seconds, so the change time is cut to seconds
	// too: a token issued in the same second as the change stays valid.
	if issuedAt.Before(changed.Truncate(time.Second)) {
		return 0, status.Error(codes.Unauthenticated, "token revoked by password change")
	}
	return id, nil
}

// bearerToken returns the token from the authorization metadata.
func bearerToken(ctx context.Context) (string, bool) {
	values := metadata.ValueFromIncomingContext(ctx, "authorization")
	if len(values) != 1 {
		return "", false
	}
	token, ok := strings.CutPrefix(values[0], bearerPrefix)
	return token, ok && token != ""
}

// userIDFrom returns the user ID put into the context by
// [Service.UnaryInterceptor].
func userIDFrom(ctx context.Context) (int64, bool) {
	id, ok := ctx.Value(userIDKey{}).(int64)
	return id, ok
}
