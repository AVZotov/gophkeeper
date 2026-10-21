package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	pb "github.com/AVZotov/gophkeeper/api/gophkeeper/v1"
	"github.com/AVZotov/gophkeeper/internal/server/storage"
)

// Sizes of the values the client sends, in bytes. The envelope is a nonce
// of 12 bytes, a data key of 32 bytes and a GCM tag of 16 bytes.
const (
	saltSize     = 16
	loginKeySize = 32
	envelopeSize = 60
	maxLoginSize = 256
)

// ipv6PrefixBits is the IPv6 prefix limited as one client: a single client
// usually gets a whole /64.
const ipv6PrefixBits = 64

// ErrSecretSize means the server secret is not [SecretSize] bytes.
var ErrSecretSize = fmt.Errorf("server secret must be %d bytes", SecretSize)

// UserStore is the user storage the service needs. [storage.Store]
// implements it.
type UserStore interface {
	CreateUser(ctx context.Context, login string, c storage.Credentials, now time.Time) error
	UserByLogin(ctx context.Context, login string) (storage.User, error)
	UserByID(ctx context.Context, id int64) (storage.User, error)
	ChangePassword(ctx context.Context, id int64, c storage.Credentials, now time.Time) error
	PasswordChangedAt(ctx context.Context, id int64) (time.Time, error)
}

// Service implements the Auth gRPC service and checks tokens for the other
// services with [Service.UnaryInterceptor]. It is safe for concurrent use.
type Service struct {
	pb.UnimplementedAuthServer

	users        UserStore
	log          *slog.Logger
	tokenKey     []byte
	fakeSaltKey  []byte
	ipLimiter    *limiter[string]
	loginLimiter *limiter[loginAttempt]
}

// loginAttempt is the key of the login limiter.
type loginAttempt struct {
	login string
	ip    string
}

// NewService returns the service. The token key and the fake salt key are
// derived from secret. Returns [ErrSecretSize] if secret is not [SecretSize]
// bytes.
func NewService(users UserStore, secret []byte, log *slog.Logger) (*Service, error) {
	if len(secret) != SecretSize {
		return nil, ErrSecretSize
	}
	return &Service{
		users:        users,
		log:          log,
		tokenKey:     deriveKey(secret, tokenKeyInfo),
		fakeSaltKey:  deriveKey(secret, fakeSaltKeyInfo),
		ipLimiter:    newLimiter[string](ipBurst, ipInterval),
		loginLimiter: newLimiter[loginAttempt](loginBurst, loginInterval),
	}, nil
}

// GetSalt returns the user's salt, or a fake one if the login is unknown.
// Returns InvalidArgument if the login is invalid.
func (s *Service) GetSalt(ctx context.Context, req *pb.GetSaltRequest) (*pb.GetSaltResponse, error) {
	if err := invalid(checkLogin(req.GetLogin())); err != nil {
		return nil, err
	}
	salt := fakeSalt(s.fakeSaltKey, req.GetLogin())
	u, err := s.users.UserByLogin(ctx, req.GetLogin())
	switch {
	case err == nil:
		salt = u.Salt
	case !errors.Is(err, storage.ErrUserNotFound):
		return nil, s.internal(ctx, "get salt", err)
	}
	return pb.GetSaltResponse_builder{Salt: salt}.Build(), nil
}

// Register creates a user. Returns InvalidArgument if the login is invalid
// or a field has the wrong size, and AlreadyExists if the login is taken.
func (s *Service) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	err := invalid(
		checkLogin(req.GetLogin()),
		checkSize("salt", req.GetSalt(), saltSize),
		checkSize("login key", req.GetLoginKey(), loginKeySize),
		checkSize("envelope", req.GetEnvelope(), envelopeSize),
	)
	if err != nil {
		return nil, err
	}

	err = s.users.CreateUser(ctx, req.GetLogin(), storage.Credentials{
		Salt:         req.GetSalt(),
		LoginKeyHash: hashLoginKey(req.GetLoginKey()),
		Envelope:     req.GetEnvelope(),
	}, time.Now())
	if errors.Is(err, storage.ErrUserExists) {
		return nil, status.Error(codes.AlreadyExists, "login is taken")
	}
	if err != nil {
		return nil, s.internal(ctx, "register", err)
	}
	return pb.RegisterResponse_builder{}.Build(), nil
}

// Login checks the login key and returns a token and the envelope. Returns
// InvalidArgument if the login is invalid or the login key has the wrong
// size, ResourceExhausted if there were too many attempts for this login
// from this client, and Unauthenticated if the login or the login key is
// wrong. The two cases look the same, so the answer does not show whether
// the user exists.
func (s *Service) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	err := invalid(
		checkLogin(req.GetLogin()),
		checkSize("login key", req.GetLoginKey(), loginKeySize),
	)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	if !s.loginLimiter.allow(loginAttempt{login: req.GetLogin(), ip: clientIP(ctx)}, now) {
		return nil, status.Error(codes.ResourceExhausted, "too many login attempts, try again later")
	}

	errWrong := status.Error(codes.Unauthenticated, "wrong login or login key")
	u, err := s.users.UserByLogin(ctx, req.GetLogin())
	if errors.Is(err, storage.ErrUserNotFound) {
		return nil, errWrong
	}
	if err != nil {
		return nil, s.internal(ctx, "login", err)
	}
	if !checkLoginKey(req.GetLoginKey(), u.LoginKeyHash) {
		return nil, errWrong
	}

	token, err := issueToken(s.tokenKey, u.ID, now)
	if err != nil {
		return nil, s.internal(ctx, "issue token", err)
	}
	return pb.LoginResponse_builder{Token: token, Envelope: u.Envelope}.Build(), nil
}

// ChangePassword replaces the user's salt, login key and envelope. It needs
// a token and the current login key. Returns InvalidArgument if a field has
// the wrong size and Unauthenticated if the current login key is wrong.
func (s *Service) ChangePassword(ctx context.Context, req *pb.ChangePasswordRequest) (*pb.ChangePasswordResponse, error) {
	id, ok := userIDFrom(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing token")
	}
	err := invalid(
		checkSize("old login key", req.GetOldLoginKey(), loginKeySize),
		checkSize("new salt", req.GetNewSalt(), saltSize),
		checkSize("new login key", req.GetNewLoginKey(), loginKeySize),
		checkSize("new envelope", req.GetNewEnvelope(), envelopeSize),
	)
	if err != nil {
		return nil, err
	}

	u, err := s.users.UserByID(ctx, id)
	if err != nil {
		return nil, s.internal(ctx, "change password", err)
	}
	if !checkLoginKey(req.GetOldLoginKey(), u.LoginKeyHash) {
		return nil, status.Error(codes.Unauthenticated, "wrong login key")
	}

	err = s.users.ChangePassword(ctx, id, storage.Credentials{
		Salt:         req.GetNewSalt(),
		LoginKeyHash: hashLoginKey(req.GetNewLoginKey()),
		Envelope:     req.GetNewEnvelope(),
	}, time.Now())
	if err != nil {
		return nil, s.internal(ctx, "change password", err)
	}
	return pb.ChangePasswordResponse_builder{}.Build(), nil
}

// internal logs err and returns a gRPC error that tells the client nothing
// about it.
func (s *Service) internal(ctx context.Context, op string, err error) error {
	s.log.ErrorContext(ctx, op+" failed", "error", err)
	return status.Error(codes.Internal, "internal error")
}

// hashLoginKey returns the hash of the login key kept in the storage. The
// login key is a random 256-bit value, so a fast hash is enough.
func hashLoginKey(loginKey []byte) []byte {
	h := sha256.Sum256(loginKey)
	return h[:]
}

// checkLoginKey reports whether loginKey matches the stored hash, in
// constant time.
func checkLoginKey(loginKey, hash []byte) bool {
	return subtle.ConstantTimeCompare(hashLoginKey(loginKey), hash) == 1
}

// invalid returns InvalidArgument listing the failed checks, or nil if all
// passed.
func invalid(checks ...error) error {
	if err := errors.Join(checks...); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return nil
}

// checkLogin returns an error if the login is empty, longer than
// [maxLoginSize] bytes, not valid UTF-8, has control characters or starts
// or ends with a space. The login is not normalized: logins that differ in
// any byte are different.
func checkLogin(login string) error {
	switch {
	case login == "":
		return errors.New("login is empty")
	case len(login) > maxLoginSize:
		return fmt.Errorf("login is longer than %d bytes", maxLoginSize)
	case !utf8.ValidString(login):
		return errors.New("login is not valid UTF-8")
	case strings.ContainsFunc(login, unicode.IsControl):
		return errors.New("login has control characters")
	case strings.TrimSpace(login) != login:
		return errors.New("login starts or ends with a space")
	}
	return nil
}

// checkSize returns an error if b is not want bytes long.
func checkSize(name string, b []byte, want int) error {
	if len(b) != want {
		return fmt.Errorf("%s is %d bytes, want %d", name, len(b), want)
	}
	return nil
}

// clientIP returns the caller's IP address without the port, as the key of
// the limiters. An IPv6 address is cut to its /64 prefix, so a client cannot
// get past the limits by changing addresses inside it. If the peer address
// is not an IP address, it is returned as is.
func clientIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return ""
	}
	ap, err := netip.ParseAddrPort(p.Addr.String())
	if err != nil {
		return p.Addr.String()
	}
	addr := ap.Addr().Unmap().WithZone("")
	if addr.Is4() {
		return addr.String()
	}
	prefix, err := addr.Prefix(ipv6PrefixBits)
	if err != nil {
		return addr.String()
	}
	return prefix.String()
}
