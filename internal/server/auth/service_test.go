package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	pb "github.com/AVZotov/gophkeeper/api/gophkeeper/v1"
	"github.com/AVZotov/gophkeeper/internal/server/storage"
)

var (
	testSecret   = bytes.Repeat([]byte{7}, SecretSize)
	errStoreDown = errors.New("store is down")
)

// fakeStore keeps users in memory. If err is set, every method returns it.
type fakeStore struct {
	users     []storage.User
	changedAt map[int64]time.Time
	err       error
}

func newFakeStore() *fakeStore {
	return &fakeStore{changedAt: make(map[int64]time.Time)}
}

func (f *fakeStore) CreateUser(_ context.Context, login string, c storage.Credentials, now time.Time) error {
	if f.err != nil {
		return f.err
	}
	if _, err := f.UserByLogin(context.Background(), login); err == nil {
		return storage.ErrUserExists
	}
	id := int64(len(f.users) + 1)
	f.users = append(f.users, storage.User{ID: id, Login: login, Credentials: c})
	f.changedAt[id] = now
	return nil
}

func (f *fakeStore) UserByLogin(_ context.Context, login string) (storage.User, error) {
	if f.err != nil {
		return storage.User{}, f.err
	}
	for _, u := range f.users {
		if u.Login == login {
			return u, nil
		}
	}
	return storage.User{}, storage.ErrUserNotFound
}

func (f *fakeStore) UserByID(_ context.Context, id int64) (storage.User, error) {
	if f.err != nil {
		return storage.User{}, f.err
	}
	for _, u := range f.users {
		if u.ID == id {
			return u, nil
		}
	}
	return storage.User{}, storage.ErrUserNotFound
}

func (f *fakeStore) ChangePassword(_ context.Context, id int64, c storage.Credentials, now time.Time) error {
	if f.err != nil {
		return f.err
	}
	for i := range f.users {
		if f.users[i].ID == id {
			f.users[i].Credentials = c
			f.changedAt[id] = now
			return nil
		}
	}
	return storage.ErrUserNotFound
}

func (f *fakeStore) PasswordChangedAt(_ context.Context, id int64) (time.Time, error) {
	if f.err != nil {
		return time.Time{}, f.err
	}
	t, ok := f.changedAt[id]
	if !ok {
		return time.Time{}, storage.ErrUserNotFound
	}
	return t, nil
}

func newTestService(t *testing.T, users UserStore) *Service {
	t.Helper()
	s, err := NewService(users, testSecret, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	return s
}

// filled returns a slice of n bytes equal to b.
func filled(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }

func registerRequest(login string, b byte) *pb.RegisterRequest {
	return pb.RegisterRequest_builder{
		Login:    login,
		Salt:     filled(b, saltSize),
		LoginKey: filled(b, loginKeySize),
		Envelope: filled(b, envelopeSize),
	}.Build()
}

// withPeer returns a context of a call from ip.
func withPeer(ctx context.Context, ip string) context.Context {
	return peer.NewContext(ctx, &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 50000}})
}

func TestNewServiceSecretSize(t *testing.T) {
	for _, n := range []int{0, SecretSize - 1, SecretSize + 1} {
		_, err := NewService(newFakeStore(), filled(1, n), slog.New(slog.DiscardHandler))
		assert.ErrorIs(t, err, ErrSecretSize, "secret of %d bytes", n)
	}
}

func TestRegister(t *testing.T) {
	store := newFakeStore()
	s := newTestService(t, store)
	ctx := t.Context()

	_, err := s.Register(ctx, registerRequest("alice", 1))
	require.NoError(t, err)

	u, err := store.UserByLogin(ctx, "alice")
	require.NoError(t, err)
	wantHash := sha256.Sum256(filled(1, loginKeySize))
	assert.Equal(t, storage.Credentials{
		Salt:         filled(1, saltSize),
		LoginKeyHash: wantHash[:],
		Envelope:     filled(1, envelopeSize),
	}, u.Credentials, "the login key itself must not be stored")
	changed, err := store.PasswordChangedAt(ctx, u.ID)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now(), changed, time.Minute, "the change time comes from the server clock")

	_, err = s.Register(ctx, registerRequest("alice", 2))
	assert.Equal(t, codes.AlreadyExists, status.Code(err))
}

func TestRegisterInvalidArgument(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*pb.RegisterRequest)
	}{
		{"invalid login", func(r *pb.RegisterRequest) { r.SetLogin(" alice") }},
		{"short salt", func(r *pb.RegisterRequest) { r.SetSalt(filled(1, saltSize-1)) }},
		{"long login key", func(r *pb.RegisterRequest) { r.SetLoginKey(filled(1, loginKeySize+1)) }},
		{"short envelope", func(r *pb.RegisterRequest) { r.SetEnvelope(filled(1, envelopeSize-1)) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newFakeStore()
			req := registerRequest("alice", 1)
			tt.modify(req)

			_, err := newTestService(t, store).Register(t.Context(), req)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			assert.Empty(t, store.users)
		})
	}
}

func TestCheckLogin(t *testing.T) {
	valid := []string{"alice", "alice smith", "алиса", "a@example.com", strings.Repeat("a", maxLoginSize)}
	for _, login := range valid {
		assert.NoError(t, checkLogin(login), "%q", login)
	}

	invalid := []string{
		"",
		strings.Repeat("a", maxLoginSize+1),
		"alice\xff",
		"ali\x00ce",
		"ali\tce",
		"alice\n",
		"ali\u0085ce",
		" alice",
		"alice ",
		"\u00a0alice",
	}
	for _, login := range invalid {
		assert.Error(t, checkLogin(login), "%q", login)
	}
}

func TestGetSalt(t *testing.T) {
	store := newFakeStore()
	s := newTestService(t, store)
	ctx := t.Context()
	_, err := s.Register(ctx, registerRequest("alice", 1))
	require.NoError(t, err)

	getSalt := func(s *Service, login string) []byte {
		resp, err := s.GetSalt(ctx, pb.GetSaltRequest_builder{Login: login}.Build())
		require.NoError(t, err)
		return resp.GetSalt()
	}

	assert.Equal(t, filled(1, saltSize), getSalt(s, "alice"))

	fake := getSalt(s, "bob")
	assert.Len(t, fake, saltSize)
	assert.Equal(t, fake, getSalt(s, "bob"), "a fake salt must not change")
	assert.NotEqual(t, fake, getSalt(s, "carol"), "logins must get different fake salts")

	other, err := NewService(store, filled(8, SecretSize), slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	assert.NotEqual(t, fake, getSalt(other, "bob"), "a fake salt must depend on the secret")
}

func TestLogin(t *testing.T) {
	store := newFakeStore()
	s := newTestService(t, store)
	ctx := t.Context()
	_, err := s.Register(ctx, registerRequest("alice", 1))
	require.NoError(t, err)

	resp, err := s.Login(ctx, pb.LoginRequest_builder{Login: "alice", LoginKey: filled(1, loginKeySize)}.Build())
	require.NoError(t, err)
	assert.Equal(t, filled(1, envelopeSize), resp.GetEnvelope())

	id, issuedAt, err := parseToken(s.tokenKey, resp.GetToken())
	require.NoError(t, err)
	assert.Equal(t, int64(1), id)
	assert.WithinDuration(t, time.Now(), issuedAt, time.Minute)
}

func TestLoginWrong(t *testing.T) {
	tests := []struct {
		name     string
		login    string
		loginKey []byte
	}{
		{"wrong login key", "alice", filled(2, loginKeySize)},
		{"unknown login", "bob", filled(1, loginKeySize)},
	}
	var messages []string
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestService(t, newFakeStore())
			_, err := s.Register(t.Context(), registerRequest("alice", 1))
			require.NoError(t, err)

			_, err = s.Login(t.Context(), pb.LoginRequest_builder{Login: tt.login, LoginKey: tt.loginKey}.Build())
			assert.Equal(t, codes.Unauthenticated, status.Code(err))
			messages = append(messages, status.Convert(err).Message())
		})
	}
	require.Len(t, messages, len(tests))
	assert.Equal(t, messages[0], messages[1], "the answer must not show whether the user exists")
}

func TestLoginRateLimit(t *testing.T) {
	s := newTestService(t, newFakeStore())
	_, err := s.Register(t.Context(), registerRequest("alice", 1))
	require.NoError(t, err)

	login := func(ip, login string, key byte) error {
		_, err := s.Login(withPeer(t.Context(), ip),
			pb.LoginRequest_builder{Login: login, LoginKey: filled(key, loginKeySize)}.Build())
		return err
	}

	for range loginBurst {
		assert.Equal(t, codes.Unauthenticated, status.Code(login("10.0.0.1", "alice", 2)))
	}
	assert.Equal(t, codes.ResourceExhausted, status.Code(login("10.0.0.1", "alice", 1)),
		"the right key must not get through once the limit is hit")

	assert.NoError(t, login("10.0.0.2", "alice", 1), "another IP has its own limit")
	assert.Equal(t, codes.Unauthenticated, status.Code(login("10.0.0.1", "bob", 1)),
		"another login has its own limit")
}

func TestChangePassword(t *testing.T) {
	store := newFakeStore()
	s := newTestService(t, store)
	_, err := s.Register(t.Context(), registerRequest("alice", 1))
	require.NoError(t, err)
	ctx := context.WithValue(t.Context(), userIDKey{}, int64(1))

	req := func(oldKey byte) *pb.ChangePasswordRequest {
		return pb.ChangePasswordRequest_builder{
			OldLoginKey: filled(oldKey, loginKeySize),
			NewSalt:     filled(3, saltSize),
			NewLoginKey: filled(3, loginKeySize),
			NewEnvelope: filled(3, envelopeSize),
		}.Build()
	}

	_, err = s.ChangePassword(ctx, req(2))
	assert.Equal(t, codes.Unauthenticated, status.Code(err), "wrong old login key")
	u, err := store.UserByID(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, filled(1, saltSize), u.Salt, "nothing must change on a wrong key")

	_, err = s.ChangePassword(t.Context(), req(1))
	assert.Equal(t, codes.Unauthenticated, status.Code(err), "no user ID in the context")

	store.changedAt[1] = time.Now().Add(-time.Hour)
	_, err = s.ChangePassword(ctx, req(1))
	require.NoError(t, err)
	u, err = store.UserByID(ctx, 1)
	require.NoError(t, err)
	wantHash := sha256.Sum256(filled(3, loginKeySize))
	assert.Equal(t, storage.Credentials{
		Salt:         filled(3, saltSize),
		LoginKeyHash: wantHash[:],
		Envelope:     filled(3, envelopeSize),
	}, u.Credentials)
	changed, err := store.PasswordChangedAt(ctx, 1)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now(), changed, time.Minute, "the change time comes from the server clock")
}

func TestChangePasswordInvalidArgument(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*pb.ChangePasswordRequest)
	}{
		{"short old login key", func(r *pb.ChangePasswordRequest) { r.SetOldLoginKey(filled(1, loginKeySize-1)) }},
		{"long new salt", func(r *pb.ChangePasswordRequest) { r.SetNewSalt(filled(1, saltSize+1)) }},
		{"empty new login key", func(r *pb.ChangePasswordRequest) { r.SetNewLoginKey(nil) }},
		{"long new envelope", func(r *pb.ChangePasswordRequest) { r.SetNewEnvelope(filled(1, envelopeSize+1)) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := pb.ChangePasswordRequest_builder{
				OldLoginKey: filled(1, loginKeySize),
				NewSalt:     filled(1, saltSize),
				NewLoginKey: filled(1, loginKeySize),
				NewEnvelope: filled(1, envelopeSize),
			}.Build()
			tt.modify(req)
			ctx := context.WithValue(t.Context(), userIDKey{}, int64(1))

			_, err := newTestService(t, newFakeStore()).ChangePassword(ctx, req)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
}

func TestLoginInvalidArgument(t *testing.T) {
	tests := []struct {
		name string
		req  *pb.LoginRequest
	}{
		{"empty login", pb.LoginRequest_builder{LoginKey: filled(1, loginKeySize)}.Build()},
		{"short login key", pb.LoginRequest_builder{Login: "alice", LoginKey: filled(1, loginKeySize-1)}.Build()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newTestService(t, newFakeStore()).Login(t.Context(), tt.req)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
}

func TestGetSaltInvalidArgument(t *testing.T) {
	_, err := newTestService(t, newFakeStore()).GetSalt(t.Context(), pb.GetSaltRequest_builder{}.Build())
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestStoreError checks that a storage failure gives Internal without
// details and is logged.
func TestStoreError(t *testing.T) {
	ctx := context.WithValue(t.Context(), userIDKey{}, int64(1))
	tests := []struct {
		name string
		call func(*Service) error
	}{
		{"GetSalt", func(s *Service) error {
			_, err := s.GetSalt(ctx, pb.GetSaltRequest_builder{Login: "alice"}.Build())
			return err
		}},
		{"Register", func(s *Service) error {
			_, err := s.Register(ctx, registerRequest("alice", 1))
			return err
		}},
		{"Login", func(s *Service) error {
			_, err := s.Login(ctx, pb.LoginRequest_builder{Login: "alice", LoginKey: filled(1, loginKeySize)}.Build())
			return err
		}},
		{"ChangePassword", func(s *Service) error {
			_, err := s.ChangePassword(ctx, pb.ChangePasswordRequest_builder{
				OldLoginKey: filled(1, loginKeySize),
				NewSalt:     filled(1, saltSize),
				NewLoginKey: filled(1, loginKeySize),
				NewEnvelope: filled(1, envelopeSize),
			}.Build())
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			s, err := NewService(&fakeStore{err: errStoreDown}, testSecret, slog.New(slog.NewTextHandler(&logs, nil)))
			require.NoError(t, err)

			err = tt.call(s)
			assert.Equal(t, codes.Internal, status.Code(err))
			assert.NotContains(t, err.Error(), errStoreDown.Error(), "the client must not see storage details")
			assert.Contains(t, logs.String(), errStoreDown.Error())
		})
	}
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
		want string
	}{
		{"IPv4", withPeer(context.Background(), "10.0.0.1"), "10.0.0.1"},
		{"IPv6", withPeer(context.Background(), "2001:db8::1"), "2001:db8::/64"},
		{"IPv6 in the same /64", withPeer(context.Background(), "2001:db8::ffff:1"), "2001:db8::/64"},
		{"IPv6 in another /64", withPeer(context.Background(), "2001:db8:0:1::1"), "2001:db8:0:1::/64"},
		{"IPv4 in IPv6", withPeer(context.Background(), "::ffff:10.0.0.1"), "10.0.0.1"},
		{"not an IP", peer.NewContext(context.Background(), &peer.Peer{Addr: fakeAddr("bufconn")}), "bufconn"},
		{"no peer", context.Background(), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, clientIP(tt.ctx))
		})
	}
}

type fakeAddr string

func (a fakeAddr) Network() string { return string(a) }
func (a fakeAddr) String() string  { return string(a) }
