package storage

import (
	"bytes"
	"context"
	"encoding/base64"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// creds returns credentials whose bytes all start with b, so different
// credentials are easy to tell apart.
func creds(b byte) Credentials {
	return Credentials{
		Salt:         []byte{b, 1},
		LoginKeyHash: []byte{b, 2},
		Envelope:     []byte{b, 3},
	}
}

func TestCreateUser(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	require.NoError(t, s.CreateUser(ctx, "alice", creds(1)))
	require.NoError(t, s.CreateUser(ctx, "bob", creds(2)))

	alice, err := s.UserByLogin(ctx, "alice")
	require.NoError(t, err)
	assert.Equal(t, "alice", alice.Login)
	assert.Equal(t, creds(1), alice.Credentials)

	bob, err := s.UserByLogin(ctx, "bob")
	require.NoError(t, err)
	assert.Equal(t, creds(2), bob.Credentials)
	assert.NotEqual(t, alice.ID, bob.ID)

	byID, err := s.UserByID(ctx, alice.ID)
	require.NoError(t, err)
	assert.Equal(t, alice, byID)

	changed, err := s.PasswordChangedAt(ctx, alice.ID)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now(), changed, time.Minute)
}

func TestCreateUserLoginTaken(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	require.NoError(t, s.CreateUser(ctx, "alice", creds(1)))

	err := s.CreateUser(ctx, "alice", creds(2))
	require.ErrorIs(t, err, ErrUserExists)

	u, err := s.UserByLogin(ctx, "alice")
	require.NoError(t, err)
	assert.Equal(t, creds(1), u.Credentials, "the first user must stay intact")
}

func TestChangePassword(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	require.NoError(t, s.CreateUser(ctx, "alice", creds(1)))
	require.NoError(t, s.CreateUser(ctx, "bob", creds(2)))
	alice, err := s.UserByLogin(ctx, "alice")
	require.NoError(t, err)
	bob, err := s.UserByLogin(ctx, "bob")
	require.NoError(t, err)

	// Move both change times into the past to see which one is updated.
	past := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err = s.pool.Exec(ctx, `UPDATE users SET password_changed_at = $1`, past)
	require.NoError(t, err)

	require.NoError(t, s.ChangePassword(ctx, alice.ID, creds(3)))

	got, err := s.UserByLogin(ctx, "alice")
	require.NoError(t, err)
	assert.Equal(t, creds(3), got.Credentials)
	changed, err := s.PasswordChangedAt(ctx, alice.ID)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now(), changed, time.Minute)

	got, err = s.UserByLogin(ctx, "bob")
	require.NoError(t, err)
	assert.Equal(t, creds(2), got.Credentials, "other users must stay intact")
	changed, err = s.PasswordChangedAt(ctx, bob.ID)
	require.NoError(t, err)
	assert.True(t, past.Equal(changed), "got %v", changed)
}

func TestUserNotFound(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	require.NoError(t, s.CreateUser(ctx, "alice", creds(1)))
	alice, err := s.UserByLogin(ctx, "alice")
	require.NoError(t, err)
	missingID := alice.ID + 1

	tests := []struct {
		name string
		call func() error
	}{
		{"UserByLogin", func() error {
			_, err := s.UserByLogin(ctx, "bob")
			return err
		}},
		{"UserByID", func() error {
			_, err := s.UserByID(ctx, missingID)
			return err
		}},
		{"ChangePassword", func() error {
			return s.ChangePassword(ctx, missingID, creds(2))
		}},
		{"PasswordChangedAt", func() error {
			_, err := s.PasswordChangedAt(ctx, missingID)
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorIs(t, tt.call(), ErrUserNotFound)
		})
	}
}

func TestUserLogValue(t *testing.T) {
	c := Credentials{
		Salt:         []byte("salt-must-not-leak"),
		LoginKeyHash: []byte("hash-must-not-leak"),
		Envelope:     []byte("envelope-must-not-leak"),
	}
	u := User{ID: 42, Login: "alice", Credentials: c}

	tests := []struct {
		name string
		args []any
		want []string
	}{
		{"User", []any{"user", u}, []string{`"user":{"id":42,"login":"alice"}`}},
		{"Credentials", []any{"creds", c}, []string{`"creds":"[REDACTED]"`}},
		{"User in slog.Any", []any{slog.Any("user", u)}, []string{`"user":{"id":42,"login":"alice"}`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			slog.New(slog.NewJSONHandler(&buf, nil)).Info("test", tt.args...)
			out := buf.String()

			for _, w := range tt.want {
				assert.Contains(t, out, w)
			}
			for _, secret := range [][]byte{c.Salt, c.LoginKeyHash, c.Envelope} {
				assert.NotContains(t, out, string(secret))
				assert.NotContains(t, out, base64.StdEncoding.EncodeToString(secret))
			}
		})
	}
}

func TestUsersCanceledContext(t *testing.T) {
	s := newStore(t)
	require.NoError(t, s.CreateUser(t.Context(), "alice", creds(1)))
	alice, err := s.UserByLogin(t.Context(), "alice")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	tests := []struct {
		name string
		call func() error
	}{
		{"CreateUser", func() error {
			return s.CreateUser(ctx, "bob", creds(2))
		}},
		{"UserByLogin", func() error {
			_, err := s.UserByLogin(ctx, "alice")
			return err
		}},
		{"UserByID", func() error {
			_, err := s.UserByID(ctx, alice.ID)
			return err
		}},
		{"ChangePassword", func() error {
			return s.ChangePassword(ctx, alice.ID, creds(2))
		}},
		{"PasswordChangedAt", func() error {
			_, err := s.PasswordChangedAt(ctx, alice.ID)
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorIs(t, tt.call(), context.Canceled)
		})
	}
}
