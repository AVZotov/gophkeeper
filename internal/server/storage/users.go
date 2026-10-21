package storage

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	// ErrUserExists means the login is already taken.
	ErrUserExists = errors.New("user already exists")
	// ErrUserNotFound means there is no user with the given login or ID.
	ErrUserNotFound = errors.New("user not found")
)

// Credentials are the user's data tied to the password. They are set at
// registration and replaced together on password change.
type Credentials struct {
	Salt         []byte
	LoginKeyHash []byte
	Envelope     []byte
}

// LogValue hides the credentials in slog output: the envelope and the login
// key hash would let anyone brute-force the password offline.
func (Credentials) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// User is a registered user.
type User struct {
	ID    int64
	Login string
	Credentials
}

// LogValue shows only the ID and the login in slog output. See
// [Credentials.LogValue].
func (u User) LogValue() slog.Value {
	return slog.GroupValue(slog.Int64("id", u.ID), slog.String("login", u.Login))
}

// CreateUser registers a user with the given login. now becomes the
// password change time, so it must come from the clock that sets token issue
// times. Returns [ErrUserExists] if the login is taken.
func (s *Store) CreateUser(ctx context.Context, login string, c Credentials, now time.Time) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO users (login, salt, login_key_hash, envelope, password_changed_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		login, c.Salt, c.LoginKeyHash, c.Envelope, now)
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == pgerrcode.UniqueViolation {
		return ErrUserExists
	}
	if err != nil {
		return fmt.Errorf("insert user: %w", err)
	}
	return nil
}

// UserByLogin returns the user with the given login. Returns
// [ErrUserNotFound] if there is none.
func (s *Store) UserByLogin(ctx context.Context, login string) (User, error) {
	return s.userWhere(ctx, "login = $1", login)
}

// UserByID returns the user with the given ID. Returns [ErrUserNotFound] if
// there is none.
func (s *Store) UserByID(ctx context.Context, id int64) (User, error) {
	return s.userWhere(ctx, "id = $1", id)
}

// userWhere returns the user matching cond, a constant SQL condition on $1.
// Returns [ErrUserNotFound] if there is none.
func (s *Store) userWhere(ctx context.Context, cond string, arg any) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT id, login, salt, login_key_hash, envelope FROM users WHERE `+cond,
		arg).Scan(&u.ID, &u.Login, &u.Salt, &u.LoginKeyHash, &u.Envelope)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrUserNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("select user: %w", err)
	}
	return u, nil
}

// ChangePassword replaces the user's credentials and sets the password change
// time to now, so tokens issued before it can be rejected. now must come from
// the clock that sets token issue times. Returns [ErrUserNotFound] if there
// is no user with this ID.
func (s *Store) ChangePassword(ctx context.Context, id int64, c Credentials, now time.Time) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE users
		 SET salt = $2, login_key_hash = $3, envelope = $4, password_changed_at = $5
		 WHERE id = $1`,
		id, c.Salt, c.LoginKeyHash, c.Envelope, now)
	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

// PasswordChangedAt returns the time given to the last [Store.ChangePassword],
// or to [Store.CreateUser] if the password never changed. Returns [ErrUserNotFound] if there is no user
// with this ID.
func (s *Store) PasswordChangedAt(ctx context.Context, id int64) (time.Time, error) {
	var t time.Time
	err := s.pool.QueryRow(ctx,
		`SELECT password_changed_at FROM users WHERE id = $1`, id).Scan(&t)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, ErrUserNotFound
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("select password change time: %w", err)
	}
	return t, nil
}
