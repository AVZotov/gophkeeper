package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
)

// ErrNoState means the state is not saved yet: the user has not logged in.
var ErrNoState = errors.New("not logged in")

// State is what the client keeps between runs besides the records.
type State struct {
	ServerAddress string
	CAPath        string
	Login         string
	Salt          []byte
	// Envelope is the sealed data key. It lets one guess the password
	// offline, so it is hidden in logs.
	Envelope []byte
	Token    string
	// LastRevision is the last revision received from the server.
	LastRevision int64
}

// LogValue hides the envelope and the token in slog output.
func (st State) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("server_address", st.ServerAddress),
		slog.String("ca_path", st.CAPath),
		slog.String("login", st.Login),
		slog.String("envelope", redacted),
		slog.String("token", redacted),
		slog.Int64("last_revision", st.LastRevision),
	)
}

const redacted = "[REDACTED]"

const selectState = `SELECT server_address, ca_path, login, salt, envelope, token, last_revision FROM state`

// State returns the saved state. Returns [ErrNoState] if it is not saved.
func (s *Store) State(ctx context.Context) (State, error) {
	st, err := scanState(s.db.QueryRowContext(ctx, selectState))
	if errors.Is(err, sql.ErrNoRows) {
		return State{}, ErrNoState
	}
	if err != nil {
		return State{}, fmt.Errorf("get state: %w", err)
	}
	return st, nil
}

// SaveState saves st, replacing the saved state. Returns an error if the
// query fails.
func (s *Store) SaveState(ctx context.Context, st State) error {
	return s.inTx(ctx, func(tx *sql.Tx) error { return saveState(ctx, tx, st) })
}

// UpdateState changes the saved state with update in one transaction, so
// changes made by another process at the same time are not lost. Returns
// [ErrNoState] if the state is not saved.
func (s *Store) UpdateState(ctx context.Context, update func(*State)) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		st, err := scanState(tx.QueryRowContext(ctx, selectState))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNoState
		}
		if err != nil {
			return fmt.Errorf("get state: %w", err)
		}
		update(&st)
		return saveState(ctx, tx, st)
	})
}

// Clear deletes all records and the state. Returns an error if the query
// fails; then nothing is deleted.
func (s *Store) Clear(ctx context.Context) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM records`); err != nil {
			return fmt.Errorf("delete records: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM state`); err != nil {
			return fmt.Errorf("delete state: %w", err)
		}
		return nil
	})
}

// scanState reads a row of [selectState].
func scanState(row *sql.Row) (State, error) {
	var st State
	err := row.Scan(&st.ServerAddress, &st.CAPath, &st.Login, &st.Salt, &st.Envelope, &st.Token, &st.LastRevision)
	return st, err
}

// saveState replaces the saved state with st.
func saveState(ctx context.Context, tx *sql.Tx, st State) error {
	_, err := tx.ExecContext(ctx,
		`INSERT OR REPLACE INTO state (id, server_address, ca_path, login, salt, envelope, token, last_revision)
		 VALUES (1, ?, ?, ?, ?, ?, ?, ?)`,
		st.ServerAddress, st.CAPath, st.Login, notNil(st.Salt), notNil(st.Envelope), st.Token, st.LastRevision)
	if err != nil {
		return fmt.Errorf("save state: %w", err)
	}
	return nil
}
