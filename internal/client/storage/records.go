package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"uuid"
)

// ErrRecordNotFound means there is no local record with this ID.
var ErrRecordNotFound = errors.New("record not found")

// Record is a local copy of a record: the fields the server sees and a mark
// of a change not pushed yet.
type Record struct {
	ID uuid.UUID
	// Revision is the last revision received from the server, 0 for a record
	// never pushed. The next push of the record is based on it.
	Revision   int64
	Deleted    bool
	Ciphertext []byte
	// Dirty means the record has a change not pushed to the server yet.
	Dirty bool
}

const recordColumns = `id, revision, deleted, ciphertext, dirty`

// SaveLocal saves a change made on this device and marks the record dirty.
// A new record gets revision 0; an existing one keeps its revision, the base
// of the next push. A deleted record has no ciphertext. Returns an error if
// the ciphertext is empty for a record that is not deleted or not empty for
// a deleted one.
func (s *Store) SaveLocal(ctx context.Context, id uuid.UUID, deleted bool, ciphertext []byte) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO records (`+recordColumns+`) VALUES (?, 0, ?, ?, 1)
		 ON CONFLICT (id) DO UPDATE SET deleted = excluded.deleted, ciphertext = excluded.ciphertext, dirty = 1`,
		id[:], deleted, notNil(ciphertext))
	if err != nil {
		return fmt.Errorf("save record %s: %w", id, err)
	}
	return nil
}

// Get returns the record with the given ID, deleted or not. Returns
// [ErrRecordNotFound] if there is no such record.
func (s *Store) Get(ctx context.Context, id uuid.UUID) (Record, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+recordColumns+` FROM records WHERE id = ?`, id[:])
	r, err := scanRecord(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrRecordNotFound
	}
	if err != nil {
		return Record{}, fmt.Errorf("get record %s: %w", id, err)
	}
	return r, nil
}

// List returns the records that are not deleted. Returns an error if the
// query fails.
func (s *Store) List(ctx context.Context) ([]Record, error) {
	return s.query(ctx, `SELECT `+recordColumns+` FROM records WHERE deleted = 0 ORDER BY id`)
}

// Dirty returns the records with changes not pushed yet, deleted ones
// included. Returns an error if the query fails.
func (s *Store) Dirty(ctx context.Context) ([]Record, error) {
	return s.query(ctx, `SELECT `+recordColumns+` FROM records WHERE dirty = 1 ORDER BY id`)
}

// MarkPushed records that the server now has server for the record pushed
// was read from: the record becomes server and is no longer dirty. It covers
// both a push the server accepted and a conflict resolved by taking the
// server version. If the record changed after pushed was read, that change
// is kept and stays dirty, based on the server revision. Returns
// [ErrRecordNotFound] if there is no such record.
func (s *Store) MarkPushed(ctx context.Context, pushed, server Record) error {
	// SET expressions see the row as it was before the update.
	res, err := s.db.ExecContext(ctx,
		`UPDATE records SET
		   revision   = ?1,
		   deleted    = iif(deleted = ?4 AND ciphertext = ?5, ?2, deleted),
		   ciphertext = iif(deleted = ?4 AND ciphertext = ?5, ?3, ciphertext),
		   dirty      = NOT (deleted = ?4 AND ciphertext = ?5)
		 WHERE id = ?6`,
		server.Revision, server.Deleted, notNil(server.Ciphertext),
		pushed.Deleted, notNil(pushed.Ciphertext), pushed.ID[:])
	if err != nil {
		return fmt.Errorf("mark record %s pushed: %w", pushed.ID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("mark record %s pushed: %w", pushed.ID, err)
	}
	if n == 0 {
		return ErrRecordNotFound
	}
	return nil
}

// ApplyRemote saves a record received from the server. A dirty local record
// is left as it is: its change is resolved by the push. r.Dirty is ignored.
// Returns an error if the ciphertext is empty for a record that is not
// deleted or not empty for a deleted one.
func (s *Store) ApplyRemote(ctx context.Context, r Record) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO records (`+recordColumns+`) VALUES (?, ?, ?, ?, 0)
		 ON CONFLICT (id) DO UPDATE SET revision = excluded.revision, deleted = excluded.deleted, ciphertext = excluded.ciphertext
		 WHERE dirty = 0`,
		r.ID[:], r.Revision, r.Deleted, notNil(r.Ciphertext))
	if err != nil {
		return fmt.Errorf("apply record %s: %w", r.ID, err)
	}
	return nil
}

// query returns the records selected by query.
func (s *Store) query(ctx context.Context, query string) ([]Record, error) {
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("select records: %w", err)
	}
	defer rows.Close()

	var records []Record
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("select records: %w", err)
		}
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("select records: %w", err)
	}
	return records, nil
}

// scanRecord reads a row of [recordColumns].
func scanRecord(row interface{ Scan(...any) error }) (Record, error) {
	var (
		r  Record
		id []byte
	)
	if err := row.Scan(&id, &r.Revision, &r.Deleted, &r.Ciphertext, &r.Dirty); err != nil {
		return Record{}, err
	}
	// The table checks that every ID is 16 bytes.
	r.ID = uuid.UUID(id)
	return r, nil
}

// notNil returns b, or an empty slice if b is nil: the driver stores a nil
// slice as NULL, and the ciphertext column is NOT NULL.
func notNil(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}
