package storage

import (
	"context"
	"errors"
	"fmt"
	"uuid"

	"github.com/jackc/pgx/v5"
)

// ErrRecordNotFound means the change is based on a revision of a record that
// does not exist.
var ErrRecordNotFound = errors.New("record not found")

// Record is a record as the server sees it: service fields and ciphertext.
type Record struct {
	ID         uuid.UUID
	Revision   int64
	Deleted    bool
	Ciphertext []byte
}

// ConflictError means the record changed after the revision the change is
// based on. Current is the record as it is now.
type ConflictError struct {
	Current Record
}

// Error reports the current revision of the record.
func (e *ConflictError) Error() string {
	return fmt.Sprintf("record changed: current revision is %d", e.Current.Revision)
}

// PushRecord creates, updates or deletes the owner's record with the given
// ID and returns the revision given to the change. baseRevision is the
// revision the change is based on, 0 for a new record. A change based on the
// current revision of a deleted record brings it back. A deleted record keeps
// an empty ciphertext.
//
// Returns [*ConflictError] if baseRevision is not the current revision,
// [ErrRecordNotFound] if there is no record and baseRevision is not 0,
// [ErrUserNotFound] if there is no owner with this ID, and an error if the
// ciphertext is empty for a record that is not deleted or not empty for a
// deleted one. A failed change does not use up a revision.
func (s *Store) PushRecord(ctx context.Context, ownerID int64, id uuid.UUID, baseRevision int64, deleted bool, ciphertext []byte) (int64, error) {
	// Under a stricter level a change waiting for the owner's row would fail
	// once the row is unlocked, instead of going on with the committed value.
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx)

	// Taking the next revision locks the owner's row until the commit, so
	// the owner's changes commit in revision order and Pull never skips one.
	var revision int64
	err = tx.QueryRow(ctx,
		`UPDATE users SET revision = revision + 1 WHERE id = $1 RETURNING revision`,
		ownerID).Scan(&revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrUserNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("next revision: %w", err)
	}

	// The ciphertext can be megabytes, and it is needed only on a conflict.
	current := Record{ID: id}
	err = tx.QueryRow(ctx,
		`SELECT revision, deleted FROM records WHERE owner_id = $1 AND id = $2`,
		ownerID, id).Scan(&current.Revision, &current.Deleted)
	found := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("select record: %w", err)
	}

	// pgx sends a nil slice as NULL, and the column is NOT NULL.
	if ciphertext == nil {
		ciphertext = []byte{}
	}
	switch {
	case !found && baseRevision != 0:
		return 0, ErrRecordNotFound
	case !found:
		_, err = tx.Exec(ctx,
			`INSERT INTO records (owner_id, id, revision, deleted, ciphertext) VALUES ($1, $2, $3, $4, $5)`,
			ownerID, id, revision, deleted, ciphertext)
	case current.Revision != baseRevision:
		err = tx.QueryRow(ctx,
			`SELECT ciphertext FROM records WHERE owner_id = $1 AND id = $2`,
			ownerID, id).Scan(&current.Ciphertext)
		if err != nil {
			return 0, fmt.Errorf("select ciphertext: %w", err)
		}
		return 0, &ConflictError{Current: current}
	default:
		_, err = tx.Exec(ctx,
			`UPDATE records SET revision = $3, deleted = $4, ciphertext = $5 WHERE owner_id = $1 AND id = $2`,
			ownerID, id, revision, deleted, ciphertext)
	}
	if err != nil {
		return 0, fmt.Errorf("write record: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return revision, nil
}

// PullRecords returns the owner's records changed after revision since,
// ordered by revision, and reports whether more are left after them. The
// page has at most maxRecords records. A record is added while the
// ciphertexts fit into maxBytes in total, except the first one: it is always
// added, so a record larger than maxBytes still gets its own page. Returns an
// error if a query fails.
func (s *Store) PullRecords(ctx context.Context, ownerID, since int64, maxRecords, maxBytes int) ([]Record, bool, error) {
	// One snapshot for both queries: the second one returns exactly the
	// records the first one picked.
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, false, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx)

	last, hasMore, err := pageEnd(ctx, tx, ownerID, since, maxRecords, maxBytes)
	if err != nil || last == since {
		return nil, false, err
	}

	rows, err := tx.Query(ctx,
		`SELECT id, revision, deleted, ciphertext FROM records
		 WHERE owner_id = $1 AND revision > $2 AND revision <= $3
		 ORDER BY revision`,
		ownerID, since, last)
	if err != nil {
		return nil, false, fmt.Errorf("select records: %w", err)
	}
	records, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Record])
	if err != nil {
		return nil, false, fmt.Errorf("select records: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, fmt.Errorf("commit: %w", err)
	}
	return records, hasMore, nil
}

// pageEnd picks the page for [Store.PullRecords] by ciphertext sizes alone
// and returns the revision of its last record, or since if the page is
// empty. Ciphertexts are not read here: the rows a query has not read yet
// still come over the connection when it is closed, and ciphertexts that do
// not make it into the page can be megabytes each.
func pageEnd(ctx context.Context, tx pgx.Tx, ownerID, since int64, maxRecords, maxBytes int) (last int64, hasMore bool, err error) {
	rows, err := tx.Query(ctx,
		`SELECT revision, octet_length(ciphertext) FROM records
		 WHERE owner_id = $1 AND revision > $2
		 ORDER BY revision
		 LIMIT $3`,
		ownerID, since, maxRecords+1)
	if err != nil {
		return 0, false, fmt.Errorf("select sizes: %w", err)
	}
	defer rows.Close()

	last = since
	var count, total int
	for rows.Next() {
		var (
			revision int64
			size     int
		)
		if err := rows.Scan(&revision, &size); err != nil {
			return 0, false, fmt.Errorf("select sizes: %w", err)
		}
		if count == maxRecords || (count > 0 && total+size > maxBytes) {
			return last, true, nil
		}
		last, total, count = revision, total+size, count+1
	}
	if err := rows.Err(); err != nil {
		return 0, false, fmt.Errorf("select sizes: %w", err)
	}
	return last, false, nil
}
