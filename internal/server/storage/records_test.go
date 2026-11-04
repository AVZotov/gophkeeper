package storage

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// noLimit is a page limit no test reaches.
const noLimit = 1 << 20

// maxPulls stops a pulling loop that would never end.
const maxPulls = 10

// newOwner registers a user and returns its ID.
func newOwner(t *testing.T, s *Store, login string) int64 {
	t.Helper()
	require.NoError(t, s.CreateUser(t.Context(), login, creds(1), testTime))
	u, err := s.UserByLogin(t.Context(), login)
	require.NoError(t, err)
	return u.ID
}

// recordID returns a record ID that starts with b.
func recordID(b byte) uuid.UUID {
	return uuid.UUID{b}
}

// push makes a change that must succeed and returns its revision.
func push(t *testing.T, s *Store, owner int64, id uuid.UUID, base int64, deleted bool, ciphertext []byte) int64 {
	t.Helper()
	revision, err := s.PushRecord(t.Context(), owner, id, base, deleted, ciphertext)
	require.NoError(t, err)
	return revision
}

// pullAll returns all the owner's records in one page.
func pullAll(t *testing.T, s *Store, owner int64) []Record {
	t.Helper()
	records, hasMore, err := s.PullRecords(t.Context(), owner, 0, noLimit, noLimit)
	require.NoError(t, err)
	require.False(t, hasMore)
	return records
}

func TestPushRecord(t *testing.T) {
	s := newStore(t)
	alice := newOwner(t, s, "alice")
	a, b := recordID(1), recordID(2)

	assert.Equal(t, int64(1), push(t, s, alice, a, 0, false, []byte("a1")))
	assert.Equal(t, int64(2), push(t, s, alice, b, 0, false, []byte("b1")))
	assert.Equal(t, int64(3), push(t, s, alice, a, 1, false, []byte("a2")))

	assert.Equal(t, []Record{
		{ID: b, Revision: 2, Ciphertext: []byte("b1")},
		{ID: a, Revision: 3, Ciphertext: []byte("a2")},
	}, pullAll(t, s, alice))
}

func TestPushRecordConflict(t *testing.T) {
	tests := []struct {
		name string
		base int64
	}{
		{"new record that exists", 0},
		{"old revision", 1},
		{"revision from the future", 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newStore(t)
			alice := newOwner(t, s, "alice")
			id := recordID(1)
			push(t, s, alice, id, 0, false, []byte("v1"))
			push(t, s, alice, id, 1, false, []byte("v2"))
			current := Record{ID: id, Revision: 2, Ciphertext: []byte("v2")}

			_, err := s.PushRecord(t.Context(), alice, id, tt.base, false, []byte("mine"))
			conflict, ok := errors.AsType[*ConflictError](err)
			require.True(t, ok, "got %v", err)
			assert.Equal(t, current, conflict.Current)
			assert.Equal(t, []Record{current}, pullAll(t, s, alice), "the record must stay intact")

			assert.Equal(t, int64(3), push(t, s, alice, recordID(2), 0, false, []byte("other")),
				"a conflict must not use up a revision")
		})
	}
}

func TestPushRecordNotFound(t *testing.T) {
	s := newStore(t)
	alice := newOwner(t, s, "alice")

	_, err := s.PushRecord(t.Context(), alice, recordID(1), 1, false, []byte("v1"))
	require.ErrorIs(t, err, ErrRecordNotFound)
	assert.Empty(t, pullAll(t, s, alice))
	assert.Equal(t, int64(1), push(t, s, alice, recordID(1), 0, false, []byte("v1")),
		"a failed change must not use up a revision")
}

func TestPushRecordCiphertextCheck(t *testing.T) {
	tests := []struct {
		name       string
		deleted    bool
		ciphertext []byte
	}{
		{"tombstone with ciphertext", true, []byte("secret")},
		{"record without ciphertext", false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newStore(t)
			alice := newOwner(t, s, "alice")

			_, err := s.PushRecord(t.Context(), alice, recordID(1), 0, tt.deleted, tt.ciphertext)
			require.Error(t, err)
			assert.Empty(t, pullAll(t, s, alice))
		})
	}
}

func TestPushRecordUnknownOwner(t *testing.T) {
	s := newStore(t)
	alice := newOwner(t, s, "alice")

	_, err := s.PushRecord(t.Context(), alice+1, recordID(1), 0, false, []byte("v1"))
	assert.ErrorIs(t, err, ErrUserNotFound)
}

func TestPushRecordDelete(t *testing.T) {
	s := newStore(t)
	alice := newOwner(t, s, "alice")
	id := recordID(1)
	push(t, s, alice, id, 0, false, []byte("v1"))

	assert.Equal(t, int64(2), push(t, s, alice, id, 1, true, nil))
	assert.Equal(t, []Record{{ID: id, Revision: 2, Deleted: true, Ciphertext: []byte{}}}, pullAll(t, s, alice),
		"a tombstone stays, without the ciphertext")

	_, err := s.PushRecord(t.Context(), alice, id, 0, false, []byte("new"))
	_, ok := errors.AsType[*ConflictError](err)
	assert.True(t, ok, "a tombstone is still a record: got %v", err)

	assert.Equal(t, int64(3), push(t, s, alice, id, 2, false, []byte("v2")))
	assert.Equal(t, []Record{{ID: id, Revision: 3, Ciphertext: []byte("v2")}}, pullAll(t, s, alice),
		"a change on top of a tombstone brings the record back")
}

func TestRecordsIsolation(t *testing.T) {
	s := newStore(t)
	alice := newOwner(t, s, "alice")
	bob := newOwner(t, s, "bob")
	id := recordID(1)

	assert.Equal(t, int64(1), push(t, s, alice, id, 0, false, []byte("alice")))
	assert.Equal(t, int64(1), push(t, s, bob, id, 0, false, []byte("bob")),
		"the same UUID of another user is another record with its own counter")
	assert.Equal(t, int64(2), push(t, s, bob, recordID(2), 0, false, []byte("bob 2")))

	_, err := s.PushRecord(t.Context(), alice, recordID(2), 2, false, []byte("alice"))
	assert.ErrorIs(t, err, ErrRecordNotFound, "another user's record must not be found")

	assert.Equal(t, []Record{{ID: id, Revision: 1, Ciphertext: []byte("alice")}}, pullAll(t, s, alice))
	assert.Equal(t, []Record{
		{ID: id, Revision: 1, Ciphertext: []byte("bob")},
		{ID: recordID(2), Revision: 2, Ciphertext: []byte("bob 2")},
	}, pullAll(t, s, bob))
}

func TestPullRecordsEmpty(t *testing.T) {
	s := newStore(t)
	alice := newOwner(t, s, "alice")
	assert.Empty(t, pullAll(t, s, alice))

	push(t, s, alice, recordID(1), 0, false, []byte("v1"))
	records, hasMore, err := s.PullRecords(t.Context(), alice, 1, noLimit, noLimit)
	require.NoError(t, err)
	assert.Empty(t, records, "nothing after the last revision")
	assert.False(t, hasMore)
}

func TestPullRecordsPages(t *testing.T) {
	tests := []struct {
		name       string
		sizes      []int
		maxRecords int
		maxBytes   int
		want       [][]int64
	}{
		{"by count", []int{1, 1, 1, 1, 1}, 2, noLimit, [][]int64{{1, 2}, {3, 4}, {5}}},
		{"by size", []int{4, 4, 4, 4, 1}, noLimit, 8, [][]int64{{1, 2}, {3, 4}, {5}}},
		{"whole pages by count", []int{1, 1, 1, 1}, 2, noLimit, [][]int64{{1, 2}, {3, 4}}},
		{"whole pages by size", []int{4, 4, 4, 4}, noLimit, 8, [][]int64{{1, 2}, {3, 4}}},
		{"record larger than the budget", []int{3, 20, 3}, noLimit, 8, [][]int64{{1}, {2}, {3}}},
		{"tombstones take no space", []int{8, 0, 0, 1}, noLimit, 8, [][]int64{{1, 2, 3}, {4}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newStore(t)
			alice := newOwner(t, s, "alice")
			// A record of size 0 is a tombstone.
			for i, size := range tt.sizes {
				push(t, s, alice, recordID(byte(i)), 0, size == 0, make([]byte, size))
			}

			var since int64
			for i, want := range tt.want {
				records, hasMore, err := s.PullRecords(t.Context(), alice, since, tt.maxRecords, tt.maxBytes)
				require.NoError(t, err)
				var got []int64
				for _, r := range records {
					got = append(got, r.Revision)
				}
				require.Equal(t, want, got, "page %d", i+1)
				assert.Equal(t, i < len(tt.want)-1, hasMore, "page %d", i+1)
				since = got[len(got)-1]
			}
		})
	}
}

// TestPullRecordsCursor pulls page by page while the records change and
// checks that the client ends up with the server state, getting no revision
// twice.
func TestPullRecordsCursor(t *testing.T) {
	s := newStore(t)
	alice := newOwner(t, s, "alice")
	for i := range 5 {
		push(t, s, alice, recordID(byte(i)), 0, false, []byte{byte(i)})
	}

	client := make(map[uuid.UUID]Record)
	var since int64
	for page := 1; ; page++ {
		require.LessOrEqual(t, page, maxPulls, "pulling never ends")
		records, hasMore, err := s.PullRecords(t.Context(), alice, since, 2, noLimit)
		require.NoError(t, err)
		for _, r := range records {
			require.Greater(t, r.Revision, since, "revisions must grow")
			since = r.Revision
			client[r.ID] = r
		}
		if page == 1 {
			// One record the client has, one it has not pulled yet, and a new
			// one.
			push(t, s, alice, recordID(0), 1, false, []byte("changed"))
			push(t, s, alice, recordID(3), 4, true, nil)
			push(t, s, alice, recordID(9), 0, false, []byte("new"))
		}
		if !hasMore {
			break
		}
	}

	server := make(map[uuid.UUID]Record)
	for _, r := range pullAll(t, s, alice) {
		server[r.ID] = r
	}
	assert.Len(t, server, 6)
	assert.Equal(t, server, client)
}

func TestPushRecordConcurrent(t *testing.T) {
	s := newStore(t)
	alice := newOwner(t, s, "alice")
	const n = 50

	revisions := make([]int64, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			revisions[i], errs[i] = s.PushRecord(t.Context(), alice, recordID(byte(i)), 0, false, []byte{byte(i)})
		})
	}
	wg.Wait()
	for _, err := range errs {
		require.NoError(t, err)
	}

	want := make([]int64, n)
	for i := range want {
		want[i] = int64(i + 1)
	}
	assert.ElementsMatch(t, want, revisions, "each change gets its own revision, without gaps")

	records := pullAll(t, s, alice)
	got := make([]int64, len(records))
	for i, r := range records {
		got[i] = r.Revision
	}
	assert.Equal(t, want, got)
}

// TestPullDuringPushes checks that a change does not show up in Pull while
// a change that took an earlier revision is not committed: the cursor would
// move past the earlier one, and the client would never get it.
func TestPullDuringPushes(t *testing.T) {
	const (
		timeout = 10 * time.Second
		tick    = 10 * time.Millisecond
	)
	s := newStore(t)
	alice := newOwner(t, s, "alice")
	first, second := recordID(1), recordID(2)

	// An uncommitted row with the same key holds the first push after it
	// took its revision. Its own revision is far from the ones pushed.
	const blockerRevision = 1000
	blocker, err := s.pool.Begin(t.Context())
	require.NoError(t, err)
	defer blocker.Rollback(t.Context())
	_, err = blocker.Exec(t.Context(),
		`INSERT INTO records (owner_id, id, revision, deleted, ciphertext) VALUES ($1, $2, $3, false, 'x')`,
		alice, first, blockerRevision)
	require.NoError(t, err)

	waiting := func() int {
		var n int
		err := s.pool.QueryRow(t.Context(),
			`SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&n)
		require.NoError(t, err)
		return n
	}
	// waitFor polls cond in the test goroutine until it holds.
	waitFor := func(msg string, cond func() bool) {
		deadline := time.Now().Add(timeout)
		for !cond() {
			require.True(t, time.Now().Before(deadline), msg)
			time.Sleep(tick)
		}
	}
	pushed := make(chan error, 2)
	pushAsync := func(id uuid.UUID) {
		go func() {
			_, err := s.PushRecord(t.Context(), alice, id, 0, false, []byte("v1"))
			pushed <- err
		}()
	}

	pushAsync(first)
	waitFor("the first push must wait", func() bool { return waiting() == 1 })
	pushAsync(second)
	// The second push either waits for the first one or, if the order is
	// broken, commits.
	var secondDone bool
	waitFor("the second push must wait or finish", func() bool {
		select {
		case err := <-pushed:
			require.NoError(t, err)
			secondDone = true
		default:
		}
		return secondDone || waiting() == 2
	})

	records, _, err := s.PullRecords(t.Context(), alice, 0, noLimit, noLimit)
	require.NoError(t, err)
	assert.Empty(t, records, "revision 2 must not show up before revision 1")

	require.NoError(t, blocker.Rollback(t.Context()))
	if !secondDone {
		require.NoError(t, <-pushed)
	}
	require.NoError(t, <-pushed)
	got := pullAll(t, s, alice)
	require.Len(t, got, 2)
	assert.Equal(t, []int64{1, 2}, []int64{got[0].Revision, got[1].Revision})
}

func TestRecordsCanceledContext(t *testing.T) {
	s := newStore(t)
	alice := newOwner(t, s, "alice")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := s.PushRecord(ctx, alice, recordID(1), 0, false, []byte("v1"))
	assert.ErrorIs(t, err, context.Canceled)
	_, _, err = s.PullRecords(ctx, alice, 0, noLimit, noLimit)
	assert.ErrorIs(t, err, context.Canceled)
}
