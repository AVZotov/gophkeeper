package storage

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// openStore opens a store in a new temporary directory and returns it with
// the path of the database file.
func openStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(t.Context(), path)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, s.Close()) })
	return s, path
}

func TestOpenAppliesMigrationsTwice(t *testing.T) {
	s, path := openStore(t)
	id := uuid.New()
	require.NoError(t, s.SaveLocal(t.Context(), id, false, []byte("x")))

	again, err := Open(t.Context(), path)
	require.NoError(t, err)
	defer again.Close()

	got, err := again.Get(t.Context(), id)
	require.NoError(t, err)
	assert.Equal(t, []byte("x"), got.Ciphertext)
}

func TestOpenCreatesPrivateFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not used on Windows")
	}
	_, path := openStore(t)

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(fileMode), info.Mode().Perm())
}

func TestOpenFails(t *testing.T) {
	s, err := Open(t.Context(), filepath.Join(t.TempDir(), "missing", "test.db"))
	assert.Error(t, err)
	assert.Nil(t, s)
}

func TestSaveLocal(t *testing.T) {
	s, _ := openStore(t)
	ctx := t.Context()

	t.Run("creates a record with revision 0", func(t *testing.T) {
		id := uuid.New()
		require.NoError(t, s.SaveLocal(ctx, id, false, []byte("v1")))

		got, err := s.Get(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, Record{ID: id, Revision: 0, Ciphertext: []byte("v1"), Dirty: true}, got)
	})

	id := uuid.New()
	require.NoError(t, s.ApplyRemote(ctx, Record{ID: id, Revision: 7, Ciphertext: []byte("remote")}))

	t.Run("keeps the revision of an existing record", func(t *testing.T) {
		require.NoError(t, s.SaveLocal(ctx, id, false, []byte("v2")))

		got, err := s.Get(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, Record{ID: id, Revision: 7, Ciphertext: []byte("v2"), Dirty: true}, got)
	})

	t.Run("deletes", func(t *testing.T) {
		require.NoError(t, s.SaveLocal(ctx, id, true, nil))

		got, err := s.Get(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, Record{ID: id, Revision: 7, Deleted: true, Dirty: true}, got)
	})

	tests := []struct {
		name       string
		deleted    bool
		ciphertext []byte
	}{
		{name: "live record without ciphertext", deleted: false, ciphertext: nil},
		{name: "deleted record with ciphertext", deleted: true, ciphertext: []byte("x")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Error(t, s.SaveLocal(ctx, uuid.New(), tt.deleted, tt.ciphertext))
		})
	}
}

func TestGetNotFound(t *testing.T) {
	s, _ := openStore(t)

	_, err := s.Get(t.Context(), uuid.New())
	assert.ErrorIs(t, err, ErrRecordNotFound)
}

func TestListAndDirty(t *testing.T) {
	s, _ := openStore(t)
	ctx := t.Context()
	var (
		localLive     = Record{ID: uuid.New(), Ciphertext: []byte("local"), Dirty: true}
		localDeleted  = Record{ID: uuid.New(), Revision: 3, Deleted: true, Dirty: true}
		remoteLive    = Record{ID: uuid.New(), Revision: 4, Ciphertext: []byte("remote")}
		remoteDeleted = Record{ID: uuid.New(), Revision: 5, Deleted: true}
	)
	require.NoError(t, s.SaveLocal(ctx, localLive.ID, false, localLive.Ciphertext))
	require.NoError(t, s.ApplyRemote(ctx, Record{ID: localDeleted.ID, Revision: 3, Ciphertext: []byte("old")}))
	require.NoError(t, s.SaveLocal(ctx, localDeleted.ID, true, nil))
	require.NoError(t, s.ApplyRemote(ctx, remoteLive))
	require.NoError(t, s.ApplyRemote(ctx, remoteDeleted))

	list, err := s.List(ctx)
	require.NoError(t, err)
	assert.ElementsMatch(t, []Record{localLive, remoteLive}, list)

	dirty, err := s.Dirty(ctx)
	require.NoError(t, err)
	assert.ElementsMatch(t, []Record{localLive, localDeleted}, dirty)
}

func TestListEmpty(t *testing.T) {
	s, _ := openStore(t)

	list, err := s.List(t.Context())
	require.NoError(t, err)
	assert.Empty(t, list)
}

// accepted returns the server version of r after the server accepted it as
// revision 9.
func accepted(r Record) Record {
	r.Revision, r.Dirty = 9, false
	return r
}

func TestMarkPushed(t *testing.T) {
	ctx := t.Context()
	serverVersion := Record{Revision: 9, Ciphertext: []byte("server")}
	tests := []struct {
		name string
		// local is the record as it was read to be pushed.
		local Record
		// server returns the server version for the pushed record.
		server func(pushed Record) Record
		want   Record
	}{
		{
			name:   "accepted change",
			local:  Record{Ciphertext: []byte("v1")},
			server: accepted,
			want:   Record{Revision: 9, Ciphertext: []byte("v1")},
		},
		{
			name:   "accepted delete",
			local:  Record{Revision: 2, Deleted: true},
			server: accepted,
			want:   Record{Revision: 9, Deleted: true},
		},
		{
			name:   "server version taken",
			local:  Record{Revision: 2, Deleted: true},
			server: func(Record) Record { return serverVersion },
			want:   Record{Revision: 9, Ciphertext: []byte("server")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, _ := openStore(t)
			id := uuid.New()
			tt.local.ID, tt.want.ID = id, id
			require.NoError(t, s.ApplyRemote(ctx, Record{ID: id, Revision: tt.local.Revision, Ciphertext: []byte("old")}))
			require.NoError(t, s.SaveLocal(ctx, id, tt.local.Deleted, tt.local.Ciphertext))
			pushed, err := s.Get(ctx, id)
			require.NoError(t, err)

			require.NoError(t, s.MarkPushed(ctx, pushed, tt.server(pushed)))

			got, err := s.Get(ctx, id)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}

	changes := []struct {
		name       string
		deleted    bool
		ciphertext []byte
	}{
		{name: "changed after read", deleted: false, ciphertext: []byte("v2")},
		{name: "deleted after read", deleted: true, ciphertext: nil},
	}
	for _, change := range changes {
		for _, server := range []struct {
			name    string
			version func(Record) Record
		}{{"accepted", accepted}, {"server version", func(Record) Record { return serverVersion }}} {
			t.Run(change.name+", "+server.name+": change stays dirty", func(t *testing.T) {
				s, _ := openStore(t)
				id := uuid.New()
				require.NoError(t, s.SaveLocal(ctx, id, false, []byte("v1")))
				pushed, err := s.Get(ctx, id)
				require.NoError(t, err)
				require.NoError(t, s.SaveLocal(ctx, id, change.deleted, change.ciphertext))

				require.NoError(t, s.MarkPushed(ctx, pushed, server.version(pushed)))

				got, err := s.Get(ctx, id)
				require.NoError(t, err)
				assert.Equal(t, Record{ID: id, Revision: 9, Deleted: change.deleted, Ciphertext: change.ciphertext, Dirty: true}, got)
			})
		}
	}

	t.Run("not found", func(t *testing.T) {
		s, _ := openStore(t)
		r := Record{ID: uuid.New(), Ciphertext: []byte("x")}
		assert.ErrorIs(t, s.MarkPushed(ctx, r, accepted(r)), ErrRecordNotFound)
	})
}

func TestApplyRemote(t *testing.T) {
	s, _ := openStore(t)
	ctx := t.Context()
	id := uuid.New()

	require.NoError(t, s.ApplyRemote(ctx, Record{ID: id, Revision: 1, Ciphertext: []byte("v1"), Dirty: true}))
	got, err := s.Get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, Record{ID: id, Revision: 1, Ciphertext: []byte("v1")}, got, "new record, dirty ignored")

	require.NoError(t, s.ApplyRemote(ctx, Record{ID: id, Revision: 2, Deleted: true}))
	got, err = s.Get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, Record{ID: id, Revision: 2, Deleted: true}, got, "clean record replaced")

	t.Run("live record without ciphertext", func(t *testing.T) {
		assert.Error(t, s.ApplyRemote(ctx, Record{ID: uuid.New(), Revision: 1}))
	})
}

func TestApplyRemoteKeepsDirty(t *testing.T) {
	s, _ := openStore(t)
	ctx := t.Context()
	id := uuid.New()
	require.NoError(t, s.ApplyRemote(ctx, Record{ID: id, Revision: 1, Ciphertext: []byte("v1")}))
	require.NoError(t, s.SaveLocal(ctx, id, false, []byte("local")))

	require.NoError(t, s.ApplyRemote(ctx, Record{ID: id, Revision: 2, Ciphertext: []byte("remote")}))

	got, err := s.Get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, Record{ID: id, Revision: 1, Ciphertext: []byte("local"), Dirty: true}, got)
}

func TestState(t *testing.T) {
	s, _ := openStore(t)
	ctx := t.Context()

	_, err := s.State(ctx)
	require.ErrorIs(t, err, ErrNoState)

	first := State{
		ServerAddress: "localhost:8443",
		CAPath:        "/etc/ca.crt",
		Login:         "alice",
		Salt:          []byte("0123456789abcdef"),
		Envelope:      []byte("envelope"),
		Token:         "token",
		LastRevision:  3,
	}
	require.NoError(t, s.SaveState(ctx, first))
	got, err := s.State(ctx)
	require.NoError(t, err)
	assert.Equal(t, first, got)

	second := first
	second.Token, second.LastRevision = "token2", 8
	require.NoError(t, s.SaveState(ctx, second))
	got, err = s.State(ctx)
	require.NoError(t, err)
	assert.Equal(t, second, got, "second save replaces the state")
}

func TestUpdateState(t *testing.T) {
	s, _ := openStore(t)
	ctx := t.Context()
	update := func(st *State) { st.Token, st.LastRevision = "new", 5 }

	require.ErrorIs(t, s.UpdateState(ctx, update), ErrNoState)

	saved := State{Login: "alice", Salt: []byte("salt"), Envelope: []byte("envelope"), Token: "old", LastRevision: 1}
	require.NoError(t, s.SaveState(ctx, saved))
	require.NoError(t, s.UpdateState(ctx, update))

	got, err := s.State(ctx)
	require.NoError(t, err)
	saved.Token, saved.LastRevision = "new", 5
	assert.Equal(t, saved, got)
}

func TestStateIsRedacted(t *testing.T) {
	st := State{Login: "alice", Envelope: []byte("envelope-secret"), Token: "token-secret"}

	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("test", "state", st)

	assert.Contains(t, buf.String(), "alice")
	assert.NotContains(t, buf.String(), "envelope-secret")
	assert.NotContains(t, buf.String(), "token-secret")
	assert.NotContains(t, buf.String(), fmt.Sprint(st.Envelope))
}

func TestClear(t *testing.T) {
	s, path := openStore(t)
	ctx := t.Context()
	secret := []byte("ciphertext-to-be-wiped")
	require.NoError(t, s.SaveLocal(ctx, uuid.New(), false, secret))
	require.NoError(t, s.ApplyRemote(ctx, Record{ID: uuid.New(), Revision: 1, Ciphertext: []byte("remote")}))
	require.NoError(t, s.SaveState(ctx, State{Login: "alice", Salt: []byte("salt"), Envelope: []byte("envelope-to-be-wiped")}))

	require.NoError(t, s.Clear(ctx))

	list, err := s.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, list)
	_, err = s.State(ctx)
	assert.ErrorIs(t, err, ErrNoState)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.False(t, bytes.Contains(data, secret), "deleted ciphertext left in the file")
	assert.False(t, bytes.Contains(data, []byte("envelope-to-be-wiped")), "deleted envelope left in the file")
}
