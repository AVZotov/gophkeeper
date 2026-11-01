package cli

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/AVZotov/gophkeeper/internal/client/recordpb"
	"github.com/AVZotov/gophkeeper/internal/client/records"
	"github.com/AVZotov/gophkeeper/internal/client/session"
	"github.com/AVZotov/gophkeeper/internal/client/storage"
	"github.com/AVZotov/gophkeeper/internal/client/vaultcrypto"
	"github.com/AVZotov/gophkeeper/internal/tlstest"
)

const offlineNotice = "Saved locally, will sync later: the server is unavailable.\n"

// cancelAfter is when TestCommandStopsOnCancel cancels the command.
const cancelAfter = 200 * time.Millisecond

var addedID = regexp.MustCompile(`Added record ([0-9a-f-]{36})\.`)

// offline is an unlocked vault whose server cannot be reached.
type offline struct {
	t     *testing.T
	app   app
	dials *atomic.Int32
}

// newOffline returns an unlocked vault with the session key in the
// environment. Every connection to the server fails at once, without
// retries.
func newOffline(t *testing.T) *offline {
	t.Helper()
	o := &offline{t: t, app: withState(t), dials: &atomic.Int32{}}
	o.app.dialOptions = []grpc.DialOption{
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			o.dials.Add(1)
			return nil, errors.New("no network")
		}),
		grpc.WithDisableRetry(),
	}
	store, err := o.app.openStore(t.Context())
	require.NoError(t, err)
	defer store.Close()
	ca := tlstest.New(t).CertFile
	require.NoError(t, store.UpdateState(t.Context(), func(st *storage.State) { st.CAPath = ca }))

	stdout, _, err := run(t, o.app, testPassword, "unlock", "--raw")
	require.NoError(t, err)
	t.Setenv(sessionEnv, strings.TrimSpace(stdout))
	return o
}

func (o *offline) run(stdin string, args ...string) (string, error) {
	o.t.Helper()
	stdout, _, err := run(o.t, o.app, stdin, args...)
	return stdout, err
}

// add runs add with args and returns the ID of the new record.
func (o *offline) add(stdin string, args ...string) string {
	o.t.Helper()
	stdout, err := o.run(stdin, append([]string{"add"}, args...)...)
	require.NoError(o.t, err)
	m := addedID.FindStringSubmatch(stdout)
	require.NotNil(o.t, m, stdout)
	assert.Contains(o.t, stdout, offlineNotice)
	return m[1]
}

func (o *offline) show(id string, args ...string) string {
	o.t.Helper()
	stdout, err := o.run("", append([]string{"show", id}, args...)...)
	require.NoError(o.t, err)
	return stdout
}

func (o *offline) store() *storage.Store {
	o.t.Helper()
	store, err := o.app.openStore(o.t.Context())
	require.NoError(o.t, err)
	o.t.Cleanup(func() { store.Close() })
	return store
}

// put saves a record with the given ID, as add does.
func (o *offline) put(id uuid.UUID, rec *recordpb.Record) {
	o.t.Helper()
	ciphertext, err := records.Seal(testVault().keys.Data, id, rec)
	require.NoError(o.t, err)
	require.NoError(o.t, o.store().SaveLocal(o.t.Context(), id, false, ciphertext))
}

// assertLines checks that every want is a line of out, ignoring the
// alignment spaces.
func assertLines(t *testing.T, out string, want ...string) {
	t.Helper()
	got := strings.Split(regexp.MustCompile(` {2,}`).ReplaceAllString(out, " "), "\n")
	for _, w := range want {
		assert.Contains(t, got, w)
	}
}

func writeFile(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "report.pdf")
	require.NoError(t, os.WriteFile(path, content, 0o600))
	return path
}

func TestAddShow(t *testing.T) {
	file := writeFile(t, []byte("file content"))
	tests := []struct {
		name  string
		stdin string
		args  []string
		want  []string
	}{
		{
			name: "login",
			args: []string{"login", "--name", "Mail", "--meta", "mail.example", "--login", "alice", "--password=secret"},
			want: []string{"Type: login", "Name: Mail", "Metadata: mail.example", "Login: alice", "Password: secret"},
		},
		{
			name:  "login with password asked",
			stdin: "asked secret\n",
			args:  []string{"login", "--name", "Mail", "--login", "alice"},
			want:  []string{"Login: alice", "Password: asked secret"},
		},
		{
			name:  "login with password asked by -",
			stdin: "asked secret\n",
			args:  []string{"login", "--name", "Mail", "--password", "-"},
			want:  []string{"Password: asked secret"},
		},
		{
			name: "text",
			args: []string{"text", "--name", "Note", "--text", "hello"},
			want: []string{"Type: text", "Name: Note", "hello"},
		},
		{
			name:  "text from the input",
			stdin: "first line\nsecond line\n",
			args:  []string{"text", "--name", "Note"},
			want:  []string{"first line", "second line"},
		},
		{
			name: "file",
			args: []string{"file", "--name", "Report", "--file", file},
			want: []string{"Type: file", "File: report.pdf", "Size: 12 bytes", "Run show with --out PATH to save the file."},
		},
		{
			name: "card",
			args: []string{"card", "--name", "Visa", "--number", "4111111111111111", "--holder", "IVAN PETROV", "--expiry", "07/29", "--cvv=123"},
			want: []string{"Type: card", "Number: 4111111111111111", "Holder: IVAN PETROV", "Expiry: 07/29", "CVV: 123"},
		},
		{
			name:  "card with CVV asked",
			stdin: "456\n",
			args:  []string{"card", "--name", "Visa", "--number", "4111", "--expiry", "12/30"},
			want:  []string{"Expiry: 12/30", "CVV: 456"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := newOffline(t)
			id := o.add(tt.stdin, tt.args...)

			out := o.show(id)
			assertLines(t, out, append([]string{"ID: " + id}, tt.want...)...)
			dirty, err := o.store().Dirty(t.Context())
			require.NoError(t, err)
			assert.Len(t, dirty, 1)
		})
	}
}

func TestShowFileOut(t *testing.T) {
	o := newOffline(t)
	content := []byte("file content")
	id := o.add("", "file", "--name", "Report", "--file", writeFile(t, content))
	out := filepath.Join(t.TempDir(), "saved.pdf")

	stdout := o.show(id, "--out", out)

	assert.Contains(t, stdout, "Saved 12 bytes to "+out)
	got, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, content, got)
	info, err := os.Stat(out)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(fileMode), info.Mode().Perm())

	_, err = o.run("", "show", id, "--out", out)
	assert.ErrorIs(t, err, os.ErrExist, "an existing file is not overwritten")

	textID := o.add("", "text", "--name", "Note", "--text", "x")
	_, err = o.run("", "show", textID, "--out", filepath.Join(t.TempDir(), "x"))
	assert.ErrorIs(t, err, errOutNotFile)
}

func TestAddFails(t *testing.T) {
	large := filepath.Join(t.TempDir(), "large.bin")
	f, err := os.Create(large)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(records.MaxFileSize+1))
	require.NoError(t, f.Close())

	tests := []struct {
		name    string
		args    []string
		wantErr error
		wantMsg string
	}{
		{name: "no name", args: []string{"login", "--login", "a", "--password=p"}, wantMsg: `"name" not set`},
		{name: "empty name", args: []string{"login", "--name", "", "--password=p"}, wantErr: records.ErrInvalid},
		{name: "file too large", args: []string{"file", "--name", "Big", "--file", large}, wantErr: records.ErrTooLarge},
		{name: "no file", args: []string{"file", "--name", "Doc", "--file", filepath.Join(t.TempDir(), "missing")}, wantErr: os.ErrNotExist},
		{name: "directory", args: []string{"file", "--name", "Doc", "--file", t.TempDir()}, wantMsg: "not a regular file"},
		{name: "card number with letters", args: []string{"card", "--name", "V", "--number", "41x1", "--expiry", "07/29", "--cvv=1"}, wantErr: records.ErrInvalid},
		{name: "expiry month 13", args: []string{"card", "--name", "V", "--number", "4111", "--expiry", "13/29", "--cvv=1"}, wantMsg: "month"},
		{name: "expiry without zero", args: []string{"card", "--name", "V", "--number", "4111", "--expiry", "7/29", "--cvv=1"}, wantMsg: "MM/YY"},
		{name: "expiry not a date", args: []string{"card", "--name", "V", "--number", "4111", "--expiry", "ab/cd", "--cvv=1"}, wantMsg: "MM/YY"},
		{name: "flag of another type", args: []string{"login", "--name", "M", "--number", "4111"}, wantMsg: "unknown flag"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := newOffline(t)

			_, err := o.run("", append([]string{"add"}, tt.args...)...)

			require.Error(t, err)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			}
			assert.ErrorContains(t, err, tt.wantMsg)
			dirty, err := o.store().Dirty(t.Context())
			require.NoError(t, err)
			assert.Empty(t, dirty, "nothing is saved")
		})
	}
}

func TestEdit(t *testing.T) {
	newFile := writeFile(t, []byte("new content"))
	tests := []struct {
		name  string
		add   []string
		stdin string
		edit  []string
		want  []string
		// absent must not be in the output of show.
		absent string
	}{
		{
			name: "name only",
			add:  []string{"login", "--name", "Mail", "--meta", "site", "--login", "alice", "--password=secret"},
			edit: []string{"--name", "Work mail"},
			want: []string{"Name: Work mail", "Metadata: site", "Login: alice", "Password: secret"},
		},
		{
			name:  "password asked",
			add:   []string{"login", "--name", "Mail", "--login", "alice", "--password=secret"},
			stdin: "new secret\n",
			edit:  []string{"--password", "-"},
			want:  []string{"Name: Mail", "Login: alice", "Password: new secret"},
		},
		{
			name:   "metadata cleared",
			add:    []string{"text", "--name", "Note", "--meta", "old", "--text", "body"},
			edit:   []string{"--meta", ""},
			want:   []string{"Name: Note", "body"},
			absent: "Metadata:",
		},
		{
			name:  "text from the input",
			add:   []string{"text", "--name", "Note", "--text", "old body"},
			stdin: "new body",
			edit:  []string{"--text", "-"},
			want:  []string{"Name: Note", "new body"},
		},
		{
			name: "file replaced",
			add:  []string{"file", "--name", "Report", "--file", writeFile(t, []byte("old"))},
			edit: []string{"--file", newFile},
			want: []string{"Name: Report", "Size: 11 bytes"},
		},
		{
			name: "card expiry",
			add:  []string{"card", "--name", "Visa", "--number", "4111", "--holder", "IVAN", "--expiry", "07/29", "--cvv=123"},
			edit: []string{"--expiry", "08/31"},
			want: []string{"Number: 4111", "Holder: IVAN", "Expiry: 08/31", "CVV: 123"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := newOffline(t)
			id := o.add("", tt.add...)

			stdout, err := o.run(tt.stdin, append([]string{"edit", id[:8]}, tt.edit...)...)
			require.NoError(t, err)

			assert.Contains(t, stdout, "Updated record "+id+".\n"+offlineNotice)
			out := o.show(id)
			assertLines(t, out, tt.want...)
			if tt.absent != "" {
				assert.NotContains(t, out, tt.absent)
			}
		})
	}
}

func TestEditFails(t *testing.T) {
	o := newOffline(t)
	id := o.add("", "login", "--name", "Mail", "--password=secret")
	before := o.show(id)

	tests := []struct {
		name    string
		args    []string
		wantErr error
		wantMsg string
	}{
		{name: "no flags", args: nil, wantErr: errNothingToChange},
		{name: "flag of another type", args: []string{"--number", "4111"}, wantMsg: "--number does not apply to a login record"},
		{name: "empty name", args: []string{"--name", ""}, wantErr: records.ErrInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := o.run("", append([]string{"edit", id}, tt.args...)...)
			require.Error(t, err)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			}
			assert.ErrorContains(t, err, tt.wantMsg)
			assert.Equal(t, before, o.show(id), "the record is not changed")
		})
	}
}

func TestIDPrefix(t *testing.T) {
	o := newOffline(t)
	first := uuid.MustParse("aaaa0000-0000-4000-8000-000000000001")
	second := uuid.MustParse("aaaa1111-0000-4000-8000-000000000002")
	deleted := uuid.MustParse("bbbb0000-0000-4000-8000-000000000003")
	o.put(first, recordpb.Record_builder{Name: "first", Text: recordpb.Text_builder{Content: "1"}.Build()}.Build())
	o.put(second, recordpb.Record_builder{Name: "second", Text: recordpb.Text_builder{Content: "2"}.Build()}.Build())
	o.put(deleted, recordpb.Record_builder{Name: "deleted", Text: recordpb.Text_builder{Content: "3"}.Build()}.Build())
	require.NoError(t, o.store().SaveLocal(t.Context(), deleted, true, nil))

	t.Run("unique prefix", func(t *testing.T) {
		assertLines(t, o.show("aaaa0"), "Name: first")
		assertLines(t, o.show("AAAA1"), "Name: second")
		assertLines(t, o.show(second.String()), "Name: second")
	})

	t.Run("ambiguous prefix", func(t *testing.T) {
		_, err := o.run("", "show", "aaaa")
		assert.ErrorIs(t, err, errAmbiguousID)
		assert.ErrorContains(t, err, "aaaa matches 2 records")
		assert.ErrorContains(t, err, first.String()+"  text  first")
		assert.ErrorContains(t, err, second.String()+"  text  second")
	})

	t.Run("empty ID", func(t *testing.T) {
		_, err := o.run("", "show", "")
		assert.ErrorIs(t, err, errEmptyID)
	})

	for _, prefix := range []string{"cccc", "bbbb0000", "aaaa0000-x"} {
		t.Run("no record "+prefix, func(t *testing.T) {
			for _, args := range [][]string{{"show", prefix}, {"edit", prefix, "--name", "x"}, {"delete", prefix}} {
				_, err := o.run("", args...)
				assert.ErrorIs(t, err, errNoRecord, args)
			}
		})
	}
}

func TestDelete(t *testing.T) {
	o := newOffline(t)
	id := o.add("", "text", "--name", "Note", "--text", "x")

	stdout, err := o.run("", "delete", id[:6])
	require.NoError(t, err)

	assert.Equal(t, "Deleted record "+id+".\n"+offlineNotice, stdout)
	list, err := o.run("", "list")
	require.NoError(t, err)
	assert.Equal(t, "ID  TYPE  NAME\n", list)
	r := storedRecord(t, o.store(), uuid.MustParse(id))
	assert.True(t, r.Deleted)
	assert.True(t, r.Dirty)
}

func TestList(t *testing.T) {
	o := newOffline(t)
	login := o.add("", "login", "--name", "Mail", "--login", "alice", "--password=secret")
	card := o.add("", "card", "--name", "Bank", "--number", "4111", "--expiry", "07/29", "--cvv=987")
	note := o.add("", "text", "--name", "Note (conflict)", "--text", "body")

	stdout, err := o.run("", "list")
	require.NoError(t, err)

	assert.Equal(t, strings.Join([]string{
		"ID                                    TYPE   NAME",
		card + "  card   Bank",
		login + "  login  Mail",
		note + "  text   Note (conflict)",
		"",
	}, "\n"), stdout, "sorted by name")
	for _, secret := range []string{"secret", "987", "4111", "alice", "body"} {
		assert.NotContains(t, stdout, secret)
	}
}

// TestListShowOffline checks that only the commands that change records
// connect to the server.
func TestListShowOffline(t *testing.T) {
	o := newOffline(t)
	id := o.add("", "text", "--name", "Note", "--text", "x")
	dials := o.dials.Load()
	require.Positive(t, dials, "add tries to sync")

	_, err := o.run("", "list")
	require.NoError(t, err)
	o.show(id)

	assert.Equal(t, dials, o.dials.Load())
}

func TestRecordCommandsNeedSession(t *testing.T) {
	a := withState(t)
	t.Setenv(sessionEnv, "")

	for _, args := range [][]string{{"list"}, {"show", "a"}, {"edit", "a", "--name", "x"}, {"delete", "a"}, {"add", "text", "--name", "x", "--text", "y"}} {
		_, _, err := run(t, a, "", args...)
		assert.ErrorIs(t, err, session.ErrLocked, args)
	}
}

// TestSyncFailureAfterChange checks that a change is kept when the sync
// after it fails for another reason than the network.
func TestSyncFailureAfterChange(t *testing.T) {
	o := newOffline(t)
	require.NoError(t, o.store().UpdateState(t.Context(), func(st *storage.State) { st.CAPath = "missing-ca.crt" }))

	_, err := o.run("", "add", "text", "--name", "Note", "--text", "x")

	assert.ErrorContains(t, err, "saved locally, but sync failed")
	dirty, err := o.store().Dirty(t.Context())
	require.NoError(t, err)
	assert.Len(t, dirty, 1)
}

func TestShowTextEnd(t *testing.T) {
	for _, text := range []string{"one\ntwo\n", "one\ntwo"} {
		o := newOffline(t)
		id := o.add(text, "text", "--name", "Note")

		out := o.show(id)
		assert.True(t, strings.HasSuffix(out, "Name:  Note\n\none\ntwo\n"), "%q", out)
	}
}

// TestCommandStopsOnCancel cancels a sync whose connection hangs, as Ctrl+C
// does.
func TestCommandStopsOnCancel(t *testing.T) {
	o := newOffline(t)
	o.app.dialOptions = []grpc.DialOption{grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})}
	ctx, cancel := context.WithTimeout(t.Context(), cancelAfter)
	defer cancel()

	cmd := newRootCmd("dev", "unknown", o.app)
	cmd.SetArgs([]string{"sync"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	err := cmd.ExecuteContext(ctx)

	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// TestUndecryptableRecord stores a ciphertext that does not open, as a
// faulty server or a damaged disk can leave.
func TestUndecryptableRecord(t *testing.T) {
	o := newOffline(t)
	good := o.add("", "text", "--name", "Note", "--text", "x")
	damaged := uuid.MustParse(good[:9] + "0000-4000-8000-000000000000")
	require.NoError(t, o.store().SaveLocal(t.Context(), damaged, false, []byte("not a ciphertext of this vault")))

	list, err := o.run("", "list")
	require.NoError(t, err, "one damaged record does not hide the others")
	assertLines(t, list, damaged.String()+" ? (cannot decrypt)", good+" text Note")

	_, err = o.run("", "show", damaged.String())
	assert.ErrorIs(t, err, vaultcrypto.ErrCorrupted)
	_, err = o.run("", "show", good[:8])
	assert.ErrorContains(t, err, damaged.String()+"  ?  (cannot decrypt)", "the matches list it too")

	_, err = o.run("", "delete", damaged.String())
	require.NoError(t, err)
	list, err = o.run("", "list")
	require.NoError(t, err)
	assert.NotContains(t, list, damaged.String())
}

func TestListSortsIgnoringCase(t *testing.T) {
	o := newOffline(t)
	for _, name := range []string{"beta", "Gamma", "alpha"} {
		o.add("", "text", "--name", name, "--text", "x")
	}

	stdout, err := o.run("", "list")
	require.NoError(t, err)

	alpha, beta, gamma := strings.Index(stdout, "alpha"), strings.Index(stdout, "beta"), strings.Index(stdout, "Gamma")
	assert.True(t, alpha < beta && beta < gamma, stdout)
}
