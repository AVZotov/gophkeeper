package cli

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AVZotov/gophkeeper/internal/client/session"
	"github.com/AVZotov/gophkeeper/internal/client/storage"
	"github.com/AVZotov/gophkeeper/internal/client/vaultcrypto"
)

const testPassword = "correct horse battery staple"

// testVault is the state of a logged in user with [testPassword] and the
// keys it opens. Argon2id is slow, so it is derived once. The CA file does
// not exist, so unlock cannot ask the server.
var testVault = sync.OnceValue(func() vaultKeys {
	salt := vaultcrypto.NewSalt()
	wrapKey, loginKey, err := vaultcrypto.DeriveKeys([]byte(testPassword), salt)
	if err != nil {
		panic(err)
	}
	dataKey := vaultcrypto.NewDataKey()
	return vaultKeys{
		state: storage.State{
			ServerAddress: "localhost:8443",
			CAPath:        "missing-ca.crt",
			Login:         "alice",
			Salt:          salt,
			Envelope:      vaultcrypto.SealEnvelope(wrapKey, dataKey),
			Token:         "token",
		},
		keys: session.Keys{Data: dataKey, Login: loginKey},
	}
})

type vaultKeys struct {
	state storage.State
	keys  session.Keys
}

// testApp returns an app with a new temporary client directory.
func testApp(t *testing.T) app {
	dir := filepath.Join(t.TempDir(), dirName)
	return app{dir: func() (string, error) { return dir, nil }}
}

// withState returns an app with the state of [testVault] saved.
func withState(t *testing.T) app {
	t.Helper()
	a := testApp(t)
	store, err := a.openStore(t.Context())
	require.NoError(t, err)
	defer store.Close()
	require.NoError(t, store.SaveState(t.Context(), testVault().state))
	return a
}

// run runs gophkeeper with args for a, with stdin as the input, and returns
// the output.
func run(t *testing.T, a app, stdin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errOut bytes.Buffer
	cmd := newRootCmd("dev", "unknown", a)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(args)
	err = cmd.ExecuteContext(t.Context())
	return out.String(), errOut.String(), err
}

// sessionPath returns the path of the session file of a.
func sessionPath(t *testing.T, a app) string {
	t.Helper()
	path, err := a.path(sessionFile)
	require.NoError(t, err)
	return path
}

func TestUnlock(t *testing.T) {
	a := withState(t)

	stdout, stderr, err := run(t, a, testPassword+"\n", "unlock")
	require.NoError(t, err)

	assert.Equal(t, passwordPrompt, stderr)
	key := strings.SplitN(stdout, `"`, 3)[1]
	require.NotEmpty(t, key)
	for _, hint := range []string{
		`export GOPHKEEPER_SESSION="` + key + `"`,
		`$env:GOPHKEEPER_SESSION="` + key + `"`,
		`set "GOPHKEEPER_SESSION=` + key + `"`,
		`export GOPHKEEPER_SESSION=$(gophkeeper unlock --raw)`,
		"expires in 1h0m0s",
	} {
		assert.Contains(t, stdout, hint)
	}

	got, err := session.Load(sessionPath(t, a), key, time.Now())
	require.NoError(t, err)
	assert.Equal(t, testVault().keys, got)
}

func TestUnlockRaw(t *testing.T) {
	a := withState(t)

	stdout, _, err := run(t, a, testPassword, "unlock", "--raw")
	require.NoError(t, err)

	key, found := strings.CutSuffix(stdout, "\n")
	require.True(t, found)
	got, err := session.Load(sessionPath(t, a), key, time.Now())
	require.NoError(t, err)
	assert.Equal(t, testVault().keys, got)
}

func TestUnlockFails(t *testing.T) {
	tests := []struct {
		name    string
		app     func(t *testing.T) app
		stdin   string
		wantErr error
		wantMsg string
	}{
		{name: "not logged in", app: testApp, stdin: testPassword, wantErr: storage.ErrNoState, wantMsg: "run gophkeeper login first"},
		{name: "wrong password, no server", app: withState, stdin: "wrong\n", wantErr: vaultcrypto.ErrWrongPassword, wantMsg: "cannot ask the server"},
		{name: "no password", app: withState, stdin: "", wantMsg: "read password"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := tt.app(t)

			stdout, _, err := run(t, a, tt.stdin, "unlock")

			require.Error(t, err)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			}
			assert.ErrorContains(t, err, tt.wantMsg)
			assert.Empty(t, stdout)
			assert.NoFileExists(t, sessionPath(t, a))
		})
	}
}

// TestUnlockKeepsKeysOffDisk looks for the keys in every file of the client
// directory after unlock.
func TestUnlockKeepsKeysOffDisk(t *testing.T) {
	a := withState(t)
	_, _, err := run(t, a, testPassword, "unlock", "--raw")
	require.NoError(t, err)

	keys := testVault().keys
	root, err := a.dir()
	require.NoError(t, err)
	var checked int
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.False(t, bytes.Contains(data, keys.Data[:]), "data key in %s", path)
		assert.False(t, bytes.Contains(data, keys.Login[:]), "login key in %s", path)
		checked++
		return nil
	})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, checked, 2, "database and session files")
}

func TestLock(t *testing.T) {
	a := withState(t)
	stdout, _, err := run(t, a, testPassword, "unlock", "--raw")
	require.NoError(t, err)
	key := strings.TrimSpace(stdout)

	stdout, _, err = run(t, a, "", "lock")
	require.NoError(t, err)

	assert.Equal(t, "Your vault is locked.\n", stdout)
	_, err = session.Load(sessionPath(t, a), key, time.Now())
	assert.ErrorIs(t, err, session.ErrLocked)

	_, _, err = run(t, a, "", "lock")
	assert.NoError(t, err, "lock without a session")
}

func TestLogout(t *testing.T) {
	a := withState(t)
	_, _, err := run(t, a, testPassword, "unlock", "--raw")
	require.NoError(t, err)
	store, err := a.openStore(t.Context())
	require.NoError(t, err)
	defer store.Close()
	id := uuid.New()
	require.NoError(t, store.ApplyRemote(t.Context(), storage.Record{ID: id, Revision: 1, Ciphertext: []byte("synced")}))

	stdout, _, err := run(t, a, "", "logout")
	require.NoError(t, err)

	assert.Equal(t, "You are logged out.\n", stdout)
	assert.NoFileExists(t, sessionPath(t, a))
	_, err = store.State(t.Context())
	assert.ErrorIs(t, err, storage.ErrNoState)
	records, err := store.List(t.Context())
	require.NoError(t, err)
	assert.Empty(t, records)

	_, _, err = run(t, a, testPassword, "unlock")
	assert.ErrorIs(t, err, storage.ErrNoState, "unlock after logout")
}

func TestLogoutKeepsChangesNotSynced(t *testing.T) {
	a := withState(t)
	_, _, err := run(t, a, testPassword, "unlock", "--raw")
	require.NoError(t, err)
	store, err := a.openStore(t.Context())
	require.NoError(t, err)
	defer store.Close()
	require.NoError(t, store.SaveLocal(t.Context(), uuid.New(), false, []byte("not synced")))

	_, _, err = run(t, a, "", "logout")
	require.ErrorContains(t, err, "1 local changes are not synced")
	assert.FileExists(t, sessionPath(t, a))
	dirty, err := store.Dirty(t.Context())
	require.NoError(t, err)
	assert.Len(t, dirty, 1)

	_, _, err = run(t, a, "", "logout", "--force")
	require.NoError(t, err)
	assert.NoFileExists(t, sessionPath(t, a))
	dirty, err = store.Dirty(t.Context())
	require.NoError(t, err)
	assert.Empty(t, dirty)
}

func TestCommandsNeedSession(t *testing.T) {
	a := withState(t)
	t.Setenv(sessionEnv, "")

	for _, args := range [][]string{{"sync"}, {"change-password"}} {
		_, _, err := run(t, a, "", args...)
		assert.ErrorIs(t, err, session.ErrLocked, args)
		assert.ErrorContains(t, err, sessionEnv+" is not set", args)
	}
}

func TestCommandsNeedLogin(t *testing.T) {
	a := testApp(t)

	for _, args := range [][]string{{"unlock"}, {"sync"}, {"change-password"}} {
		_, _, err := run(t, a, "", args...)
		assert.ErrorIs(t, err, storage.ErrNoState, args)
	}
}

func TestCommandsFailWithoutDir(t *testing.T) {
	// A file where the client directory should be.
	blocker := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))
	a := app{dir: func() (string, error) { return filepath.Join(blocker, dirName), nil }}

	for _, args := range [][]string{{"unlock"}, {"lock"}, {"logout"}, {"login", "alice"}, {"sync"}} {
		_, _, err := run(t, a, testPassword, args...)
		assert.ErrorContains(t, err, "create client directory", args)
	}
}

func TestReadLine(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{name: "lines", input: "first\nsecond\n", want: []string{"first", "second"}},
		{name: "CRLF", input: "first\r\nsecond\r\n", want: []string{"first", "second"}},
		{name: "no final line break", input: "first\nsecond", want: []string{"first", "second"}},
		{name: "empty line", input: "\nsecond\n", want: []string{"", "second"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// One byte per read, as a pipe may give it.
			r := iotest.OneByteReader(strings.NewReader(tt.input))
			for _, want := range tt.want {
				got, err := readLine(r)
				require.NoError(t, err)
				assert.Equal(t, want, string(got))
			}
			_, err := readLine(r)
			assert.Error(t, err, "input is over")
		})
	}
}
