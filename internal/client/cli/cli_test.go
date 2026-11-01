package cli

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
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
// keys it opens. Argon2id is slow, so it is derived once.
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

// testDir returns a function that gives a new temporary client directory.
func testDir(t *testing.T) func() (string, error) {
	dir := filepath.Join(t.TempDir(), dirName)
	return func() (string, error) { return dir, nil }
}

// loggedIn returns a client directory with the state of [testVault] saved.
func loggedIn(t *testing.T) func() (string, error) {
	t.Helper()
	dir := testDir(t)
	store, err := files{dir: dir}.openStore(t.Context())
	require.NoError(t, err)
	defer store.Close()
	require.NoError(t, store.SaveState(t.Context(), testVault().state))
	return dir
}

// run runs gophkeeper with args in the client directory dir, with stdin as
// the input, and returns the output.
func run(t *testing.T, dir func() (string, error), stdin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errOut bytes.Buffer
	cmd := newRootCmd("dev", "unknown", dir)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(args)
	err = cmd.ExecuteContext(t.Context())
	return out.String(), errOut.String(), err
}

// sessionPath returns the path of the session file in dir.
func sessionPath(t *testing.T, dir func() (string, error)) string {
	t.Helper()
	d, err := dir()
	require.NoError(t, err)
	return filepath.Join(d, sessionFile)
}

func TestUnlock(t *testing.T) {
	dir := loggedIn(t)

	stdout, stderr, err := run(t, dir, testPassword+"\n", "unlock")
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

	t.Setenv(session.EnvVar, key)
	got, err := session.Load(sessionPath(t, dir), time.Now())
	require.NoError(t, err)
	assert.Equal(t, testVault().keys, got)
}

func TestUnlockRaw(t *testing.T) {
	dir := loggedIn(t)

	stdout, _, err := run(t, dir, testPassword, "unlock", "--raw")
	require.NoError(t, err)

	key, found := strings.CutSuffix(stdout, "\n")
	require.True(t, found)
	t.Setenv(session.EnvVar, key)
	got, err := session.Load(sessionPath(t, dir), time.Now())
	require.NoError(t, err)
	assert.Equal(t, testVault().keys, got)
}

func TestUnlockFails(t *testing.T) {
	tests := []struct {
		name    string
		dir     func(t *testing.T) func() (string, error)
		stdin   string
		wantErr error
		wantMsg string
	}{
		{name: "not logged in", dir: testDir, stdin: testPassword, wantErr: storage.ErrNoState, wantMsg: "run gophkeeper login first"},
		{name: "wrong password", dir: loggedIn, stdin: "wrong\n", wantErr: vaultcrypto.ErrWrongPassword, wantMsg: "wrong password"},
		{name: "no password", dir: loggedIn, stdin: "", wantMsg: "read password"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := tt.dir(t)

			stdout, _, err := run(t, dir, tt.stdin, "unlock")

			require.Error(t, err)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			}
			assert.ErrorContains(t, err, tt.wantMsg)
			assert.Empty(t, stdout)
			assert.NoFileExists(t, sessionPath(t, dir))
		})
	}
}

// TestUnlockKeepsKeysOffDisk looks for the keys in every file of the client
// directory after unlock.
func TestUnlockKeepsKeysOffDisk(t *testing.T) {
	dir := loggedIn(t)
	_, _, err := run(t, dir, testPassword, "unlock", "--raw")
	require.NoError(t, err)

	keys := testVault().keys
	root, err := dir()
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
	dir := loggedIn(t)
	key, _, err := run(t, dir, testPassword, "unlock", "--raw")
	require.NoError(t, err)

	stdout, _, err := run(t, dir, "", "lock")
	require.NoError(t, err)

	assert.Equal(t, "Your vault is locked.\n", stdout)
	t.Setenv(session.EnvVar, strings.TrimSpace(key))
	_, err = session.Load(sessionPath(t, dir), time.Now())
	assert.ErrorIs(t, err, session.ErrLocked)

	_, _, err = run(t, dir, "", "lock")
	assert.NoError(t, err, "lock without a session")
}

func TestLogout(t *testing.T) {
	dir := loggedIn(t)
	_, _, err := run(t, dir, testPassword, "unlock", "--raw")
	require.NoError(t, err)
	f := files{dir: dir}
	store, err := f.openStore(t.Context())
	require.NoError(t, err)
	require.NoError(t, store.SaveLocal(t.Context(), uuid.New(), false, []byte("ciphertext")))
	require.NoError(t, store.Close())

	stdout, _, err := run(t, dir, "", "logout")
	require.NoError(t, err)

	assert.Equal(t, "You are logged out.\n", stdout)
	assert.NoFileExists(t, sessionPath(t, dir))
	store, err = f.openStore(t.Context())
	require.NoError(t, err)
	defer store.Close()
	_, err = store.State(t.Context())
	assert.ErrorIs(t, err, storage.ErrNoState)
	records, err := store.List(t.Context())
	require.NoError(t, err)
	assert.Empty(t, records)

	_, _, err = run(t, dir, testPassword, "unlock")
	assert.ErrorIs(t, err, storage.ErrNoState, "unlock after logout")
}

func TestCommandsFailWithoutDir(t *testing.T) {
	// A file where the client directory should be.
	blocker := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))
	dir := func() (string, error) { return filepath.Join(blocker, dirName), nil }

	for _, args := range [][]string{{"unlock"}, {"lock"}, {"logout"}} {
		_, _, err := run(t, dir, testPassword, args...)
		assert.ErrorContains(t, err, "create client directory", args)
	}
}
