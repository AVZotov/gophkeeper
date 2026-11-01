package session

import (
	"bytes"
	"encoding/base64"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AVZotov/gophkeeper/internal/client/vaultcrypto"
)

var testNow = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func testKeys() Keys {
	return Keys{Data: vaultcrypto.NewDataKey(), Login: vaultcrypto.LoginKey(vaultcrypto.NewDataKey())}
}

// unlock starts a session in a new temporary directory, puts its key into
// [EnvVar] and returns the path of the session file.
func unlock(t *testing.T, keys Keys) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "session")
	key, err := Unlock(path, keys, testNow)
	require.NoError(t, err)
	t.Setenv(EnvVar, key)
	return path
}

func TestUnlockLoad(t *testing.T) {
	keys := testKeys()
	path := unlock(t, keys)

	got, err := Load(path, testNow)
	require.NoError(t, err)
	assert.Equal(t, keys, got)
}

func TestUnlockWritesPrivateFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not used on Windows")
	}
	path := filepath.Join(t.TempDir(), "session")
	require.NoError(t, os.WriteFile(path, []byte("old"), 0o644))

	_, err := Unlock(path, testKeys(), testNow)
	require.NoError(t, err)

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestUnlockFails(t *testing.T) {
	_, err := Unlock(filepath.Join(t.TempDir(), "missing", "session"), testKeys(), testNow)
	assert.Error(t, err)
}

func TestKeysNotOnDisk(t *testing.T) {
	keys := testKeys()
	path := unlock(t, keys)
	sessionKey, err := base64.RawURLEncoding.DecodeString(os.Getenv(EnvVar))
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	for name, secret := range map[string][]byte{
		"data key":    keys.Data[:],
		"login key":   keys.Login[:],
		"session key": sessionKey,
	} {
		assert.False(t, bytes.Contains(data, secret), name)
	}
}

func TestLoadExpiry(t *testing.T) {
	path := unlock(t, testKeys())

	_, err := Load(path, testNow.Add(TTL-time.Second))
	require.NoError(t, err)

	_, err = Load(path, testNow.Add(TTL))
	assert.ErrorIs(t, err, ErrLocked)
	assert.ErrorContains(t, err, "expired")
}

func TestLoadLocked(t *testing.T) {
	otherKey := vaultcrypto.NewSessionKey()
	tests := []struct {
		name string
		key  string
	}{
		{name: "key not set", key: ""},
		{name: "key not base64", key: "not base64!"},
		{name: "key too short", key: base64.RawURLEncoding.EncodeToString([]byte("short"))},
		{name: "wrong key", key: base64.RawURLEncoding.EncodeToString(otherKey[:])},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := unlock(t, testKeys())
			t.Setenv(EnvVar, tt.key)

			_, err := Load(path, testNow)
			assert.ErrorIs(t, err, ErrLocked)
		})
	}
}

func TestLoadTamperedFile(t *testing.T) {
	tests := []struct {
		name   string
		modify func(data []byte) []byte
	}{
		{name: "expiry extended", modify: func(data []byte) []byte {
			data[expirySize-2]++
			return data
		}},
		{name: "sealed keys modified", modify: func(data []byte) []byte {
			data[len(data)-1] ^= 1
			return data
		}},
		{name: "truncated", modify: func(data []byte) []byte { return data[:expirySize-1] }},
		{name: "empty", modify: func([]byte) []byte { return nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := unlock(t, testKeys())
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(path, tt.modify(data), 0o600))

			_, err = Load(path, testNow)
			assert.ErrorIs(t, err, ErrLocked)
		})
	}
}

func TestLoadReadFails(t *testing.T) {
	path := unlock(t, testKeys())
	require.NoError(t, os.Remove(path))
	require.NoError(t, os.Mkdir(path, 0o700))

	_, err := Load(path, testNow)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrLocked)
}

func TestUnlockReplacesSession(t *testing.T) {
	path := unlock(t, testKeys())
	oldKey := os.Getenv(EnvVar)

	keys := testKeys()
	newKey, err := Unlock(path, keys, testNow)
	require.NoError(t, err)

	_, err = Load(path, testNow)
	require.ErrorIs(t, err, ErrLocked, "old key")

	t.Setenv(EnvVar, newKey)
	got, err := Load(path, testNow)
	require.NoError(t, err)
	assert.Equal(t, keys, got)
	assert.NotEqual(t, oldKey, newKey)
}

func TestLock(t *testing.T) {
	path := unlock(t, testKeys())

	require.NoError(t, Lock(path))
	assert.NoFileExists(t, path)

	_, err := Load(path, testNow)
	assert.ErrorIs(t, err, ErrLocked)

	assert.NoError(t, Lock(path), "lock without a session")
}

func TestKeysAreRedacted(t *testing.T) {
	keys := testKeys()

	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("test", "keys", keys)

	assert.Contains(t, buf.String(), "keys=[REDACTED]")
}
