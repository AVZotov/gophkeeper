// Package session keeps an unlocked vault between commands. It follows
// Bitwarden CLI (bw unlock and bw lock): [Unlock] seals the data key and the
// login key with a random session key into a file with a lifetime, and the
// user keeps the session key in an environment variable of the terminal.
// The keys are never written to disk in the clear.
package session

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/AVZotov/gophkeeper/internal/client/vaultcrypto"
)

// TTL is the lifetime of a session.
const TTL = time.Hour

// expirySize is the size of the expiry time at the start of the session
// file: Unix seconds, big-endian.
const expirySize = 8

// ErrLocked means there is no usable session: the key is not set or is
// wrong, or the session has expired or ended.
var ErrLocked = errors.New("vault is locked, run gophkeeper unlock")

// encoding writes the session key without characters that shells treat
// specially.
var encoding = base64.RawURLEncoding

// Keys are the keys an unlocked vault works with.
type Keys struct {
	Data  vaultcrypto.DataKey
	Login vaultcrypto.LoginKey
}

// LogValue hides the keys in slog output.
func (Keys) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// Unlock starts a session that ends [TTL] after now: it seals keys with a
// new session key into the file at path and returns the key, encoded for an
// environment variable. The file is readable only by its owner and replaces the previous
// session, so the old key stops working. Returns an error if the file cannot
// be written.
func Unlock(path string, keys Keys, now time.Time) (string, error) {
	key := vaultcrypto.NewSessionKey()
	expiry := binary.BigEndian.AppendUint64(nil, uint64(now.Add(TTL).Unix()))
	if err := save(path, key, expiry, keys); err != nil {
		return "", err
	}
	return encoding.EncodeToString(key[:]), nil
}

// Load opens the session in the file at path with the encoded key and
// returns its keys. Returns [ErrLocked] if the key is empty or malformed,
// there is no session, the key does not open it or the session expired by
// now, and an error if the file cannot be read.
func Load(path, key string, now time.Time) (Keys, error) {
	_, _, keys, err := open(path, key, now)
	return keys, err
}

// Update replaces the keys of the session in the file at path, opened with
// the encoded key. The session keeps its key and expiry, so commands in other
// terminals go on working. Returns the errors of [Load] and an error if the
// file cannot be written.
func Update(path, key string, keys Keys, now time.Time) error {
	sessionKey, expiry, _, err := open(path, key, now)
	if err != nil {
		return err
	}
	return save(path, sessionKey, expiry, keys)
}

// open opens the session like [Load] and also returns its key and expiry.
func open(path, key string, now time.Time) (vaultcrypto.SessionKey, []byte, Keys, error) {
	if key == "" {
		return vaultcrypto.SessionKey{}, nil, Keys{}, fmt.Errorf("no session key: %w", ErrLocked)
	}
	raw, err := encoding.DecodeString(key)
	if err != nil || len(raw) != vaultcrypto.KeySize {
		return vaultcrypto.SessionKey{}, nil, Keys{}, fmt.Errorf("malformed session key: %w", ErrLocked)
	}
	sessionKey := vaultcrypto.SessionKey(raw)

	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return vaultcrypto.SessionKey{}, nil, Keys{}, fmt.Errorf("no session: %w", ErrLocked)
	}
	if err != nil {
		return vaultcrypto.SessionKey{}, nil, Keys{}, fmt.Errorf("read session: %w", err)
	}
	if len(data) < expirySize {
		return vaultcrypto.SessionKey{}, nil, Keys{}, fmt.Errorf("corrupted session: %w", ErrLocked)
	}

	expiry, sealed := data[:expirySize], data[expirySize:]
	dataKey, loginKey, err := vaultcrypto.OpenSession(sessionKey, sealed, expiry)
	if err != nil {
		return vaultcrypto.SessionKey{}, nil, Keys{}, fmt.Errorf("wrong session key: %w", ErrLocked)
	}
	if !now.Before(time.Unix(int64(binary.BigEndian.Uint64(expiry)), 0)) {
		return vaultcrypto.SessionKey{}, nil, Keys{}, fmt.Errorf("session expired: %w", ErrLocked)
	}
	return sessionKey, expiry, Keys{Data: dataKey, Login: loginKey}, nil
}

// save writes keys sealed with the session key to the file at path, after
// the expiry. The expiry is bound to the sealed keys, so it cannot be
// extended.
func save(path string, key vaultcrypto.SessionKey, expiry []byte, keys Keys) error {
	data := append(bytes.Clone(expiry), vaultcrypto.SealSession(key, keys.Data, keys.Login, expiry)...)
	if err := writeFile(path, data); err != nil {
		return fmt.Errorf("write session: %w", err)
	}
	return nil
}

// Lock ends the session by removing the file at path. Returns an error if
// the file exists and cannot be removed.
func Lock(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove session: %w", err)
	}
	return nil
}

// writeFile replaces the file at path with data in one step, so a reader
// never sees half a file. The file is readable only by its owner, whatever
// the mode of the file it replaces.
func writeFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())

	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
