// Package vaultcrypto is the client-side cryptography of GophKeeper: it
// derives keys from the master password, seals the data key into the
// envelope and encrypts records.
//
// Keys are distinct types, so one cannot be passed where another is
// expected. fmt and slog print them as [REDACTED].
package vaultcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"uuid"

	"golang.org/x/crypto/argon2"
)

const (
	// KeySize is the size of every key in bytes.
	KeySize = 32
	// SaltSize is the size of the salt in bytes.
	SaltSize = 16
)

// Argon2id parameters. Changing them locks existing users out.
const (
	argon2Time    = 3
	argon2Memory  = 64 * 1024 // KiB
	argon2Threads = 4
)

// HKDF labels that make the wrap key and the login key independent.
// Changing them locks existing users out.
const (
	wrapKeyInfo  = "gophkeeper/v1/wrap-key"
	loginKeyInfo = "gophkeeper/v1/login-key"
)

// Sizes of the AES-GCM nonce and tag in bytes.
const (
	nonceSize = 12
	tagSize   = 16
)

// envelopeSize is the size of a sealed data key: nonce, key and GCM tag.
const envelopeSize = nonceSize + KeySize + tagSize

const redacted = "[REDACTED]"

var (
	// ErrWrongPassword means the envelope did not open with the key from the
	// password. A damaged envelope of the right size gives the same error.
	ErrWrongPassword = errors.New("wrong password")
	// ErrCorrupted means the input is malformed or was tampered with.
	ErrCorrupted = errors.New("corrupted data")
)

// DataKey encrypts records. It is created once at registration and stored
// only inside the envelope.
type DataKey [KeySize]byte

// WrapKey seals the data key into the envelope. See [DeriveKeys].
type WrapKey [KeySize]byte

// LoginKey proves to the server that the user knows the password. See
// [DeriveKeys].
type LoginKey [KeySize]byte

// String hides the key.
func (DataKey) String() string { return redacted }

// Format hides the key for every fmt verb.
func (DataKey) Format(f fmt.State, _ rune) { io.WriteString(f, redacted) }

// LogValue hides the key in slog output.
func (DataKey) LogValue() slog.Value { return slog.StringValue(redacted) }

// String hides the key.
func (WrapKey) String() string { return redacted }

// Format hides the key for every fmt verb.
func (WrapKey) Format(f fmt.State, _ rune) { io.WriteString(f, redacted) }

// LogValue hides the key in slog output.
func (WrapKey) LogValue() slog.Value { return slog.StringValue(redacted) }

// String hides the key.
func (LoginKey) String() string { return redacted }

// Format hides the key for every fmt verb.
func (LoginKey) Format(f fmt.State, _ rune) { io.WriteString(f, redacted) }

// LogValue hides the key in slog output.
func (LoginKey) LogValue() slog.Value { return slog.StringValue(redacted) }

// NewSalt returns a random salt of [SaltSize] bytes for [DeriveKeys].
func NewSalt() []byte {
	salt := make([]byte, SaltSize)
	rand.Read(salt)
	return salt
}

// NewDataKey returns a random data key.
func NewDataKey() DataKey {
	var key DataKey
	rand.Read(key[:])
	return key
}

// DeriveKeys derives the wrap key and the login key from the password and
// the salt. Argon2id makes the master key, HKDF splits it into two keys. It
// is slow on purpose, to make password guessing expensive. Returns
// [ErrCorrupted] if the salt is not [SaltSize] bytes.
func DeriveKeys(password, salt []byte) (WrapKey, LoginKey, error) {
	if len(salt) != SaltSize {
		return WrapKey{}, LoginKey{}, fmt.Errorf("%w: salt is %d bytes, want %d", ErrCorrupted, len(salt), SaltSize)
	}
	master := argon2.IDKey(password, salt, argon2Time, argon2Memory, argon2Threads, KeySize)

	return WrapKey(expand(master, wrapKeyInfo)), LoginKey(expand(master, loginKeyInfo)), nil
}

// SealEnvelope encrypts the data key with the wrap key. The result is a
// random nonce followed by the ciphertext.
func SealEnvelope(wrap WrapKey, data DataKey) []byte {
	return newAEAD(wrap).Seal(nil, nil, data[:], nil)
}

// OpenEnvelope decrypts the data key sealed by [SealEnvelope]. Returns
// [ErrWrongPassword] if the envelope does not open with this wrap key and
// [ErrCorrupted] if it has the wrong size.
func OpenEnvelope(wrap WrapKey, envelope []byte) (DataKey, error) {
	if len(envelope) != envelopeSize {
		return DataKey{}, fmt.Errorf("%w: envelope is %d bytes, want %d", ErrCorrupted, len(envelope), envelopeSize)
	}
	plain, err := newAEAD(wrap).Open(nil, nil, envelope, nil)
	if err != nil {
		return DataKey{}, ErrWrongPassword
	}

	return DataKey(plain), nil
}

// EncryptRecord encrypts a record with the data key. The record id is bound
// to the ciphertext, so the ciphertext cannot be moved to another record.
// The result is a random nonce followed by the ciphertext.
func EncryptRecord(key DataKey, id uuid.UUID, plaintext []byte) []byte {
	return newAEAD(key).Seal(nil, nil, plaintext, id[:])
}

// DecryptRecord decrypts a record encrypted by [EncryptRecord]. Returns
// [ErrCorrupted] if the ciphertext was modified, belongs to another record or
// was encrypted with another key.
func DecryptRecord(key DataKey, id uuid.UUID, ciphertext []byte) ([]byte, error) {
	plain, err := newAEAD(key).Open(nil, nil, ciphertext, id[:])
	if err != nil {
		return nil, fmt.Errorf("decrypt record %s: %w", id, ErrCorrupted)
	}

	return plain, nil
}

// expand derives a subkey from the master key. The master key from Argon2id
// is already uniformly random, so HKDF-Extract is not needed.
func expand(master []byte, info string) [KeySize]byte {
	key, err := hkdf.Expand(sha256.New, master, info, KeySize)
	if err != nil {
		panic(err)
	}

	return [KeySize]byte(key)
}

// newAEAD returns AES-256-GCM that puts a random 12-byte nonce before the
// ciphertext on Seal and reads it back on Open.
func newAEAD(key [KeySize]byte) cipher.AEAD {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		panic(err)
	}

	return aead
}
