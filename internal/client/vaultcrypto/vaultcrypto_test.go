package vaultcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testPassword = []byte("correct horse battery staple")
	testSalt     = []byte("0123456789abcdef")
)

// flip returns a copy of b with one bit of byte i inverted.
func flip(b []byte, i int) []byte {
	c := bytes.Clone(b)
	c[i] ^= 1
	return c
}

// seq returns a key filled with consecutive bytes starting at start.
func seq(start byte) [KeySize]byte {
	var k [KeySize]byte
	for i := range k {
		k[i] = start + byte(i)
	}
	return k
}

// stdGCM returns plain AES-256-GCM with an explicit nonce, to check the
// stored format without the code under test.
func stdGCM(t *testing.T, key [KeySize]byte) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher(key[:])
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	return gcm
}

// stdSeal encrypts with plain AES-256-GCM and puts a random nonce in front.
func stdSeal(t *testing.T, key [KeySize]byte, plaintext, aad []byte) []byte {
	t.Helper()
	nonce := make([]byte, 12)
	rand.Read(nonce)
	return stdGCM(t, key).Seal(nonce, nonce, plaintext, aad)
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func deriveTestKeys(t *testing.T, password, salt []byte) (WrapKey, LoginKey) {
	t.Helper()
	wrap, login, err := DeriveKeys(password, salt)
	require.NoError(t, err)
	return wrap, login
}

func TestNewSalt(t *testing.T) {
	a, b := NewSalt(), NewSalt()

	assert.Len(t, a, SaltSize)
	assert.NotEqual(t, a, b)
}

func TestNewDataKey(t *testing.T) {
	a, b := NewDataKey(), NewDataKey()

	assert.NotEqual(t, DataKey{}, a)
	assert.NotEqual(t, a, b)
}

// TestDeriveKeysKnownAnswer pins the Argon2id parameters, the HKDF labels and
// the derivation scheme. If it fails, existing users can no longer log in.
func TestDeriveKeysKnownAnswer(t *testing.T) {
	wrap, login := deriveTestKeys(t, testPassword, testSalt)

	assert.Equal(t, "12516dce49ff1ffaec18428401a8a14d16a1f43d845027c7a2dc90367dfed7fb", hex.EncodeToString(wrap[:]))
	assert.Equal(t, "a1bd1057208120b9e336aea9fe5b2e3323ae12d863c4366a2bfc2615af2b6eec", hex.EncodeToString(login[:]))
}

func TestDeriveKeys(t *testing.T) {
	wrap, login := deriveTestKeys(t, testPassword, testSalt)

	t.Run("depends on salt", func(t *testing.T) {
		wrap2, login2 := deriveTestKeys(t, testPassword, []byte("fedcba9876543210"))
		assert.NotEqual(t, wrap, wrap2)
		assert.NotEqual(t, login, login2)
	})

	t.Run("depends on password", func(t *testing.T) {
		wrap2, login2 := deriveTestKeys(t, []byte("wrong password"), testSalt)
		assert.NotEqual(t, wrap, wrap2)
		assert.NotEqual(t, login, login2)
	})
}

func TestDeriveKeysRejectsBadSalt(t *testing.T) {
	tests := []struct {
		name string
		salt []byte
	}{
		{name: "empty", salt: nil},
		{name: "short", salt: make([]byte, SaltSize-1)},
		{name: "long", salt: make([]byte, SaltSize+1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := DeriveKeys(testPassword, tt.salt)
			assert.ErrorIs(t, err, ErrCorrupted)
		})
	}
}

func TestEnvelope(t *testing.T) {
	wrap := WrapKey(seq(32))
	data := NewDataKey()
	envelope := SealEnvelope(wrap, data)

	t.Run("opens with the right key", func(t *testing.T) {
		got, err := OpenEnvelope(wrap, envelope)
		require.NoError(t, err)
		assert.Equal(t, data, got)
	})

	t.Run("does not open with a wrong key", func(t *testing.T) {
		_, err := OpenEnvelope(WrapKey(seq(33)), envelope)
		assert.ErrorIs(t, err, ErrWrongPassword)
	})

	t.Run("fresh nonce on every seal", func(t *testing.T) {
		assert.NotEqual(t, envelope, SealEnvelope(wrap, data))
	})

	tests := []struct {
		name     string
		envelope []byte
		wantErr  error
	}{
		{name: "nonce modified", envelope: flip(envelope, 0), wantErr: ErrWrongPassword},
		{name: "ciphertext modified", envelope: flip(envelope, 12), wantErr: ErrWrongPassword},
		{name: "tag modified", envelope: flip(envelope, len(envelope)-1), wantErr: ErrWrongPassword},
		{name: "truncated", envelope: envelope[:len(envelope)-1], wantErr: ErrCorrupted},
		{name: "too long", envelope: append(bytes.Clone(envelope), 0), wantErr: ErrCorrupted},
		{name: "empty", envelope: []byte{}, wantErr: ErrCorrupted},
		{name: "nil", envelope: nil, wantErr: ErrCorrupted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := OpenEnvelope(wrap, tt.envelope)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

// TestEnvelopeFormat pins the stored envelope format: 12-byte nonce, then the
// encrypted data key and the tag, no AAD.
func TestEnvelopeFormat(t *testing.T) {
	wrap := WrapKey(seq(32))
	data := DataKey(seq(64))

	t.Run("plain GCM opens SealEnvelope output", func(t *testing.T) {
		envelope := SealEnvelope(wrap, data)
		require.Len(t, envelope, 60)

		got, err := stdGCM(t, wrap).Open(nil, envelope[:12], envelope[12:], nil)
		require.NoError(t, err)
		assert.Equal(t, data[:], got)
	})

	t.Run("OpenEnvelope opens plain GCM output", func(t *testing.T) {
		got, err := OpenEnvelope(wrap, stdSeal(t, wrap, data[:], nil))
		require.NoError(t, err)
		assert.Equal(t, data, got)
	})

	// Encrypted outside this package, nonce = bytes 200..211.
	t.Run("fixed vector", func(t *testing.T) {
		envelope := mustHex(t, "c8c9cacbcccdcecfd0d1d2d3e508eca1f713e48516d6c9a6ae354b9bc195612d"+
			"85a72ea605ac7fa1952e3be773b4da1739f2e636e7b2fa6de3d53e37")

		got, err := OpenEnvelope(wrap, envelope)
		require.NoError(t, err)
		assert.Equal(t, data, got)
	})
}

func TestRecord(t *testing.T) {
	key := NewDataKey()
	id := uuid.New()
	plaintext := []byte("bank: 1234 5678 9012 3456")
	ciphertext := EncryptRecord(key, id, plaintext)

	t.Run("round trip", func(t *testing.T) {
		got, err := DecryptRecord(key, id, ciphertext)
		require.NoError(t, err)
		assert.Equal(t, plaintext, got)
	})

	t.Run("empty plaintext round trip", func(t *testing.T) {
		got, err := DecryptRecord(key, id, EncryptRecord(key, id, nil))
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("fresh nonce on every encryption", func(t *testing.T) {
		assert.NotEqual(t, ciphertext, EncryptRecord(key, id, plaintext))
	})

	tests := []struct {
		name       string
		key        DataKey
		id         uuid.UUID
		ciphertext []byte
	}{
		{name: "other record id", key: key, id: uuid.New(), ciphertext: ciphertext},
		{name: "other key", key: NewDataKey(), id: id, ciphertext: ciphertext},
		{name: "nonce modified", key: key, id: id, ciphertext: flip(ciphertext, 0)},
		{name: "ciphertext modified", key: key, id: id, ciphertext: flip(ciphertext, 12)},
		{name: "tag modified", key: key, id: id, ciphertext: flip(ciphertext, len(ciphertext)-1)},
		{name: "truncated", key: key, id: id, ciphertext: ciphertext[:10]},
		{name: "empty", key: key, id: id, ciphertext: []byte{}},
		{name: "nil", key: key, id: id, ciphertext: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecryptRecord(tt.key, tt.id, tt.ciphertext)
			assert.ErrorIs(t, err, ErrCorrupted)
			assert.Nil(t, got)
		})
	}
}

// TestRecordFormat pins the stored record format: 12-byte nonce, then the
// ciphertext and the tag, with the 16 bytes of the record UUID as AAD.
func TestRecordFormat(t *testing.T) {
	key := DataKey(seq(0))
	id := uuid.MustParse("0199f3a2-7c4e-7b1d-9f3a-2c4e7b1d9f3a")
	plaintext := []byte("secret record")

	t.Run("plain GCM opens EncryptRecord output", func(t *testing.T) {
		ciphertext := EncryptRecord(key, id, plaintext)
		require.Len(t, ciphertext, 12+len(plaintext)+16)

		got, err := stdGCM(t, key).Open(nil, ciphertext[:12], ciphertext[12:], id[:])
		require.NoError(t, err)
		assert.Equal(t, plaintext, got)
	})

	t.Run("DecryptRecord opens plain GCM output", func(t *testing.T) {
		got, err := DecryptRecord(key, id, stdSeal(t, key, plaintext, id[:]))
		require.NoError(t, err)
		assert.Equal(t, plaintext, got)
	})

	// Encrypted outside this package, nonce = bytes 100..111.
	t.Run("fixed vector", func(t *testing.T) {
		ciphertext := mustHex(t, "6465666768696a6b6c6d6e6f3b7ebd141c9d76ec5b01309abeff12479d4d3804"+
			"9dff87ab0248fb0a3a")

		got, err := DecryptRecord(key, id, ciphertext)
		require.NoError(t, err)
		assert.Equal(t, plaintext, got)
	})
}

func TestKeysAreRedacted(t *testing.T) {
	raw := seq(0xA0)
	tests := []struct {
		name string
		key  any
	}{
		{name: "data key", key: DataKey(raw)},
		{name: "wrap key", key: WrapKey(raw)},
		{name: "login key", key: LoginKey(raw)},
	}
	noTime := func(_ []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
				assert.Equal(t, redacted, fmt.Sprintf(verb, tt.key), verb)
			}
			assert.Equal(t, redacted, fmt.Sprint(tt.key))
			require.Implements(t, (*fmt.Stringer)(nil), tt.key)
			assert.Equal(t, redacted, tt.key.(fmt.Stringer).String())

			var buf bytes.Buffer
			slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{ReplaceAttr: noTime})).Info("test", "key", tt.key)
			assert.JSONEq(t, `{"level":"INFO","msg":"test","key":"[REDACTED]"}`, buf.String())
		})
	}
}

func BenchmarkDeriveKeys(b *testing.B) {
	for b.Loop() {
		if _, _, err := DeriveKeys(testPassword, testSalt); err != nil {
			b.Fatal(err)
		}
	}
}
