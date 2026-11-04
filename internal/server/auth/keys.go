package auth

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
)

// SecretSize is the size of the server secret in bytes.
const SecretSize = 32

// HKDF labels that make the token key and the fake salt key independent.
// Changing them invalidates all tokens and changes all fake salts.
const (
	tokenKeyInfo    = "gophkeeper/v1/server/token-key"
	fakeSaltKeyInfo = "gophkeeper/v1/server/fake-salt-key"
)

// derivedKeySize is the size of the keys derived from the secret.
const derivedKeySize = 32

// deriveKey derives a subkey from the server secret. The secret is random,
// so HKDF-Extract is not needed.
func deriveKey(secret []byte, info string) []byte {
	key, err := hkdf.Expand(sha256.New, secret, info, derivedKeySize)
	if err != nil {
		panic(err)
	}
	return key
}

// fakeSalt returns the salt given out for an unknown login. It is the same
// for the same login, so repeated requests do not reveal that the user does
// not exist.
func fakeSalt(key []byte, login string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(login))
	return mac.Sum(nil)[:saltSize]
}
