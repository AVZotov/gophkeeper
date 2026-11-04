// Package recordpb is the plaintext format of a GophKeeper record. The client
// encrypts a marshaled [Record] and sends the server only the ciphertext.
//
// The code is generated from record.proto; only this file and redact.go are
// written by hand. slog prints every message of the package as [REDACTED].
// fmt does not: the generated String shows the content.
package recordpb
