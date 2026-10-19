// Package recordpb contains the plaintext format of a GophKeeper record.
// The client marshals a [Record], encrypts it and sends only the ciphertext;
// the server never sees this format.
//
// The code is generated from record.proto by "task proto"; this file is the
// only one written by hand.
package recordpb
