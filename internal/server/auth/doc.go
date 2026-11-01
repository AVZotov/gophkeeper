// Package auth is the server side of authentication: the Auth gRPC service,
// access tokens and their checks.
//
// A token is checked in two steps. The tap handle runs before the server
// reads the message of a call: it checks the token signature and expiry,
// so a client without a valid token cannot make the server read a large
// message. The interceptor then rejects tokens revoked by a password
// change: that needs the storage, which the tap handle must not use.
//
// The server never sees the password. It stores a hash of the login key and
// gives out a token after checking it. For an unknown login it returns a
// fake salt, so the answer does not show whether the user exists.
package auth
