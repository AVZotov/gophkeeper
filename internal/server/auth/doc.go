// Package auth is the server side of authentication: the Auth gRPC service,
// access tokens and the interceptor that checks them.
//
// The server never sees the password. It stores a hash of the login key and
// gives out a token after checking it. For an unknown login it returns a
// fake salt, so the answer does not show whether the user exists.
package auth
