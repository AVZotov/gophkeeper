// Command server is the GophKeeper server. It stores encrypted user records
// and syncs them between the owner's clients. For now it serves only the
// Auth service, over TLS only.
//
// Configuration comes from flags and environment variables; a variable
// overrides its flag:
//
//	-a         ADDRESS        address to listen on (default localhost:8443)
//	-d         DATABASE_DSN   PostgreSQL connection string (required)
//	-tls-cert  TLS_CERT       TLS certificate file (default certs/server.crt)
//	-tls-key   TLS_KEY        TLS private key file (default certs/server.key)
//	           SERVER_SECRET  server secret, 32 bytes in hex (required)
//
// The secret has no flag, so it does not show in the process list.
//
// The first SIGINT or SIGTERM stops the server gracefully, waiting for calls
// in progress for a limited time; a second one ends it at once.
package main
