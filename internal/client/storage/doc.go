// Package storage keeps the client data in a local SQLite file: copies of
// the records and the state of the client. One database belongs to one
// user. [Open] applies the embedded migrations, so the schema is up to date
// before the first query.
package storage
