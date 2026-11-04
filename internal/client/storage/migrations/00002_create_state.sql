-- +goose Up
-- The only row of the table: the database belongs to one user.
CREATE TABLE state (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    server_address TEXT NOT NULL,
    ca_path        TEXT NOT NULL,
    login          TEXT NOT NULL,
    salt           BLOB NOT NULL,
    envelope       BLOB NOT NULL,
    token          TEXT NOT NULL,
    -- Last revision received from the server.
    last_revision  INTEGER NOT NULL
) STRICT;

-- +goose Down
DROP TABLE state;
