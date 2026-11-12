-- +goose Up
CREATE TABLE records (
    id         BLOB PRIMARY KEY CHECK (length(id) = 16),
    -- Last revision received from the server, 0 for a record never pushed.
    revision   INTEGER NOT NULL,
    deleted    INTEGER NOT NULL CHECK (deleted IN (0, 1)),
    ciphertext BLOB NOT NULL,
    -- 1 if the record has a change not pushed to the server yet.
    dirty      INTEGER NOT NULL CHECK (dirty IN (0, 1)),
    -- Only a deleted record has no ciphertext.
    CHECK (deleted = (length(ciphertext) = 0))
) STRICT;

-- +goose Down
DROP TABLE records;
