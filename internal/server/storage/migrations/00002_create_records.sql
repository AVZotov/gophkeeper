-- +goose Up
CREATE TABLE records (
    owner_id   bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    id         uuid NOT NULL,
    -- Value of the owner's revision counter given to the last change.
    revision   bigint NOT NULL,
    deleted    boolean NOT NULL,
    -- Ciphertext does not compress, so it is stored without trying.
    ciphertext bytea STORAGE EXTERNAL NOT NULL,
    PRIMARY KEY (owner_id, id),
    -- Also the index Pull reads records in revision order by.
    UNIQUE (owner_id, revision),
    -- Only a deleted record has no ciphertext.
    CHECK (deleted = (octet_length(ciphertext) = 0))
);

-- +goose Down
DROP TABLE records;
