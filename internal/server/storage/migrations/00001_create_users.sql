-- +goose Up
CREATE TABLE users (
    id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    login               text NOT NULL UNIQUE,
    salt                bytea NOT NULL,
    login_key_hash      bytea NOT NULL,
    envelope            bytea NOT NULL,
    -- Last revision given to any of the user's records.
    revision            bigint NOT NULL DEFAULT 0,
    password_changed_at timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE users;
