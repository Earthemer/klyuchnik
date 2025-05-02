CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    login VARCHAR(255) NOT NULL UNIQUE,
    master_password_hash BYTEA NOT NULL,
    salt BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS password_entries (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    service_name VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    encrypted_password BYTEA NOT NULL,
    encrypted_url BYTEA NULL,
    encrypted_notes BYTEA NULL
);

CREATE INDEX IF NOT EXISTS idx_password_entries_user_id ON password_entries(user_id);
CREATE INDEX IF NOT EXISTS idx_password_entries_service_name ON password_entries(service_name);