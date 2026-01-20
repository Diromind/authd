-- SQLite schema for authd

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- User providers table
CREATE TABLE IF NOT EXISTS user_providers (
    user_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    PRIMARY KEY (user_id, provider),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Unique constraint on provider_id per provider (one OAuth account can't be linked to multiple users)
CREATE UNIQUE INDEX IF NOT EXISTS idx_provider_id_unique ON user_providers(provider, provider_id);

-- Refresh tokens table
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Index for fast user lookup
CREATE INDEX IF NOT EXISTS idx_refresh_user_id ON refresh_tokens(user_id);
