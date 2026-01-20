-- SQLite schema for authd
-- This file contains the complete database schema for SQLite

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    google_id TEXT,
    google_refresh_token TEXT,
    yandex_id TEXT,
    yandex_refresh_token TEXT
);

-- Unique constraints on provider IDs
CREATE UNIQUE INDEX IF NOT EXISTS idx_google_id_unique ON users(google_id) WHERE google_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_yandex_id_unique ON users(yandex_id) WHERE yandex_id IS NOT NULL;

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
