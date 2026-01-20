CREATE TABLE `authd/users` (
    id Uuid,
    created_at Timestamp64,
    updated_at Timestamp64,
    PRIMARY KEY (id)
);

CREATE TABLE `authd/user_providers` (
    user_id Uuid,
    provider Utf8,
    provider_id Utf8,
    refresh_token Utf8,
    INDEX idx_provider_lookup GLOBAL UNIQUE SYNC ON (provider, provider_id),
    PRIMARY KEY (user_id, provider)
);

CREATE TABLE `authd/refresh_tokens` (
    token Utf8,
    user_id Uuid,
    created_at Timestamp64,
    expires_at Timestamp64,
    INDEX idx_user_id GLOBAL ON (user_id),
    PRIMARY KEY (token)
);
