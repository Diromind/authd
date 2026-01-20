CREATE TABLE `authd/users` (
    id Uuid,
    created_at Timestamp64,
    updated_at Timestamp64,
    google_id Utf8,
    google_refresh_token Utf8,
    yandex_id Utf8,
    yandex_refresh_token Utf8,
    INDEX idx_google_id GLOBAL UNIQUE SYNC ON (google_id),
    INDEX idx_yandex_id GLOBAL UNIQUE SYNC ON (yandex_id),
    PRIMARY KEY (id)
);

CREATE TABLE `authd/refresh_tokens` (
    token Utf8,
    user_id Uuid,
    created_at Timestamp64,
    expires_at Timestamp64,
    INDEX idx_user_id GLOBAL ON (user_id),
    PRIMARY KEY (token)
);
