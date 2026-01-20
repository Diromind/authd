package core

import (
	"time"

	"github.com/google/uuid"
)

// Provider represents an OAuth authentication provider
type Provider string

const (
	ProviderGoogle Provider = "google"
	ProviderYandex Provider = "yandex"
	// Future providers can be added here
)

// User represents an authenticated user with linked OAuth accounts
type User struct {
	ID                 uuid.UUID
	CreatedAt          time.Time
	UpdatedAt          time.Time
	GoogleID           *string // Nullable - only if Google account linked
	GoogleRefreshToken *string // OAuth refresh token from Google
	YandexID           *string // Nullable - only if Yandex account linked
	YandexRefreshToken *string // OAuth refresh token from Yandex
}

// RefreshToken represents an authd session token
type RefreshToken struct {
	Token     string
	UserID    uuid.UUID
	CreatedAt time.Time
	ExpiresAt time.Time
}
