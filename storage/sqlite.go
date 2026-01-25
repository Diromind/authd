package storage

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"strings"
	"time"

	"authd/core"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

//go:embed schema/sqlite/schema.sql
var sqliteSchema string

type SQLiteRepository struct {
	db *sql.DB
}

func NewSQLiteRepository(dbPath string) (*SQLiteRepository, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	repo := &SQLiteRepository{db: db}

	if err := repo.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return repo, nil
}

func (r *SQLiteRepository) Close() error {
	return r.db.Close()
}

func (r *SQLiteRepository) initSchema() error {
	_, err := r.db.Exec(sqliteSchema)
	return err
}

func (r *SQLiteRepository) FindByID(ctx context.Context, id uuid.UUID) (*core.User, error) {
	userQuery := `
		SELECT id, created_at, updated_at
		FROM users
		WHERE id = ?
	`

	var user core.User
	var idStr string
	var createdAt, updatedAt int64

	err := r.db.QueryRowContext(ctx, userQuery, id.String()).Scan(
		&idStr,
		&createdAt,
		&updatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, core.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	user.ID = uuid.MustParse(idStr)
	user.CreatedAt = time.Unix(createdAt, 0)
	user.UpdatedAt = time.Unix(updatedAt, 0)

	providersQuery := `
		SELECT provider, provider_id, refresh_token
		FROM user_providers
		WHERE user_id = ?
	`

	rows, err := r.db.QueryContext(ctx, providersQuery, id.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	user.Providers = []core.ProviderAuthData{}
	for rows.Next() {
		var providerData core.ProviderAuthData
		var providerStr string
		err := rows.Scan(&providerStr, &providerData.ProviderID, &providerData.RefreshToken)
		if err != nil {
			return nil, err
		}
		providerData.Provider = core.Provider(providerStr)
		user.Providers = append(user.Providers, providerData)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return &user, nil
}

func (r *SQLiteRepository) FindByProviderID(ctx context.Context, providerID string, provider core.Provider) (*core.User, error) {
	query := `
		SELECT user_id
		FROM user_providers
		WHERE provider = ? AND provider_id = ?
	`

	var userIDStr string
	err := r.db.QueryRowContext(ctx, query, string(provider), providerID).Scan(&userIDStr)
	if err == sql.ErrNoRows {
		return nil, core.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	userID := uuid.MustParse(userIDStr)
	return r.FindByID(ctx, userID)
}

func (r *SQLiteRepository) CreateUser(ctx context.Context, user *core.User) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	userQuery := `
		INSERT INTO users (id, created_at, updated_at)
		VALUES (?, ?, ?)
	`
	_, err = tx.ExecContext(ctx, userQuery,
		user.ID.String(),
		user.CreatedAt.Unix(),
		user.UpdatedAt.Unix(),
	)
	if err != nil {
		return err
	}

	providerQuery := `
		INSERT INTO user_providers (user_id, provider, provider_id, refresh_token)
		VALUES (?, ?, ?, ?)
	`
	for _, providerData := range user.Providers {
		_, err = tx.ExecContext(ctx, providerQuery,
			user.ID.String(),
			string(providerData.Provider),
			providerData.ProviderID,
			providerData.RefreshToken,
		)
		if err != nil {
			if isUniqueConstraintError(err) {
				return core.ErrAlreadyExists
			}
			return err
		}
	}

	return tx.Commit()
}

func (r *SQLiteRepository) UpdateProviderRefreshToken(ctx context.Context, userID uuid.UUID, refreshToken string, provider core.Provider) error {
	query := `
		UPDATE user_providers
		SET refresh_token = ?
		WHERE user_id = ? AND provider = ?
	`

	result, err := r.db.ExecContext(ctx, query, refreshToken, userID.String(), string(provider))
	if err != nil {
		return err
	}

	_, err = r.db.ExecContext(ctx, `UPDATE users SET updated_at = ? WHERE id = ?`, time.Now().Unix(), userID.String())
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return core.ErrNotFound
	}

	return nil
}

func (r *SQLiteRepository) CreateRefreshToken(ctx context.Context, token *core.RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (token_id, token_key_hash, user_id, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?)
	`

	_, err := r.db.ExecContext(ctx, query,
		token.TokenID,
		token.TokenKeyHash,
		token.UserID.String(),
		token.CreatedAt.Unix(),
		token.ExpiresAt.Unix(),
	)

	return err
}

func (r *SQLiteRepository) FindRefreshTokenByID(ctx context.Context, tokenID string) (*core.RefreshToken, error) {
	query := `
		SELECT token_id, token_key_hash, user_id, created_at, expires_at
		FROM refresh_tokens
		WHERE token_id = ?
	`

	var refreshToken core.RefreshToken
	var userIDStr string
	var createdAt, expiresAt int64

	err := r.db.QueryRowContext(ctx, query, tokenID).Scan(
		&refreshToken.TokenID,
		&refreshToken.TokenKeyHash,
		&userIDStr,
		&createdAt,
		&expiresAt,
	)

	if err == sql.ErrNoRows {
		return nil, core.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	refreshToken.UserID = uuid.MustParse(userIDStr)
	refreshToken.CreatedAt = time.Unix(createdAt, 0)
	refreshToken.ExpiresAt = time.Unix(expiresAt, 0)

	return &refreshToken, nil
}

func (r *SQLiteRepository) DeleteRefreshTokenByID(ctx context.Context, tokenID string) error {
	query := `DELETE FROM refresh_tokens WHERE token_id = ?`
	_, err := r.db.ExecContext(ctx, query, tokenID)
	return err
}

func (r *SQLiteRepository) DeleteAllUserRefreshTokens(ctx context.Context, userID uuid.UUID) error {
	query := `DELETE FROM refresh_tokens WHERE user_id = ?`
	_, err := r.db.ExecContext(ctx, query, userID.String())
	return err
}

func (r *SQLiteRepository) DeleteExpiredRefreshTokens(ctx context.Context) (int64, error) {
	query := `DELETE FROM refresh_tokens WHERE expires_at < ?`
	result, err := r.db.ExecContext(ctx, query, time.Now().Unix())
	if err != nil {
		return 0, err
	}

	count, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}

	return count, nil
}

func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}
	errMsg := err.Error()
	return strings.Contains(errMsg, "UNIQUE constraint failed") ||
		strings.Contains(errMsg, "UNIQUE") ||
		strings.Contains(errMsg, "unique")
}
