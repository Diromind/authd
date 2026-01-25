package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidEncryptionKey = errors.New("encryption key must be 32 bytes for AES-256")
	ErrInvalidCiphertext    = errors.New("invalid ciphertext")
)

type CryptoService struct {
	encryptionKey []byte
}

// NewCryptoService creates a new crypto service with the provided encryption key.
// The key must be exactly 32 bytes for AES-256.
func NewCryptoService(encryptionKey string) (*CryptoService, error) {
	key := []byte(encryptionKey)
	if len(key) != 32 {
		return nil, ErrInvalidEncryptionKey
	}

	return &CryptoService{
		encryptionKey: key,
	}, nil
}

// EncryptToken encrypts a token using AES-256-GCM.
// Returns base64-encoded ciphertext with nonce prepended.
func (cs *CryptoService) EncryptToken(plaintext string) (string, error) {
	block, err := aes.NewCipher(cs.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (cs *CryptoService) DecryptToken(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	block, err := aes.NewCipher(cs.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", ErrInvalidCiphertext
	}

	nonce, cipherbytes := data[:nonceSize], data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, cipherbytes, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// HashToken creates a bcrypt hash of a token for secure storage.
// Uses bcrypt cost of 12 for a good balance between security and performance.
func (cs *CryptoService) HashToken(token string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(token), 12)
	if err != nil {
		return "", fmt.Errorf("failed to hash token: %w", err)
	}
	return string(hash), nil
}

func (cs *CryptoService) VerifyTokenHash(token, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(token))
	return err == nil
}

type RefreshTokenParts struct {
	ID  string // Token ID
	Key string // Token Key
}

func GenerateRefreshToken() (fullToken string, parts *RefreshTokenParts, err error) {
	idBytes := make([]byte, 32)
	if _, err := rand.Read(idBytes); err != nil {
		return "", nil, fmt.Errorf("failed to generate token ID: %w", err)
	}

	keyBytes := make([]byte, 48)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", nil, fmt.Errorf("failed to generate token key: %w", err)
	}

	id := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(idBytes)
	key := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(keyBytes)

	fullToken = fmt.Sprintf("ADRT_%s.%s", id, key)

	return fullToken, &RefreshTokenParts{
		ID:  id,
		Key: key,
	}, nil
}

func ParseRefreshToken(token string) (*RefreshTokenParts, error) {
	if len(token) < 6 || token[:5] != "ADRT_" {
		return nil, errors.New("invalid token format: missing ADRT_ prefix")
	}

	tokenBody := token[5:]
	parts := make([]byte, 0, len(tokenBody))
	for i := 0; i < len(tokenBody); i++ {
		if tokenBody[i] == '.' {
			id := string(parts)
			key := tokenBody[i+1:]

			if len(id) == 0 || len(key) == 0 {
				return nil, errors.New("invalid token format: empty ID or Key")
			}

			return &RefreshTokenParts{
				ID:  id,
				Key: key,
			}, nil
		}
		parts = append(parts, tokenBody[i])
	}

	return nil, errors.New("invalid token format: missing separator")
}
