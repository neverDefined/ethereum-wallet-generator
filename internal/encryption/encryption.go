package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	SaltSize         = 32
	NonceSize        = 12
	KeySize          = 32
	PBKDF2Iterations = 100000
	gcmTagSize       = 16
)

// Encrypt encrypts plaintext using AES-256-GCM with a password-derived key
func Encrypt(plaintext, password string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	// Generate random salt
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	// Derive key from password using PBKDF2
	key := pbkdf2.Key([]byte(password), salt, PBKDF2Iterations, KeySize, sha256.New)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Create GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Generate random nonce
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Encrypt and authenticate
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	// Format: base64(salt + nonce + ciphertext)
	combined := append(salt, append(nonce, ciphertext...)...)
	return base64.StdEncoding.EncodeToString(combined), nil
}

// Decrypt decrypts ciphertext using AES-256-GCM with a password-derived key
func Decrypt(encrypted, password string) (string, error) {
	if encrypted == "" {
		return "", nil
	}

	// Decode base64
	combined, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", errors.New("invalid encrypted data format")
	}

	// Check minimum length
	minLen := SaltSize + NonceSize + gcmTagSize
	if len(combined) < minLen {
		return "", errors.New("encrypted data too short")
	}

	// Extract salt, nonce, and ciphertext
	salt := combined[:SaltSize]
	nonce := combined[SaltSize : SaltSize+NonceSize]
	ciphertext := combined[SaltSize+NonceSize:]

	// Derive key from password using PBKDF2
	key := pbkdf2.Key([]byte(password), salt, PBKDF2Iterations, KeySize, sha256.New)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Create GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Decrypt and verify
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", errors.New("decryption failed: invalid password or corrupted data")
	}

	return string(plaintext), nil
}
