package db

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql/driver"
	"encoding/base64"
	"fmt"
	"io"
	"sync"
)

var (
	encKeyMu sync.RWMutex
	encKey   []byte
)

// SetEncryptionKey configures the global AES-256-GCM key for EncryptedString.
// key must be exactly 32 bytes. Call once at startup before any DB access.
// If key is nil, EncryptedString stores and reads values as plaintext.
func SetEncryptionKey(key []byte) {
	encKeyMu.Lock()
	defer encKeyMu.Unlock()
	encKey = key
}

// EncryptedString transparently encrypts on write and decrypts on read using
// AES-256-GCM. Falls back to plaintext when no key is set, or for legacy rows
// that were stored before encryption was enabled.
type EncryptedString string

const encPrefix = "enc:"

// Value implements driver.Valuer — encrypts before writing to the DB.
func (e EncryptedString) Value() (driver.Value, error) {
	encKeyMu.RLock()
	key := encKey
	encKeyMu.RUnlock()

	plaintext := string(e)
	if len(key) == 0 {
		return plaintext, nil
	}

	ciphertext, err := gcmEncrypt(key, []byte(plaintext))
	if err != nil {
		return nil, fmt.Errorf("encrypted field: encrypt: %w", err)
	}
	return encPrefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Scan implements sql.Scanner — decrypts the value read from the DB.
// Rows without the "enc:" prefix are treated as plaintext (migration-safe).
func (e *EncryptedString) Scan(src interface{}) error {
	var raw string
	switch v := src.(type) {
	case string:
		raw = v
	case []byte:
		raw = string(v)
	case nil:
		*e = ""
		return nil
	default:
		return fmt.Errorf("encrypted field: unsupported source type %T", src)
	}

	encKeyMu.RLock()
	key := encKey
	encKeyMu.RUnlock()

	if len(key) == 0 || len(raw) < len(encPrefix) || raw[:len(encPrefix)] != encPrefix {
		*e = EncryptedString(raw)
		return nil
	}

	decoded, err := base64.StdEncoding.DecodeString(raw[len(encPrefix):])
	if err != nil {
		// Not valid base64 — treat as plaintext rather than fail hard.
		*e = EncryptedString(raw)
		return nil
	}

	plaintext, err := gcmDecrypt(key, decoded)
	if err != nil {
		return fmt.Errorf("encrypted field: decrypt: %w", err)
	}
	*e = EncryptedString(plaintext)
	return nil
}

func gcmEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func gcmDecrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
