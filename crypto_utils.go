package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "io"
    "log"
    "os"
)

// encryptionKey хранится в коде (32 байта для AES-256)
var (
    // Читаем ключ шифрования из окружения
    encryptionKey []byte
)

func init() {
    keyStr := os.Getenv("ENCRYPTION_KEY")
    if keyStr == "" {
        log.Fatal("Environment variable ENCRYPTION_KEY not set")
    }
    encryptionKey = []byte(keyStr)
}

// encryptToken шифрует plainText используя AES-GCM и возвращает результат в base64
func encryptToken(plainText string) (string, error) {
    block, err := aes.NewCipher(encryptionKey)
    if err != nil {
        return "", fmt.Errorf("failed to create cipher: %w", err)
    }
    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", fmt.Errorf("failed to create GCM: %w", err)
    }
    nonce := make([]byte, aesgcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return "", fmt.Errorf("failed to read nonce: %w", err)
    }
    cipherText := aesgcm.Seal(nonce, nonce, []byte(plainText), nil)
    return base64.StdEncoding.EncodeToString(cipherText), nil
}

// decryptToken декодирует base64, расшифровывает AES-GCM и возвращает исходный plainText
func decryptToken(encText string) (string, error) {
    data, err := base64.StdEncoding.DecodeString(encText)
    if err != nil {
        return "", fmt.Errorf("failed to base64 decode: %w", err)
    }
    block, err := aes.NewCipher(encryptionKey)
    if err != nil {
        return "", fmt.Errorf("failed to create cipher: %w", err)
    }
    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", fmt.Errorf("failed to create GCM: %w", err)
    }
    nonceSize := aesgcm.NonceSize()
    if len(data) < nonceSize {
        return "", fmt.Errorf("ciphertext too short")
    }
    nonce, cipherText := data[:nonceSize], data[nonceSize:]
    plainText, err := aesgcm.Open(nil, nonce, cipherText, nil)
    if err != nil {
        return "", fmt.Errorf("failed to decrypt: %w", err)
    }
    return string(plainText), nil
}