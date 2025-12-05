// TEST-RULE: go.crypto.aes.gcm-mode
// TEST-METADATA: assetType=algorithm, findingType=cipher, operation=encrypt, algorithmPrimitive=ae, algorithmName=AES-GCM, algorithmFamily=AES, library=crypto/cipher, api=cipher.NewGCM, cipher=AES, algorithmMode=gcm

package main

import (
	"crypto/aes"
	"crypto/cipher"
)

// Scenario: Basic AES-GCM mode
func main() {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	plaintext := make([]byte, 100)

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	_ = ciphertext
}

