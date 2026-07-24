// TEST-RULE: go.crypto.aes.gcm-mode
// TEST-METADATA: assetType=algorithm, findingType=cipher, algorithmPrimitive=ae, algorithmName=AES-GCM, algorithmFamily=AES, library=crypto/cipher, api=cipher.NewGCMWithRandomNonce, cipher=AES, algorithmMode=gcm

package main

import (
	"crypto/aes"
	"crypto/cipher"
)

// Scenario: AES-GCM with random nonce
func main() {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	plaintext := make([]byte, 100)

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCMWithRandomNonce(block)
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	_ = ciphertext
}

