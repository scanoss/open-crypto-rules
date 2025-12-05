// TEST-RULE: go.crypto.aes.gcm-mode
// TEST-METADATA: assetType=algorithm, findingType=cipher, operation=encrypt, algorithmPrimitive=ae, algorithmName=AES-GCM, algorithmFamily=AES, library=crypto/cipher, api=cipher.NewGCMWithTagSize, cipher=AES, algorithmMode=gcm

package main

import (
	"crypto/aes"
	"crypto/cipher"
)

// Scenario: AES-GCM with custom tag size
func main() {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	plaintext := make([]byte, 100)

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCMWithTagSize(block, 16)
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	_ = ciphertext
}

