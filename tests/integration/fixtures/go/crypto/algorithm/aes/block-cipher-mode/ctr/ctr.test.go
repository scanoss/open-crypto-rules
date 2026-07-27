// TEST-RULE: go.crypto.aes.block-cipher-mode-encrypt
// TEST-METADATA: assetType=algorithm, findingType=cipher, operation=encrypt, algorithmPrimitive=block-cipher, algorithmName=AES-CTR, algorithmFamily=AES, library=crypto/cipher, api=cipher.NewCTR, cipher=AES

package main

import (
	"crypto/aes"
	"crypto/cipher"
)

// Scenario: AES-CTR mode
func main() {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	plaintext := make([]byte, 100)

	block, _ := aes.NewCipher(key)
	ctr := cipher.NewCTR(block, iv)
	ctr.XORKeyStream(plaintext, plaintext)
}

