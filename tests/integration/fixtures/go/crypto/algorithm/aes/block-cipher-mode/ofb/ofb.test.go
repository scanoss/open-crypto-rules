// TEST-RULE: go.crypto.aes.block-cipher-mode-encrypt
// TEST-METADATA: assetType=algorithm, findingType=cipher, operation=encrypt, algorithmPrimitive=block-cipher, algorithmName=AES-OFB, algorithmFamily=AES, library=crypto/cipher, api=cipher.NewOFB, cipher=AES

package main

import (
	"crypto/aes"
	"crypto/cipher"
)

// Scenario: AES-OFB mode
func main() {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	plaintext := make([]byte, 100)

	block, _ := aes.NewCipher(key)
	ofb := cipher.NewOFB(block, iv)
	ofb.XORKeyStream(plaintext, plaintext)
}

