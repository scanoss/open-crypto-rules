// TEST-RULE: go.crypto.aes.block-cipher-mode-encrypt
// TEST-METADATA: assetType=algorithm, findingType=cipher, operation=encrypt, algorithmPrimitive=block-cipher, algorithmName=AES-CBC, algorithmFamily=AES, library=crypto/cipher, api=cipher.NewCBCEncrypter, cipher=AES

package main

import (
	"crypto/aes"
	"crypto/cipher"
)

// Scenario: AES-CBC mode encrypter
func main() {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	plaintext := make([]byte, 100)

	block, _ := aes.NewCipher(key)
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(plaintext, plaintext)
}

