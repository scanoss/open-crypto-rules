// TEST-RULE: go.crypto.aes.block-cipher-mode-encrypt
// TEST-METADATA: assetType=algorithm, findingType=cipher, operation=encrypt, algorithmPrimitive=block-cipher, algorithmName=AES-CFB, algorithmFamily=AES, library=crypto/cipher, api=cipher.NewCFBEncrypter, cipher=AES

package main

import (
	"crypto/aes"
	"crypto/cipher"
)

// Scenario: AES-CFB mode encrypter
func main() {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	plaintext := make([]byte, 100)

	block, _ := aes.NewCipher(key)
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(plaintext, plaintext)
}

