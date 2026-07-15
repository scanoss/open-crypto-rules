// TEST-RULE: go.crypto.aes.block-cipher-mode-decrypt
// TEST-METADATA: assetType=algorithm, findingType=cipher, operation=decrypt, algorithmPrimitive=block-cipher, algorithmName=AES-CFB, algorithmFamily=AES, library=crypto/cipher, api=cipher.NewCFBDecrypter, cipher=AES

package main

import (
	"crypto/aes"
	"crypto/cipher"
)

// Scenario: AES-CFB mode decrypter
func main() {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	plaintext := make([]byte, 100)

	block, _ := aes.NewCipher(key)
	cfbDec := cipher.NewCFBDecrypter(block, iv)
	cfbDec.XORKeyStream(plaintext, plaintext)
}

