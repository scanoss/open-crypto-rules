// TEST-RULE: go.crypto.aes.block-cipher-mode-decrypt
// TEST-METADATA: assetType=algorithm, findingType=cipher, operation=decrypt, algorithmPrimitive=block-cipher, algorithmName=AES-CBC, algorithmFamily=AES, library=crypto/cipher, api=cipher.NewCBCDecrypter, cipher=AES

package main

import (
	"crypto/aes"
	"crypto/cipher"
)

// Scenario: AES-CBC mode decrypter
func main() {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	plaintext := make([]byte, 100)

	block, _ := aes.NewCipher(key)
	cbcDec := cipher.NewCBCDecrypter(block, iv)
	cbcDec.CryptBlocks(plaintext, plaintext)
}

