// TEST-RULE: go.crypto.3des.block-cipher-mode-encrypt
// TEST-METADATA: assetType=algorithm, findingType=cipher, operation=encrypt, algorithmPrimitive=block-cipher, algorithmName=3DES-CBC, algorithmFamily=3DES, library=crypto/cipher, api=cipher.NewCBCEncrypter, cipher=3DES

package main

import (
	"crypto/cipher"
	"crypto/des"
)

// Scenario: 3DES-CBC mode encrypter
func main() {
	key := make([]byte, 24)
	iv := make([]byte, 8)
	plaintext := make([]byte, 100)

	block, _ := des.NewTripleDESCipher(key)
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(plaintext, plaintext)
}

