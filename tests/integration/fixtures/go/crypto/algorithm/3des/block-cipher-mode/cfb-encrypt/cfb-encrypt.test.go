// TEST-RULE: go.crypto.3des.block-cipher-mode-encrypt
// TEST-METADATA: assetType=algorithm, findingType=cipher, operation=encrypt, algorithmPrimitive=block-cipher, algorithmName=3DES-CFB, algorithmFamily=3DES, library=crypto/cipher, api=cipher.NewCFBEncrypter, cipher=3DES

package main

import (
	"crypto/cipher"
	"crypto/des"
)

// Scenario: 3DES-CFB mode encrypter
func main() {
	key := make([]byte, 24)
	iv := make([]byte, 8)
	plaintext := make([]byte, 100)

	block, _ := des.NewTripleDESCipher(key)
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(plaintext, plaintext)
}

