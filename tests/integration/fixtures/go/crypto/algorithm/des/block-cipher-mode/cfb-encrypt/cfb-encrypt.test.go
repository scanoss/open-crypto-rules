// TEST-RULE: go.crypto.des.block-cipher-mode-encrypt
// TEST-METADATA: assetType=algorithm, findingType=cipher, operation=encrypt, algorithmPrimitive=block-cipher, algorithmName=DES-CFB, algorithmFamily=DES, library=crypto/cipher, api=cipher.NewCFBEncrypter, cipher=DES

package main

import (
	"crypto/cipher"
	"crypto/des"
)

// Scenario: DES-CFB mode encrypter
func main() {
	key := make([]byte, 8)
	iv := make([]byte, 8)
	plaintext := make([]byte, 100)

	block, _ := des.NewCipher(key)
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(plaintext, plaintext)
}

