// TEST-RULE: go.crypto.des.block-cipher-mode-encrypt
// TEST-METADATA: assetType=algorithm, findingType=cipher, operation=encrypt, algorithmPrimitive=block-cipher, algorithmName=DES-OFB, algorithmFamily=DES, library=crypto/cipher, api=cipher.NewOFB, cipher=DES

package main

import (
	"crypto/cipher"
	"crypto/des"
)

// Scenario: DES-OFB mode
func main() {
	key := make([]byte, 8)
	iv := make([]byte, 8)
	plaintext := make([]byte, 100)

	block, _ := des.NewCipher(key)
	ofb := cipher.NewOFB(block, iv)
	ofb.XORKeyStream(plaintext, plaintext)
}

