// TEST-RULE: go.crypto.3des.block-cipher-mode-encrypt
// TEST-METADATA: assetType=algorithm, findingType=cipher, operation=encrypt, algorithmPrimitive=block-cipher, algorithmName=3DES-OFB, algorithmFamily=3DES, library=crypto/cipher, api=cipher.NewOFB, cipher=3DES

package main

import (
	"crypto/cipher"
	"crypto/des"
)

// Scenario: 3DES-OFB mode
func main() {
	key := make([]byte, 24)
	iv := make([]byte, 8)
	plaintext := make([]byte, 100)

	block, _ := des.NewTripleDESCipher(key)
	ofb := cipher.NewOFB(block, iv)
	ofb.XORKeyStream(plaintext, plaintext)
}

