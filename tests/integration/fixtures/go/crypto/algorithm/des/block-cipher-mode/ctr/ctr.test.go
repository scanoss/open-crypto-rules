// TEST-RULE: go.crypto.des.block-cipher-mode-encrypt
// TEST-METADATA: assetType=algorithm, findingType=cipher, operation=encrypt, algorithmPrimitive=block-cipher, algorithmName=DES-CTR, algorithmFamily=DES, library=crypto/cipher, api=cipher.NewCTR, cipher=DES

package main

import (
	"crypto/cipher"
	"crypto/des"
)

// Scenario: DES-CTR mode
func main() {
	key := make([]byte, 8)
	iv := make([]byte, 8)
	plaintext := make([]byte, 100)

	block, _ := des.NewCipher(key)
	ctr := cipher.NewCTR(block, iv)
	ctr.XORKeyStream(plaintext, plaintext)
}

