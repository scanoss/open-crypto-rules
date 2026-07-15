// TEST-RULE: go.crypto.des.block-cipher-mode-decrypt
// TEST-METADATA: assetType=algorithm, findingType=cipher, operation=decrypt, algorithmPrimitive=block-cipher, algorithmName=DES-CFB, algorithmFamily=DES, library=crypto/cipher, api=cipher.NewCFBDecrypter, cipher=DES

package main

import (
	"crypto/cipher"
	"crypto/des"
)

// Scenario: DES-CFB mode decrypter
func main() {
	key := make([]byte, 8)
	iv := make([]byte, 8)
	plaintext := make([]byte, 100)

	block, _ := des.NewCipher(key)
	cfbDec := cipher.NewCFBDecrypter(block, iv)
	cfbDec.XORKeyStream(plaintext, plaintext)
}

