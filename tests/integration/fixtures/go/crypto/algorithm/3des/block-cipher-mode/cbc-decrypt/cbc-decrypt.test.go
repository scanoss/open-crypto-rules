// TEST-RULE: go.crypto.3des.block-cipher-mode-decrypt
// TEST-METADATA: assetType=algorithm, findingType=cipher, operation=decrypt, algorithmPrimitive=block-cipher, algorithmName=3DES-CBC, algorithmFamily=3DES, library=crypto/cipher, api=cipher.NewCBCDecrypter, cipher=3DES

package main

import (
	"crypto/cipher"
	"crypto/des"
)

// Scenario: 3DES-CBC mode decrypter
func main() {
	key := make([]byte, 24)
	iv := make([]byte, 8)
	plaintext := make([]byte, 100)

	block, _ := des.NewTripleDESCipher(key)
	cbcDec := cipher.NewCBCDecrypter(block, iv)
	cbcDec.CryptBlocks(plaintext, plaintext)
}

