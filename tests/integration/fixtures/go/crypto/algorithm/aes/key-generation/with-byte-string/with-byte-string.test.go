// TEST-RULE: go.crypto.aes.key-generation
// TEST-METADATA: assetType=algorithm, findingType=key_generation, operation=keygen, algorithmPrimitive=block-cipher, algorithmName=AES, algorithmFamily=AES, library=crypto/aes, api=aes.NewCipher, materialSource=generated

package main

import (
	"crypto/aes"
)

func main() {
	keyStr := "1234567890123456"
	block, _ := aes.NewCipher([]byte(keyStr))
	_ = block
}

