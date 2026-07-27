// TEST-RULE: go.crypto.aes.key-generation
// TEST-METADATA: assetType=algorithm, findingType=key_generation, operation=keygen, algorithmPrimitive=block-cipher, algorithmName=AES, algorithmFamily=AES, library=crypto/aes, api=aes.NewCipher, materialSource=generated

package main

import (
	"crypto/aes"
)

// Scenario: AES key generation with 256-bit (32-byte) key
func main() {
	key := make([]byte, 32)
	block, _ := aes.NewCipher(key)
	_ = block
}

