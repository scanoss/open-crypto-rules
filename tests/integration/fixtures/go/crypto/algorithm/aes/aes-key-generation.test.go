// TEST-RULE: go.crypto.aes.key-generation
// TEST-METADATA: algorithmFamily=AES, library=crypto/aes, api=aes.NewCipher, algorithmParameterSetIdentifier=32

package main

import (
	"crypto/aes"
)

func main() {
	// Test AES key generation with 32-byte key (AES-256)
	key := make([]byte, 32)
	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	_ = cipher
}
