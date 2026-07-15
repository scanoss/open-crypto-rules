// TEST-RULE: go.crypto.aes.key-generation
// TEST-METADATA: assetType=algorithm, findingType=key_generation, operation=keygen, algorithmPrimitive=block-cipher, algorithmName=AES, algorithmFamily=AES, library=crypto/aes, api=aes.NewCipher, materialSource=generated

package main

import (
	"crypto/aes"
)

func main() {
	key := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	block, _ := aes.NewCipher(key)
	_ = block
}

