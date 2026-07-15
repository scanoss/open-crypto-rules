// TEST-RULE: go.crypto.3des.key-generation
// TEST-METADATA: assetType=algorithm, findingType=key_generation, operation=keygen, algorithmPrimitive=block-cipher, algorithmName=3DES, algorithmFamily=3DES, algorithmParameterSetIdentifier=168, library=crypto/des, api=des.NewTripleDESCipher, materialSource=generated

package main

import (
	"crypto/des"
)

// Scenario: 3DES key generation
func main() {
	key := make([]byte, 24)
	block, _ := des.NewTripleDESCipher(key)
	_ = block
}

