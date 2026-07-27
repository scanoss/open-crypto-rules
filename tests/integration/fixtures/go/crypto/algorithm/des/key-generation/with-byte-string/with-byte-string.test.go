// TEST-RULE: go.crypto.des.key-generation
// TEST-METADATA: assetType=algorithm, findingType=key_generation, operation=keygen, algorithmPrimitive=block-cipher, algorithmName=DES, algorithmFamily=DES, algorithmParameterSetIdentifier=56, library=crypto/des, api=des.NewCipher, materialSource=generated

package main

import (
	"crypto/des"
)

func main() {
	keyStr := "12345678"
	block, _ := des.NewCipher([]byte(keyStr))
	_ = block
}

