// TEST-RULE: go.crypto.des.key-generation
// TEST-METADATA: assetType=algorithm, findingType=key_generation, operation=keygen, algorithmPrimitive=block-cipher, algorithmName=DES, algorithmFamily=DES, algorithmParameterSetIdentifier=56, library=crypto/des, api=des.NewCipher, materialSource=generated

package main

import (
	"crypto/des"
)

func main() {
	key := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	block, _ := des.NewCipher(key)
	_ = block
}

