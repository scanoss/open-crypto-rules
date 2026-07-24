// TEST-RULE: go.crypto.3des.key-generation
// TEST-METADATA: assetType=algorithm, findingType=key_generation, operation=keygen, algorithmPrimitive=block-cipher, algorithmName=3DES, algorithmFamily=3DES, algorithmParameterSetIdentifier=168, library=crypto/des, api=des.NewTripleDESCipher, materialSource=generated

package main

import (
	"crypto/des"
)

func main() {
	key := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17}
	block, _ := des.NewTripleDESCipher(key)
	_ = block
}

