// TEST-RULE: go.crypto.ecdsa.key-generation
// TEST-METADATA: assetType=algorithm, findingType=key_generation, operation=keygen, algorithmPrimitive=signature, algorithmName=ECDSA-P256, algorithmFamily=ECDSA, library=crypto/ecdsa, api=ecdsa.GenerateKey, curve=P256, materialSource=generated, algorithmParameterSetIdentifier=256

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

// Scenario: ECDSA P256 key generation
func main() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	_ = key
}
