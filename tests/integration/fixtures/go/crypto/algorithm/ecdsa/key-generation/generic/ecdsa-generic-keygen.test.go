// TEST-RULE: go.crypto.ecdsa.key-generation
// TEST-METADATA: assetType=algorithm, findingType=key_generation, operation=keygen, algorithmPrimitive=signature, algorithmName=ECDSA-P256, algorithmFamily=ECDSA, library=crypto/ecdsa, api=ecdsa.GenerateKey, materialSource=generated

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

// Scenario: ECDSA key generation with variable curve
func main() {
	curve := elliptic.P256() // curve chosen at runtime
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	_ = key
}
