// TEST-RULE: go.crypto.ecdsa.key-generation
// TEST-METADATA: assetType=algorithm, findingType=key_generation, operation=keygen, algorithmPrimitive=signature, algorithmName=ECDSA-P521, algorithmFamily=ECDSA, library=crypto/ecdsa, api=ecdsa.GenerateKey, curve=P521, materialSource=generated, algorithmParameterSetIdentifier=521

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

// Scenario: ECDSA P521 key generation
func main() {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
	_ = key
}
