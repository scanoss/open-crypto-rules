// TEST-RULE: go.crypto.ecdsa.key-generation
// TEST-METADATA: assetType=algorithm, findingType=key_generation, operation=keygen, algorithmPrimitive=signature, algorithmName=ECDSA-P224, algorithmFamily=ECDSA, library=crypto/ecdsa, api=ecdsa.GenerateKey, curve=P224, materialSource=generated, algorithmParameterSetIdentifier=224

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

// Scenario: ECDSA P224 key generation
func main() {
	key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		panic(err)
	}
	_ = key
}
