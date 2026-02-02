// TEST-RULE: go.crypto.ecdsa.key-generation
// TEST-METADATA: assetType=algorithm, findingType=key_generation, operation=keygen, algorithmPrimitive=signature, algorithmName=ECDSA-P384, algorithmFamily=ECDSA, library=crypto/ecdsa, api=ecdsa.GenerateKey, curve=P384, materialSource=generated, algorithmParameterSetIdentifier=384

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

// Scenario: ECDSA P384 key generation
func main() {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		panic(err)
	}
	_ = key
}
