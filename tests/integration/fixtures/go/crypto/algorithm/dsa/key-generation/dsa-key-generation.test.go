// TEST-RULE: go.crypto.dsa.key-generation
// TEST-METADATA: assetType=algorithm, findingType=key_generation, operation=keygen, algorithmPrimitive=signature, algorithmName=DSA, algorithmFamily=DSA, library=crypto/dsa, api=dsa.GenerateKey, materialSource=generated

package main

import (
	"crypto/dsa"
	"crypto/rand"
)

// Scenario: DSA key generation
func main() {
	var params dsa.Parameters
	dsa.GenerateParameters(&params, rand.Reader, dsa.L2048N256)
	var privKey dsa.PrivateKey
	privKey.PublicKey.Parameters = params
	dsa.GenerateKey(&privKey, rand.Reader)
	_ = privKey
}
