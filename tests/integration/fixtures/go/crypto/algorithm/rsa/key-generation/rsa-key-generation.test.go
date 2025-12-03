// TEST-RULE: go.crypto.rsa.key-generation
// TEST-METADATA: assetType=algorithm, findingType=key_generation, operation=keygen, algorithmPrimitive=pke, algorithmName=RSA, algorithmFamily=RSA, library=crypto/rsa, api=rsa.GenerateKey, materialSource=generated

package main

import (
	"crypto/rand"
	"crypto/rsa"
)

// Scenario: RSA key generation
func main() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	_ = key
}
