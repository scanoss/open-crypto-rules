// TEST-RULE: go.crypto.rsa.multi-prime-key-generation
// TEST-METADATA: assetType=algorithm, findingType=key_generation, operation=keygen, algorithmPrimitive=pke, algorithmName=RSA, algorithmFamily=RSA, library=crypto/rsa, api=rsa.GenerateMultiPrimeKey, materialSource=generated

package main

import (
	"crypto/rand"
	"crypto/rsa"
)

// Scenario: Multi-prime RSA key generation
func main() {
	key, _ := rsa.GenerateMultiPrimeKey(rand.Reader, 3, 2048)
	_ = key
}
