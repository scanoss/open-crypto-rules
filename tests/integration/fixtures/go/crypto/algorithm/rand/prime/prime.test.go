// TEST-RULE: go.crypto.rand.usage
// TEST-METADATA: assetType=algorithm, findingType=rng, operation=other, algorithmPrimitive=drbg, algorithmName=CSPRNG, algorithmFamily=CSPRNG, library=crypto/rand, api=rand.Prime

package main

import (
	"crypto/rand"
)

// Scenario: crypto/rand.Prime() - should match
func main() {
	p, _ := rand.Prime(rand.Reader, 256)
	_ = p
}

