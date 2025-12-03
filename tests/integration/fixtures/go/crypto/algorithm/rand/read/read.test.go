// TEST-RULE: go.crypto.rand.usage
// TEST-METADATA: assetType=algorithm, findingType=rng, operation=other, algorithmPrimitive=drbg, algorithmName=CSPRNG, algorithmFamily=CSPRNG, library=crypto/rand, api=rand.Read

package main

import (
	"crypto/rand"
)

// Scenario: crypto/rand.Read() - should match
func main() {
	b := make([]byte, 32)
	rand.Read(b)
}

