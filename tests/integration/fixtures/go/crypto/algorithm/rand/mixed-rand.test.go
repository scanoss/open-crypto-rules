// TEST-RULE: go.crypto.rand.usage
// TEST-METADATA: assetType=algorithm, findingType=rng, operation=other, algorithmPrimitive=drbg, algorithmName=CSPRNG, algorithmFamily=CSPRNG, library=crypto/rand, api=rand.Read

package main

import (
	"crypto/rand"
	mathrand "math/rand"
)

// Scenario: Mixed math/rand and crypto/rand usage
// Line 15: mathrand.Intn() - should NOT match (uses math/rand)
// Line 18: rand.Read() - should match (uses crypto/rand)
func main() {
	// This should NOT match - uses math/rand
	n := mathrand.Intn(100)
	_ = n

	// This SHOULD match - uses crypto/rand
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		println("broke")
	}
}

