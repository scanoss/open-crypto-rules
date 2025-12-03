// TEST-RULE: go.crypto.rand.usage
// TEST-METADATA: assetType=algorithm, findingType=rng, operation=other, algorithmPrimitive=drbg, algorithmName=CSPRNG, algorithmFamily=CSPRNG, library=crypto/rand, api=rand.Reader

package main

import (
	"crypto/rand"
)

// Scenario: crypto/rand.Reader short assignment - should match
func main() {
	r := rand.Reader
	_ = r
}

