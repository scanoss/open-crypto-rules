// TEST-RULE: go.crypto.rand.usage
// TEST-METADATA: assetType=algorithm, findingType=rng, operation=other, algorithmPrimitive=drbg, algorithmName=CSPRNG, algorithmFamily=CSPRNG, library=crypto/rand, api=rand.Text

package main

import (
	"crypto/rand"
)

// Scenario: rand.Text()
func main() {
	_ = rand.Text()
}

