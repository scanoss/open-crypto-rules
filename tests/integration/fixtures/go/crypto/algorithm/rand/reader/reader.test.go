// TEST-RULE: go.crypto.rand.usage
// TEST-METADATA: assetType=algorithm, findingType=rng, operation=other, algorithmPrimitive=drbg, algorithmName=CSPRNG, algorithmFamily=CSPRNG, library=crypto/rand, api=rand.Reader

package main

import (
	"crypto/rand"
	"io"
)

// Scenario: crypto/rand.Reader assignment - should match
func main() {
	var r io.Reader = rand.Reader
	_ = r
}

