// TEST-RULE: go.crypto.rand.usage
// TEST-METADATA: assetType=algorithm, findingType=rng, operation=other, algorithmPrimitive=drbg, algorithmName=CSPRNG, algorithmFamily=CSPRNG, library=crypto/rand, api=rand.Reader

package main

import (
	"crypto/rand"
	"io"
)

// Scenario: io.ReadFull(rand.Reader, ...) - should match
func main() {
	b := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		println("broke")
	}
}

