// TEST-RULE: go.crypto.rand.usage
// TEST-METADATA: assetType=algorithm, findingType=rng, operation=other, algorithmPrimitive=drbg, algorithmName=CSPRNG, algorithmFamily=CSPRNG, library=crypto/rand, api=rand.Int

package main

import (
	"crypto/rand"
	"math/big"
)

// Scenario: crypto/rand.Int() - should match
func main() {
	max := big.NewInt(100)
	serialNumber, _ := rand.Int(rand.Reader, max)
	_ = serialNumber
}

