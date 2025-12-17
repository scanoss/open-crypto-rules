// TEST-RULE: go.crypto.rand.usage
// TEST-METADATA: assetType=algorithm, findingType=rng, operation=other, algorithmPrimitive=drbg, algorithmName=CSPRNG, algorithmFamily=CSPRNG, library=crypto/rand

// current matching to mathrand.Int() and it shouldn't, the api=rand.Read is api=rand.Int - leaving this here to note for later
package main

import (
	"crypto/rand"
	mathrand "math/rand"
)

func main() {
	// This should NOT match - uses math/rand
	n := mathrand.Int()
	_ = n

	// This SHOULD match - uses crypto/rand
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		println("broke")
	}
}

