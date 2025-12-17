package bn256_test

import (
	"golang.org/x/crypto/bn256"
)

// TEST-RULE: go.xcrypto.bn256.pairing
// TEST-METADATA: operation:keyexchange findingType:key_exchange api:bn256.Pair
func testPair() {
	g1 := new(bn256.G1)
	g2 := new(bn256.G2)
	
	// ruleid: go.xcrypto.bn256.pairing
	result := bn256.Pair(g1, g2)
	_ = result
}
