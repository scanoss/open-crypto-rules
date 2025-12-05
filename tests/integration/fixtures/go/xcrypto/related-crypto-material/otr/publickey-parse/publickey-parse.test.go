// TEST-RULE: go.xcrypto.otr.publickey-parse
// TEST-METADATA: assetType=related-crypto-material, findingType=key_generation, operation=other, materialType=public-key, library=golang.org/x/crypto/otr, api=otr.PublicKey.Parse

package main

import (
	"golang.org/x/crypto/otr"
)

// Scenario: otr.PublicKey.Parse() - should match
func main() {
	var pubKey otr.PublicKey
	keyData := []byte("key data")
	
	// Should match - otr.PublicKey.Parse
	_, err := pubKey.Parse(keyData)
	_ = err
}

