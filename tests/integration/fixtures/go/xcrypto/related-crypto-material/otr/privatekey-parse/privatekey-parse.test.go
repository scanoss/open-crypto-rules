// TEST-RULE: go.xcrypto.otr.privatekey-parse
// TEST-METADATA: assetType=related-crypto-material, findingType=key_generation, operation=other, materialType=private-key, library=golang.org/x/crypto/otr, api=otr.PrivateKey.Parse

package main

import (
	"golang.org/x/crypto/otr"
)

// Scenario: otr.PrivateKey.Parse() - should match
func main() {
	var privKey otr.PrivateKey
	keyData := []byte("key data")
	
	// Should match - otr.PrivateKey.Parse
	_, err := privKey.Parse(keyData)
	_ = err
}

