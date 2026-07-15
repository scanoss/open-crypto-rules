// TEST-RULE: go.crypto.rsa.key-type
// TEST-METADATA: assetType=algorithm, findingType=key_generation, algorithmPrimitive=pke, algorithmName=RSA, algorithmFamily=RSA, library=crypto/rsa, api=rsa.Public

package main

import (
	"crypto/rsa"
)

// Scenario: RSA key type declarations
func main() {
	var pubKey *rsa.PublicKey
	_ = pubKey
}
