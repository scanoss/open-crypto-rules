// TEST-RULE: go.crypto.dsa.key-type
// TEST-METADATA: assetType=algorithm, findingType=key_generation, algorithmPrimitive=signature, algorithmName=DSA, algorithmFamily=DSA, library=crypto/dsa, api=dsa.Private

package main

import (
	"crypto/dsa"
)

// Scenario: DSA key type declarations
func main() {
	var privKey dsa.PrivateKey
	_ = privKey
}
