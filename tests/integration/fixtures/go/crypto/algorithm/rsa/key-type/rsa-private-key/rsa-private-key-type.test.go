// TEST-RULE: go.crypto.rsa.key-type
// TEST-METADATA: assetType=algorithm, findingType=key_generation, operation=keygen, algorithmPrimitive=pke, algorithmName=RSA, algorithmFamily=RSA, library=crypto/rsa, api=rsa.Private

package main

import (
	"crypto/rsa"
)

// Scenario: RSA key type declarations
func main() {
	var privKey *rsa.PrivateKey
	_ = privKey
}
