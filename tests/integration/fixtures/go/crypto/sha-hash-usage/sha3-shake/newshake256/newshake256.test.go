// TEST-RULE: go.crypto.sha3.shake-usage
// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, primitive=xof, algorithmName=SHAKE256, algorithmFamily=SHA-3, parameterSetIdentifier=SHAKE256, library=crypto/sha3, api=sha3.NewSHAKE256

package main

import (
	"crypto/sha3"
)

// Scenario: SHAKE256 usage with NewSHAKE256()
func main() {
	shake := sha3.NewSHAKE256()
	_ = shake
}

