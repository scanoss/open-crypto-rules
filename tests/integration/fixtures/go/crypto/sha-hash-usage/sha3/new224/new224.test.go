// TEST-RULE: go.crypto.sha3.hash-usage
// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, primitive=hash, algorithmName=SHA-3-224, algorithmFamily=SHA-3, parameterSetIdentifier=224, library=crypto/sha3, api=sha3.New224

package main

import (
	"crypto/sha3"
)

// Scenario: SHA-3-224 hash usage with New224()
func main() {
	hasher := sha3.New224()
	_ = hasher
}

