// TEST-RULE: go.crypto.sha3.hash-usage
// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, primitive=hash, algorithmName=SHA-3-512, algorithmFamily=SHA-3, parameterSetIdentifier=512, library=crypto/sha3, api=sha3.New512

package main

import (
	"crypto/sha3"
)

// Scenario: SHA-3-512 hash usage with New512()
func main() {
	hasher := sha3.New512()
	_ = hasher
}

