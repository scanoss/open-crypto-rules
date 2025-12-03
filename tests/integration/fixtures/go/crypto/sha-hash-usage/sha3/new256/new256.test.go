// TEST-RULE: go.crypto.sha3.hash-usage
// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, primitive=hash, algorithmName=SHA-3-256, algorithmFamily=SHA-3, parameterSetIdentifier=256, library=crypto/sha3, api=sha3.New256

package main

import (
	"crypto/sha3"
)

// Scenario: SHA-3-256 hash usage with New256()
func main() {
	hasher := sha3.New256()
	_ = hasher
}

