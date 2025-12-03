// TEST-RULE: go.crypto.sha3.hash-usage
// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, primitive=hash, algorithmName=SHA-3-384, algorithmFamily=SHA-3, parameterSetIdentifier=384, library=crypto/sha3, api=sha3.New384

package main

import (
	"crypto/sha3"
)

// Scenario: SHA-3-384 hash usage with New384()
func main() {
	hasher := sha3.New384()
	_ = hasher
}

