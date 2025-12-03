// TEST-RULE: go.crypto.sha512.hash-usage-variant
// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, primitive=hash, algorithmName=SHA-512_256, algorithmFamily=SHA-2, parameterSetIdentifier=512_256, library=crypto/sha512, api=sha512.New512_256

package main

import (
	"crypto/sha512"
)

// Scenario: SHA-512/256 hash usage with New512_256()
func main() {
	hasher := sha512.New512_256()
	_ = hasher
}

