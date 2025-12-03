// TEST-RULE: go.crypto.sha1.hash-usage
// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, primitive=hash, algorithmName=SHA-1, algorithmFamily=SHA-1, parameterSetIdentifier=160, library=crypto/sha1, api=sha1.New

package main

import (
	"crypto/sha1"
)

// Scenario: SHA-1 hash usage with New()
func main() {
	hasher := sha1.New()
	_ = hasher
}

