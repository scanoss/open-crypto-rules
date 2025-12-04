// TEST-RULE: go.crypto.sha256.hash-usage
// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, algorithmPrimitive=hash, algorithmName=SHA-256, algorithmFamily=SHA-2, algorithmParameterSetIdentifier=256, library=crypto/sha256, api=sha256.New

package main

import (
	"crypto/sha256"
)

// Scenario: SHA-256 hash usage with New()
func main() {
	hasher := sha256.New()
	_ = hasher
}

