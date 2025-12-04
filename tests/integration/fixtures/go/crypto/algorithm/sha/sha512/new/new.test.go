// TEST-RULE: go.crypto.sha512.hash-usage
// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, algorithmPrimitive=hash, algorithmName=SHA-512, algorithmFamily=SHA-2, algorithmParameterSetIdentifier=512, library=crypto/sha512, api=sha512.New

package main

import (
	"crypto/sha512"
)

// Scenario: SHA-512 hash usage with New() - should default to variant 512
func main() {
	hasher := sha512.New()
	_ = hasher
}

