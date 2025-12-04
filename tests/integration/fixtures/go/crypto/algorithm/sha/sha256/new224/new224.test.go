// TEST-RULE: go.crypto.sha256.hash-usage-variant
// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, algorithmPrimitive=hash, algorithmName=SHA-224, algorithmFamily=SHA-2, algorithmParameterSetIdentifier=224, library=crypto/sha256, api=sha256.New224

package main

import (
	"crypto/sha256"
)

// Scenario: SHA-224 hash usage with New224()
func main() {
	hasher := sha256.New224()
	_ = hasher
}

