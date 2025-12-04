// TEST-RULE: go.crypto.sha256.hash-usage-variant
// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, algorithmPrimitive=hash, algorithmName=SHA-256, algorithmFamily=SHA-2, algorithmParameterSetIdentifier=256, library=crypto/sha256, api=sha256.Sum256

package main

import (
	"crypto/sha256"
)

// Scenario: SHA-256 hash usage with Sum256()
func main() {
	data := []byte("test message")
	hash := sha256.Sum256(data)
	_ = hash
}

