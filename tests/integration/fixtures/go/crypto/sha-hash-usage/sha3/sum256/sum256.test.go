// TEST-RULE: go.crypto.sha3.hash-usage
// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, algorithmPrimitive=hash, algorithmName=SHA-3-256, algorithmFamily=SHA-3, algorithmParameterSetIdentifier=256, library=crypto/sha3, api=sha3.Sum256

package main

import (
	"crypto/sha3"
)

// Scenario: SHA-3-256 hash usage with Sum256()
func main() {
	data := []byte("test message")
	hash := sha3.Sum256(data)
	_ = hash
}

