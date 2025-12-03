// TEST-RULE: go.crypto.sha3.hash-usage
// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, primitive=hash, algorithmName=SHA-3-512, algorithmFamily=SHA-3, parameterSetIdentifier=512, library=crypto/sha3, api=sha3.Sum512

package main

import (
	"crypto/sha3"
)

// Scenario: SHA-3-512 hash usage with Sum512()
func main() {
	data := []byte("test message")
	hash := sha3.Sum512(data)
	_ = hash
}

