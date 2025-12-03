// TEST-RULE: go.crypto.sha256.hash-usage-variant
// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, primitive=hash, algorithmName=SHA-224, algorithmFamily=SHA-2, parameterSetIdentifier=224, library=crypto/sha256, api=sha256.Sum224

package main

import (
	"crypto/sha256"
)

// Scenario: SHA-224 hash usage with Sum224()
func main() {
	data := []byte("test message")
	hash := sha256.Sum224(data)
	_ = hash
}

