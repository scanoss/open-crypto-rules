// TEST-RULE: go.crypto.sha512.hash-usage-variant
// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, primitive=hash, algorithmName=SHA-384, algorithmFamily=SHA-2, parameterSetIdentifier=384, library=crypto/sha512, api=sha512.Sum384

package main

import (
	"crypto/sha512"
)

// Scenario: SHA-384 hash usage with Sum384()
func main() {
	data := []byte("test message")
	hash := sha512.Sum384(data)
	_ = hash
}

