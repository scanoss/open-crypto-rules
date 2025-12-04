// TEST-RULE: go.crypto.sha512.hash-usage-variant
// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, algorithmPrimitive=hash, algorithmName=SHA-512, algorithmFamily=SHA-2, algorithmParameterSetIdentifier=512, library=crypto/sha512, api=sha512.Sum512

package main

import (
	"crypto/sha512"
)

// Scenario: SHA-512 hash usage with Sum512()
func main() {
	data := []byte("test message")
	hash := sha512.Sum512(data)
	_ = hash
}

