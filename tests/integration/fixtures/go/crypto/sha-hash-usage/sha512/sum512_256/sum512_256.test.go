// TEST-RULE: go.crypto.sha512.hash-usage-variant
// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, algorithmPrimitive=hash, algorithmName=SHA-512_256, algorithmFamily=SHA-2, algorithmParameterSetIdentifier=512_256, library=crypto/sha512, api=sha512.Sum512_256

package main

import (
	"crypto/sha512"
)

// Scenario: SHA-512/256 hash usage with Sum512_256()
func main() {
	data := []byte("test message")
	hash := sha512.Sum512_256(data)
	_ = hash
}

