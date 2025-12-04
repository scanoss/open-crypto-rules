// TEST-RULE: go.crypto.sha512.hash-usage-variant
// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, algorithmPrimitive=hash, algorithmName=SHA-512_224, algorithmFamily=SHA-2, algorithmParameterSetIdentifier=512_224, library=crypto/sha512, api=sha512.New512_224

package main

import (
	"crypto/sha512"
)

// Scenario: SHA-512 hash usage with New512()
func main() {
	hasher := sha512.New512_224()
	_ = hasher
}
