// TEST-RULE: go.crypto.sha3.shake-usage
// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, algorithmPrimitive=xof, algorithmName=SHAKE256, algorithmFamily=SHA-3, algorithmParameterSetIdentifier=SHAKE256, library=crypto/sha3, api=sha3.SumSHAKE256

package main

import (
	"crypto/sha3"
)

// Scenario: SHAKE256 usage with SumSHAKE256()
func main() {
	data := []byte("test message")
	hash := sha3.SumSHAKE256(data, 32)
	_ = hash
}
