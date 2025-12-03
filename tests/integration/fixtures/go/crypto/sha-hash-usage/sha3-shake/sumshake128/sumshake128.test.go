// TEST-RULE: go.crypto.sha3.shake-usage
// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, primitive=xof, algorithmName=SHAKE128, algorithmFamily=SHA-3, parameterSetIdentifier=SHAKE128, library=crypto/sha3, api=sha3.SumSHAKE128

package main

import (
	"crypto/sha3"
)

// Scenario: SHAKE128 usage with SumSHAKE128()
func main() {
	data := []byte("test message")
	hash := sha3.SumSHAKE128(data, 16)
	_ = hash
}

