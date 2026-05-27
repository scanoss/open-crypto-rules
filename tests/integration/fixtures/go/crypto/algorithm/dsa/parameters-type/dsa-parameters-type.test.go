// TEST-RULE: go.crypto.dsa.parameters-type
// TEST-METADATA: assetType=algorithm, findingType=key_generation, algorithmPrimitive=signature, algorithmName=DSA, algorithmFamily=DSA, library=crypto/dsa, api=dsa.Parameters

package main

import (
	"crypto/dsa"
)

// Scenario: DSA parameters type declaration
func main() {
	var params dsa.Parameters
	_ = params
}
