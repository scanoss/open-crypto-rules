// TEST-RULE: go.crypto.dsa.parameter-generation
// TEST-METADATA: assetType=algorithm, findingType=key_generation, algorithmPrimitive=signature, algorithmName=DSA, algorithmFamily=DSA, algorithmParameterSetIdentifier=2048, library=crypto/dsa, api=dsa.GenerateParameters, materialSource=generated

package main

import (
	"crypto/dsa"
	"crypto/rand"
)

func main() {
	var params dsa.Parameters
	dsa.GenerateParameters(&params, rand.Reader, dsa.L2048N224)
	_ = params
}

