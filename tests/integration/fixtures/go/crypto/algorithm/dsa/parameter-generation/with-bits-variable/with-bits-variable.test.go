// TEST-RULE: go.crypto.dsa.parameter-generation
// TEST-METADATA: assetType=algorithm, findingType=key_generation, operation=keygen, algorithmPrimitive=signature, algorithmName=DSA, algorithmFamily=DSA, library=crypto/dsa, api=dsa.GenerateParameters, materialSource=generated

package main

import (
	"crypto/dsa"
	"crypto/rand"
)

func main() {
	var params dsa.Parameters
	bits := dsa.L2048N256
	dsa.GenerateParameters(&params, rand.Reader, bits)
	_ = params
}

