// TEST-RULE: go.crypto.dsa.sign-with-params
// TEST-METADATA: assetType=algorithm, findingType=signature, operation=sign, algorithmPrimitive=signature, algorithmName=DSA, algorithmFamily=DSA, library=crypto/dsa, api=dsa.Sign

package main

import (
	"crypto/dsa"
	"crypto/rand"
)

// Scenario: DSA signing with params
func main() {
	var params dsa.Parameters
	dsa.GenerateParameters(&params, rand.Reader, dsa.L2048N256)
	var privKey dsa.PrivateKey
	privKey.PublicKey.Parameters = params
	dsa.GenerateKey(&privKey, rand.Reader)
	hash := []byte("test message")
	r, s, _ := dsa.Sign(rand.Reader, &privKey, hash)
	_ = r
	_ = s
}
