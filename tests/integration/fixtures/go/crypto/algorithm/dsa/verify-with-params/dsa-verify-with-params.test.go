// TEST-RULE: go.crypto.dsa.verify-with-params
// TEST-METADATA: assetType=algorithm, findingType=signature, operation=verify, algorithmPrimitive=signature, algorithmName=DSA, algorithmFamily=DSA, library=crypto/dsa, api=dsa.Verify

package main

import (
	"crypto/dsa"
	"crypto/rand"
)

// Scenario: DSA verification with params
func main() {
	var params dsa.Parameters
	dsa.GenerateParameters(&params, rand.Reader, dsa.L2048N256)
	var privKey dsa.PrivateKey
	privKey.PublicKey.Parameters = params
	dsa.GenerateKey(&privKey, rand.Reader)
	pubKey := &privKey.PublicKey
	hash := []byte("test message")
	r, s, _ := dsa.Sign(rand.Reader, &privKey, hash)
	valid := dsa.Verify(pubKey, hash, r, s)
	_ = valid
}
