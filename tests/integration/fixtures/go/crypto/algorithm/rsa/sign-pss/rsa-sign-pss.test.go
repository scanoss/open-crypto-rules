// TEST-RULE: go.crypto.rsa.sign-pss
// TEST-METADATA: assetType=algorithm, findingType=signature, operation=sign, algorithmPrimitive=signature, algorithmName=RSA-PSS-SHA256, algorithmFamily=RSA, library=crypto/rsa, api=rsa.SignPSS

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

// Scenario: RSA signing with PSS
func main() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	plaintext := []byte("test message")
	hashed := sha256.Sum256(plaintext)
	pssOpts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	}
	signature, _ := rsa.SignPSS(rand.Reader, key, crypto.SHA256, hashed[:], pssOpts)
	_ = signature
}
