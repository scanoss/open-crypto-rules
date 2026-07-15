// TEST-RULE: go.crypto.rsa.verify-pss
// TEST-METADATA: assetType=algorithm, findingType=signature, algorithmPrimitive=signature, algorithmName=RSA-PSS-SHA256, algorithmFamily=RSA, library=crypto/rsa, api=rsa.VerifyPSS

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

// Scenario: RSA verification with PSS
func main() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubKey := &key.PublicKey
	plaintext := []byte("test message")
	hashed := sha256.Sum256(plaintext)
	pssOpts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	}
	signature, _ := rsa.SignPSS(rand.Reader, key, crypto.SHA256, hashed[:], pssOpts)
	valid := rsa.VerifyPSS(pubKey, crypto.SHA256, hashed[:], signature, pssOpts)
	_ = valid
}
