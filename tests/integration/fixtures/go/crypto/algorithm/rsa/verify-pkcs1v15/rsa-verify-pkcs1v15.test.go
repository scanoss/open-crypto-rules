// TEST-RULE: go.crypto.rsa.verify-pkcs1v15
// TEST-METADATA: assetType=algorithm, findingType=signature, algorithmPrimitive=signature, algorithmName=RSA-PKCS1v15-SHA256, algorithmFamily=RSA, library=crypto/rsa, api=rsa.VerifyPKCS1v15

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

// Scenario: RSA verification with PKCS1v15
func main() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubKey := &key.PublicKey
	plaintext := []byte("test message")
	hashed := sha256.Sum256(plaintext)
	signature, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
	valid := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], signature)
	_ = valid
}
