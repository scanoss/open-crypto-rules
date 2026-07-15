// TEST-RULE: go.crypto.rsa.encrypt-oaep
// TEST-METADATA: assetType=algorithm, findingType=cipher, operation=encrypt, algorithmPrimitive=pke, algorithmName=RSA-OAEP-sha512, algorithmFamily=RSA, library=crypto/rsa, api=rsa.EncryptOAEP

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
)

func main() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubKey := &key.PublicKey
	plaintext := []byte("test message")
	ciphertext, _ := rsa.EncryptOAEP(sha512.New(), rand.Reader, pubKey, plaintext, nil)
	_ = ciphertext
}

