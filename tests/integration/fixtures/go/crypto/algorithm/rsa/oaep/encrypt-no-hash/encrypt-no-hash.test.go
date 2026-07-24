// TEST-RULE: go.crypto.rsa.encrypt-oaep
// TEST-METADATA: assetType=algorithm, findingType=cipher, operation=encrypt, algorithmPrimitive=pke, algorithmName=RSA-OAEP-$hash, algorithmFamily=RSA, library=crypto/rsa, api=rsa.EncryptOAEP

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"hash"
)

func main() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubKey := &key.PublicKey
	plaintext := []byte("test message")
	var hashFunc hash.Hash
	ciphertext, _ := rsa.EncryptOAEP(hashFunc, rand.Reader, pubKey, plaintext, nil)
	_ = ciphertext
}

