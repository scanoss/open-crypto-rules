// TEST-RULE: go.crypto.rsa.decrypt-oaep
// TEST-METADATA: assetType=algorithm, findingType=cipher, operation=decrypt, algorithmPrimitive=pke, algorithmName=RSA-OAEP-$hash, algorithmFamily=RSA, library=crypto/rsa, api=rsa.DecryptOAEP

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
	decrypted, _ := rsa.DecryptOAEP(hashFunc, rand.Reader, key, ciphertext, nil)
	_ = decrypted
}

