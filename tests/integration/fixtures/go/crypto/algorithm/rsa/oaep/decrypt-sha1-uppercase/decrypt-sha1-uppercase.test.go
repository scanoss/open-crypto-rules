// TEST-RULE: go.crypto.rsa.decrypt-oaep
// TEST-METADATA: assetType=algorithm, findingType=cipher, operation=decrypt, algorithmPrimitive=pke, algorithmName=RSA-OAEP-SHA1, algorithmFamily=RSA, library=crypto/rsa, api=rsa.DecryptOAEP

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

func main() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubKey := &key.PublicKey
	plaintext := []byte("test message")
	ciphertext, _ := rsa.EncryptOAEP(crypto.SHA1.New(), rand.Reader, pubKey, plaintext, nil)
	decrypted, _ := rsa.DecryptOAEP(crypto.SHA1.New(), rand.Reader, key, ciphertext, nil)
	_ = decrypted
}

