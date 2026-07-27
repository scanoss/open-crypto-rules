// TEST-RULE: go.crypto.rsa.encrypt-oaep
// TEST-METADATA: assetType=algorithm, findingType=cipher, operation=encrypt, algorithmPrimitive=pke, algorithmName=RSA-OAEP-md5, algorithmFamily=RSA, library=crypto/rsa, api=rsa.EncryptOAEP

package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
)

func main() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubKey := &key.PublicKey
	plaintext := []byte("test message")
	ciphertext, _ := rsa.EncryptOAEP(md5.New(), rand.Reader, pubKey, plaintext, nil)
	_ = ciphertext
}

