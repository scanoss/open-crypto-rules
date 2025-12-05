// TEST-RULE: go.crypto.rsa.encrypt-pkcs1v15
// TEST-METADATA: assetType=algorithm, findingType=cipher, operation=encrypt, algorithmPrimitive=pke, algorithmName=RSA-PKCS1v15, algorithmFamily=RSA, library=crypto/rsa, api=rsa.EncryptPKCS1v15

package main

import (
	"crypto/rand"
	"crypto/rsa"
)

func main() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubKey := &key.PublicKey
	plaintext := []byte("test message")
	ciphertext, _ := rsa.EncryptPKCS1v15(rand.Reader, pubKey, plaintext)
	_ = ciphertext
}

