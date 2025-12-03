// TEST-RULE: go.crypto.rsa.decrypt-pkcs1v15
// TEST-METADATA: assetType=algorithm, findingType=cipher, operation=decrypt, algorithmPrimitive=pke, algorithmName=RSA-PKCS1v15, algorithmFamily=RSA, library=crypto/rsa, api=rsa.DecryptPKCS1v15

package main

import (
	"crypto/rand"
	"crypto/rsa"
)

func main() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	ciphertext := []byte("encrypted data")
	decrypted, _ := rsa.DecryptPKCS1v15(rand.Reader, key, ciphertext)
	_ = decrypted
}

