package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

// TEST-RULE: go.crypto.x509.pkix-public-key
// TEST-METADATA: assetType:related-crypto-material findingType:key_generation operation:keygen materialType:public-key library:crypto/x509 api:x509.ParsePKIXPublicKey
func testParsePKIXPublicKey() {
	derBytes := []byte{}
	// ruleid: go.crypto.x509.pkix-public-key
	_, err := x509.ParsePKIXPublicKey(derBytes)
	_ = err
}

// TEST-RULE: go.crypto.x509.pkix-public-key
// TEST-METADATA: assetType:related-crypto-material findingType:key_generation operation:keygen materialType:public-key library:crypto/x509 api:x509.MarshalPKIXPublicKey
func testMarshalPKIXPublicKey() {
	pubKey := getRsaKey().Public()
	// ruleid: go.crypto.x509.pkix-public-key
	derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	_ = derBytes
	_ = err
}

// TEST-RULE: go.crypto.x509.parse-pkcs8-private-key
// TEST-METADATA: assetType:related-crypto-material findingType:key_generation operation:keygen materialType:private-key library:crypto/x509 api:x509.ParsePKCS8PrivateKey
func testParsePKCS8PrivateKey() {
	derBytes := []byte{}
	// ruleid: go.crypto.x509.parse-pkcs8-private-key
	_, err := x509.ParsePKCS8PrivateKey(derBytes)
	_ = err
}

// TEST-RULE: go.crypto.x509.parse-pkcs8-private-key
// TEST-METADATA: assetType:related-crypto-material findingType:key_generation operation:keygen materialType:private-key library:crypto/x509 api:x509.MarshalPKCS8PrivateKey
func testMarshalPKCS8PrivateKey() {
	privKey := getRsaKey()
	// ruleid: go.crypto.x509.parse-pkcs8-private-key
	derBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	_ = derBytes
	_ = err
}

// TEST-RULE: go.crypto.x509.pem-block
// TEST-METADATA: assetType:related-crypto-material findingType:key_generation operation:keygen materialType:private-key library:crypto/x509 api:x509.DecryptPEMBlock
func testDecryptPEMBlock() {
	block := &pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: []byte("encrypted data"),
	}
	password := []byte("password")
	// ruleid: go.crypto.x509.pem-block
	data, err := x509.DecryptPEMBlock(block, password)
	_ = data
	_ = err
}

// TEST-RULE: go.crypto.x509.pem-block
// TEST-METADATA: assetType:related-crypto-material findingType:key_generation operation:keygen materialType:private-key library:crypto/x509 api:x509.EncryptPEMBlock
func testEncryptPEMBlock() {
	data := []byte("private key data")
	password := []byte("password")
	alg := x509.PEMCipherAES256
	// ruleid: go.crypto.x509.pem-block
	block, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", data, password, alg)
	_ = block
	_ = err
}

// TEST-RULE: go.crypto.x509.pem-block
// TEST-METADATA: assetType:related-crypto-material findingType:key_generation operation:keygen materialType:private-key library:crypto/x509 api:x509.IsEncryptedPEMBlock
func testIsEncryptedPEMBlock() {
	block := &pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: []byte("encrypted data"),
	}
	// ruleid: go.crypto.x509.pem-block
	encrypted := x509.IsEncryptedPEMBlock(block)
	_ = encrypted
}

func getRsaKey() *rsa.PrivateKey {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	return key
}

