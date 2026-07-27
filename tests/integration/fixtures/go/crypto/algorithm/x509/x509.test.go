package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
)

// TEST-RULE: go.crypto.x509.parse-pkcs1-key
// TEST-METADATA: assetType:algorithm findingType:key_generation algorithmName:RSA algorithmFamily:RSA library:crypto/x509
func testParsePKCS1PrivateKey() {
	derBytes := []byte{}
	// ruleid: go.crypto.x509.parse-pkcs1-key
	_, err := x509.ParsePKCS1PrivateKey(derBytes)
	_ = err
}

// TEST-RULE: go.crypto.x509.parse-pkcs1-key
// TEST-METADATA: assetType:algorithm findingType:key_generation algorithmName:RSA algorithmFamily:RSA library:crypto/x509
func testMarshalPKCS1PrivateKey() {
	var key = getRsaKey()
	// ruleid: go.crypto.x509.parse-pkcs1-key
	derBytes := x509.MarshalPKCS1PrivateKey(key)
	_ = derBytes
}

// TEST-RULE: go.crypto.x509.parse-pkcs1-key
// TEST-METADATA: assetType:algorithm findingType:key_generation algorithmName:RSA algorithmFamily:RSA library:crypto/x509
func testParsePKCS1PublicKey() {
	derBytes := []byte{}
	// ruleid: go.crypto.x509.parse-pkcs1-key
	_, err := x509.ParsePKCS1PublicKey(derBytes)
	_ = err
}

// TEST-RULE: go.crypto.x509.parse-pkcs1-key
// TEST-METADATA: assetType:algorithm findingType:key_generation algorithmName:RSA algorithmFamily:RSA library:crypto/x509
func testMarshalPKCS1PublicKey() {
	var key = getRsaKey()
	// ruleid: go.crypto.x509.parse-pkcs1-key
	derBytes := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	_ = derBytes
}

// TEST-RULE: go.crypto.x509.parse-ec-private-key
// TEST-METADATA: assetType:algorithm findingType:key_generation algorithmName:ECDSA algorithmFamily:ECDSA library:crypto/x509
func testParseECPrivateKey() {
	derBytes := []byte{}
	// ruleid: go.crypto.x509.parse-ec-private-key
	_, err := x509.ParseECPrivateKey(derBytes)
	_ = err
}

// TEST-RULE: go.crypto.x509.parse-ec-private-key
// TEST-METADATA: assetType:algorithm findingType:key_generation algorithmName:ECDSA algorithmFamily:ECDSA library:crypto/x509
func testMarshalECPrivateKey() {
	var key = getEcdsaKey()
	// ruleid: go.crypto.x509.parse-ec-private-key
	derBytes, err := x509.MarshalECPrivateKey(key)
	_ = derBytes
	_ = err
}

func getRsaKey() *rsa.PrivateKey {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	return key
}

func getEcdsaKey() *ecdsa.PrivateKey {
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return ecdsaKey
}
