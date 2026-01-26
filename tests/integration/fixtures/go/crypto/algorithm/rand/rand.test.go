package main

import (
	"crypto/rand"
	"io"
	"math/big"
)

// TEST-RULE: go.crypto.rand.usage
// TEST-METADATA: assetType:algorithm findingType:rng operation:other algorithmPrimitive:drbg algorithmName:CSPRNG algorithmFamily:CSPRNG library:crypto/rand
func testRead() {
	b := make([]byte, 32)
	// ruleid: go.crypto.rand.usage
	rand.Read(b)
}

// TEST-RULE: go.crypto.rand.usage
// TEST-METADATA: assetType:algorithm findingType:rng operation:other algorithmPrimitive:drbg algorithmName:CSPRNG algorithmFamily:CSPRNG library:crypto/rand
func testReaderAssignment() {
	// ruleid: go.crypto.rand.usage
	var r io.Reader = rand.Reader
	_ = r
}

// TEST-RULE: go.crypto.rand.usage
// TEST-METADATA: assetType:algorithm findingType:rng operation:other algorithmPrimitive:drbg algorithmName:CSPRNG algorithmFamily:CSPRNG library:crypto/rand
func testReaderShortAssignment() {
	// ruleid: go.crypto.rand.usage
	r := rand.Reader
	_ = r
}

// TEST-RULE: go.crypto.rand.usage
// TEST-METADATA: assetType:algorithm findingType:rng operation:other algorithmPrimitive:drbg algorithmName:CSPRNG algorithmFamily:CSPRNG library:crypto/rand
func testReadFull() {
	b := make([]byte, 32)
	// ruleid: go.crypto.rand.usage
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		println("broke")
	}
}

// TEST-RULE: go.crypto.rand.usage
// TEST-METADATA: assetType:algorithm findingType:rng operation:other algorithmPrimitive:drbg algorithmName:CSPRNG algorithmFamily:CSPRNG library:crypto/rand
func testInt() {
	max := big.NewInt(100)
	// ruleid: go.crypto.rand.usage
	serialNumber, _ := rand.Int(rand.Reader, max)
	_ = serialNumber
}

// TEST-RULE: go.crypto.rand.usage
// TEST-METADATA: assetType:algorithm findingType:rng operation:other algorithmPrimitive:drbg algorithmName:CSPRNG algorithmFamily:CSPRNG library:crypto/rand
func testPrime() {
	// ruleid: go.crypto.rand.usage
	p, _ := rand.Prime(rand.Reader, 256)
	_ = p
}

