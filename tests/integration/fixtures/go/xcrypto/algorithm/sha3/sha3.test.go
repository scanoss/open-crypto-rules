package sha3_test

import (
	"golang.org/x/crypto/sha3"
)

// TEST-RULE: go.xcrypto.sha3.hash
// TEST-METADATA: operation:digest findingType:hash
func testSHA3_224_New() {
	// ruleid: go.xcrypto.sha3.hash
	hasher := sha3.New224()
	_ = hasher
}

// TEST-RULE: go.xcrypto.sha3.hash
// TEST-METADATA: operation:digest findingType:hash
func testSHA3_224_Sum() {
	data := []byte("test")
	// ruleid: go.xcrypto.sha3.hash
	hash := sha3.Sum224(data)
	_ = hash
}

// TEST-RULE: go.xcrypto.sha3.hash
// TEST-METADATA: operation:digest findingType:hash
func testSHA3_256_New() {
	// ruleid: go.xcrypto.sha3.hash
	hasher := sha3.New256()
	_ = hasher
}

// TEST-RULE: go.xcrypto.sha3.hash
// TEST-METADATA: operation:digest findingType:hash
func testSHA3_256_Sum() {
	data := []byte("test")
	// ruleid: go.xcrypto.sha3.hash
	hash := sha3.Sum256(data)
	_ = hash
}

// TEST-RULE: go.xcrypto.sha3.hash
// TEST-METADATA: operation:digest findingType:hash
func testSHA3_384_New() {
	// ruleid: go.xcrypto.sha3.hash
	hasher := sha3.New384()
	_ = hasher
}

// TEST-RULE: go.xcrypto.sha3.hash
// TEST-METADATA: operation:digest findingType:hash
func testSHA3_384_Sum() {
	data := []byte("test")
	// ruleid: go.xcrypto.sha3.hash
	hash := sha3.Sum384(data)
	_ = hash
}

// TEST-RULE: go.xcrypto.sha3.hash
// TEST-METADATA: operation:digest findingType:hash
func testSHA3_512_New() {
	// ruleid: go.xcrypto.sha3.hash
	hasher := sha3.New512()
	_ = hasher
}

// TEST-RULE: go.xcrypto.sha3.hash
// TEST-METADATA: operation:digest findingType:hash
func testSHA3_512_Sum() {
	data := []byte("test")
	// ruleid: go.xcrypto.sha3.hash
	hash := sha3.Sum512(data)
	_ = hash
}

// TEST-RULE: go.xcrypto.sha3.legacy-keccak
// TEST-METADATA: operation:digest findingType:hash
func testLegacyKeccak256() {
	// ruleid: go.xcrypto.sha3.legacy-keccak
	hasher := sha3.NewLegacyKeccak256()
	_ = hasher
}

// TEST-RULE: go.xcrypto.sha3.legacy-keccak
// TEST-METADATA: operation:digest findingType:hash
func testLegacyKeccak512() {
	// ruleid: go.xcrypto.sha3.legacy-keccak
	hasher := sha3.NewLegacyKeccak512()
	_ = hasher
}

// TEST-RULE: go.xcrypto.sha3.shake
// TEST-METADATA: operation:digest findingType:hash
func testSHAKE128_New() {
	// ruleid: go.xcrypto.sha3.shake
	shake := sha3.NewShake128()
	_ = shake
}

// TEST-RULE: go.xcrypto.sha3.shake
// TEST-METADATA: operation:digest findingType:hash
func testSHAKE128_Sum() {
	var hash [32]byte
	data := []byte("test")
	// ruleid: go.xcrypto.sha3.shake
	sha3.ShakeSum128(hash[:], data)
}

// TEST-RULE: go.xcrypto.sha3.shake
// TEST-METADATA: operation:digest findingType:hash
func testSHAKE256_New() {
	// ruleid: go.xcrypto.sha3.shake
	shake := sha3.NewShake256()
	_ = shake
}

// TEST-RULE: go.xcrypto.sha3.shake
// TEST-METADATA: operation:digest findingType:hash
func testSHAKE256_Sum() {
	var hash [64]byte
	data := []byte("test")
	// ruleid: go.xcrypto.sha3.shake
	sha3.ShakeSum256(hash[:], data)
}

// TEST-RULE: go.xcrypto.sha3.cshake
// TEST-METADATA: operation:digest findingType:hash
func testcSHAKE128() {
	n := []byte("name")
	s := []byte("customization")
	
	// ruleid: go.xcrypto.sha3.cshake
	cshake := sha3.NewCShake128(n, s)
	_ = cshake
}

// TEST-RULE: go.xcrypto.sha3.cshake
// TEST-METADATA: operation:digest findingType:hash
func testcSHAKE256() {
	n := []byte("name")
	s := []byte("customization")
	
	// ruleid: go.xcrypto.sha3.cshake
	cshake := sha3.NewCShake256(n, s)
	_ = cshake
}
