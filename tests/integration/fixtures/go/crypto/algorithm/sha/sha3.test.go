package sha_test

import (
	"crypto"
	"crypto/sha3"
)

// TEST-RULE: go.crypto.sha3.hash-usage
// TEST-METADATA: operation:digest findingType:hash algorithmName:SHA3-224 algorithmParameterSetIdentifier:224 api:sha3.New224
func testSHA3_224New() {
	// ruleid: go.crypto.sha3.hash-usage
	hasher := sha3.New224()
	_ = hasher
}

// TEST-RULE: go.crypto.sha3.hash-usage
// TEST-METADATA: operation:digest findingType:hash algorithmName:SHA3-224 algorithmParameterSetIdentifier:224 api:sha3.Sum224
func testSHA3_224Sum() {
	data := []byte("test message")
	// ruleid: go.crypto.sha3.hash-usage
	hash := sha3.Sum224(data)
	_ = hash
}

// TEST-RULE: go.crypto.sha3.hash-usage
// TEST-METADATA: operation:digest findingType:hash algorithmName:SHA3-224 algorithmParameterSetIdentifier:224 api:crypto.SHA3_224
func testSHA3_224CryptoConst() {
	// ruleid: go.crypto.sha3.hash-usage
	hasher := crypto.SHA3_224.New()
	_ = hasher
}

// TEST-RULE: go.crypto.sha3.hash-usage
// TEST-METADATA: operation:digest findingType:hash algorithmName:SHA3-256 algorithmParameterSetIdentifier:256 api:sha3.New256
func testSHA3_256New() {
	// ruleid: go.crypto.sha3.hash-usage
	hasher := sha3.New256()
	_ = hasher
}

// TEST-RULE: go.crypto.sha3.hash-usage
// TEST-METADATA: operation:digest findingType:hash algorithmName:SHA3-256 algorithmParameterSetIdentifier:256 api:sha3.Sum256
func testSHA3_256Sum() {
	data := []byte("test message")
	// ruleid: go.crypto.sha3.hash-usage
	hash := sha3.Sum256(data)
	_ = hash
}

// TEST-RULE: go.crypto.sha3.hash-usage
// TEST-METADATA: operation:digest findingType:hash algorithmName:SHA3-256 algorithmParameterSetIdentifier:256 api:crypto.SHA3_256
func testSHA3_256CryptoConst() {
	// ruleid: go.crypto.sha3.hash-usage
	hasher := crypto.SHA3_256.New()
	_ = hasher
}

// TEST-RULE: go.crypto.sha3.hash-usage
// TEST-METADATA: operation:digest findingType:hash algorithmName:SHA3-384 algorithmParameterSetIdentifier:384 api:sha3.New384
func testSHA3_384New() {
	// ruleid: go.crypto.sha3.hash-usage
	hasher := sha3.New384()
	_ = hasher
}

// TEST-RULE: go.crypto.sha3.hash-usage
// TEST-METADATA: operation:digest findingType:hash algorithmName:SHA3-384 algorithmParameterSetIdentifier:384 api:sha3.Sum384
func testSHA3_384Sum() {
	data := []byte("test message")
	// ruleid: go.crypto.sha3.hash-usage
	hash := sha3.Sum384(data)
	_ = hash
}

// TEST-RULE: go.crypto.sha3.hash-usage
// TEST-METADATA: operation:digest findingType:hash algorithmName:SHA3-384 algorithmParameterSetIdentifier:384 api:crypto.SHA3_384
func testSHA3_384CryptoConst() {
	// ruleid: go.crypto.sha3.hash-usage
	hasher := crypto.SHA3_384.New()
	_ = hasher
}

// TEST-RULE: go.crypto.sha3.hash-usage
// TEST-METADATA: operation:digest findingType:hash algorithmName:SHA3-512 algorithmParameterSetIdentifier:512 api:sha3.New512
func testSHA3_512New() {
	// ruleid: go.crypto.sha3.hash-usage
	hasher := sha3.New512()
	_ = hasher
}

// TEST-RULE: go.crypto.sha3.hash-usage
// TEST-METADATA: operation:digest findingType:hash algorithmName:SHA3-512 algorithmParameterSetIdentifier:512 api:sha3.Sum512
func testSHA3_512Sum() {
	data := []byte("test message")
	// ruleid: go.crypto.sha3.hash-usage
	hash := sha3.Sum512(data)
	_ = hash
}

// TEST-RULE: go.crypto.sha3.hash-usage
// TEST-METADATA: operation:digest findingType:hash algorithmName:SHA3-512 algorithmParameterSetIdentifier:512 api:crypto.SHA3_512
func testSHA3_512CryptoConst() {
	// ruleid: go.crypto.sha3.hash-usage
	hasher := crypto.SHA3_512.New()
	_ = hasher
}


