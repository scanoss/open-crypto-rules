package sha_test

import (
	"crypto"
	"crypto/sha512"
)

// TEST-RULE: go.crypto.sha512.hash-usage-512
// TEST-METADATA: operation:digest findingType:hash algorithmName:SHA-512 algorithmParameterSetIdentifier:512 api:sha512.New
func testSHA512New() {
	// ruleid: go.crypto.sha512.hash-usage-512
	hasher := sha512.New()
	_ = hasher
}

// TEST-RULE: go.crypto.sha512.hash-usage-512
// TEST-METADATA: operation:digest findingType:hash algorithmName:SHA-512 algorithmParameterSetIdentifier:512 api:sha512.Sum512
func testSHA512Sum() {
	data := []byte("test message")
	// ruleid: go.crypto.sha512.hash-usage-512
	hash := sha512.Sum512(data)
	_ = hash
}

// TEST-RULE: go.crypto.sha512.hash-usage-512
// TEST-METADATA: operation:digest findingType:hash algorithmName:SHA-512 algorithmParameterSetIdentifier:512 api:crypto.SHA512
func testSHA512CryptoConst() {
	// ruleid: go.crypto.sha512.hash-usage-512
	hasher := crypto.SHA512.New()
	_ = hasher
}

// TEST-RULE: go.crypto.sha512.hash-usage-384
// TEST-METADATA: operation:digest findingType:hash algorithmName:SHA-384 algorithmParameterSetIdentifier:384 api:sha512.New384
func testSHA384New() {
	// ruleid: go.crypto.sha512.hash-usage-384
	hasher := sha512.New384()
	_ = hasher
}

// TEST-RULE: go.crypto.sha512.hash-usage-384
// TEST-METADATA: operation:digest findingType:hash algorithmName:SHA-384 algorithmParameterSetIdentifier:384 api:sha512.Sum384
func testSHA384Sum() {
	data := []byte("test message")
	// ruleid: go.crypto.sha512.hash-usage-384
	hash := sha512.Sum384(data)
	_ = hash
}

// TEST-RULE: go.crypto.sha512.hash-usage-384
// TEST-METADATA: operation:digest findingType:hash algorithmName:SHA-384 algorithmParameterSetIdentifier:384 api:crypto.SHA384
func testSHA384CryptoConst() {
	// ruleid: go.crypto.sha512.hash-usage-384
	hasher := crypto.SHA384.New()
	_ = hasher
}

// TEST-RULE: go.crypto.sha512.hash-usage-512-224
// TEST-METADATA: operation:digest findingType:hash algorithmName:SHA-512/224 algorithmParameterSetIdentifier:512_224 api:sha512.New512_224
func testSHA512_224New() {
	// ruleid: go.crypto.sha512.hash-usage-512-224
	hasher := sha512.New512_224()
	_ = hasher
}

// TEST-RULE: go.crypto.sha512.hash-usage-512-224
// TEST-METADATA: operation:digest findingType:hash algorithmName:SHA-512/224 algorithmParameterSetIdentifier:512_224 api:sha512.Sum512_224
func testSHA512_224Sum() {
	data := []byte("test message")
	// ruleid: go.crypto.sha512.hash-usage-512-224
	hash := sha512.Sum512_224(data)
	_ = hash
}

// TEST-RULE: go.crypto.sha512.hash-usage-512-224
// TEST-METADATA: operation:digest findingType:hash algorithmName:SHA-512/224 algorithmParameterSetIdentifier:512_224 api:crypto.SHA512_224
func testSHA512_224CryptoConst() {
	// ruleid: go.crypto.sha512.hash-usage-512-224
	hasher := crypto.SHA512_224.New()
	_ = hasher
}

// TEST-RULE: go.crypto.sha512.hash-usage-512-256
// TEST-METADATA: operation:digest findingType:hash algorithmName:SHA-512/256 algorithmParameterSetIdentifier:512_256 api:sha512.New512_256
func testSHA512_256New() {
	// ruleid: go.crypto.sha512.hash-usage-512-256
	hasher := sha512.New512_256()
	_ = hasher
}

// TEST-RULE: go.crypto.sha512.hash-usage-512-256
// TEST-METADATA: operation:digest findingType:hash algorithmName:SHA-512/256 algorithmParameterSetIdentifier:512_256 api:sha512.Sum512_256
func testSHA512_256Sum() {
	data := []byte("test message")
	// ruleid: go.crypto.sha512.hash-usage-512-256
	hash := sha512.Sum512_256(data)
	_ = hash
}

// TEST-RULE: go.crypto.sha512.hash-usage-512-256
// TEST-METADATA: operation:digest findingType:hash algorithmName:SHA-512/256 algorithmParameterSetIdentifier:512_256 api:crypto.SHA512_256
func testSHA512_256CryptoConst() {
	// ruleid: go.crypto.sha512.hash-usage-512-256
	hasher := crypto.SHA512_256.New()
	_ = hasher
}

