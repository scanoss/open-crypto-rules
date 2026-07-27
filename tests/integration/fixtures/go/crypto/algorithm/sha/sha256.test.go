package sha_test

import (
	"crypto"
	"crypto/sha256"
)

// TEST-RULE: go.crypto.sha256.hash-usage-256
// TEST-METADATA: operation:digest findingType:hash
func testSHA256New() {
	// ruleid: go.crypto.sha256.hash-usage-256
	hasher := sha256.New()
	_ = hasher
}

// TEST-RULE: go.crypto.sha256.hash-usage-256
// TEST-METADATA: operation:digest findingType:hash algorithmName:SHA-256 algorithmParameterSetIdentifier:256
func testSHA256Sum() {
	data := []byte("test message")
	// ruleid: go.crypto.sha256.hash-usage-256
	hash := sha256.Sum256(data)
	_ = hash
}

// TEST-RULE: go.crypto.sha256.hash-usage-256
// TEST-METADATA: operation:digest findingType:hash algorithmName:SHA-256 algorithmParameterSetIdentifier:256
func testSHA256CryptoConst() {
	// ruleid: go.crypto.sha256.hash-usage-256
	hasher := crypto.SHA256.New()
	_ = hasher
}

// TEST-RULE: go.crypto.sha256.hash-usage-224
// TEST-METADATA: operation:digest findingType:hash algorithmName:SHA-224 algorithmParameterSetIdentifier:224
func testSHA224New() {
	// ruleid: go.crypto.sha256.hash-usage-224
	hasher := sha256.New224()
	_ = hasher
}

// TEST-RULE: go.crypto.sha256.hash-usage-224
// TEST-METADATA: operation:digest findingType:hash
func testSHA224Sum() {
	data := []byte("test message")
	// ruleid: go.crypto.sha256.hash-usage-224
	hash := sha256.Sum224(data)
	_ = hash
}

// TEST-RULE: go.crypto.sha256.hash-usage-224
// TEST-METADATA: operation:digest findingType:hash
func testSHA224CryptoConst() {
	// ruleid: go.crypto.sha256.hash-usage-224
	hasher := crypto.SHA224.New()
	_ = hasher
}
