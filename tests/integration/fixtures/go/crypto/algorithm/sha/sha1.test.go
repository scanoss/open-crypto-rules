package sha_test

import (
	"crypto"
	"crypto/sha1"
)

// TEST-RULE: go.crypto.sha1.hash-usage
// TEST-METADATA: operation:digest findingType:hash algorithmName:SHA-1 api:crypto.SHA1
func testSHA1New() {
	// ruleid: go.crypto.sha1.hash-usage
	hasher := sha1.New()
	_ = hasher
}

// TEST-RULE: go.crypto.sha1.hash-usage
// TEST-METADATA: operation:digest findingType:hash algorithmName:SHA-1 api:crypto.SHA1
func testSHA1Sum() {
	data := []byte("test message")
	// ruleid: go.crypto.sha1.hash-usage
	hash := sha1.Sum(data)
	_ = hash
}

// TEST-RULE: go.crypto.sha1.hash-usage
// TEST-METADATA: operation:digest findingType:hash algorithmName:SHA-1 api:crypto.SHA1
func testSHA1CryptoConst() {
	// ruleid: go.crypto.sha1.hash-usage
	hasher := crypto.SHA1.New()
	_ = hasher
}

