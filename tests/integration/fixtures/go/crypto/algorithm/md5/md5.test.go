package md5_test

import (
	"crypto"
	"crypto/md5"
)

// TEST-RULE: go.crypto.md5.hash-usage
// TEST-METADATA: operation:digest findingType:hash algorithmName:MD5 api:crypto.MD5
func testMD5New() {
	// ruleid: go.crypto.md5.hash-usage
	hasher := md5.New()
	_ = hasher
}

// TEST-RULE: go.crypto.md5.hash-usage
// TEST-METADATA: operation:digest findingType:hash algorithmName:MD5 api:crypto.MD5
func testMD5Sum() {
	data := []byte("test message")
	// ruleid: go.crypto.md5.hash-usage
	hash := md5.Sum(data)
	_ = hash
}

// TEST-RULE: go.crypto.md5.hash-usage
// TEST-METADATA: operation:digest findingType:hash algorithmName:MD5 api:crypto.MD5
func testMD5CryptoConst() {
	// ruleid: go.crypto.md5.hash-usage
	hasher := crypto.MD5.New()
	_ = hasher
}

