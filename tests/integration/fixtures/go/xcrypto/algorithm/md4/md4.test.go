package md4_test

import (
	"golang.org/x/crypto/md4"
)

// TEST-RULE: go.xcrypto.md4.hash-usage
// TEST-METADATA: operation:digest findingType:hash api:md4.New
func testMD4New() {
	// ruleid: go.xcrypto.md4.hash-usage
	hasher := md4.New()
	_ = hasher
}

