package ripemd160_test

import (
	"golang.org/x/crypto/ripemd160"
)

// TEST-RULE: go.xcrypto.ripemd160.hash-usage
// TEST-METADATA: operation:digest findingType:hash api:ripemd160.New
func testRIPEMD160New() {
	// ruleid: go.xcrypto.ripemd160.hash-usage
	hasher := ripemd160.New()
	_ = hasher
}

