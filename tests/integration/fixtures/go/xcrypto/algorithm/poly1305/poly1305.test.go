package poly1305_test

import (
	"golang.org/x/crypto/poly1305"
)

// TEST-RULE: go.xcrypto.poly1305.mac
// TEST-METADATA: operation:sign findingType:mac api:poly1305.New
func testPoly1305New() {
	key := [32]byte{}
	
	// ruleid: go.xcrypto.poly1305.mac
	mac := poly1305.New(&key)
	_ = mac
}

// TEST-RULE: go.xcrypto.poly1305.sum
// TEST-METADATA: operation:sign findingType:mac api:poly1305.Sum
func testPoly1305Sum() {
	message := [16]byte{'H', 'e', 'l', 'l', 'o', ' ', 'G', 'o', 'p', 'h', 'e', 'r', 's'}
	key := [32]byte{}
	in := []byte{}
	
	// ruleid: go.xcrypto.poly1305.sum
	poly1305.Sum(&message, in, &key)
}

// TEST-RULE: go.xcrypto.poly1305.verify
// TEST-METADATA: operation:verify findingType:mac api:poly1305.Verify
func testPoly1305Verify() {
	tag := [16]byte{}
	message := []byte("test message")
	key := [32]byte{}
	
	// ruleid: go.xcrypto.poly1305.verify
	valid := poly1305.Verify(&tag, message, &key)
	_ = valid
}

