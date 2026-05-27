package twofish_test

import (
	"golang.org/x/crypto/twofish"
)

// TEST-RULE: go.xcrypto.twofish.block-cipher
// TEST-METADATA: findingType:cipher
func testNewCipherWithSize16() {
	key := make([]byte, 16)
	
	// ruleid: go.xcrypto.twofish.block-cipher
	cipher, _ := twofish.NewCipher(key)
	_ = cipher
}

// TEST-RULE: go.xcrypto.twofish.block-cipher
// TEST-METADATA: findingType:cipher
func testNewCipherWithSize32() {
	key := make([]byte, 32)
	
	// ruleid: go.xcrypto.twofish.block-cipher
	cipher, _ := twofish.NewCipher(key)
	_ = cipher
}

// TEST-RULE: go.xcrypto.twofish.block-cipher
// TEST-METADATA: findingType:cipher
func testNewCipher() {
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	
	// ruleid: go.xcrypto.twofish.block-cipher
	cipher, _ := twofish.NewCipher(key)
	_ = cipher
}
