package cast5_test

import (
	"golang.org/x/crypto/cast5"
)

// TEST-RULE: go.xcrypto.cast5.block-cipher
// TEST-METADATA: operation:encrypt findingType:cipher
func testNewCipherWithSize() {
	key := make([]byte, 16)
	
	// ruleid: go.xcrypto.cast5.block-cipher
	cipher, _ := cast5.NewCipher(key)
	_ = cipher
}

// TEST-RULE: go.xcrypto.cast5.block-cipher
// TEST-METADATA: operation:encrypt findingType:cipher
func testNewCipher() {
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	
	// ruleid: go.xcrypto.cast5.block-cipher
	cipher, _ := cast5.NewCipher(key)
	_ = cipher
}

