package chacha20_test

import (
	"golang.org/x/crypto/chacha20"
)

// TEST-RULE: go.xcrypto.chacha20.stream-cipher
// TEST-METADATA: operation:encrypt findingType:cipher algorithmParameterSetIdentifier:32 api:chacha20.NewUnauthenticatedCipher
func testNewUnauthenticatedCipherWithSize() {
	key := make([]byte, 32)
	nonce := make([]byte, 24)
	
	// ruleid: go.xcrypto.chacha20.stream-cipher
	cipher, _ := chacha20.NewUnauthenticatedCipher(key, nonce)
	_ = cipher
}

// TEST-RULE: go.xcrypto.chacha20.stream-cipher
// TEST-METADATA: operation:encrypt findingType:cipher api:chacha20.NewUnauthenticatedCipher
func testNewUnauthenticatedCipher() {
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	             17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	nonce := make([]byte, 24)
	
	// ruleid: go.xcrypto.chacha20.stream-cipher
	cipher, _ := chacha20.NewUnauthenticatedCipher(key, nonce)
	_ = cipher
}

// TEST-RULE: go.xcrypto.chacha20.hchacha20
// TEST-METADATA: operation:digest findingType:hash api:chacha20.HChaCha20
func testHChaCha20() {
	var nonce []byte
	var key []byte
	
	// ruleid: go.xcrypto.chacha20.hchacha20
	chacha20.HChaCha20(key, nonce)
}
