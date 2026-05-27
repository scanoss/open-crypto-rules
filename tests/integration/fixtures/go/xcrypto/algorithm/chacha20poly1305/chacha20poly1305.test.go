package chacha20poly1305_test

import (
	"golang.org/x/crypto/chacha20poly1305"
)

// TEST-RULE: go.xcrypto.chacha20poly1305.aead
// TEST-METADATA: findingType:cipher
func testChaCha20Poly1305New() {
	key := make([]byte, 32)
	// ruleid: go.xcrypto.chacha20poly1305.aead
	aead, _ := chacha20poly1305.New(key)
	_ = aead
}

// TEST-RULE: go.xcrypto.chacha20poly1305.aead
// TEST-METADATA: findingType:cipher
func testXChaCha20Poly1305NewX() {
	key := make([]byte, 32)
	// ruleid: go.xcrypto.chacha20poly1305.aead
	aead, _ := chacha20poly1305.NewX(key)
	_ = aead
}

// TEST-RULE: go.xcrypto.chacha20poly1305.constants
// TEST-METADATA: findingType:cipher
func testChaCha20Poly1305Constants() {
	// ruleid: go.xcrypto.chacha20poly1305.constants
	keySize := chacha20poly1305.KeySize
	// ruleid: go.xcrypto.chacha20poly1305.constants
	nonceSize := chacha20poly1305.NonceSize
	// ruleid: go.xcrypto.chacha20poly1305.constants
	overhead := chacha20poly1305.Overhead
	_, _, _ = keySize, nonceSize, overhead
}
