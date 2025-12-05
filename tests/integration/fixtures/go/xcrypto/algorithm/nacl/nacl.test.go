package nacl_test

import (
	"golang.org/x/crypto/nacl/secretbox"
)

// TEST-RULE: go.xcrypto.nacl.secretbox.encrypt
// TEST-METADATA: operation:encrypt findingType:cipher api:secretbox.Seal|secretbox.Overhead
func testSecretboxSeal() {
	var key [32]byte
	var nonce [24]byte
	message := []byte("test message")
	
	// ruleid: go.xcrypto.nacl.secretbox.encrypt
	encrypted := secretbox.Seal(nil, message, &nonce, &key)
	_ = encrypted
}

// TEST-RULE: go.xcrypto.nacl.secretbox.encrypt
// TEST-METADATA: operation:encrypt findingType:cipher api:secretbox.Seal|secretbox.Overhead
func testSecretboxOverhead() {
	// ruleid: go.xcrypto.nacl.secretbox.encrypt
	overhead := secretbox.Overhead
	_ = overhead
}

// TEST-RULE: go.xcrypto.nacl.secretbox.open
// TEST-METADATA: operation:decrypt findingType:cipher api:secretbox.Open
func testSecretboxOpen() {
	var key [32]byte
	var nonce [24]byte
	ciphertext := []byte("encrypted data")
	
	// ruleid: go.xcrypto.nacl.secretbox.open
	decrypted, ok := secretbox.Open(nil, ciphertext, &nonce, &key)
	_, _ = decrypted, ok
}
