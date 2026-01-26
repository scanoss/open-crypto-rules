package argon2_test

import (
	"golang.org/x/crypto/argon2"
)

// TEST-RULE: go.xcrypto.argon2.key-derivation
// TEST-METADATA: operation:keyderive findingType:kdf
func testIDKey() {
	password := []byte("myPassword")
	salt := []byte("randomSalt")

	// ruleid: go.xcrypto.argon2.key-derivation
	key := argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
	_ = key
}

// TEST-RULE: go.xcrypto.argon2.key-derivation
// TEST-METADATA: operation:keyderive findingType:kdf
func testKey() {
	password := []byte("myPassword")
	salt := []byte("randomSalt")

	// ruleid: go.xcrypto.argon2.key-derivation
	key := argon2.Key(password, salt, 3, 32*1024, 4, 16)
	_ = key
}

