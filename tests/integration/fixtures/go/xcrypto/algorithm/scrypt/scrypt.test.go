package scrypt_test

import (
	"golang.org/x/crypto/scrypt"
)

// TEST-RULE: go.xcrypto.scrypt.key-derivation
// TEST-METADATA: operation:keyderive findingType:kdf algorithmParameterSetIdentifier:16 api:scrypt.Key
func testScryptKey16() {
	password := []byte("password")
	salt := []byte("salt")
	
	// ruleid: go.xcrypto.scrypt.key-derivation
	key, _ := scrypt.Key(password, salt, 32768, 8, 1, 16)
	_ = key
}

// TEST-RULE: go.xcrypto.scrypt.key-derivation
// TEST-METADATA: operation:keyderive findingType:kdf algorithmParameterSetIdentifier:32 api:scrypt.Key
func testScryptKey32() {
	password := []byte("password")
	salt := []byte("salt")
	
	// ruleid: go.xcrypto.scrypt.key-derivation
	key, _ := scrypt.Key(password, salt, 32768, 8, 1, 32)
	_ = key
}

// TEST-RULE: go.xcrypto.scrypt.key-derivation
// TEST-METADATA: operation:keyderive findingType:kdf api:scrypt.Key
func testScryptKeyGeneric() {
	password := []byte("password")
	salt := []byte("salt")
	keyLen := 64
	
	// ruleid: go.xcrypto.scrypt.key-derivation
	key, _ := scrypt.Key(password, salt, 32768, 8, 1, keyLen)
	_ = key
}
