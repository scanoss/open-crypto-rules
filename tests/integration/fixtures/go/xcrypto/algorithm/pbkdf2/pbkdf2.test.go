package pbkdf2_test

import (
	"crypto"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"

	"golang.org/x/crypto/pbkdf2"
)

// TEST-RULE: go.xcrypto.pbkdf2.key-derivation
// TEST-METADATA: operation:keyderive findingType:kdf iterations:10000 algorithmParameterSetIdentifier:10000-32 api:pbkdf2.Key
func testPBKDF2_SHA256_AllLiterals() {
	password := []byte("password")
	salt := []byte("salt")
	
	// ruleid: go.xcrypto.pbkdf2.key-derivation
	key := pbkdf2.Key(password, salt, 10000, 32, sha256.New)
	_ = key
}

// TEST-RULE: go.xcrypto.pbkdf2.key-derivation
// TEST-METADATA: operation:keyderive findingType:kdf iterations:50000 algorithmParameterSetIdentifier:50000-64 api:pbkdf2.Key
func testPBKDF2_SHA512_AllLiterals() {
	password := []byte("password")
	salt := []byte("salt")
	
	// ruleid: go.xcrypto.pbkdf2.key-derivation
	key := pbkdf2.Key(password, salt, 50000, 64, sha512.New)
	_ = key
}

// TEST-RULE: go.xcrypto.pbkdf2.key-derivation
// TEST-METADATA: operation:keyderive findingType:kdf iterations:100000 api:pbkdf2.Key
func testPBKDF2_SHA256_IterationsOnly() {
	password := []byte("password")
	salt := []byte("salt")
	keyLen := 32
	
	// ruleid: go.xcrypto.pbkdf2.key-derivation
	key := pbkdf2.Key(password, salt, 100000, keyLen, sha256.New)
	_ = key
}

// TEST-RULE: go.xcrypto.pbkdf2.key-derivation
// TEST-METADATA: operation:keyderive findingType:kdf algorithmParameterSetIdentifier:24 api:pbkdf2.Key
func testPBKDF2_SHA1_KeyLenOnly() {
	password := []byte("password")
	salt := []byte("salt")
	iterations := 5000
	
	// ruleid: go.xcrypto.pbkdf2.key-derivation
	key := pbkdf2.Key(password, salt, iterations, 24, sha1.New)
	_ = key
}

// TEST-RULE: go.xcrypto.pbkdf2.key-derivation
// TEST-METADATA: operation:keyderive findingType:kdf api:pbkdf2.Key
func testPBKDF2_MD5_AllDynamic() {
	password := []byte("password")
	salt := []byte("salt")
	iterations := 1000
	keyLen := 16
	
	// ruleid: go.xcrypto.pbkdf2.key-derivation
	key := pbkdf2.Key(password, salt, iterations, keyLen, md5.New)
	_ = key
}

// TEST-RULE: go.xcrypto.pbkdf2.key-derivation
// TEST-METADATA: operation:keyderive findingType:kdf iterations:20000 algorithmParameterSetIdentifier:20000-32 api:pbkdf2.Key
func testPBKDF2_CryptoConstant_AllLiterals() {
	password := []byte("password")
	salt := []byte("salt")
	
	// ruleid: go.xcrypto.pbkdf2.key-derivation
	key := pbkdf2.Key(password, salt, 20000, 32, crypto.SHA256.New)
	_ = key
}

// TEST-RULE: go.xcrypto.pbkdf2.key-derivation
// TEST-METADATA: operation:keyderive findingType:kdf iterations:15000 api:pbkdf2.Key
func testPBKDF2_SHA384_IterationsOnly() {
	password := []byte("password")
	salt := []byte("salt")
	keyLen := 48
	
	// ruleid: go.xcrypto.pbkdf2.key-derivation
	key := pbkdf2.Key(password, salt, 15000, keyLen, sha512.New384)
	_ = key
}

// TEST-RULE: go.xcrypto.pbkdf2.key-derivation
// TEST-METADATA: operation:keyderive findingType:kdf api:pbkdf2.Key
func testPBKDF2_SHA224_AllDynamic() {
	password := []byte("password")
	salt := []byte("salt")
	iterations := 8000
	keyLen := 28
	
	// ruleid: go.xcrypto.pbkdf2.key-derivation
	key := pbkdf2.Key(password, salt, iterations, keyLen, sha256.New224)
	_ = key
}
