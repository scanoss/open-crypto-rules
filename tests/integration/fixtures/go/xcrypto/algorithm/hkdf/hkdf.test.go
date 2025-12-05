package hkdf_test

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"io"

	"golang.org/x/crypto/hkdf"
)

// TEST-RULE: go.xcrypto.hkdf.new
// TEST-METADATA: operation:keyderive findingType:kdf algorithmName:HKDF-sha256 api:hkdf.New
func testHKDFNew_SHA256() {
	secret := []byte("secret")
	salt := []byte("salt")
	info := []byte("info")
	
	// ruleid: go.xcrypto.hkdf.new
	kdf := hkdf.New(sha256.New, secret, salt, info)
	key := make([]byte, 32)
	io.ReadFull(kdf, key)
}

// TEST-RULE: go.xcrypto.hkdf.new
// TEST-METADATA: operation:keyderive findingType:kdf algorithmName:HKDF-sha512 api:hkdf.New
func testHKDFNew_SHA512() {
	secret := []byte("secret")
	salt := []byte("salt")
	info := []byte("info")
	
	// ruleid: go.xcrypto.hkdf.new
	kdf := hkdf.New(sha512.New, secret, salt, info)
	key := make([]byte, 64)
	io.ReadFull(kdf, key)
}

// TEST-RULE: go.xcrypto.hkdf.new
// TEST-METADATA: operation:keyderive findingType:kdf algorithmName:HKDF-sha1 api:hkdf.New
func testHKDFNew_SHA1() {
	secret := []byte("secret")
	salt := []byte("salt")
	info := []byte("info")
	
	// ruleid: go.xcrypto.hkdf.new
	kdf := hkdf.New(sha1.New, secret, salt, info)
	key := make([]byte, 20)
	io.ReadFull(kdf, key)
}

// TEST-RULE: go.xcrypto.hkdf.new
// TEST-METADATA: operation:keyderive findingType:kdf algorithmName:HKDF-md5 api:hkdf.New
func testHKDFNew_MD5() {
	secret := []byte("secret")
	salt := []byte("salt")
	info := []byte("info")
	
	// ruleid: go.xcrypto.hkdf.new
	kdf := hkdf.New(md5.New, secret, salt, info)
	key := make([]byte, 16)
	io.ReadFull(kdf, key)
}

// TEST-RULE: go.xcrypto.hkdf.new
// TEST-METADATA: operation:keyderive findingType:kdf algorithmName:HKDF-sha224 api:hkdf.New
func testHKDFNew_SHA224() {
	secret := []byte("secret")
	salt := []byte("salt")
	info := []byte("info")
	
	// ruleid: go.xcrypto.hkdf.new
	kdf := hkdf.New(sha256.New224, secret, salt, info)
	key := make([]byte, 28)
	io.ReadFull(kdf, key)
}

// TEST-RULE: go.xcrypto.hkdf.extract
// TEST-METADATA: operation:keyderive findingType:kdf algorithmName:HKDF-sha256 api:hkdf.Extract
func testHKDFExtract_SHA256() {
	secret := []byte("secret")
	salt := []byte("salt")
	
	// ruleid: go.xcrypto.hkdf.extract
	prk := hkdf.Extract(sha256.New, secret, salt)
	_ = prk
}

// TEST-RULE: go.xcrypto.hkdf.extract
// TEST-METADATA: operation:keyderive findingType:kdf algorithmName:HKDF-sha512 api:hkdf.Extract
func testHKDFExtract_SHA512() {
	secret := []byte("secret")
	salt := []byte("salt")
	
	// ruleid: go.xcrypto.hkdf.extract
	prk := hkdf.Extract(sha512.New, secret, salt)
	_ = prk
}

// TEST-RULE: go.xcrypto.hkdf.extract
// TEST-METADATA: operation:keyderive findingType:kdf algorithmName:HKDF-sha384 api:hkdf.Extract
func testHKDFExtract_SHA384() {
	secret := []byte("secret")
	salt := []byte("salt")
	
	// ruleid: go.xcrypto.hkdf.extract
	prk := hkdf.Extract(sha512.New384, secret, salt)
	_ = prk
}

// TEST-RULE: go.xcrypto.hkdf.expand
// TEST-METADATA: operation:keyderive findingType:kdf algorithmName:HKDF-sha256 api:hkdf.Expand
func testHKDFExpand_SHA256() {
	prk := []byte("pseudorandom key")
	info := []byte("info")
	
	// ruleid: go.xcrypto.hkdf.expand
	kdf := hkdf.Expand(sha256.New, prk, info)
	key := make([]byte, 32)
	io.ReadFull(kdf, key)
}

// TEST-RULE: go.xcrypto.hkdf.expand
// TEST-METADATA: operation:keyderive findingType:kdf algorithmName:HKDF-sha512 api:hkdf.Expand
func testHKDFExpand_SHA512() {
	prk := []byte("pseudorandom key")
	info := []byte("info")
	
	// ruleid: go.xcrypto.hkdf.expand
	kdf := hkdf.Expand(sha512.New, prk, info)
	key := make([]byte, 64)
	io.ReadFull(kdf, key)
}

// TEST-RULE: go.xcrypto.hkdf.expand
// TEST-METADATA: operation:keyderive findingType:kdf algorithmName:HKDF-sha1 api:hkdf.Expand
func testHKDFExpand_SHA1() {
	prk := []byte("pseudorandom key")
	info := []byte("info")
	
	// ruleid: go.xcrypto.hkdf.expand
	kdf := hkdf.Expand(sha1.New, prk, info)
	key := make([]byte, 20)
	io.ReadFull(kdf, key)
}
