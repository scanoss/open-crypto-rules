package xtea_test

import (
	"golang.org/x/crypto/xtea"
)

// TEST-RULE: go.xcrypto.xtea.key-generation
// TEST-METADATA: operation:keygen findingType:key_generation algorithmParameterSetIdentifier:16 api:xtea.NewCipher
func testKeyGenerationWithSize() {
	key := make([]byte, 16)
	
	// ruleid: go.xcrypto.xtea.key-generation
	cipher, err := xtea.NewCipher(key)
	if err != nil {
		panic(err)
	}
	_ = cipher
}

// TEST-RULE: go.xcrypto.xtea.key-generation
// TEST-METADATA: operation:keygen findingType:key_generation api:xtea.NewCipher
func testKeyGenerationDirect() {
	key := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
	             0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	
	// ruleid: go.xcrypto.xtea.key-generation
	cipher, _ := xtea.NewCipher(key)
	_ = cipher
}

// TEST-RULE: go.xcrypto.xtea.encrypt
// TEST-METADATA: operation:encrypt findingType:cipher api:Cipher.Encrypt
func testEncrypt() {
	key := make([]byte, 16)
	cipher, err := xtea.NewCipher(key)
	if err != nil {
		panic(err)
	}
	
	var dst, src [8]byte
	// ruleid: go.xcrypto.xtea.encrypt
	cipher.Encrypt(dst[:], src[:])
}

// TEST-RULE: go.xcrypto.xtea.encrypt
// TEST-METADATA: operation:encrypt findingType:cipher api:Cipher.Encrypt
func testEncryptUnderscore() {
	key := make([]byte, 16)
	cipher, _ := xtea.NewCipher(key)
	
	var dst, src [8]byte
	// ruleid: go.xcrypto.xtea.encrypt
	cipher.Encrypt(dst[:], src[:])
}

// TEST-RULE: go.xcrypto.xtea.encrypt
// TEST-METADATA: operation:encrypt findingType:cipher api:Cipher.Encrypt
func testEncryptDirect() {
	key := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
	             0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	cipher := &xtea.Cipher{}
	cipher, _ = xtea.NewCipher(key)
	
	var dst, src [8]byte
	// ruleid: go.xcrypto.xtea.encrypt
	cipher.Encrypt(dst[:], src[:])
}

// TEST-RULE: go.xcrypto.xtea.decrypt
// TEST-METADATA: operation:decrypt findingType:cipher api:Cipher.Decrypt
func testDecrypt() {
	key := make([]byte, 16)
	cipher, err := xtea.NewCipher(key)
	if err != nil {
		panic(err)
	}
	
	var dst, src [8]byte
	// ruleid: go.xcrypto.xtea.decrypt
	cipher.Decrypt(dst[:], src[:])
}

// TEST-RULE: go.xcrypto.xtea.decrypt
// TEST-METADATA: operation:decrypt findingType:cipher api:Cipher.Decrypt
func testDecryptUnderscore() {
	key := make([]byte, 16)
	cipher, _ := xtea.NewCipher(key)
	
	var dst, src [8]byte
	// ruleid: go.xcrypto.xtea.decrypt
	cipher.Decrypt(dst[:], src[:])
}

// TEST-RULE: go.xcrypto.xtea.decrypt
// TEST-METADATA: operation:decrypt findingType:cipher api:Cipher.Decrypt
func testDecryptDirect() {
	key := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
	             0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	cipher := &xtea.Cipher{}
	cipher, _ = xtea.NewCipher(key)
	
	var dst, src [8]byte
	// ruleid: go.xcrypto.xtea.decrypt
	cipher.Decrypt(dst[:], src[:])
}

