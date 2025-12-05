package blowfish_test

import (
	"golang.org/x/crypto/blowfish"
)

// TEST-RULE: go.xcrypto.blowfish.key-generation
// TEST-METADATA: operation:keygen findingType:key_generation api:blowfish.NewCipher
func testKeyGeneration() {
	key := make([]byte, 16)
	
	// ruleid: go.xcrypto.blowfish.key-generation
	cipher, err := blowfish.NewCipher(key)
	if err != nil {
		panic(err)
	}
	_ = cipher
}

// TEST-RULE: go.xcrypto.blowfish.key-generation
// TEST-METADATA: operation:keygen findingType:key_generation algorithmParameterSetIdentifier:16 api:blowfish.NewCipher
func testKeyGenerationWithSize() {
	key := make([]byte, 16)
	
	// ruleid: go.xcrypto.blowfish.key-generation
	cipher, _ := blowfish.NewCipher(key)
	_ = cipher
}

// TEST-RULE: go.xcrypto.blowfish.salted-key-generation
// TEST-METADATA: operation:keygen findingType:key_generation api:blowfish.NewSaltedCipher
func testSaltedKeyGeneration() {
	key := make([]byte, 16)
	salt := make([]byte, 16)
	
	// ruleid: go.xcrypto.blowfish.salted-key-generation
	cipher, err := blowfish.NewSaltedCipher(key, salt)
	if err != nil {
		panic(err)
	}
	_ = cipher
}

// TEST-RULE: go.xcrypto.blowfish.salted-key-generation
// TEST-METADATA: operation:keygen findingType:key_generation algorithmParameterSetIdentifier:16 api:blowfish.NewSaltedCipher
func testSaltedKeyGenerationWithSize() {
	key := make([]byte, 16)
	salt := []byte{0x01, 0x02, 0x03, 0x04}
	
	// ruleid: go.xcrypto.blowfish.salted-key-generation
	cipher, _ := blowfish.NewSaltedCipher(key, salt)
	_ = cipher
}

// TEST-RULE: go.xcrypto.blowfish.key-expansion
// TEST-METADATA: operation:keygen findingType:key_generation api:blowfish.ExpandKey
func testKeyExpansion() {
	key := make([]byte, 16)
	cipher, _ := blowfish.NewCipher(key)
	expansionKey := make([]byte, 8)
	
	// ruleid: go.xcrypto.blowfish.key-expansion
	blowfish.ExpandKey(expansionKey, cipher)
}

// TEST-RULE: go.xcrypto.blowfish.encrypt
// TEST-METADATA: operation:encrypt findingType:cipher api:Cipher.Encrypt
func testEncrypt() {
	key := make([]byte, 16)
	cipher, err := blowfish.NewCipher(key)
	if err != nil {
		panic(err)
	}
	
	var dst, src [8]byte
	// ruleid: go.xcrypto.blowfish.encrypt
	cipher.Encrypt(dst[:], src[:])
}

// TEST-RULE: go.xcrypto.blowfish.encrypt
// TEST-METADATA: operation:encrypt findingType:cipher api:Cipher.Encrypt
func testEncryptUnderscore() {
	key := make([]byte, 16)
	cipher, _ := blowfish.NewCipher(key)
	
	var dst, src [8]byte
	// ruleid: go.xcrypto.blowfish.encrypt
	cipher.Encrypt(dst[:], src[:])
}

// TEST-RULE: go.xcrypto.blowfish.encrypt
// TEST-METADATA: operation:encrypt findingType:cipher api:Cipher.Encrypt
func testEncryptDirect() {
	key := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	cipher := &blowfish.Cipher{}
	cipher, _ = blowfish.NewCipher(key)
	
	var dst, src [8]byte
	// ruleid: go.xcrypto.blowfish.encrypt
	cipher.Encrypt(dst[:], src[:])
}

// TEST-RULE: go.xcrypto.blowfish.encrypt
// TEST-METADATA: operation:encrypt findingType:cipher api:Cipher.Encrypt
func testEncryptSalted() {
	key := make([]byte, 16)
	salt := make([]byte, 16)
	cipher, _ := blowfish.NewSaltedCipher(key, salt)
	
	var dst, src [8]byte
	// ruleid: go.xcrypto.blowfish.encrypt
	cipher.Encrypt(dst[:], src[:])
}

// TEST-RULE: go.xcrypto.blowfish.decrypt
// TEST-METADATA: operation:decrypt findingType:cipher api:Cipher.Decrypt
func testDecrypt() {
	key := make([]byte, 16)
	cipher, err := blowfish.NewCipher(key)
	if err != nil {
		panic(err)
	}
	
	var dst, src [8]byte
	// ruleid: go.xcrypto.blowfish.decrypt
	cipher.Decrypt(dst[:], src[:])
}

// TEST-RULE: go.xcrypto.blowfish.decrypt
// TEST-METADATA: operation:decrypt findingType:cipher api:Cipher.Decrypt
func testDecryptUnderscore() {
	key := make([]byte, 16)
	cipher, _ := blowfish.NewCipher(key)
	
	var dst, src [8]byte
	// ruleid: go.xcrypto.blowfish.decrypt
	cipher.Decrypt(dst[:], src[:])
}

// TEST-RULE: go.xcrypto.blowfish.decrypt
// TEST-METADATA: operation:decrypt findingType:cipher api:Cipher.Decrypt
func testDecryptDirect() {
	key := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	cipher := &blowfish.Cipher{}
	cipher, _ = blowfish.NewCipher(key)
	
	var dst, src [8]byte
	// ruleid: go.xcrypto.blowfish.decrypt
	cipher.Decrypt(dst[:], src[:])
}

// TEST-RULE: go.xcrypto.blowfish.decrypt
// TEST-METADATA: operation:decrypt findingType:cipher api:Cipher.Decrypt
func testDecryptSalted() {
	key := make([]byte, 16)
	salt := make([]byte, 16)
	cipher, _ := blowfish.NewSaltedCipher(key, salt)
	
	var dst, src [8]byte
	// ruleid: go.xcrypto.blowfish.decrypt
	cipher.Decrypt(dst[:], src[:])
}
