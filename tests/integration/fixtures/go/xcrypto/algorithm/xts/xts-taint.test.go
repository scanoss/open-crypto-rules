package xts_test

import (
	"crypto/aes"

	"golang.org/x/crypto/xts"
)

// TEST-RULE: go.xcrypto.xts.encrypt-decrypt
// TEST-METADATA: operation:decrypt findingType:cipher api:xts.Cipher.Encrypt
func testDirectUsage() {
	key := make([]byte, 32)
	cipher, _ := xts.NewCipher(aes.NewCipher, key)
	
	plaintext := make([]byte, 512)
	ciphertext := make([]byte, 512)
	
	// ruleid: go.xcrypto.xts.encrypt-decrypt
	cipher.Encrypt(ciphertext, plaintext, 0)
}

// TEST-RULE: go.xcrypto.xts.encrypt-decrypt
// TEST-METADATA: operation:decrypt findingType:cipher api:xts.Cipher.Encrypt
func testCrossFunctionTaint() {
	key := make([]byte, 32)
	cipher, _ := xts.NewCipher(aes.NewCipher, key)
	
	// Taint should propagate through function parameter
	encryptWithCipher(cipher, make([]byte, 512), make([]byte, 512))
}

func encryptWithCipher(c *xts.Cipher, dst, src []byte) {
	// ruleid: go.xcrypto.xts.encrypt-decrypt
	c.Encrypt(dst, src, 0)
}

// TEST-RULE: go.xcrypto.xts.encrypt-decrypt
// TEST-METADATA: operation:decrypt findingType:cipher api:xts.Cipher.Encrypt
func testStructFieldTaint() {
	type DiskEncryptor struct {
		Cipher *xts.Cipher
	}
	
	key := make([]byte, 32)
	cipher, _ := xts.NewCipher(aes.NewCipher, key)
	
	// Taint should propagate through struct field assignment
	encryptor := &DiskEncryptor{
		Cipher: cipher,
	}
	
	plaintext := make([]byte, 512)
	ciphertext := make([]byte, 512)
	
	// ruleid: go.xcrypto.xts.encrypt-decrypt
	encryptor.Cipher.Encrypt(ciphertext, plaintext, 0)
}

// TEST-RULE: go.xcrypto.xts.encrypt-decrypt
// TEST-METADATA: operation:decrypt findingType:cipher api:xts.Cipher.Encrypt
func testNestedStructTaint() {
	type CryptoConfig struct {
		Cipher *xts.Cipher
	}
	
	type StorageService struct {
		Config *CryptoConfig
	}
	
	key := make([]byte, 32)
	cipher, _ := xts.NewCipher(aes.NewCipher, key)
	
	// Multiple levels of struct nesting
	service := &StorageService{
		Config: &CryptoConfig{
			Cipher: cipher,
		},
	}
	
	plaintext := make([]byte, 512)
	ciphertext := make([]byte, 512)
	
	// ruleid: go.xcrypto.xts.encrypt-decrypt
	service.Config.Cipher.Encrypt(ciphertext, plaintext, 0)
}

// TEST-RULE: go.xcrypto.xts.encrypt-decrypt
// TEST-METADATA: operation:decrypt findingType:cipher
func testMultipleOperations() {
	key := make([]byte, 32)
	cipher, _ := xts.NewCipher(aes.NewCipher, key)
	
	data := make([]byte, 512)
	encrypted := make([]byte, 512)
	decrypted := make([]byte, 512)
	
	// Multiple taint sinks from same source
	// ruleid: go.xcrypto.xts.encrypt-decrypt
	// api: xts.Cipher.Encrypt
	cipher.Encrypt(encrypted, data, 0)
	
	// ruleid: go.xcrypto.xts.encrypt-decrypt
	// api: xts.Cipher.Decrypt
	cipher.Decrypt(decrypted, encrypted, 0)
}
