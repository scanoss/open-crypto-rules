package xts_test

import (
	"crypto/aes"

	"golang.org/x/crypto/xts"
)

// TEST-RULE: go.xcrypto.xts.cipher-creation
// TEST-METADATA: operation:encrypt findingType:cipher
func testCipherCreationDirectKeySize() {
	key := make([]byte, 32)
	// ruleid: go.xcrypto.xts.cipher-creation
	cipher, _ := xts.NewCipher(aes.NewCipher, key)
	_ = cipher
}

// TEST-RULE: go.xcrypto.xts.cipher-creation
// TEST-METADATA: operation:encrypt findingType:cipher
func testCipherCreationInlineKeySize() {
	// ruleid: go.xcrypto.xts.cipher-creation
	cipher, _ := xts.NewCipher(aes.NewCipher, make([]byte, 64))
	_ = cipher
}

// TEST-RULE: go.xcrypto.xts.cipher-creation
// TEST-METADATA: operation:encrypt findingType:cipher
func testCipherCreationGeneric() {
	key := []byte("32-byte-key-for-xts-encryption!!")
	// ruleid: go.xcrypto.xts.cipher-creation
	cipher, err := xts.NewCipher(aes.NewCipher, key)
	if err != nil {
		panic(err)
	}
	_ = cipher
}

// TEST-RULE: go.xcrypto.xts.encrypt-decrypt
// TEST-METADATA: operation:encrypt findingType:cipher
func testEncryptDirect() {
	key := make([]byte, 32)
	cipher, _ := xts.NewCipher(aes.NewCipher, key)
	
	plaintext := make([]byte, 512)
	ciphertext := make([]byte, 512)
	sectorNum := uint64(0)
	
	// ruleid: go.xcrypto.xts.encrypt-decrypt
	cipher.Encrypt(ciphertext, plaintext, sectorNum)
}

// TEST-RULE: go.xcrypto.xts.encrypt-decrypt
// TEST-METADATA: operation:encrypt findingType:cipher
func testDecryptDirect() {
	key := make([]byte, 32)
	cipher, _ := xts.NewCipher(aes.NewCipher, key)
	
	ciphertext := make([]byte, 512)
	plaintext := make([]byte, 512)
	sectorNum := uint64(0)
	
	// ruleid: go.xcrypto.xts.encrypt-decrypt
	cipher.Decrypt(plaintext, ciphertext, sectorNum)
}

// TEST-RULE: go.xcrypto.xts.encrypt-decrypt
// TEST-METADATA: operation:encrypt findingType:cipher
func testEncryptDecryptChained() {
	key := make([]byte, 32)
	cipher, _ := xts.NewCipher(aes.NewCipher, key)
	
	data := make([]byte, 512)
	encrypted := make([]byte, 512)
	decrypted := make([]byte, 512)
	
	// ruleid: go.xcrypto.xts.encrypt-decrypt
	// api: xts.Cipher.Encrypt
	cipher.Encrypt(encrypted, data, 0)
	
	// ruleid: go.xcrypto.xts.encrypt-decrypt
	// api: xts.Cipher.Decrypt
	cipher.Decrypt(decrypted, encrypted, 0)
}

// TEST-RULE: go.xcrypto.xts.encrypt-decrypt
// TEST-METADATA: operation:encrypt findingType:cipher
func testEncryptCrossFunction() {
	cipher := createCipher()
	
	plaintext := make([]byte, 512)
	ciphertext := make([]byte, 512)
	
	// ruleid: go.xcrypto.xts.encrypt-decrypt
	cipher.Encrypt(ciphertext, plaintext, 0)
}

func createCipher() *xts.Cipher {
	key := make([]byte, 32)
	cipher, _ := xts.NewCipher(aes.NewCipher, key)
	return cipher
}

// TEST-RULE: go.xcrypto.xts.encrypt-decrypt
// TEST-METADATA: operation:encrypt findingType:cipher
func testDecryptCrossFunction() {
	cipher := createCipher()
	
	ciphertext := make([]byte, 512)
	plaintext := make([]byte, 512)
	
	// ruleid: go.xcrypto.xts.encrypt-decrypt
	cipher.Decrypt(plaintext, ciphertext, 0)
}

// TEST-RULE: go.xcrypto.xts.encrypt-decrypt
// TEST-METADATA: operation:encrypt findingType:cipher
func testStructFieldAccess() {
	type DiskEncryptor struct {
		Cipher *xts.Cipher
	}
	
	key := make([]byte, 32)
	cipher, _ := xts.NewCipher(aes.NewCipher, key)
	
	encryptor := &DiskEncryptor{
		Cipher: cipher,
	}
	
	plaintext := make([]byte, 512)
	ciphertext := make([]byte, 512)
	
	// ruleid: go.xcrypto.xts.encrypt-decrypt
	encryptor.Cipher.Encrypt(ciphertext, plaintext, 0)
}

// TEST-RULE: go.xcrypto.xts.encrypt-decrypt
// TEST-METADATA: operation:encrypt findingType:cipher
func testNestedStructFieldAccess() {
	type CryptoConfig struct {
		Cipher *xts.Cipher
	}
	
	type StorageService struct {
		Config *CryptoConfig
	}
	
	key := make([]byte, 32)
	cipher, _ := xts.NewCipher(aes.NewCipher, key)
	
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
