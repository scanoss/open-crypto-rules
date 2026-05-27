package bcrypt_test

import (
	"golang.org/x/crypto/bcrypt"
)

// TEST-RULE: go.xcrypto.bcrypt.password-hash
// TEST-METADATA: operation:keyderive findingType:kdf
func testGenerateFromPasswordWithCost() {
	password := []byte("myPassword123")
	
	// ruleid: go.xcrypto.bcrypt.password-hash
	hash, err := bcrypt.GenerateFromPassword(password, 10)
	if err != nil {
		panic(err)
	}
	_ = hash
}

// TEST-RULE: go.xcrypto.bcrypt.password-hash
// TEST-METADATA: operation:keyderive findingType:kdf
func testGenerateFromPasswordDefault() {
	password := []byte("myPassword123")
	
	// ruleid: go.xcrypto.bcrypt.password-hash
	hash, _ := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	_ = hash
}

// TEST-RULE: go.xcrypto.bcrypt.password-hash
// TEST-METADATA: operation:keyderive findingType:kdf
func testGenerateFromPasswordHighCost() {
	password := []byte("myPassword123")
	cost := 14
	
	// ruleid: go.xcrypto.bcrypt.password-hash
	hash := generateHash(password, cost)
	_ = hash
}

func generateHash(pwd []byte, cost int) []byte {
	hash, _ := bcrypt.GenerateFromPassword(pwd, cost)
	return hash
}

// TEST-RULE: go.xcrypto.bcrypt.password-verify
// TEST-METADATA: operation:verify findingType:kdf
func testCompareHashAndPassword() {
	password := []byte("myPassword123")
	hash, _ := bcrypt.GenerateFromPassword(password, 10)
	
	// ruleid: go.xcrypto.bcrypt.password-verify
	err := bcrypt.CompareHashAndPassword(hash, password)
	if err != nil {
		panic("password mismatch")
	}
}

// TEST-RULE: go.xcrypto.bcrypt.password-verify
// TEST-METADATA: operation:verify findingType:kdf
func testCompareHashAndPasswordInline() {
	hash := []byte("$2a$10$...")
	password := []byte("myPassword123")
	
	// ruleid: go.xcrypto.bcrypt.password-verify
	if bcrypt.CompareHashAndPassword(hash, password) != nil {
		panic("password mismatch")
	}
}

// TEST-RULE: go.xcrypto.bcrypt.cost-extraction
// TEST-METADATA: operation:keyderive findingType:kdf
func testCostExtraction() {
	password := []byte("myPassword123")
	hash, _ := bcrypt.GenerateFromPassword(password, 12)
	
	// ruleid: go.xcrypto.bcrypt.cost-extraction
	cost, err := bcrypt.Cost(hash)
	if err != nil {
		panic(err)
	}
	_ = cost
}

// TEST-RULE: go.xcrypto.bcrypt.cost-extraction
// TEST-METADATA: operation:keyderive findingType:kdf
func testCostExtractionIgnoreError() {
	hash := []byte("$2a$10$...")
	
	// ruleid: go.xcrypto.bcrypt.cost-extraction
	cost, _ := bcrypt.Cost(hash)
	_ = cost
}

