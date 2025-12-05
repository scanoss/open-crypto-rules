package blake2s_test

import (
	"golang.org/x/crypto/blake2s"
)

// TEST-RULE: go.xcrypto.blake2s.hash-usage
// TEST-METADATA: operation:digest findingType:hash algorithmParameterSetIdentifier:256 api:blake2s.New256
func testBlake2s256() {
	// ruleid: go.xcrypto.blake2s.hash-usage
	hasher, _ := blake2s.New256(nil)
	_ = hasher
}

// TEST-RULE: go.xcrypto.blake2s.hash-usage
// TEST-METADATA: operation:digest findingType:hash algorithmParameterSetIdentifier:256 api:blake2s.Sum256
func testBlake2sSum256() {
	data := []byte("test")
	// ruleid: go.xcrypto.blake2s.hash-usage
	hash := blake2s.Sum256(data)
	_ = hash
}

// TEST-RULE: go.xcrypto.blake2s.hash-usage
// TEST-METADATA: operation:digest findingType:hash api:blake2s.NewXOF
func testBlake2sXOF() {
	// ruleid: go.xcrypto.blake2s.hash-usage
	xof, _ := blake2s.NewXOF(32, nil)
	_ = xof
}
