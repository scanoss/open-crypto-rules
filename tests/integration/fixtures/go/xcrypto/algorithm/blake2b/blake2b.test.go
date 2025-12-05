package blake2b_test

import (
	"golang.org/x/crypto/blake2b"
)

// TEST-RULE: go.xcrypto.blake2b.hash-usage
// TEST-METADATA: operation:digest findingType:hash algorithmParameterSetIdentifier:256 api:blake2b.New256
func testBlake2b256() {
	// ruleid: go.xcrypto.blake2b.hash-usage
	hasher, _ := blake2b.New256(nil)
	_ = hasher
}

// TEST-RULE: go.xcrypto.blake2b.hash-usage
// TEST-METADATA: operation:digest findingType:hash algorithmParameterSetIdentifier:512 api:blake2b.Sum512
func testBlake2bSum512() {
	data := []byte("test")
	// ruleid: go.xcrypto.blake2b.hash-usage
	hash := blake2b.Sum512(data)
	_ = hash
}

// TEST-RULE: go.xcrypto.blake2b.hash-usage
// TEST-METADATA: operation:digest findingType:hash algorithmParameterSetIdentifier:64 api:blake2b.New
func testBlake2bNew() {
	// ruleid: go.xcrypto.blake2b.hash-usage
	hasher, _ := blake2b.New(64, nil)
	_ = hasher
}

// TEST-RULE: go.xcrypto.blake2b.hash-usage
// TEST-METADATA: operation:digest findingType:hash api:blake2b.NewXOF
func testBlake2bXOF() {
	// ruleid: go.xcrypto.blake2b.hash-usage
	xof, _ := blake2b.NewXOF(64, nil)
	_ = xof
}
