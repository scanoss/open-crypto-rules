package tea_test

import (
	"golang.org/x/crypto/tea"
)

// TEST-RULE: go.xcrypto.tea.block-cipher
// TEST-METADATA: operation:encrypt findingType:cipher
func testNewCipherWithSize() {
	key := make([]byte, 16)
	
	// ruleid: go.xcrypto.tea.block-cipher
	cipher, _ := tea.NewCipher(key)
	_ = cipher
}

// TEST-RULE: go.xcrypto.tea.block-cipher
// TEST-METADATA: operation:encrypt findingType:cipher
func testNewCipher() {
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	
	// ruleid: go.xcrypto.tea.block-cipher
	cipher, _ := tea.NewCipher(key)
	_ = cipher
}

// TEST-RULE: go.xcrypto.tea.block-cipher-with-rounds
// TEST-METADATA: operation:encrypt findingType:cipher
func testNewCipherWithRoundsAndSize() {
	key := make([]byte, 16)
	
	// ruleid: go.xcrypto.tea.block-cipher-with-rounds
	cipher, _ := tea.NewCipherWithRounds(key, 64)
	_ = cipher
}

// TEST-RULE: go.xcrypto.tea.block-cipher-with-rounds
// TEST-METADATA: operation:encrypt findingType:cipher
func testNewCipherWithRounds() {
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	
	// ruleid: go.xcrypto.tea.block-cipher-with-rounds
	cipher, _ := tea.NewCipherWithRounds(key, 32)
	_ = cipher
}
