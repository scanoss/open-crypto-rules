package cryptobyte_test

import (
	"golang.org/x/crypto/cryptobyte"
)

// TEST-RULE: go.xcrypto.cryptobyte.usage
// TEST-METADATA: operation:other findingType:other api:cryptobyte.NewBuilder
func testNewBuilder() {
	// ruleid: go.xcrypto.cryptobyte.usage
	builder := cryptobyte.NewBuilder(nil)
	_ = builder
}

// TEST-RULE: go.xcrypto.cryptobyte.usage
// TEST-METADATA: operation:other findingType:other api:cryptobyte.String
func testString() {
	data := []byte{0x01, 0x02, 0x03}
	
	// ruleid: go.xcrypto.cryptobyte.usage
	str := cryptobyte.String(data)
	_ = str
}

