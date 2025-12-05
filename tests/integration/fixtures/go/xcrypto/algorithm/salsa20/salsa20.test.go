package salsa20_test

import (
	"golang.org/x/crypto/salsa20/salsa"
)

// TEST-RULE: go.xcrypto.salsa20.stream-cipher
// TEST-METADATA: operation:encrypt findingType:cipher api:salsa.XORKeyStream
func testXORKeyStream() {
	var out [64]byte
	var in [64]byte
	var nonce [16]byte
	var key [32]byte
	
	// ruleid: go.xcrypto.salsa20.stream-cipher
	salsa.XORKeyStream(out[:], in[:], &nonce, &key)
}

// TEST-RULE: go.xcrypto.salsa20.hsalsa20
// TEST-METADATA: operation:digest findingType:hash api:salsa.HSalsa20
func testHSalsa20() {
	var out [32]byte
	var in [16]byte
	var key [32]byte
	var constant [16]byte
	
	// ruleid: go.xcrypto.salsa20.hsalsa20
	salsa.HSalsa20(&out, &in, &key, &constant)
}

// TEST-RULE: go.xcrypto.salsa20.core208
// TEST-METADATA: operation:encrypt findingType:cipher api:salsa.Core208
func testCore208() {
	var out [64]byte
	var in [64]byte
	
	// ruleid: go.xcrypto.salsa20.core208
	salsa.Core208(&out, &in)
}
