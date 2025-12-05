package curve25519_test

import (
	"golang.org/x/crypto/curve25519"
)

// TEST-RULE: go.xcrypto.curve25519.key-exchange
// TEST-METADATA: operation:keyexchange findingType:key_exchange api:curve25519.ScalarMult
func testScalarMult() {
	var dst [32]byte
	scalar := [32]byte{}
	point := [32]byte{}
	
	// ruleid: go.xcrypto.curve25519.key-exchange
	curve25519.ScalarMult(&dst, &scalar, &point)
}

// TEST-RULE: go.xcrypto.curve25519.key-exchange
// TEST-METADATA: operation:keyexchange findingType:key_exchange api:curve25519.X25519
func testX25519() {
	scalar := [32]byte{}
	point := [32]byte{}
	
	// ruleid: go.xcrypto.curve25519.key-exchange
	_, _ = curve25519.X25519(scalar[:], point[:])
}

// TEST-RULE: go.xcrypto.curve25519.public-key-derivation
// TEST-METADATA: operation:keygen findingType:key_generation api:curve25519.ScalarBaseMult
func testScalarBaseMult() {
	var dst [32]byte
	scalar := [32]byte{}
	
	// ruleid: go.xcrypto.curve25519.public-key-derivation
	curve25519.ScalarBaseMult(&dst, &scalar)
}
