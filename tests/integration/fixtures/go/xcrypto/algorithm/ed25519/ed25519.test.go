package ed25519_test

import (
	"crypto/rand"
	"golang.org/x/crypto/ed25519"
)

// TEST-RULE: go.xcrypto.ed25519.generatekey
// TEST-METADATA: operation:keygen findingType:key_generation api:ed25519.GenerateKey
func testEd25519GenerateKey() {
	// ruleid: go.xcrypto.ed25519.generatekey
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	_, _ = pubKey, privKey
}

// TEST-RULE: go.xcrypto.ed25519.newkey-from-seed
// TEST-METADATA: operation:keygen findingType:key_generation api:ed25519.NewKeyFromSeed
func testEd25519NewKeyFromSeed() {
	seed := make([]byte, ed25519.SeedSize)
	rand.Read(seed)
	
	// ruleid: go.xcrypto.ed25519.newkey-from-seed
	privKey := ed25519.NewKeyFromSeed(seed)
	_ = privKey
}

// TEST-RULE: go.xcrypto.ed25519.sign
// TEST-METADATA: operation:sign findingType:signature api:ed25519.Sign
func testEd25519Sign() {
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	_ = pubKey
	message := []byte("test message")
	
	// ruleid: go.xcrypto.ed25519.sign
	signature := ed25519.Sign(privKey, message)
	_ = signature
}

// TEST-RULE: go.xcrypto.ed25519.verify
// TEST-METADATA: operation:verify findingType:signature api:ed25519.Verify
func testEd25519Verify() {
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	message := []byte("test message")
	signature := ed25519.Sign(privKey, message)
	
	// ruleid: go.xcrypto.ed25519.verify
	valid := ed25519.Verify(pubKey, message, signature)
	_ = valid
}
