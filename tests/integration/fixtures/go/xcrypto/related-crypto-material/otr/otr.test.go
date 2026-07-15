package otr_test

import (
	"crypto/rand"

	"golang.org/x/crypto/otr"
)

// TEST-RULE: go.xcrypto.otr.privatekey-generation
// TEST-METADATA: operation:other findingType:key_generation api:otr.PrivateKey.Generate
func testPrivateKeyGenerate() {
	var privKey otr.PrivateKey
	// ruleid: go.xcrypto.otr.privatekey-generation
	privKey.Generate(rand.Reader)
}

// TEST-RULE: go.xcrypto.otr.privatekey-operations
// TEST-METADATA: operation:other findingType:key_generation api:otr.PrivateKey.Import
func testPrivateKeyImport() {
	var privKey otr.PrivateKey
	keyData := []byte("key data")
	
	// ruleid: go.xcrypto.otr.privatekey-operations
	success := privKey.Import(keyData)
	_ = success
}

// TEST-RULE: go.xcrypto.otr.privatekey-operations
// TEST-METADATA: operation:other findingType:key_generation api:otr.PrivateKey.Serialize
func testPrivateKeySerialize() {
	var privKey otr.PrivateKey
	keyData := []byte("key data")
	
	// ruleid: go.xcrypto.otr.privatekey-operations
	serialized := privKey.Serialize(keyData)
	_ = serialized
}

// TEST-RULE: go.xcrypto.otr.privatekey-operations
// TEST-METADATA: operation:other findingType:key_generation api:otr.PrivateKey.Parse
func testPrivateKeyParse() {
	var privKey otr.PrivateKey
	keyData := []byte("key data")
	
	// ruleid: go.xcrypto.otr.privatekey-operations
	_, ok := privKey.Parse(keyData)
	_ = ok
}

// TEST-RULE: go.xcrypto.otr.sign
// TEST-METADATA: operation:sign findingType:signature api:otr.PrivateKey.Sign
func testPrivateKeySign() {
	var privKey otr.PrivateKey
	privKey.Generate(rand.Reader)
	hashed := []byte("hashed data")
	
	// ruleid: go.xcrypto.otr.sign
	signature := privKey.Sign(rand.Reader, hashed)
	_ = signature
}

// TEST-RULE: go.xcrypto.otr.publickey-operations
// TEST-METADATA: operation:other findingType:key_generation api:otr.PublicKey.Serialize
func testPublicKeySerialize() {
	var pubKey otr.PublicKey
	keyData := []byte("key data")
	
	// ruleid: go.xcrypto.otr.publickey-operations
	serialized := pubKey.Serialize(keyData)
	_ = serialized
}

// TEST-RULE: go.xcrypto.otr.publickey-operations
// TEST-METADATA: operation:other findingType:key_generation api:otr.PublicKey.Parse
func testPublicKeyParse() {
	var pubKey otr.PublicKey
	keyData := []byte("key data")
	
	// ruleid: go.xcrypto.otr.publickey-operations
	_, ok := pubKey.Parse(keyData)
	_ = ok
}

// TEST-RULE: go.xcrypto.otr.verify
// TEST-METADATA: operation:verify findingType:signature api:otr.PublicKey.Verify
func testPublicKeyVerify() {
	var pubKey otr.PublicKey
	hashed := []byte("hashed data")
	signature := []byte("signature data with exactly 40 bytes!!")
	
	// ruleid: go.xcrypto.otr.verify
	_, ok := pubKey.Verify(hashed, signature)
	_ = ok
}

// TEST-RULE: go.xcrypto.otr.fingerprint
// TEST-METADATA: operation:digest findingType:hash api:otr.PublicKey.Fingerprint
func testFingerprint() {
	var pubKey otr.PublicKey
	
	// ruleid: go.xcrypto.otr.fingerprint
	fingerprint := pubKey.Fingerprint()
	_ = fingerprint
}

// TEST-RULE: go.xcrypto.otr.privatekey-generation
// TEST-METADATA: operation:other findingType:key_generation api:otr.PrivateKey.Generate
func testPrivateKeyGenerateCrossFunction() {
	var key otr.PrivateKey
	generateKey(&key)
}

func generateKey(key *otr.PrivateKey) {
	// ruleid: go.xcrypto.otr.privatekey-generation
	key.Generate(rand.Reader)
}

// TEST-RULE: go.xcrypto.otr.privatekey-operations
// TEST-METADATA: operation:other findingType:key_generation api:otr.PrivateKey.Serialize
func testPrivateKeySerializeStruct() {
	type KeyStore struct {
		PrivateKey otr.PrivateKey
	}
	
	var store KeyStore
	data := []byte("key data")
	
	// ruleid: go.xcrypto.otr.privatekey-operations
	store.PrivateKey.Serialize(data)
}

// TEST-RULE: go.xcrypto.otr.privatekey-operations
// TEST-METADATA: operation:other findingType:key_generation api:otr.PrivateKey.Import
func testPrivateKeyImportStruct() {
	type KeyStore struct {
		Key otr.PrivateKey
	}
	
	var store KeyStore
	data := []byte("key data")
	
	// ruleid: go.xcrypto.otr.privatekey-operations
	store.Key.Import(data)
}

// TEST-RULE: go.xcrypto.otr.sign
// TEST-METADATA: operation:sign findingType:signature api:otr.PrivateKey.Sign
func testPrivateKeySignStruct() {
	type KeyStore struct {
		PrivateKey otr.PrivateKey
	}
	
	var store KeyStore
	store.PrivateKey.Generate(rand.Reader)
	hashed := []byte("hashed data")
	
	// ruleid: go.xcrypto.otr.sign
	signature := store.PrivateKey.Sign(rand.Reader, hashed)
	_ = signature
}

// TEST-RULE: go.xcrypto.otr.publickey-operations
// TEST-METADATA: operation:other findingType:key_generation api:otr.PublicKey.Serialize
func testPublicKeySerializeStruct() {
	type KeyStore struct {
		PublicKey otr.PublicKey
	}
	
	var store KeyStore
	data := []byte("key data")
	
	// ruleid: go.xcrypto.otr.publickey-operations
	store.PublicKey.Serialize(data)
}

// TEST-RULE: go.xcrypto.otr.verify
// TEST-METADATA: operation:verify findingType:signature api:otr.PublicKey.Verify
func testPublicKeyVerifyStruct() {
	type Identity struct {
		PublicKey otr.PublicKey
	}
	
	var identity Identity
	hashed := []byte("hashed data")
	signature := []byte("signature data with exactly 40 bytes!!")
	
	// ruleid: go.xcrypto.otr.verify
	_, ok := identity.PublicKey.Verify(hashed, signature)
	_ = ok
}

// TEST-RULE: go.xcrypto.otr.fingerprint
// TEST-METADATA: operation:digest findingType:hash api:otr.PublicKey.Fingerprint
func testFingerprintStructField() {
	type Identity struct {
		PublicKey otr.PublicKey
	}
	
	var identity Identity
	
	// ruleid: go.xcrypto.otr.fingerprint
	identity.PublicKey.Fingerprint()
}

// TEST-RULE: go.xcrypto.otr.sign
// TEST-METADATA: operation:sign findingType:signature api:otr.PrivateKey.Sign
func testPrivateKeySignCrossFunction() {
	var key otr.PrivateKey
	key.Generate(rand.Reader)
	signData(&key, []byte("hashed"))
}

func signData(key *otr.PrivateKey, hashed []byte) {
	// ruleid: go.xcrypto.otr.sign
	key.Sign(rand.Reader, hashed)
}

// TEST-RULE: go.xcrypto.otr.verify
// TEST-METADATA: operation:verify findingType:signature api:otr.PublicKey.Verify
func testPublicKeyVerifyCrossFunction() {
	var key otr.PublicKey
	signature := []byte("signature data with exactly 40 bytes!!")
	verifySignature(&key, []byte("hashed"), signature)
}

func verifySignature(key *otr.PublicKey, hashed, sig []byte) {
	// ruleid: go.xcrypto.otr.verify
	key.Verify(hashed, sig)
}

// TEST-RULE: go.xcrypto.otr.privatekey-operations
// TEST-METADATA: operation:other findingType:key_generation api:otr.PrivateKey.Serialize
func testPrivateKeySerializeCrossFunction() {
	var key otr.PrivateKey
	serializePrivateKey(&key, []byte("data"))
}

func serializePrivateKey(key *otr.PrivateKey, data []byte) {
	// ruleid: go.xcrypto.otr.privatekey-operations
	key.Serialize(data)
}

// TEST-RULE: go.xcrypto.otr.publickey-operations
// TEST-METADATA: operation:other findingType:key_generation api:otr.PublicKey.Serialize
func testPublicKeySerializeCrossFunction() {
	var key otr.PublicKey
	serializePublicKey(&key, []byte("data"))
}

func serializePublicKey(key *otr.PublicKey, data []byte) {
	// ruleid: go.xcrypto.otr.publickey-operations
	key.Serialize(data)
}
