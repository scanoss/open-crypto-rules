package openpgp_test

import (
	"os"

	"golang.org/x/crypto/openpgp"
)

// TEST-RULE: go.xcrypto.openpgp.encrypt
// TEST-METADATA: assetType=protocol, findingType=cipher, operation=encrypt, protocolName=OpenPGP, protocolType=other, library=golang.org/x/crypto/openpgp

func test1Encrypt() {
	plaintext, err := openpgp.Encrypt(os.Stdout, nil, nil, nil, nil)
	_ = plaintext
	_ = err
}

// TEST-METADATA: assetType=protocol, findingType=cipher, operation=encrypt, protocolName=OpenPGP, protocolType=other, library=golang.org/x/crypto/openpgp

func test2SymmetricallyEncrypt() {
	symmWriter, symmErr := openpgp.SymmetricallyEncrypt(os.Stdout, []byte("password"), nil, nil)
	_ = symmWriter
	_ = symmErr
}

// TEST-RULE: go.xcrypto.openpgp.decrypt
// TEST-METADATA: assetType=protocol, findingType=cipher, operation=decrypt, protocolName=OpenPGP, protocolType=other, library=golang.org/x/crypto/openpgp

func test3ReadMessage() {
	message, err := openpgp.ReadMessage(os.Stdin, nil, nil, nil)
	_ = message
	_ = err
}

// TEST-RULE: go.xcrypto.openpgp.sign
// TEST-METADATA: assetType=protocol, findingType=signature, operation=sign, protocolName=OpenPGP, protocolType=other, library=golang.org/x/crypto/openpgp

func test4Sign() {
	writer, err := openpgp.Sign(os.Stdout, nil, nil, nil)
	_ = writer
	_ = err
}

// TEST-METADATA: assetType=protocol, findingType=signature, operation=sign, protocolName=OpenPGP, protocolType=other, library=golang.org/x/crypto/openpgp

func test5DetachSign() {
	detachErr := openpgp.DetachSign(os.Stdout, nil, os.Stdin, nil)
	_ = detachErr
}

// TEST-METADATA: assetType=protocol, findingType=signature, operation=sign, protocolName=OpenPGP, protocolType=other, library=golang.org/x/crypto/openpgp

func test6DetachSignText() {
	textErr := openpgp.DetachSignText(os.Stdout, nil, os.Stdin, nil)
	_ = textErr
}

// TEST-METADATA: assetType=protocol, findingType=signature, operation=sign, protocolName=OpenPGP, protocolType=other, library=golang.org/x/crypto/openpgp

func test7ArmoredDetachSign() {
	armoredErr := openpgp.ArmoredDetachSign(os.Stdout, nil, os.Stdin, nil)
	_ = armoredErr
}

// TEST-METADATA: assetType=protocol, findingType=signature, operation=sign, protocolName=OpenPGP, protocolType=other, library=golang.org/x/crypto/openpgp

func test8ArmoredDetachSignText() {
	armoredTextErr := openpgp.ArmoredDetachSignText(os.Stdout, nil, os.Stdin, nil)
	_ = armoredTextErr
}

// TEST-METADATA: assetType=protocol, findingType=signature, operation=sign, protocolName=OpenPGP, protocolType=other, library=golang.org/x/crypto/openpgp

func test9SignIdentity() {
	entity, _ := openpgp.NewEntity("Test", "Comment", "test@example.com", nil)
	signErr := entity.SignIdentity("sign-me", nil, nil)
	_ = signErr
}

// TEST-RULE: go.xcrypto.openpgp.verify
// TEST-METADATA: assetType=protocol, findingType=signature, operation=verify, protocolName=OpenPGP, protocolType=other, library=golang.org/x/crypto/openpgp

func test10CheckDetachedSignature() {
	signer, err := openpgp.CheckDetachedSignature(nil, os.Stdin, os.Stdin)
	_ = signer
	_ = err
}

// TEST-METADATA: assetType=protocol, findingType=signature, operation=verify, protocolName=OpenPGP, protocolType=other, library=golang.org/x/crypto/openpgp

func test11CheckArmoredDetachedSignature() {
	armoredSigner, armoredErr := openpgp.CheckArmoredDetachedSignature(nil, os.Stdin, os.Stdin)
	_ = armoredSigner
	_ = armoredErr
}

// TEST-RULE: go.xcrypto.openpgp.keygen
// TEST-METADATA: assetType=protocol, findingType=key_generation, operation=keygen, protocolName=OpenPGP, protocolType=other, library=golang.org/x/crypto/openpgp

func test12NewEntity() {
	entity, err := openpgp.NewEntity("Test User", "Comment", "test@example.com", nil)
	_ = entity
	_ = err
}

// TEST-METADATA: assetType=protocol, findingType=key_generation, operation=keygen, protocolName=OpenPGP, protocolType=other, library=golang.org/x/crypto/openpgp

func test13ReadEntity() {
	readEntity, readErr := openpgp.ReadEntity(nil)
	_ = readEntity
	_ = readErr
}

// TEST-METADATA: assetType=protocol, findingType=key_generation, operation=keygen, protocolName=OpenPGP, protocolType=other, library=golang.org/x/crypto/openpgp

func test14ReadKeyRing() {
	keyring, keyringErr := openpgp.ReadKeyRing(os.Stdin)
	_ = keyring
	_ = keyringErr
}

// TEST-METADATA: assetType=protocol, findingType=key_generation, operation=keygen, protocolName=OpenPGP, protocolType=other, library=golang.org/x/crypto/openpgp

func test15ReadArmoredKeyRing() {
	armoredKeyring, armoredErr := openpgp.ReadArmoredKeyRing(os.Stdin)
	_ = armoredKeyring
	_ = armoredErr
}

// TEST-METADATA: assetType=protocol, findingType=key_generation, operation=keygen, protocolName=OpenPGP, protocolType=other, library=golang.org/x/crypto/openpgp

func test16Serialize() {
	entity, _ := openpgp.NewEntity("Test", "Comment", "test@example.com", nil)
	if entity != nil {
		serializeErr := entity.Serialize(os.Stdout)
		_ = serializeErr
	}
}

// TEST-METADATA: assetType=protocol, findingType=key_generation, operation=keygen, protocolName=OpenPGP, protocolType=other, library=golang.org/x/crypto/openpgp

func test17SerializePrivate() {
	entity, _ := openpgp.NewEntity("Test", "Comment", "test@example.com", nil)
	if entity != nil {
		privateErr := entity.SerializePrivate(os.Stdout, nil)
		_ = privateErr
	}
}

