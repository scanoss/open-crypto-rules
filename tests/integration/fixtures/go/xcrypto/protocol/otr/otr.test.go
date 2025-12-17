package otr_test

import (
	"crypto/rand"

	"golang.org/x/crypto/otr"
)

// TEST-RULE: go.xcrypto.otr.encrypt
// TEST-METADATA: operation:encrypt findingType:cipher api:otr.Conversation.Send
func testEncryptDirect() {
	var privKey otr.PrivateKey
	privKey.Generate(rand.Reader)
	
	conv := &otr.Conversation{
		PrivateKey: &privKey,
	}
	
	message := []byte("secret message")
	// ruleid: go.xcrypto.otr.encrypt
	encrypted, err := conv.Send(message)
	if err != nil {
		panic(err)
	}
	_ = encrypted
}

// TEST-RULE: go.xcrypto.otr.decrypt
// TEST-METADATA: operation:decrypt findingType:cipher api:otr.Conversation.Receive
func testDecryptDirect() {
	var privKey otr.PrivateKey
	privKey.Generate(rand.Reader)
	
	conv := &otr.Conversation{
		PrivateKey: &privKey,
	}
	
	encrypted := []byte("encrypted data")
	// ruleid: go.xcrypto.otr.decrypt
	plaintext, _, _, _, err := conv.Receive(encrypted)
	if err != nil {
		panic(err)
	}
	_ = plaintext
}

// TEST-RULE: go.xcrypto.otr.keyexchange
// TEST-METADATA: operation:keyexchange findingType:key_exchange api:otr.Conversation.Authenticate
func testAuthenticateDirect() {
	var privKey otr.PrivateKey
	privKey.Generate(rand.Reader)
	
	conv := &otr.Conversation{
		PrivateKey: &privKey,
	}
	
	secret := []byte("shared-secret")
	question := "What is the answer?"
	
	// ruleid: go.xcrypto.otr.keyexchange
	result, err := conv.Authenticate(question, secret)
	if err != nil {
		panic(err)
	}
	_ = result
}

// TEST-RULE: go.xcrypto.otr.conversation-operations
// TEST-METADATA: operation:other findingType:cipher api:otr.Conversation.End
func testEndConversation() {
	var privKey otr.PrivateKey
	privKey.Generate(rand.Reader)
	
	conv := &otr.Conversation{
		PrivateKey: &privKey,
	}
	
	// ruleid: go.xcrypto.otr.conversation-operations
	messages := conv.End()
	_ = messages
}

// TEST-RULE: go.xcrypto.otr.conversation-operations
// TEST-METADATA: operation:other findingType:cipher api:otr.Conversation.IsEncrypted
func testIsEncrypted() {
	var privKey otr.PrivateKey
	privKey.Generate(rand.Reader)
	
	conv := &otr.Conversation{
		PrivateKey: &privKey,
	}
	
	// ruleid: go.xcrypto.otr.conversation-operations
	encrypted := conv.IsEncrypted()
	_ = encrypted
}

// TEST-RULE: go.xcrypto.otr.conversation-operations
// TEST-METADATA: operation:other findingType:cipher api:otr.Conversation.SMPQuestion
func testSMPQuestion() {
	var privKey otr.PrivateKey
	privKey.Generate(rand.Reader)
	
	conv := &otr.Conversation{
		PrivateKey: &privKey,
	}
	
	// ruleid: go.xcrypto.otr.conversation-operations
	question := conv.SMPQuestion()
	_ = question
}

// TEST-RULE: go.xcrypto.otr.encrypt
// TEST-METADATA: operation:encrypt findingType:cipher api:otr.Conversation.Send
func testEncryptCrossFunction() {
	conv := createConversation()
	
	message := []byte("secret message")
	// ruleid: go.xcrypto.otr.encrypt
	encrypted, _ := conv.Send(message)
	_ = encrypted
}

// TEST-RULE: go.xcrypto.otr.decrypt
// TEST-METADATA: operation:decrypt findingType:cipher api:otr.Conversation.Receive
func testDecryptCrossFunction() {
	conv := createConversation()
	
	encrypted := []byte("encrypted data")
	// ruleid: go.xcrypto.otr.decrypt
	plaintext, _, _, _, _ := conv.Receive(encrypted)
	_ = plaintext
}

// TEST-RULE: go.xcrypto.otr.keyexchange
// TEST-METADATA: operation:keyexchange findingType:key_exchange api:otr.Conversation.Authenticate
func testAuthenticateCrossFunction() {
	conv := createConversation()
	
	secret := []byte("shared-secret")
	// ruleid: go.xcrypto.otr.keyexchange
	result, _ := conv.Authenticate("question", secret)
	_ = result
}

func createConversation() *otr.Conversation {
	var privKey otr.PrivateKey
	privKey.Generate(rand.Reader)
	return &otr.Conversation{
		PrivateKey: &privKey,
	}
}

// TEST-RULE: go.xcrypto.otr.encrypt
// TEST-METADATA: operation:encrypt findingType:cipher api:otr.Conversation.Send
func testEncryptStructField() {
	type ChatSession struct {
		Conversation *otr.Conversation
	}
	
	var privKey otr.PrivateKey
	privKey.Generate(rand.Reader)
	conv := &otr.Conversation{
		PrivateKey: &privKey,
	}
	
	session := &ChatSession{
		Conversation: conv,
	}
	
	message := []byte("secret message")
	// ruleid: go.xcrypto.otr.encrypt
	encrypted, _ := session.Conversation.Send(message)
	_ = encrypted
}

// TEST-RULE: go.xcrypto.otr.decrypt
// TEST-METADATA: operation:decrypt findingType:cipher api:otr.Conversation.Receive
func testDecryptStructField() {
	type ChatSession struct {
		Conversation *otr.Conversation
	}
	
	var privKey otr.PrivateKey
	privKey.Generate(rand.Reader)
	conv := &otr.Conversation{
		PrivateKey: &privKey,
	}
	
	session := &ChatSession{
		Conversation: conv,
	}
	
	encrypted := []byte("encrypted data")
	// ruleid: go.xcrypto.otr.decrypt
	plaintext, _, _, _, _ := session.Conversation.Receive(encrypted)
	_ = plaintext
}

// TEST-RULE: go.xcrypto.otr.keyexchange
// TEST-METADATA: operation:keyexchange findingType:key_exchange api:otr.Conversation.Authenticate
func testAuthenticateStructField() {
	type ChatSession struct {
		Conversation *otr.Conversation
	}
	
	var privKey otr.PrivateKey
	privKey.Generate(rand.Reader)
	conv := &otr.Conversation{
		PrivateKey: &privKey,
	}
	
	session := &ChatSession{
		Conversation: conv,
	}
	
	secret := []byte("shared-secret")
	// ruleid: go.xcrypto.otr.keyexchange
	result, _ := session.Conversation.Authenticate("question", secret)
	_ = result
}

// TEST-RULE: go.xcrypto.otr.encrypt
// TEST-METADATA: operation:encrypt findingType:cipher api:otr.Conversation.Send
func testEncryptCommonFieldName() {
	type Messenger struct {
		Conv *otr.Conversation
	}
	
	var privKey otr.PrivateKey
	privKey.Generate(rand.Reader)
	conv := &otr.Conversation{
		PrivateKey: &privKey,
	}
	
	messenger := &Messenger{
		Conv: conv,
	}
	
	message := []byte("secret message")
	// ruleid: go.xcrypto.otr.encrypt
	encrypted, _ := messenger.Conv.Send(message)
	_ = encrypted
}

// TEST-RULE: go.xcrypto.otr.conversation-operations
// TEST-METADATA: operation:other findingType:cipher api:otr.Conversation.End
func testEndStructField() {
	type ChatSession struct {
		Conversation *otr.Conversation
	}
	
	var privKey otr.PrivateKey
	privKey.Generate(rand.Reader)
	conv := &otr.Conversation{
		PrivateKey: &privKey,
	}
	
	session := &ChatSession{
		Conversation: conv,
	}
	
	// ruleid: go.xcrypto.otr.conversation-operations
	messages := session.Conversation.End()
	_ = messages
}

// TEST-RULE: go.xcrypto.otr.conversation-operations
// TEST-METADATA: operation:other findingType:cipher api:otr.Conversation.IsEncrypted
func testIsEncryptedStructField() {
	type ChatSession struct {
		Conv *otr.Conversation
	}
	
	var privKey otr.PrivateKey
	privKey.Generate(rand.Reader)
	conv := &otr.Conversation{
		PrivateKey: &privKey,
	}
	
	session := &ChatSession{
		Conv: conv,
	}
	
	// ruleid: go.xcrypto.otr.conversation-operations
	encrypted := session.Conv.IsEncrypted()
	_ = encrypted
}
