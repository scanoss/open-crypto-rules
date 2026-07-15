package otr_test

import (
	"crypto/rand"

	"golang.org/x/crypto/otr"
)

// TEST-RULE: go.xcrypto.otr.encrypt
// TEST-METADATA: operation:encrypt findingType:cipher api:otr.Conversation.Send
func testDirectSend() {
	var privKey otr.PrivateKey
	privKey.Generate(rand.Reader)
	
	conv := &otr.Conversation{
		PrivateKey: &privKey,
	}
	
	// ruleid: go.xcrypto.otr.encrypt
	conv.Send([]byte("message"))
}

// TEST-RULE: go.xcrypto.otr.decrypt
// TEST-METADATA: operation:decrypt findingType:cipher api:otr.Conversation.Receive
func testDirectReceive() {
	var privKey otr.PrivateKey
	privKey.Generate(rand.Reader)
	
	conv := &otr.Conversation{
		PrivateKey: &privKey,
	}
	
	// ruleid: go.xcrypto.otr.decrypt
	conv.Receive([]byte("encrypted"))
}

// TEST-RULE: go.xcrypto.otr.keyexchange
// TEST-METADATA: operation:keyexchange findingType:key_exchange api:otr.Conversation.Authenticate
func testDirectAuthenticate() {
	var privKey otr.PrivateKey
	privKey.Generate(rand.Reader)
	
	conv := &otr.Conversation{
		PrivateKey: &privKey,
	}
	
	// ruleid: go.xcrypto.otr.keyexchange
	conv.Authenticate("question", []byte("secret"))
}

// TEST-RULE: go.xcrypto.otr.encrypt
// TEST-METADATA: operation:encrypt findingType:cipher api:otr.Conversation.Send
func testCrossFunctionSend() {
	var privKey otr.PrivateKey
	privKey.Generate(rand.Reader)
	
	conv := &otr.Conversation{
		PrivateKey: &privKey,
	}
	sendMessage(conv, []byte("message"))
}

func sendMessage(c *otr.Conversation, msg []byte) {
	// ruleid: go.xcrypto.otr.encrypt
	c.Send(msg)
}

// TEST-RULE: go.xcrypto.otr.decrypt
// TEST-METADATA: operation:decrypt findingType:cipher api:otr.Conversation.Receive
func testCrossFunctionReceive() {
	var privKey otr.PrivateKey
	privKey.Generate(rand.Reader)
	
	conv := &otr.Conversation{
		PrivateKey: &privKey,
	}
	receiveMessage(conv, []byte("encrypted"))
}

func receiveMessage(c *otr.Conversation, data []byte) {
	// ruleid: go.xcrypto.otr.decrypt
	c.Receive(data)
}

// TEST-RULE: go.xcrypto.otr.encrypt
// TEST-METADATA: operation:encrypt findingType:cipher api:otr.Conversation.Send
func testStructFieldSend() {
	type Session struct {
		Conversation *otr.Conversation
	}
	
	var privKey otr.PrivateKey
	privKey.Generate(rand.Reader)
	conv := &otr.Conversation{
		PrivateKey: &privKey,
	}
	
	session := &Session{Conversation: conv}
	
	// ruleid: go.xcrypto.otr.encrypt
	session.Conversation.Send([]byte("message"))
}

// TEST-RULE: go.xcrypto.otr.decrypt
// TEST-METADATA: operation:decrypt findingType:cipher api:otr.Conversation.Receive
func testStructFieldReceive() {
	type Session struct {
		Conv *otr.Conversation
	}
	
	var privKey otr.PrivateKey
	privKey.Generate(rand.Reader)
	conv := &otr.Conversation{
		PrivateKey: &privKey,
	}
	
	session := &Session{Conv: conv}
	
	// ruleid: go.xcrypto.otr.decrypt
	session.Conv.Receive([]byte("encrypted"))
}

// TEST-RULE: go.xcrypto.otr.encrypt
// TEST-METADATA: operation:encrypt findingType:cipher api:otr.Conversation.Send
//
// TEST-RULE: go.xcrypto.otr.decrypt
// TEST-METADATA: operation:decrypt findingType:cipher api:otr.Conversation.Receive
//
// TEST-RULE: go.xcrypto.otr.keyexchange
// TEST-METADATA: operation:keyexchange findingType:key_exchange api:otr.Conversation.Authenticate
func testMultipleOperationsSameConversation() {
	var privKey otr.PrivateKey
	privKey.Generate(rand.Reader)
	
	conv := &otr.Conversation{
		PrivateKey: &privKey,
	}
	
	// All three operations on the same conversation
	// ruleid: go.xcrypto.otr.keyexchange
	conv.Authenticate("question", []byte("secret"))
	
	// ruleid: go.xcrypto.otr.encrypt
	conv.Send([]byte("message"))
	
	// ruleid: go.xcrypto.otr.decrypt
	conv.Receive([]byte("encrypted"))
}

// TEST-RULE: go.xcrypto.otr.conversation-operations
// TEST-METADATA: operation:other findingType:cipher api:otr.Conversation.End
func testConversationEnd() {
	var privKey otr.PrivateKey
	privKey.Generate(rand.Reader)
	
	conv := &otr.Conversation{
		PrivateKey: &privKey,
	}
	
	// ruleid: go.xcrypto.otr.conversation-operations
	conv.End()
}

// TEST-RULE: go.xcrypto.otr.conversation-operations
// TEST-METADATA: operation:other findingType:cipher api:otr.Conversation.IsEncrypted
func testIsEncryptedCheck() {
	var privKey otr.PrivateKey
	privKey.Generate(rand.Reader)
	
	conv := &otr.Conversation{
		PrivateKey: &privKey,
	}
	
	// ruleid: go.xcrypto.otr.conversation-operations
	conv.IsEncrypted()
}

// TEST-RULE: go.xcrypto.otr.conversation-operations
// TEST-METADATA: operation:other findingType:cipher api:otr.Conversation.SMPQuestion
func testSMPQuestionCheck() {
	var privKey otr.PrivateKey
	privKey.Generate(rand.Reader)
	
	conv := &otr.Conversation{
		PrivateKey: &privKey,
	}
	
	// ruleid: go.xcrypto.otr.conversation-operations
	conv.SMPQuestion()
}
