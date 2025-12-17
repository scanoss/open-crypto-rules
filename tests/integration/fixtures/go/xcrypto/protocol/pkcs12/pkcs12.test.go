package pkcs12_test

import (
	"golang.org/x/crypto/pkcs12"
)

// TEST-RULE: go.xcrypto.pkcs12.decode
// TEST-METADATA: operation:decrypt findingType:cipher api:pkcs12.Decode
func testPKCS12Decode() {
	pfxData := []byte("mock pfx data")
	password := "password"
	
	// ruleid: go.xcrypto.pkcs12.decode
	privateKey, certificate, err := pkcs12.Decode(pfxData, password)
	if err != nil {
		panic(err)
	}
	_, _, _ = privateKey, certificate, err
}

