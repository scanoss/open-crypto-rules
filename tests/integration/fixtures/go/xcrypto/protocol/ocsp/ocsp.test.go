package ocsp_test

import (
	"crypto/x509"
	"math/big"

	"golang.org/x/crypto/ocsp"
)

// TEST-RULE: go.xcrypto.ocsp.operations
// TEST-METADATA: operation:verify findingType:certificate_handling api:ocsp.CreateRequest
func testCreateRequest() {
	cert := &x509.Certificate{}
	issuer := &x509.Certificate{}
	
	// ruleid: go.xcrypto.ocsp.operations
	request, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		panic(err)
	}
	_ = request
}

// TEST-RULE: go.xcrypto.ocsp.operations
// TEST-METADATA: operation:verify findingType:certificate_handling api:ocsp.ParseRequest
func testParseRequest() {
	requestBytes := []byte("mock request")
	
	// ruleid: go.xcrypto.ocsp.operations
	request, err := ocsp.ParseRequest(requestBytes)
	if err != nil {
		panic(err)
	}
	_ = request
}

// TEST-RULE: go.xcrypto.ocsp.operations
// TEST-METADATA: operation:verify findingType:certificate_handling api:ocsp.CreateResponse
func testCreateResponse() {
	issuer := &x509.Certificate{}
	responderCert := &x509.Certificate{}
	template := ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: big.NewInt(1),
	}
	
	// ruleid: go.xcrypto.ocsp.operations
	response, err := ocsp.CreateResponse(issuer, responderCert, template, nil)
	if err != nil {
		panic(err)
	}
	_ = response
}

// TEST-RULE: go.xcrypto.ocsp.operations
// TEST-METADATA: operation:verify findingType:certificate_handling api:ocsp.ParseResponse
func testParseResponse() {
	responseBytes := []byte("mock response")
	
	// ruleid: go.xcrypto.ocsp.operations
	response, err := ocsp.ParseResponse(responseBytes, nil)
	if err != nil {
		panic(err)
	}
	_ = response
}

// TEST-RULE: go.xcrypto.ocsp.operations
// TEST-METADATA: operation:verify findingType:certificate_handling api:ocsp.ParseResponseForCert
func testParseResponseForCert() {
	responseBytes := []byte("mock response")
	cert := &x509.Certificate{}
	issuer := &x509.Certificate{}
	
	// ruleid: go.xcrypto.ocsp.operations
	response, err := ocsp.ParseResponseForCert(responseBytes, cert, issuer)
	if err != nil {
		panic(err)
	}
	_ = response
}

// TEST-RULE: go.xcrypto.ocsp.operations
// TEST-METADATA: operation:verify findingType:certificate_handling api:ocsp.CreateRequest
func testCreateRequestCrossFunction() {
	cert := &x509.Certificate{}
	issuer := &x509.Certificate{}
	createOCSPRequest(cert, issuer)
}

func createOCSPRequest(cert, issuer *x509.Certificate) {
	// ruleid: go.xcrypto.ocsp.operations
	ocsp.CreateRequest(cert, issuer, nil)
}

// TEST-RULE: go.xcrypto.ocsp.operations
// TEST-METADATA: operation:verify findingType:certificate_handling api:ocsp.ParseResponse
func testParseResponseInline() {
	// ruleid: go.xcrypto.ocsp.operations
	resp, _ := ocsp.ParseResponse([]byte("data"), nil)
	_ = resp
}

// TEST-RULE: go.xcrypto.ocsp.operations
// TEST-METADATA: operation:verify findingType:certificate_handling api:ocsp.ParseResponseForCert
func testParseResponseForCertInline() {
	cert := &x509.Certificate{}
	issuer := &x509.Certificate{}
	
	// ruleid: go.xcrypto.ocsp.operations
	resp, _ := ocsp.ParseResponseForCert([]byte("data"), cert, issuer)
	_ = resp
}

