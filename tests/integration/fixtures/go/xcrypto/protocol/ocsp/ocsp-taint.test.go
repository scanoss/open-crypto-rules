package ocsp_test

import (
	"crypto/x509"

	"golang.org/x/crypto/ocsp"
)

// TEST-RULE: go.xcrypto.ocsp.verify
// TEST-METADATA: operation:verify findingType:certificate_handling api:ocsp.Response.CheckSignatureFrom
func testDirectVerify() {
	responseBytes := []byte("mock response")
	issuer := &x509.Certificate{}
	
	resp, err := ocsp.ParseResponse(responseBytes, nil)
	if err != nil {
		panic(err)
	}
	
	// ruleid: go.xcrypto.ocsp.verify
	err = resp.CheckSignatureFrom(issuer)
	if err != nil {
		panic(err)
	}
}

// TEST-RULE: go.xcrypto.ocsp.verify
// TEST-METADATA: operation:verify findingType:certificate_handling api:ocsp.Response.CheckSignatureFrom
func testParseResponseForCertVerify() {
	responseBytes := []byte("mock response")
	cert := &x509.Certificate{}
	issuer := &x509.Certificate{}
	
	resp, err := ocsp.ParseResponseForCert(responseBytes, cert, issuer)
	if err != nil {
		panic(err)
	}
	
	// ruleid: go.xcrypto.ocsp.verify
	err = resp.CheckSignatureFrom(issuer)
	if err != nil {
		panic(err)
	}
}

// TEST-RULE: go.xcrypto.ocsp.verify
// TEST-METADATA: operation:verify findingType:certificate_handling api:ocsp.Response.CheckSignatureFrom
func testCrossFunctionVerify() {
	responseBytes := []byte("mock response")
	resp, _ := ocsp.ParseResponse(responseBytes, nil)
	
	issuer := &x509.Certificate{}
	verifyResponse(resp, issuer)
}

func verifyResponse(resp *ocsp.Response, issuer *x509.Certificate) {
	// ruleid: go.xcrypto.ocsp.verify
	resp.CheckSignatureFrom(issuer)
}

// TEST-RULE: go.xcrypto.ocsp.verify
// TEST-METADATA: operation:verify findingType:certificate_handling api:ocsp.Response.CheckSignatureFrom
func testStructFieldVerify() {
	type CertValidator struct {
		Response *ocsp.Response
	}
	
	responseBytes := []byte("mock response")
	resp, _ := ocsp.ParseResponse(responseBytes, nil)
	
	validator := &CertValidator{
		Response: resp,
	}
	
	issuer := &x509.Certificate{}
	// ruleid: go.xcrypto.ocsp.verify
	validator.Response.CheckSignatureFrom(issuer)
}

// TEST-RULE: go.xcrypto.ocsp.verify
// TEST-METADATA: operation:verify findingType:certificate_handling api:ocsp.Response.CheckSignatureFrom
func testCommonFieldNameVerify() {
	type Validator struct {
		Resp *ocsp.Response
	}
	
	responseBytes := []byte("mock response")
	resp, _ := ocsp.ParseResponse(responseBytes, nil)
	
	validator := &Validator{
		Resp: resp,
	}
	
	issuer := &x509.Certificate{}
	// ruleid: go.xcrypto.ocsp.verify
	validator.Resp.CheckSignatureFrom(issuer)
}

// TEST-RULE: go.xcrypto.ocsp.verify
// TEST-METADATA: operation:verify findingType:certificate_handling api:ocsp.Response.CheckSignatureFrom
func testOCSPResponseFieldNameVerify() {
	type CertChecker struct {
		OCSPResponse *ocsp.Response
	}
	
	responseBytes := []byte("mock response")
	resp, _ := ocsp.ParseResponse(responseBytes, nil)
	
	checker := &CertChecker{
		OCSPResponse: resp,
	}
	
	issuer := &x509.Certificate{}
	// ruleid: go.xcrypto.ocsp.verify
	checker.OCSPResponse.CheckSignatureFrom(issuer)
}

// TEST-RULE: go.xcrypto.ocsp.verify
// TEST-METADATA: operation:verify findingType:certificate_handling api:ocsp.Response.CheckSignatureFrom
func testInlineParseAndVerify() {
	issuer := &x509.Certificate{}
	
	// ruleid: go.xcrypto.ocsp.verify
	resp, _ := ocsp.ParseResponse([]byte("data"), nil)
	resp.CheckSignatureFrom(issuer)
}

// TEST-RULE: go.xcrypto.ocsp.verify
// TEST-METADATA: operation:verify findingType:certificate_handling api:ocsp.Response.CheckSignatureFrom
func testNestedStructVerify() {
	type CertStore struct {
		Response *ocsp.Response
	}
	
	type Validator struct {
		Store *CertStore
	}
	
	responseBytes := []byte("mock response")
	resp, _ := ocsp.ParseResponse(responseBytes, nil)
	
	store := &CertStore{Response: resp}
	validator := &Validator{Store: store}
	
	issuer := &x509.Certificate{}
	// ruleid: go.xcrypto.ocsp.verify
	validator.Store.Response.CheckSignatureFrom(issuer)
}

