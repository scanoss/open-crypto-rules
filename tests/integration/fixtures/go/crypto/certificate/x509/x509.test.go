package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

// TEST-RULE: go.crypto.x509.certificate-verify
// TEST-METADATA: assetType:certificate findingType:certificate_handling operation:verify library:crypto/x509 api:Certificate.Verify materialSource:loaded
func testBasicVerifyWithAssignment() {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	opts := x509.VerifyOptions{}

	// ruleid: go.crypto.x509.certificate-verify
	chains, err := cert.Verify(opts)
	if err != nil {
		println("panic!")
	}

	_ = chains
}

// TEST-RULE: go.crypto.x509.certificate-verify
// TEST-METADATA: assetType:certificate findingType:certificate_handling operation:verify library:crypto/x509 api:Certificate.Verify materialSource:loaded
func testDirectCallNoAssignment() {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	opts := x509.VerifyOptions{}

	// ruleid: go.crypto.x509.certificate-verify
	cert.Verify(opts)
}

// TEST-RULE: go.crypto.x509.certificate-verify
// TEST-METADATA: assetType:certificate findingType:certificate_handling operation:verify library:crypto/x509 api:Certificate.Verify materialSource:loaded
func testExplicitVariableDeclaration() {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	opts := x509.VerifyOptions{}

	var chains [][]*x509.Certificate
	// ruleid: go.crypto.x509.certificate-verify
	chains, err := cert.Verify(opts)
	if err != nil {
		panic(err)
	}

	_ = chains
}

