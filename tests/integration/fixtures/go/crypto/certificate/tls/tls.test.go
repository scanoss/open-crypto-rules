package main

import (
	"crypto/tls"
)

// TEST-RULE: go.crypto.tls.load-key-pair
// TEST-METADATA: assetType:certificate findingType:certificate_handling operation:other library:crypto/tls api:tls.LoadX509KeyPair materialSource:loaded
func testLoadX509KeyPair() {
	certFile := "server.crt"
	keyFile := "server.key"
	// ruleid: go.crypto.tls.load-key-pair
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		panic(err)
	}
	_ = cert
}

// TEST-RULE: go.crypto.tls.load-key-pair
// TEST-METADATA: assetType:certificate findingType:certificate_handling operation:other library:crypto/tls api:tls.LoadX509KeyPair materialSource:loaded
func testX509KeyPair() {
	certPEM := []byte("cert")
	keyPEM := []byte("key")
	// ruleid: go.crypto.tls.load-key-pair
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	_ = cert
}

