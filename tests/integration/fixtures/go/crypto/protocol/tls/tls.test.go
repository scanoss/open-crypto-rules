package main

import (
	"crypto/tls"
)

// TEST-RULE: go.crypto.tls.version-ssl30
// TEST-METADATA: assetType:protocol findingType:key_exchange operation:keyexchange protocolName:TLS protocolType:tls protocolVersion:SSL3.0 library:crypto/tls api:tls.VersionSSL30
func testVersionSSL30Reference() {
	// ruleid: go.crypto.tls.version-ssl30
	version := tls.VersionSSL30
	_ = version
}

// TEST-RULE: go.crypto.tls.version-ssl30
// TEST-METADATA: assetType:protocol findingType:key_exchange operation:keyexchange protocolName:TLS protocolType:tls protocolVersion:SSL3.0 library:crypto/tls api:tls.VersionSSL30
func testVersionSSL30MinVersion() {
	config := &tls.Config{}
	// ruleid: go.crypto.tls.version-ssl30
	config.MinVersion = tls.VersionSSL30
}

// TEST-RULE: go.crypto.tls.version-tls10
// TEST-METADATA: assetType:protocol findingType:key_exchange operation:keyexchange protocolName:TLS protocolType:tls protocolVersion:1.0 library:crypto/tls api:tls.VersionTLS10
func testVersionTLS10Reference() {
	// ruleid: go.crypto.tls.version-tls10
	version := tls.VersionTLS10
	_ = version
}

// TEST-RULE: go.crypto.tls.version-tls10
// TEST-METADATA: assetType:protocol findingType:key_exchange operation:keyexchange protocolName:TLS protocolType:tls protocolVersion:1.0 library:crypto/tls api:tls.VersionTLS10
func testVersionTLS10MaxVersion() {
	config := &tls.Config{}
	// ruleid: go.crypto.tls.version-tls10
	config.MaxVersion = tls.VersionTLS10
}

// TEST-RULE: go.crypto.tls.version-tls11
// TEST-METADATA: assetType:protocol findingType:key_exchange operation:keyexchange protocolName:TLS protocolType:tls protocolVersion:1.1 library:crypto/tls api:tls.VersionTLS11
func testVersionTLS11() {
	// ruleid: go.crypto.tls.version-tls11
	version := tls.VersionTLS11
	_ = version
}

// TEST-RULE: go.crypto.tls.version-tls12
// TEST-METADATA: assetType:protocol findingType:key_exchange operation:keyexchange protocolName:TLS protocolType:tls protocolVersion:1.2 library:crypto/tls api:tls.VersionTLS12
func testVersionTLS12() {
	config := &tls.Config{}
	// ruleid: go.crypto.tls.version-tls12
	config.MinVersion = tls.VersionTLS12
}

// TEST-RULE: go.crypto.tls.version-tls13
// TEST-METADATA: assetType:protocol findingType:key_exchange operation:keyexchange protocolName:TLS protocolType:tls protocolVersion:1.3 library:crypto/tls api:tls.VersionTLS13
func testVersionTLS13() {
	// ruleid: go.crypto.tls.version-tls13
	version := tls.VersionTLS13
	_ = version
}

// TEST-RULE: go.crypto.tls.cipher-suite
// TEST-METADATA: assetType:protocol findingType:cipher operation:encrypt protocolName:TLS protocolType:tls library:crypto/tls api:tls.CipherSuite
func testCipherSuiteReference() {
	// ruleid: go.crypto.tls.cipher-suite
	suite := tls.TLS_RSA_WITH_AES_128_CBC_SHA
	_ = suite
}

// TEST-RULE: go.crypto.tls.cipher-suite
// TEST-METADATA: assetType:protocol findingType:cipher operation:encrypt protocolName:TLS protocolType:tls library:crypto/tls api:tls.CipherSuite
func testCipherSuitesConfig() {
	config := &tls.Config{}
	// ruleid: go.crypto.tls.cipher-suite
	config.CipherSuites = []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	}
}

// TEST-RULE: go.crypto.tls.curve-preferences
// TEST-METADATA: assetType:protocol findingType:key_exchange operation:keyexchange protocolName:TLS protocolType:tls library:crypto/tls api:tls.CurvePreferences
func testCurvePreferencesReference() {
	// ruleid: go.crypto.tls.curve-preferences
	curve := tls.CurveP256
	_ = curve
}

// TEST-RULE: go.crypto.tls.curve-preferences
// TEST-METADATA: assetType:protocol findingType:key_exchange operation:keyexchange protocolName:TLS protocolType:tls library:crypto/tls api:tls.CurvePreferences
func testCurvePreferencesConfig() {
	config := &tls.Config{}
	// ruleid: go.crypto.tls.curve-preferences
	config.CurvePreferences = []tls.CurveID{
		tls.CurveP256,
		tls.X25519,
	}
}

// TEST-RULE: go.crypto.tls.curve-preferences
// TEST-METADATA: assetType:protocol findingType:key_exchange operation:keyexchange protocolName:TLS protocolType:tls library:crypto/tls api:tls.CurvePreferences
func testCurvePreferencesInline() {
	config := &tls.Config{
		// ruleid: go.crypto.tls.curve-preferences
		CurvePreferences: []tls.CurveID{tls.CurveP384, tls.X25519},
	}
	_ = config
}

