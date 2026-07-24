package acme_test

import (
	"context"

	"golang.org/x/crypto/acme"
)

// TEST-RULE: go.xcrypto.acme.registration
// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

// Scenario 1: Direct usage (basic taint tracking)
func testDirectUsage() {
	client := &acme.Client{}
	ctx := context.Background()
	
	// Should be detected via taint tracking
	_, err := client.Register(ctx, &acme.Account{}, func(string) bool { return true })
	_ = err
}

// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

// Scenario 2: Cross-function taint tracking
func testCrossFunctionTracking() {
	client := createACMEClient()
	ctx := context.Background()
	
	// Should be detected - taint flows from createACMEClient()
	_, err := client.Register(ctx, &acme.Account{}, func(string) bool { return true })
	_ = err
}

func createACMEClient() *acme.Client {
	return &acme.Client{}
}

// TEST-RULE: go.xcrypto.acme.authorization
// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

// Scenario 3: Struct field propagation (same file)
type ACMEService struct {
	Client *acme.Client
}

func testStructFieldPropagation() {
	client := &acme.Client{}
	
	// Propagate taint: client -> service (via struct field)
	service := &ACMEService{Client: client}
	
	ctx := context.Background()
	
	// Should be detected - taint flows through struct field
	_, err := service.Client.Authorize(ctx, "example.com")
	_ = err
}

// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

// Scenario 4: Nested struct field propagation
type AppConfig struct {
	ACMEService *ACMEService
}

func testNestedStructPropagation() {
	client := &acme.Client{}
	service := &ACMEService{Client: client}
	config := &AppConfig{ACMEService: service}
	
	ctx := context.Background()
	
	// Should be detected - taint flows through nested struct
	_, err := config.ACMEService.Client.Authorize(ctx, "test.com")
	_ = err
}
