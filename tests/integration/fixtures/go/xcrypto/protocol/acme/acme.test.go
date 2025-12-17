package acme_test

import (
	"context"
	"crypto"

	"golang.org/x/crypto/acme"
)

// TEST-RULE: go.xcrypto.acme.client-creation
// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

func testClientCreation() {
	client := &acme.Client{
		Key: nil,
	}
	_ = client
}

// TEST-RULE: go.xcrypto.acme.client-operations
// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

func testDiscover() {
	client := &acme.Client{}
	ctx := context.Background()
	_, err := client.Discover(ctx)
	_ = err
}

// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

func testGetReg() {
	client := &acme.Client{}
	ctx := context.Background()
	_, err := client.GetReg(ctx, "https://example.com/acct/1")
	_ = err
}

// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

func testUpdateReg() {
	client := &acme.Client{}
	ctx := context.Background()
	_, err := client.UpdateReg(ctx, &acme.Account{})
	_ = err
}

// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

func testDeactivateReg() {
	client := &acme.Client{}
	ctx := context.Background()
	err := client.DeactivateReg(ctx)
	_ = err
}

// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

func testAccountKeyRollover() {
	client := &acme.Client{}
	ctx := context.Background()
	var newKey crypto.Signer
	err := client.AccountKeyRollover(ctx, newKey)
	_ = err
}

// TEST-RULE: go.xcrypto.acme.registration
// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

func testRegister() {
	client := &acme.Client{}
	ctx := context.Background()
	_, err := client.Register(ctx, &acme.Account{}, func(string) bool { return true })
	_ = err
}

// TEST-RULE: go.xcrypto.acme.authorization
// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

func testAuthorize() {
	client := &acme.Client{}
	ctx := context.Background()
	_, err := client.Authorize(ctx, "example.com")
	_ = err
}

// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

func testAuthorizeIP() {
	client := &acme.Client{}
	ctx := context.Background()
	_, err := client.AuthorizeIP(ctx, "192.168.1.1")
	_ = err
}

// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

func testAuthorizeOrder() {
	client := &acme.Client{}
	ctx := context.Background()
	_, err := client.AuthorizeOrder(ctx, []acme.AuthzID{{Type: "dns", Value: "example.com"}})
	_ = err
}

// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

func testGetAuthorization() {
	client := &acme.Client{}
	ctx := context.Background()
	_, err := client.GetAuthorization(ctx, "https://example.com/authz/1")
	_ = err
}

// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

func testWaitAuthorization() {
	client := &acme.Client{}
	ctx := context.Background()
	_, err := client.WaitAuthorization(ctx, "https://example.com/authz/1")
	_ = err
}

// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

func testRevokeAuthorization() {
	client := &acme.Client{}
	ctx := context.Background()
	err := client.RevokeAuthorization(ctx, "https://example.com/authz/1")
	_ = err
}

// TEST-RULE: go.xcrypto.acme.challenge
// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

func testGetChallenge() {
	client := &acme.Client{}
	ctx := context.Background()
	_, err := client.GetChallenge(ctx, "https://example.com/chal/1")
	_ = err
}

// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

func testAccept() {
	client := &acme.Client{}
	ctx := context.Background()
	_, err := client.Accept(ctx, &acme.Challenge{})
	_ = err
}

// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

func testDNS01ChallengeRecord() {
	client := &acme.Client{}
	record, _ := client.DNS01ChallengeRecord("token123")
	_ = record
}

// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

func testHTTP01ChallengeResponse() {
	client := &acme.Client{}
	response, _ := client.HTTP01ChallengeResponse("token123")
	_ = response
}

// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

func testHTTP01ChallengePath() {
	client := &acme.Client{}
	path := client.HTTP01ChallengePath("token123")
	_ = path
}

// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

func testTLSALPN01ChallengeCert() {
	client := &acme.Client{}
	_, err := client.TLSALPN01ChallengeCert("token123", "example.com")
	_ = err
}

// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

func testTLSSNI01ChallengeCert() {
	client := &acme.Client{}
	_, _, err := client.TLSSNI01ChallengeCert("token123")
	_ = err
}

// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

func testTLSSNI02ChallengeCert() {
	client := &acme.Client{}
	_, _, err := client.TLSSNI02ChallengeCert("token123")
	_ = err
}

// TEST-RULE: go.xcrypto.acme.order
// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

func testGetOrder() {
	client := &acme.Client{}
	ctx := context.Background()
	_, err := client.GetOrder(ctx, "https://example.com/order/1")
	_ = err
}

// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

func testWaitOrder() {
	client := &acme.Client{}
	ctx := context.Background()
	_, err := client.WaitOrder(ctx, "https://example.com/order/1")
	_ = err
}

// TEST-RULE: go.xcrypto.acme.certificate
// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

func testCreateCert() {
	client := &acme.Client{}
	ctx := context.Background()
	_, _, err := client.CreateCert(ctx, []byte("csr"), 0, true)
	_ = err
}

// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

func testCreateOrderCert() {
	client := &acme.Client{}
	ctx := context.Background()
	_, _, err := client.CreateOrderCert(ctx, "https://example.com/order/1", []byte("csr"), true)
	_ = err
}

// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

func testFetchCert() {
	client := &acme.Client{}
	ctx := context.Background()
	_, err := client.FetchCert(ctx, "https://example.com/cert/1", true)
	_ = err
}

// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

func testRevokeCert() {
	client := &acme.Client{}
	ctx := context.Background()
	var key crypto.Signer
	err := client.RevokeCert(ctx, key, []byte("cert"), 0)
	_ = err
}

// TEST-METADATA: assetType=protocol, findingType=certificate_handling, operation=other, protocolName=ACME, protocolType=other, library=golang.org/x/crypto/acme

func testListCertAlternates() {
	client := &acme.Client{}
	ctx := context.Background()
	_, err := client.ListCertAlternates(ctx, "https://example.com/cert/1")
	_ = err
}
