// TEST-RULE: rust.openssl.x509.from-pem
// TEST-METADATA: assetType=certificate, findingType=certificate, operation=load, certificateFormat=PEM, library=openssl, algorithmFamily=X509
fn test_x509_from_pem() {
    use openssl::x509::X509;
    let pem_data = b"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----";
    let cert = X509::from_pem(pem_data);
    _ = cert;
}

// TEST-RULE: rust.openssl.x509.from-der
// TEST-METADATA: assetType=certificate, findingType=certificate, operation=load, certificateFormat=DER, library=openssl, algorithmFamily=X509
fn test_x509_from_der() {
    use openssl::x509::X509;
    let der_data = [0u8; 100];
    let cert = X509::from_der(&der_data);
    _ = cert;
}

// TEST-RULE: rust.openssl.x509.stack-from-pem
// TEST-METADATA: assetType=certificate, findingType=certificate, operation=load, certificateFormat=PEM, library=openssl, algorithmFamily=X509
fn test_x509_stack_from_pem() {
    use openssl::x509::X509;
    let pem_data = b"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----";
    let certs = X509::stack_from_pem(pem_data);
    _ = certs;
}

// TEST-RULE: rust.openssl.x509.builder
// TEST-METADATA: assetType=certificate, findingType=certificate, operation=generate, library=openssl, algorithmFamily=X509
fn test_x509_builder() {
    use openssl::x509::X509;
    let builder = X509::builder();
    _ = builder;
}

// TEST-RULE: rust.openssl.x509.sign
// TEST-METADATA: assetType=certificate, findingType=certificate, operation=sign, library=openssl, algorithmFamily=X509
fn test_x509_sign() {
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::X509;
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    let mut builder = X509::builder().unwrap();
    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
}

// TEST-RULE: rust.openssl.x509.to-pem
// TEST-METADATA: assetType=certificate, findingType=certificate, operation=serialize, certificateFormat=PEM, library=openssl, algorithmFamily=X509
fn test_x509_to_pem() {
    use openssl::x509::X509;
    let pem_data = b"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----";
    let cert = X509::from_pem(pem_data).unwrap();
    let pem = cert.to_pem();
    _ = pem;
}

// TEST-RULE: rust.openssl.x509.to-der
// TEST-METADATA: assetType=certificate, findingType=certificate, operation=serialize, certificateFormat=DER, library=openssl, algorithmFamily=X509
fn test_x509_to_der() {
    use openssl::x509::X509;
    let pem_data = b"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----";
    let cert = X509::from_pem(pem_data).unwrap();
    let der = cert.to_der();
    _ = der;
}

// TEST-RULE: rust.openssl.x509.verify-signature
// TEST-METADATA: assetType=certificate, findingType=certificate, operation=verify, library=openssl, algorithmFamily=X509
fn test_x509_verify_signature() {
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::X509;
    let pem_data = b"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----";
    let cert = X509::from_pem(pem_data).unwrap();
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    let _ = cert.verify(&pkey);
}

// TEST-RULE: rust.openssl.x509.store-builder
// TEST-METADATA: assetType=certificate, findingType=certificate, operation=store, library=openssl, algorithmFamily=X509
fn test_x509_store_builder() {
    use openssl::x509::store::X509StoreBuilder;
    let store = X509StoreBuilder::new();
    _ = store;
}

// TEST-RULE: rust.openssl.x509.store-add-cert
// TEST-METADATA: assetType=certificate, findingType=certificate, operation=store, library=openssl, algorithmFamily=X509
fn test_x509_store_add_cert() {
    use openssl::x509::store::X509StoreBuilder;
    use openssl::x509::X509;
    let pem_data = b"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----";
    let cert = X509::from_pem(pem_data).unwrap();
    let mut store = X509StoreBuilder::new().unwrap();
    store.add_cert(cert).unwrap();
}

// TEST-RULE: rust.openssl.x509.store-context
// TEST-METADATA: assetType=certificate, findingType=certificate, operation=verify, library=openssl, algorithmFamily=X509
fn test_x509_store_context() {
    use openssl::x509::X509StoreContext;
    let ctx = X509StoreContext::new();
    _ = ctx;
}

// TEST-RULE: rust.openssl.x509.verify-cert
// TEST-METADATA: assetType=certificate, findingType=certificate, operation=verify, library=openssl, algorithmFamily=X509
fn test_x509_verify_cert_chain() {
    use openssl::stack::Stack;
    use openssl::x509::store::X509StoreBuilder;
    use openssl::x509::{X509StoreContext, X509};
    let store = X509StoreBuilder::new().unwrap().build();
    let pem_data = b"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----";
    let cert = X509::from_pem(pem_data).unwrap();
    let chain = Stack::new().unwrap();
    let mut ctx = X509StoreContext::new().unwrap();
    let _ = ctx.init(&store, &cert, &chain, |c| c.verify_cert());
}

// TEST-RULE: rust.openssl.x509.req-from-pem
// TEST-METADATA: assetType=certificate, findingType=csr, operation=load, certificateFormat=PEM, library=openssl, algorithmFamily=X509
fn test_x509_req_from_pem() {
    use openssl::x509::X509Req;
    let pem_data = b"-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----";
    let req = X509Req::from_pem(pem_data);
    _ = req;
}

// TEST-RULE: rust.openssl.x509.req-from-der
// TEST-METADATA: assetType=certificate, findingType=csr, operation=load, certificateFormat=DER, library=openssl, algorithmFamily=X509
fn test_x509_req_from_der() {
    use openssl::x509::X509Req;
    let der_data = [0u8; 100];
    let req = X509Req::from_der(&der_data);
    _ = req;
}

// TEST-RULE: rust.openssl.x509.req-builder
// TEST-METADATA: assetType=certificate, findingType=csr, operation=generate, library=openssl, algorithmFamily=X509
fn test_x509_req_builder() {
    use openssl::x509::X509Req;
    let builder = X509Req::builder();
    _ = builder;
}

// TEST-RULE: rust.openssl.x509.req-sign
// TEST-METADATA: assetType=certificate, findingType=csr, operation=sign, library=openssl, algorithmFamily=X509
fn test_x509_req_sign() {
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::X509Req;
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    let mut builder = X509Req::builder().unwrap();
    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
}

// TEST-RULE: rust.openssl.x509.req-to-pem
// TEST-METADATA: assetType=certificate, findingType=csr, operation=serialize, certificateFormat=PEM, library=openssl, algorithmFamily=X509
fn test_x509_req_to_pem() {
    use openssl::x509::X509Req;
    let pem_data = b"-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----";
    let req = X509Req::from_pem(pem_data).unwrap();
    let pem = req.to_pem();
    _ = pem;
}

// TEST-RULE: rust.openssl.x509.req-to-der
// TEST-METADATA: assetType=certificate, findingType=csr, operation=serialize, certificateFormat=DER, library=openssl, algorithmFamily=X509
fn test_x509_req_to_der() {
    use openssl::x509::X509Req;
    let pem_data = b"-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----";
    let req = X509Req::from_pem(pem_data).unwrap();
    let der = req.to_der();
    _ = der;
}

// TEST-RULE: rust.openssl.x509.req-verify
// TEST-METADATA: assetType=certificate, findingType=csr, operation=verify, library=openssl, algorithmFamily=X509
fn test_x509_req_verify() {
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::X509Req;
    let pem_data = b"-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----";
    let req = X509Req::from_pem(pem_data).unwrap();
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    let _ = req.verify(&pkey);
}

// TEST-RULE: rust.openssl.x509.crl-from-pem
// TEST-METADATA: assetType=certificate, findingType=crl, operation=load, certificateFormat=PEM, library=openssl, algorithmFamily=X509
fn test_x509_crl_from_pem() {
    use openssl::x509::X509Crl;
    let pem_data = b"-----BEGIN X509 CRL-----\n...\n-----END X509 CRL-----";
    let crl = X509Crl::from_pem(pem_data);
    _ = crl;
}

// TEST-RULE: rust.openssl.x509.crl-from-der
// TEST-METADATA: assetType=certificate, findingType=crl, operation=load, certificateFormat=DER, library=openssl, algorithmFamily=X509
fn test_x509_crl_from_der() {
    use openssl::x509::X509Crl;
    let der_data = [0u8; 100];
    let crl = X509Crl::from_der(&der_data);
    _ = crl;
}

// TEST-RULE: rust.openssl.x509.crl-verify
// TEST-METADATA: assetType=certificate, findingType=crl, operation=verify, library=openssl, algorithmFamily=X509
fn test_x509_crl_verify() {
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::X509Crl;
    let pem_data = b"-----BEGIN X509 CRL-----\n...\n-----END X509 CRL-----";
    let crl = X509Crl::from_pem(pem_data).unwrap();
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    let _ = crl.verify(&pkey);
}

// TEST-RULE: rust.openssl.x509.crl-to-pem
// TEST-METADATA: assetType=certificate, findingType=crl, operation=serialize, certificateFormat=PEM, library=openssl, algorithmFamily=X509
fn test_x509_crl_to_pem() {
    use openssl::x509::X509Crl;
    let pem_data = b"-----BEGIN X509 CRL-----\n...\n-----END X509 CRL-----";
    let crl = X509Crl::from_pem(pem_data).unwrap();
    let pem = crl.to_pem();
    _ = pem;
}

// TEST-RULE: rust.openssl.x509.crl-to-der
// TEST-METADATA: assetType=certificate, findingType=crl, operation=serialize, certificateFormat=DER, library=openssl, algorithmFamily=X509
fn test_x509_crl_to_der() {
    use openssl::x509::X509Crl;
    let pem_data = b"-----BEGIN X509 CRL-----\n...\n-----END X509 CRL-----";
    let crl = X509Crl::from_pem(pem_data).unwrap();
    let der = crl.to_der();
    _ = der;
}
