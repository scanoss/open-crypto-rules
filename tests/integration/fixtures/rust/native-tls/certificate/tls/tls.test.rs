// TEST-RULE: rust.native-tls.tls.add-root-certificate
// TEST-METADATA: assetType=certificate, findingType=certificate_handling, operation=other, library=native-tls, materialSource=loaded
fn test_add_root_certificate() {
    use native_tls::{Certificate, TlsConnector};
    let builder = TlsConnector::builder();
    let cert_data = b"-----BEGIN CERTIFICATE-----\n...";
    builder.add_root_certificate(Certificate::from_pem(cert_data).unwrap());
}

// TEST-RULE: rust.native-tls.tls.add-root-certificate
// TEST-METADATA: assetType=certificate, findingType=certificate_handling, operation=other, library=native-tls, materialSource=loaded
fn test_add_root_certificate_der() {
    use native_tls::{Certificate, TlsConnector};
    let builder = TlsConnector::builder();
    let cert_data = vec![0x30, 0x82, 0x03, 0x00];
    builder.add_root_certificate(Certificate::from_der(&cert_data).unwrap());
}

// TEST-RULE: rust.native-tls.tls.identity
// TEST-METADATA: assetType=certificate, findingType=certificate_handling, operation=other, library=native-tls, materialSource=loaded
fn test_identity() {
    use native_tls::{Identity, TlsConnector};
    let builder = TlsConnector::builder();
    let pkcs12_data = vec![0x30, 0x82, 0x03, 0x00];
    let password = "password";
    builder.identity(Identity::from_pkcs12(&pkcs12_data, password).unwrap());
}
