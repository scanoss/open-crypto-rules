// TEST-RULE: rust.openssl.tls.ssl-acceptor-modern
// TEST-METADATA: assetType=protocol, findingType=protocol, operation=init, protocolName=TLS, algorithmFamily=TLS, library=openssl, securityProfile=mozilla_modern
fn test_ssl_acceptor_mozilla_modern() {
    use openssl::ssl::{SslAcceptor, SslMethod};
    let builder = SslAcceptor::mozilla_modern(SslMethod::tls()).unwrap();
    _ = builder;
}

// TEST-RULE: rust.openssl.tls.ssl-acceptor-modern
// TEST-METADATA: assetType=protocol, findingType=protocol, operation=init, protocolName=TLS, algorithmFamily=TLS, library=openssl, securityProfile=mozilla_modern
fn test_ssl_acceptor_mozilla_modern_fully_qualified() {
    let builder =
        openssl::ssl::SslAcceptor::mozilla_modern(openssl::ssl::SslMethod::tls()).unwrap();
    _ = builder;
}

// TEST-RULE: rust.openssl.tls.ssl-acceptor-intermediate
// TEST-METADATA: assetType=protocol, findingType=protocol, operation=init, protocolName=TLS, algorithmFamily=TLS, library=openssl, securityProfile=mozilla_intermediate
fn test_ssl_acceptor_mozilla_intermediate() {
    use openssl::ssl::{SslAcceptor, SslMethod};
    let builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    _ = builder;
}

// TEST-RULE: rust.openssl.tls.ssl-connector-builder
// TEST-METADATA: assetType=protocol, findingType=protocol, operation=init, protocolName=TLS, algorithmFamily=TLS, library=openssl
fn test_ssl_connector_builder() {
    use openssl::ssl::{SslConnector, SslMethod};
    let builder = SslConnector::builder(SslMethod::tls()).unwrap();
    _ = builder;
}

// TEST-RULE: rust.openssl.tls.ssl-context-builder
// TEST-METADATA: assetType=protocol, findingType=protocol, operation=init, protocolName=TLS, algorithmFamily=TLS, library=openssl
fn test_ssl_context_builder() {
    use openssl::ssl::{SslContext, SslMethod};
    let builder = SslContext::builder(SslMethod::tls()).unwrap();
    _ = builder;
}

// TEST-RULE: rust.openssl.tls.ssl-method-tls
// TEST-METADATA: assetType=protocol, findingType=protocol, operation=init, protocolName=TLS, algorithmFamily=TLS, library=openssl
fn test_ssl_method_tls() {
    use openssl::ssl::SslMethod;
    let method = SslMethod::tls();
    _ = method;
}

// TEST-RULE: rust.openssl.tls.ssl-method-tls
// TEST-METADATA: assetType=protocol, findingType=protocol, operation=init, protocolName=TLS, algorithmFamily=TLS, library=openssl
fn test_ssl_method_tls_client() {
    use openssl::ssl::SslMethod;
    let method = SslMethod::tls_client();
    _ = method;
}

// TEST-RULE: rust.openssl.tls.ssl-method-dtls
// TEST-METADATA: assetType=protocol, findingType=protocol, operation=init, protocolName=DTLS, algorithmFamily=TLS, library=openssl
fn test_ssl_method_dtls() {
    use openssl::ssl::SslMethod;
    let method = SslMethod::dtls();
    _ = method;
}

// TEST-RULE: rust.openssl.tls.set-private-key-file
// TEST-METADATA: assetType=protocol, findingType=protocol, operation=configure, protocolName=TLS, algorithmFamily=TLS, library=openssl, configType=private_key
fn test_set_private_key_file() {
    use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
    let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file("key.pem", SslFiletype::PEM)
        .unwrap();
}

// TEST-RULE: rust.openssl.tls.set-private-key
// TEST-METADATA: assetType=protocol, findingType=protocol, operation=configure, protocolName=TLS, algorithmFamily=TLS, library=openssl, configType=private_key
fn test_set_private_key() {
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::ssl::{SslAcceptor, SslMethod};
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls()).unwrap();
    builder.set_private_key(&pkey).unwrap();
}

// TEST-RULE: rust.openssl.tls.set-certificate-chain-file
// TEST-METADATA: assetType=protocol, findingType=protocol, operation=configure, protocolName=TLS, algorithmFamily=TLS, library=openssl, configType=certificate_chain
fn test_set_certificate_chain_file() {
    use openssl::ssl::{SslAcceptor, SslMethod};
    let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls()).unwrap();
    builder.set_certificate_chain_file("cert.pem").unwrap();
}

// TEST-RULE: rust.openssl.tls.set-certificate-file
// TEST-METADATA: assetType=protocol, findingType=protocol, operation=configure, protocolName=TLS, algorithmFamily=TLS, library=openssl, configType=certificate
fn test_set_certificate_file() {
    use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
    let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls()).unwrap();
    builder
        .set_certificate_file("cert.pem", SslFiletype::PEM)
        .unwrap();
}

// TEST-RULE: rust.openssl.tls.set-certificate
// TEST-METADATA: assetType=protocol, findingType=protocol, operation=configure, protocolName=TLS, algorithmFamily=TLS, library=openssl, configType=certificate
fn test_set_certificate() {
    use openssl::ssl::{SslAcceptor, SslMethod};
    use openssl::x509::X509;
    let cert_pem = b"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----";
    let cert = X509::from_pem(cert_pem).unwrap();
    let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls()).unwrap();
    builder.set_certificate(&cert).unwrap();
}

// TEST-RULE: rust.openssl.tls.set-ca-file
// TEST-METADATA: assetType=protocol, findingType=protocol, operation=configure, protocolName=TLS, algorithmFamily=TLS, library=openssl, configType=ca_certificate
fn test_set_ca_file() {
    use openssl::ssl::{SslConnector, SslMethod};
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_ca_file("ca.pem").unwrap();
}

// TEST-RULE: rust.openssl.tls.load-verify-locations
// TEST-METADATA: assetType=protocol, findingType=protocol, operation=configure, protocolName=TLS, algorithmFamily=TLS, library=openssl, configType=ca_certificate
fn test_load_verify_locations() {
    use openssl::ssl::{SslConnector, SslMethod};
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder
        .load_verify_locations(Some("ca.pem".as_ref()), None)
        .unwrap();
}

// TEST-RULE: rust.openssl.tls.set-default-verify-paths
// TEST-METADATA: assetType=protocol, findingType=protocol, operation=configure, protocolName=TLS, algorithmFamily=TLS, library=openssl, configType=ca_certificate
fn test_set_default_verify_paths() {
    use openssl::ssl::{SslConnector, SslMethod};
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_default_verify_paths().unwrap();
}

// TEST-RULE: rust.openssl.tls.set-cipher-list
// TEST-METADATA: assetType=protocol, findingType=protocol, operation=configure, protocolName=TLS, algorithmFamily=TLS, library=openssl, configType=cipher_list
fn test_set_cipher_list() {
    use openssl::ssl::{SslAcceptor, SslMethod};
    let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls()).unwrap();
    builder.set_cipher_list("HIGH:!aNULL:!MD5").unwrap();
}

// TEST-RULE: rust.openssl.tls.set-ciphersuites
// TEST-METADATA: assetType=protocol, findingType=protocol, operation=configure, protocolName=TLS, algorithmFamily=TLS, library=openssl, configType=cipher_suites
fn test_set_ciphersuites() {
    use openssl::ssl::{SslAcceptor, SslMethod};
    let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls()).unwrap();
    builder
        .set_ciphersuites("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256")
        .unwrap();
}

// TEST-RULE: rust.openssl.tls.set-min-proto-version
// TEST-METADATA: assetType=protocol, findingType=protocol, operation=configure, protocolName=TLS, algorithmFamily=TLS, library=openssl, configType=protocol_version
fn test_set_min_proto_version() {
    use openssl::ssl::{SslAcceptor, SslMethod, SslVersion};
    let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls()).unwrap();
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
}

// TEST-RULE: rust.openssl.tls.set-max-proto-version
// TEST-METADATA: assetType=protocol, findingType=protocol, operation=configure, protocolName=TLS, algorithmFamily=TLS, library=openssl, configType=protocol_version
fn test_set_max_proto_version() {
    use openssl::ssl::{SslAcceptor, SslMethod, SslVersion};
    let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls()).unwrap();
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
}

// TEST-RULE: rust.openssl.tls.set-alpn-protos
// TEST-METADATA: assetType=protocol, findingType=protocol, operation=configure, protocolName=TLS, algorithmFamily=TLS, library=openssl, configType=alpn
fn test_set_alpn_protos() {
    use openssl::ssl::{SslConnector, SslMethod};
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_alpn_protos(b"\x02h2\x08http/1.1").unwrap();
}

// TEST-RULE: rust.openssl.tls.set-verify
// TEST-METADATA: assetType=protocol, findingType=protocol, operation=configure, protocolName=TLS, algorithmFamily=TLS, library=openssl, configType=verification
fn test_set_verify() {
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_verify(SslVerifyMode::PEER);
}

// TEST-RULE: rust.openssl.tls.set-groups-list
// TEST-METADATA: assetType=protocol, findingType=protocol, operation=configure, protocolName=TLS, algorithmFamily=TLS, library=openssl, configType=key_exchange_groups
fn test_set_groups_list() {
    use openssl::ssl::{SslAcceptor, SslMethod};
    let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls()).unwrap();
    builder.set_groups_list("X25519:P-256:P-384").unwrap();
}

// TEST-RULE: rust.openssl.tls.set-sigalgs-list
// TEST-METADATA: assetType=protocol, findingType=protocol, operation=configure, protocolName=TLS, algorithmFamily=TLS, library=openssl, configType=signature_algorithms
fn test_set_sigalgs_list() {
    use openssl::ssl::{SslAcceptor, SslMethod};
    let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls()).unwrap();
    builder.set_sigalgs_list("ECDSA+SHA256:RSA+SHA256").unwrap();
}

// TEST-RULE: rust.openssl.tls.ssl-new
// TEST-METADATA: assetType=protocol, findingType=protocol, operation=init, protocolName=TLS, algorithmFamily=TLS, library=openssl
fn test_ssl_new() {
    use openssl::ssl::{Ssl, SslContext, SslMethod};
    let ctx = SslContext::builder(SslMethod::tls()).unwrap().build();
    let ssl = Ssl::new(&ctx);
    _ = ssl;
}

// TEST-RULE: rust.openssl.tls.ssl-connect
// TEST-METADATA: assetType=protocol, findingType=protocol, operation=handshake, protocolName=TLS, algorithmFamily=TLS, library=openssl, role=client
fn test_ssl_connect() {
    use openssl::ssl::{Ssl, SslContext, SslMethod};
    use std::net::TcpStream;
    let ctx = SslContext::builder(SslMethod::tls()).unwrap().build();
    let ssl = Ssl::new(&ctx).unwrap();
    let stream = TcpStream::connect("example.com:443").unwrap();
    let _ = ssl.connect(stream);
}

// TEST-RULE: rust.openssl.tls.ssl-accept
// TEST-METADATA: assetType=protocol, findingType=protocol, operation=handshake, protocolName=TLS, algorithmFamily=TLS, library=openssl, role=server
fn test_ssl_accept() {
    use openssl::ssl::{Ssl, SslContext, SslMethod};
    use std::net::TcpStream;
    let ctx = SslContext::builder(SslMethod::tls()).unwrap().build();
    let ssl = Ssl::new(&ctx).unwrap();
    let stream = TcpStream::connect("127.0.0.1:8443").unwrap();
    let _ = ssl.accept(stream);
}

// TEST-RULE: rust.openssl.tls.acceptor-accept
// TEST-METADATA: assetType=protocol, findingType=protocol, operation=handshake, protocolName=TLS, algorithmFamily=TLS, library=openssl, role=server
fn test_acceptor_accept() {
    use openssl::ssl::{SslAcceptor, SslMethod};
    use std::net::TcpStream;
    let acceptor = SslAcceptor::mozilla_modern(SslMethod::tls())
        .unwrap()
        .build();
    let stream = TcpStream::connect("127.0.0.1:8443").unwrap();
    let _ = acceptor.accept(stream);
}

// TEST-RULE: rust.openssl.tls.connector-connect
// TEST-METADATA: assetType=protocol, findingType=protocol, operation=handshake, protocolName=TLS, algorithmFamily=TLS, library=openssl, role=client
fn test_connector_connect() {
    use openssl::ssl::{SslConnector, SslMethod};
    use std::net::TcpStream;
    let connector = SslConnector::builder(SslMethod::tls()).unwrap().build();
    let stream = TcpStream::connect("example.com:443").unwrap();
    let _ = connector.connect("example.com", stream);
}

// TEST-RULE: rust.openssl.tls.stream-new
// TEST-METADATA: assetType=protocol, findingType=protocol, operation=init, protocolName=TLS, algorithmFamily=TLS, library=openssl
fn test_stream_new() {
    use openssl::ssl::{Ssl, SslContext, SslMethod, SslStream};
    use std::net::TcpStream;
    let ctx = SslContext::builder(SslMethod::tls()).unwrap().build();
    let ssl = Ssl::new(&ctx).unwrap();
    let stream = TcpStream::connect("example.com:443").unwrap();
    let ssl_stream = SslStream::new(ssl, stream);
    _ = ssl_stream;
}

// TEST-RULE: rust.openssl.tls.stream-handshake
// TEST-METADATA: assetType=protocol, findingType=protocol, operation=handshake, protocolName=TLS, algorithmFamily=TLS, library=openssl
fn test_stream_handshake() {
    use openssl::ssl::{Ssl, SslContext, SslMethod, SslStream};
    use std::net::TcpStream;
    let ctx = SslContext::builder(SslMethod::tls()).unwrap().build();
    let ssl = Ssl::new(&ctx).unwrap();
    let stream = TcpStream::connect("example.com:443").unwrap();
    let mut ssl_stream = SslStream::new(ssl, stream).unwrap();
    let _ = ssl_stream.do_handshake();
}
