// TEST-METADATA: assetType=protocol, findingType=key_exchange, operation=keyexchange, protocolName=TLS, protocolType=tls, protocolVersion=1.0, library=native-tls
fn test_protocol_version_tls10_min() {
    use native_tls::TlsConnector;
    let builder = TlsConnector::builder();
    builder.min_protocol_version(native_tls::Protocol::Tlsv10);
}

// TEST-METADATA: assetType=protocol, findingType=key_exchange, operation=keyexchange, protocolName=TLS, protocolType=tls, protocolVersion=1.1, library=native-tls
fn test_protocol_version_tls11() {
    use native_tls::{Protocol, TlsConnector};
    let builder = TlsConnector::builder();
    builder.min_protocol_version(Protocol::Tlsv11);
}

// TEST-METADATA: assetType=protocol, findingType=key_exchange, operation=keyexchange, protocolName=TLS, protocolType=tls, protocolVersion=1.2, library=native-tls
fn test_protocol_version_tls12_max() {
    use native_tls::{Protocol, TlsConnector};
    let builder = TlsConnector::builder();
    builder.max_protocol_version(Protocol::Tlsv12);
}

// TEST-METADATA: assetType=protocol, findingType=key_exchange, operation=keyexchange, protocolName=TLS, protocolType=tls, protocolVersion=1.3, library=native-tls
fn test_protocol_version_tls13_max() {
    use native_tls::{Protocol::Tlsv13, TlsConnector};
    let builder = TlsConnector::builder();
    builder.max_protocol_version(Tlsv13);
}
