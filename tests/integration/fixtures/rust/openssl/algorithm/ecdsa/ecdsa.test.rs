// TEST-RULE: rust.openssl.ecdsa.sign
// TEST-METADATA: assetType=algorithm, findingType=signature, operation=sign, algorithmName=ECDSA, algorithmFamily=ECDSA, library=openssl, algorithmPrimitive=signature
fn test_ecdsa_sign() {
    use openssl::ec::{EcGroup, EcKey};
    use openssl::ecdsa::EcdsaSig;
    use openssl::nid::Nid;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = EcKey::generate(&group).unwrap();
    let data = [0u8; 32];
    let sig = EcdsaSig::sign(&data, &key).unwrap();
    _ = sig;
}

// TEST-RULE: rust.openssl.ecdsa.verify
// TEST-METADATA: assetType=algorithm, findingType=signature, operation=verify, algorithmName=ECDSA, algorithmFamily=ECDSA, library=openssl, algorithmPrimitive=signature
fn test_ecdsa_verify() {
    use openssl::ec::{EcGroup, EcKey};
    use openssl::ecdsa::EcdsaSig;
    use openssl::nid::Nid;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = EcKey::generate(&group).unwrap();
    let data = [0u8; 32];
    let sig_der = [0u8; 72];
    let sig = EcdsaSig::from_der(&sig_der).unwrap();
    let result = sig.verify(&data, &key);
    _ = result;
}

// TEST-RULE: rust.openssl.ecdsa.sig-from-der
// TEST-METADATA: assetType=algorithm, findingType=signature, algorithmName=ECDSA, algorithmFamily=ECDSA, library=openssl, algorithmPrimitive=signature, signatureFormat=DER
fn test_ecdsa_sig_from_der() {
    use openssl::ecdsa::EcdsaSig;
    let der_data = [0u8; 72];
    let sig = EcdsaSig::from_der(&der_data);
    _ = sig;
}

// TEST-RULE: rust.openssl.ecdsa.sig-from-components
// TEST-METADATA: assetType=algorithm, findingType=signature, algorithmName=ECDSA, algorithmFamily=ECDSA, library=openssl, algorithmPrimitive=signature
fn test_ecdsa_sig_from_components() {
    use openssl::bn::BigNum;
    use openssl::ecdsa::EcdsaSig;
    let r = BigNum::new().unwrap();
    let s = BigNum::new().unwrap();
    let sig = EcdsaSig::from_private_components(r, s);
    _ = sig;
}

// TEST-RULE: rust.openssl.ecdsa.sig-to-der
// TEST-METADATA: assetType=algorithm, findingType=signature, algorithmName=ECDSA, algorithmFamily=ECDSA, library=openssl, algorithmPrimitive=signature, signatureFormat=DER
fn test_ecdsa_sig_to_der() {
    use openssl::ec::{EcGroup, EcKey};
    use openssl::ecdsa::EcdsaSig;
    use openssl::nid::Nid;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = EcKey::generate(&group).unwrap();
    let data = [0u8; 32];
    let sig = EcdsaSig::sign(&data, &key).unwrap();
    let der = sig.to_der();
    _ = der;
}
