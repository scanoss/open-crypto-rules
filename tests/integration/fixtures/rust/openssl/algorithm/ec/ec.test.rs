// TEST-METADATA: assetType=algorithm, findingType=signature, algorithmName=EC, algorithmFamily=EC, library=openssl, algorithmPrimitive=signature, ellipticCurve=Nid X9_62_PRIME256V1
fn test_ecgroup_from_curve_name_p256() {
    use openssl::ec::EcGroup;
    use openssl::nid::Nid;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    _ = group;
}

// TEST-METADATA: assetType=algorithm, findingType=signature, algorithmName=EC, algorithmFamily=EC, library=openssl, algorithmPrimitive=signature, ellipticCurve=Nid SECP384R1
fn test_ecgroup_from_curve_name_p384() {
    use openssl::ec::EcGroup;
    use openssl::nid::Nid;
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    _ = group;
}

// TEST-RULE: rust.openssl.ec.curve-from-components
// TEST-METADATA: assetType=algorithm, findingType=signature, algorithmName=EC, algorithmFamily=EC, library=openssl, algorithmPrimitive=signature
fn test_ecgroup_from_components() {
    use openssl::bn::{BigNum, BigNumContext};
    use openssl::ec::EcGroup;
    let p = BigNum::new().unwrap();
    let a = BigNum::new().unwrap();
    let b = BigNum::new().unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let group = EcGroup::from_components(p, a, b, &mut ctx);
    _ = group;
}

// TEST-RULE: rust.openssl.ec.key-generate
// TEST-METADATA: assetType=algorithm, findingType=signature, operation=keygen, algorithmName=EC, algorithmFamily=EC, library=openssl, algorithmPrimitive=signature
fn test_eckey_generate() {
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = EcKey::generate(&group).unwrap();
    _ = key;
}

// TEST-RULE: rust.openssl.ec.key-from-curve-name
// TEST-METADATA: assetType=algorithm, findingType=signature, algorithmName=EC, algorithmFamily=EC, library=openssl, algorithmPrimitive=signature
fn test_eckey_from_curve_name() {
    use openssl::ec::EcKey;
    use openssl::nid::Nid;
    let key = EcKey::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    _ = key;
}

// TEST-RULE: rust.openssl.ec.key-from-group
// TEST-METADATA: assetType=algorithm, findingType=signature, algorithmName=EC, algorithmFamily=EC, library=openssl, algorithmPrimitive=signature
fn test_eckey_from_group() {
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = EcKey::from_group(&group).unwrap();
    _ = key;
}

// TEST-RULE: rust.openssl.ec.key-from-public-key
// TEST-METADATA: assetType=algorithm, findingType=signature, algorithmName=EC, algorithmFamily=EC, library=openssl, algorithmPrimitive=signature
fn test_eckey_from_public_key() {
    use openssl::ec::{EcGroup, EcKey, EcPoint};
    use openssl::nid::Nid;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let point = EcPoint::new(&group).unwrap();
    let key = EcKey::from_public_key(&group, &point);
    _ = key;
}

// TEST-RULE: rust.openssl.ec.key-from-public-key-affine
// TEST-METADATA: assetType=algorithm, findingType=signature, algorithmName=EC, algorithmFamily=EC, library=openssl, algorithmPrimitive=signature
fn test_eckey_from_public_key_affine_coordinates() {
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let x = BigNum::new().unwrap();
    let y = BigNum::new().unwrap();
    let key = EcKey::from_public_key_affine_coordinates(&group, &x, &y);
    _ = key;
}

// TEST-RULE: rust.openssl.ec.key-from-private-components
// TEST-METADATA: assetType=algorithm, findingType=signature, algorithmName=EC, algorithmFamily=EC, library=openssl, algorithmPrimitive=signature
fn test_eckey_from_private_components() {
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey, EcPoint};
    use openssl::nid::Nid;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let private_num = BigNum::new().unwrap();
    let public_key = EcPoint::new(&group).unwrap();
    let key = EcKey::from_private_components(&group, &private_num, &public_key);
    _ = key;
}

// TEST-RULE: rust.openssl.ec.private-key-from-pem
// TEST-METADATA: assetType=algorithm, findingType=signature, algorithmName=EC, algorithmFamily=EC, library=openssl, algorithmPrimitive=signature, keyFormat=PEM
fn test_eckey_private_key_from_pem() {
    use openssl::ec::EcKey;
    let pem_data = b"-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----";
    let key = EcKey::private_key_from_pem(pem_data);
    _ = key;
}

// TEST-RULE: rust.openssl.ec.private-key-from-der
// TEST-METADATA: assetType=algorithm, findingType=signature, algorithmName=EC, algorithmFamily=EC, library=openssl, algorithmPrimitive=signature, keyFormat=DER
fn test_eckey_private_key_from_der() {
    use openssl::ec::EcKey;
    let der_data = [0u8; 100];
    let key = EcKey::private_key_from_der(&der_data);
    _ = key;
}

// TEST-RULE: rust.openssl.ec.public-key-from-pem
// TEST-METADATA: assetType=algorithm, findingType=signature, algorithmName=EC, algorithmFamily=EC, library=openssl, algorithmPrimitive=signature, keyFormat=PEM
fn test_eckey_public_key_from_pem() {
    use openssl::ec::EcKey;
    let pem_data = b"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----";
    let key = EcKey::public_key_from_pem(pem_data);
    _ = key;
}

// TEST-RULE: rust.openssl.ec.public-key-from-der
// TEST-METADATA: assetType=algorithm, findingType=signature, algorithmName=EC, algorithmFamily=EC, library=openssl, algorithmPrimitive=signature, keyFormat=DER
fn test_eckey_public_key_from_der() {
    use openssl::ec::EcKey;
    let der_data = [0u8; 100];
    let key = EcKey::public_key_from_der(&der_data);
    _ = key;
}

// TEST-RULE: rust.openssl.ec.private-key-to-der
// TEST-METADATA: assetType=algorithm, findingType=signature, algorithmName=EC, algorithmFamily=EC, library=openssl, algorithmPrimitive=signature, keyFormat=DER
fn test_eckey_private_key_to_der() {
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = EcKey::generate(&group).unwrap();
    let der = key.private_key_to_der();
    _ = der;
}

// TEST-RULE: rust.openssl.ec.private-key-to-pem
// TEST-METADATA: assetType=algorithm, findingType=signature, algorithmName=EC, algorithmFamily=EC, library=openssl, algorithmPrimitive=signature, keyFormat=PEM
fn test_eckey_private_key_to_pem() {
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = EcKey::generate(&group).unwrap();
    let pem = key.private_key_to_pem();
    _ = pem;
}

// TEST-RULE: rust.openssl.ec.public-key-to-der
// TEST-METADATA: assetType=algorithm, findingType=signature, algorithmName=EC, algorithmFamily=EC, library=openssl, algorithmPrimitive=signature, keyFormat=DER
fn test_eckey_public_key_to_der() {
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = EcKey::generate(&group).unwrap();
    let der = key.public_key_to_der();
    _ = der;
}

// TEST-RULE: rust.openssl.ec.public-key-to-pem
// TEST-METADATA: assetType=algorithm, findingType=signature, algorithmName=EC, algorithmFamily=EC, library=openssl, algorithmPrimitive=signature, keyFormat=PEM
fn test_eckey_public_key_to_pem() {
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = EcKey::generate(&group).unwrap();
    let pem = key.public_key_to_pem();
    _ = pem;
}

// TEST-RULE: rust.openssl.ec.point-from-bytes
// TEST-METADATA: assetType=algorithm, findingType=signature, algorithmName=EC, algorithmFamily=EC, library=openssl, algorithmPrimitive=signature
fn test_ecpoint_from_bytes() {
    use openssl::bn::BigNumContext;
    use openssl::ec::{EcGroup, EcPoint};
    use openssl::nid::Nid;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let point_bytes = [0u8; 65];
    let point = EcPoint::from_bytes(&group, &point_bytes, &mut ctx);
    _ = point;
}

// TEST-RULE: rust.openssl.ec.point-from-hex
// TEST-METADATA: assetType=algorithm, findingType=signature, algorithmName=EC, algorithmFamily=EC, library=openssl, algorithmPrimitive=signature
fn test_ecpoint_from_hex_str() {
    use openssl::bn::BigNumContext;
    use openssl::ec::{EcGroup, EcPoint};
    use openssl::nid::Nid;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let hex_str = "04...";
    let point = EcPoint::from_hex_str(&group, hex_str, &mut ctx);
    _ = point;
}
