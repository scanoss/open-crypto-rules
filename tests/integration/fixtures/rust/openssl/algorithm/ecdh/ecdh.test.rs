// TEST-RULE: rust.openssl.ecdh.deriver-new
// TEST-METADATA: assetType=algorithm, findingType=keyderive, algorithmName=ECDH, algorithmFamily=ECDH, library=openssl, algorithmPrimitive=key-agree
fn test_deriver_new() {
    use openssl::derive::Deriver;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();
    let deriver = Deriver::new(&pkey).unwrap();
    _ = deriver;
}

// TEST-RULE: rust.openssl.ecdh.set-peer
// TEST-METADATA: assetType=algorithm, findingType=keyderive, algorithmName=ECDH, algorithmFamily=ECDH, library=openssl, algorithmPrimitive=key-agree
fn test_deriver_set_peer() {
    use openssl::derive::Deriver;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let my_key = EcKey::generate(&group).unwrap();
    let peer_key = EcKey::generate(&group).unwrap();
    let my_pkey = PKey::from_ec_key(my_key).unwrap();
    let peer_pkey = PKey::from_ec_key(peer_key).unwrap();
    let mut deriver = Deriver::new(&my_pkey).unwrap();
    let _ = deriver.set_peer(&peer_pkey);
}

// TEST-RULE: rust.openssl.ecdh.derive
// TEST-METADATA: assetType=algorithm, findingType=keyderive, algorithmName=ECDH, algorithmFamily=ECDH, library=openssl, algorithmPrimitive=key-agree
fn test_deriver_derive() {
    use openssl::derive::Deriver;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let my_key = EcKey::generate(&group).unwrap();
    let peer_key = EcKey::generate(&group).unwrap();
    let my_pkey = PKey::from_ec_key(my_key).unwrap();
    let peer_pkey = PKey::from_ec_key(peer_key).unwrap();
    let mut deriver = Deriver::new(&my_pkey).unwrap();
    deriver.set_peer(&peer_pkey).unwrap();
    let mut shared_secret = vec![0u8; 32];
    let _ = deriver.derive(&mut shared_secret);
}
