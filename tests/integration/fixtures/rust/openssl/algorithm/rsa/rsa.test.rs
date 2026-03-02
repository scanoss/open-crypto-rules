// TEST-METADATA: assetType=algorithm, findingType=pke, operation=keygen, algorithmName=RSA, algorithmFamily=RSA, library=openssl, algorithmPrimitive=pke, algorithmParameterSetIdentifier=2048
fn test_rsa_generate_with_import() {
    use openssl::rsa::Rsa;
    let rsa = Rsa::generate(2048).unwrap();
    _ = rsa;
}

// TEST-METADATA: assetType=algorithm, findingType=pke, operation=keygen, algorithmName=RSA, algorithmFamily=RSA, library=openssl, algorithmPrimitive=pke, algorithmParameterSetIdentifier=4096
fn test_rsa_generate_fully_qualified() {
    let rsa = openssl::rsa::Rsa::generate(4096).unwrap();
    _ = rsa;
}

// TEST-RULE: rust.openssl.rsa.keygen-variable
// TEST-METADATA: assetType=algorithm, findingType=pke, operation=keygen, algorithmName=RSA, algorithmFamily=RSA, library=openssl, algorithmPrimitive=pke
fn test_rsa_generate_variable_size() {
    use openssl::rsa::Rsa;
    let key_size = 2048;
    let rsa = Rsa::generate(key_size).unwrap();
    _ = rsa;
}

// TEST-RULE: rust.openssl.rsa.keygen-with-exponent
// TEST-METADATA: assetType=algorithm, findingType=pke, operation=keygen, algorithmName=RSA, algorithmFamily=RSA, library=openssl, algorithmPrimitive=pke
fn test_rsa_generate_with_exponent() {
    use openssl::bn::BigNum;
    use openssl::rsa::Rsa;
    let e = BigNum::from_u32(65537).unwrap();
    let rsa = Rsa::generate_with_e(2048, &e).unwrap();
    _ = rsa;
}

// TEST-RULE: rust.openssl.rsa.from-public-components
// TEST-METADATA: assetType=algorithm, findingType=pke, operation=keygen, algorithmName=RSA, algorithmFamily=RSA, library=openssl, algorithmPrimitive=pke
fn test_rsa_from_public_components() {
    use openssl::bn::BigNum;
    use openssl::rsa::Rsa;
    let n = BigNum::from_slice(&[0u8; 256]).unwrap();
    let e = BigNum::from_slice(&[1, 0, 1]).unwrap();
    let rsa = Rsa::from_public_components(n, e).unwrap();
    _ = rsa;
}

// TEST-RULE: rust.openssl.rsa.from-private-components
// TEST-METADATA: assetType=algorithm, findingType=pke, operation=keygen, algorithmName=RSA, algorithmFamily=RSA, library=openssl, algorithmPrimitive=pke
fn test_rsa_from_private_components() {
    use openssl::bn::BigNum;
    use openssl::rsa::Rsa;
    let n = BigNum::new().unwrap();
    let e = BigNum::new().unwrap();
    let d = BigNum::new().unwrap();
    let p = BigNum::new().unwrap();
    let q = BigNum::new().unwrap();
    let dmp1 = BigNum::new().unwrap();
    let dmq1 = BigNum::new().unwrap();
    let iqmp = BigNum::new().unwrap();
    let rsa = Rsa::from_private_components(n, e, d, p, q, dmp1, dmq1, iqmp);
    _ = rsa;
}

// TEST-RULE: rust.openssl.rsa.private-key-builder
// TEST-METADATA: assetType=algorithm, findingType=pke, operation=keygen, algorithmName=RSA, algorithmFamily=RSA, library=openssl, algorithmPrimitive=pke
fn test_rsa_private_key_builder() {
    use openssl::bn::BigNum;
    use openssl::rsa::RsaPrivateKeyBuilder;
    let n = BigNum::new().unwrap();
    let e = BigNum::new().unwrap();
    let d = BigNum::new().unwrap();
    let builder = RsaPrivateKeyBuilder::new(n, e, d);
    _ = builder;
}

// TEST-RULE: rust.openssl.rsa.private-key-from-pem
// TEST-METADATA: assetType=algorithm, findingType=pke, operation=load, algorithmName=RSA, algorithmFamily=RSA, library=openssl, algorithmPrimitive=pke, keyFormat=PEM
fn test_rsa_private_key_from_pem() {
    use openssl::rsa::Rsa;
    let pem_data = b"-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----";
    let rsa = Rsa::private_key_from_pem(pem_data);
    _ = rsa;
}

// TEST-RULE: rust.openssl.rsa.private-key-from-der
// TEST-METADATA: assetType=algorithm, findingType=pke, operation=load, algorithmName=RSA, algorithmFamily=RSA, library=openssl, algorithmPrimitive=pke, keyFormat=DER
fn test_rsa_private_key_from_der() {
    use openssl::rsa::Rsa;
    let der_data = [0u8; 100];
    let rsa = Rsa::private_key_from_der(&der_data);
    _ = rsa;
}

// TEST-RULE: rust.openssl.rsa.public-key-from-pem
// TEST-METADATA: assetType=algorithm, findingType=pke, operation=load, algorithmName=RSA, algorithmFamily=RSA, library=openssl, algorithmPrimitive=pke, keyFormat=PEM
fn test_rsa_public_key_from_pem() {
    use openssl::rsa::Rsa;
    let pem_data = b"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----";
    let rsa = Rsa::public_key_from_pem(pem_data);
    _ = rsa;
}

// TEST-RULE: rust.openssl.rsa.public-key-from-der
// TEST-METADATA: assetType=algorithm, findingType=pke, operation=load, algorithmName=RSA, algorithmFamily=RSA, library=openssl, algorithmPrimitive=pke, keyFormat=DER
fn test_rsa_public_key_from_der() {
    use openssl::rsa::Rsa;
    let der_data = [0u8; 100];
    let rsa = Rsa::public_key_from_der(&der_data);
    _ = rsa;
}

// TEST-RULE: rust.openssl.rsa.private-key-to-der
// TEST-METADATA: assetType=algorithm, findingType=pke, operation=serialize, algorithmName=RSA, algorithmFamily=RSA, library=openssl, algorithmPrimitive=pke, keyFormat=DER
fn test_rsa_private_key_to_der() {
    use openssl::rsa::Rsa;
    let rsa = Rsa::generate(2048).unwrap();
    let der = rsa.private_key_to_der();
    _ = der;
}

// TEST-RULE: rust.openssl.rsa.private-key-to-pem
// TEST-METADATA: assetType=algorithm, findingType=pke, operation=serialize, algorithmName=RSA, algorithmFamily=RSA, library=openssl, algorithmPrimitive=pke, keyFormat=PEM
fn test_rsa_private_key_to_pem() {
    use openssl::rsa::Rsa;
    let rsa = Rsa::generate(2048).unwrap();
    let pem = rsa.private_key_to_pem();
    _ = pem;
}

// TEST-RULE: rust.openssl.rsa.public-key-to-der
// TEST-METADATA: assetType=algorithm, findingType=pke, operation=serialize, algorithmName=RSA, algorithmFamily=RSA, library=openssl, algorithmPrimitive=pke, keyFormat=DER
fn test_rsa_public_key_to_der() {
    use openssl::rsa::Rsa;
    let rsa = Rsa::generate(2048).unwrap();
    let der = rsa.public_key_to_der();
    _ = der;
}

// TEST-RULE: rust.openssl.rsa.public-key-to-pem
// TEST-METADATA: assetType=algorithm, findingType=pke, operation=serialize, algorithmName=RSA, algorithmFamily=RSA, library=openssl, algorithmPrimitive=pke, keyFormat=PEM
fn test_rsa_public_key_to_pem() {
    use openssl::rsa::Rsa;
    let rsa = Rsa::generate(2048).unwrap();
    let pem = rsa.public_key_to_pem();
    _ = pem;
}

// TEST-RULE: rust.openssl.rsa.decrypt-oaep
// TEST-METADATA: assetType=algorithm, findingType=pke, operation=decrypt, algorithmName=RSA-OAEP, algorithmFamily=RSA, library=openssl, algorithmPrimitive=pke, padding=oaep
fn test_rsa_decrypt_oaep() {
    use openssl::rsa::{Padding, Rsa};
    let rsa = Rsa::generate(2048).unwrap();
    let cipher_text = [0u8; 256];
    let mut plaintext = [0u8; 256];
    let _ = rsa.private_decrypt(&cipher_text, &mut plaintext, Padding::PKCS1_OAEP);
}

// TEST-RULE: rust.openssl.rsa.decrypt-pkcs1
// TEST-METADATA: assetType=algorithm, findingType=pke, operation=decrypt, algorithmName=RSA-PKCS1-1.5, algorithmFamily=RSA, library=openssl, algorithmPrimitive=pke, padding=pkcs1v15
fn test_rsa_decrypt_pkcs1() {
    use openssl::rsa::{Padding, Rsa};
    let rsa = Rsa::generate(2048).unwrap();
    let cipher_text = [0u8; 256];
    let mut plaintext = [0u8; 256];
    let _ = rsa.private_decrypt(&cipher_text, &mut plaintext, Padding::PKCS1);
}

// TEST-RULE: rust.openssl.rsa.encrypt-oaep
// TEST-METADATA: assetType=algorithm, findingType=pke, operation=encrypt, algorithmName=RSA-OAEP, algorithmFamily=RSA, library=openssl, algorithmPrimitive=pke, padding=oaep
fn test_rsa_encrypt_oaep() {
    use openssl::rsa::{Padding, Rsa};
    let rsa = Rsa::generate(2048).unwrap();
    let plaintext = b"hello";
    let mut ciphertext = [0u8; 256];
    let _ = rsa.public_encrypt(plaintext, &mut ciphertext, Padding::PKCS1_OAEP);
}

// TEST-RULE: rust.openssl.rsa.encrypt-pkcs1
// TEST-METADATA: assetType=algorithm, findingType=pke, operation=encrypt, algorithmName=RSA-PKCS1-1.5, algorithmFamily=RSA, library=openssl, algorithmPrimitive=pke, padding=pkcs1v15
fn test_rsa_encrypt_pkcs1() {
    use openssl::rsa::{Padding, Rsa};
    let rsa = Rsa::generate(2048).unwrap();
    let plaintext = b"hello";
    let mut ciphertext = [0u8; 256];
    let _ = rsa.public_encrypt(plaintext, &mut ciphertext, Padding::PKCS1);
}

// TEST-RULE: rust.openssl.rsa.private-encrypt
// TEST-METADATA: assetType=algorithm, findingType=signature, operation=sign, algorithmName=RSA, algorithmFamily=RSA, library=openssl, algorithmPrimitive=signature
fn test_rsa_private_encrypt() {
    use openssl::rsa::{Padding, Rsa};
    let rsa = Rsa::generate(2048).unwrap();
    let data = b"data to sign";
    let mut signature = [0u8; 256];
    let _ = rsa.private_encrypt(data, &mut signature, Padding::PKCS1);
}

// TEST-RULE: rust.openssl.rsa.public-decrypt
// TEST-METADATA: assetType=algorithm, findingType=signature, operation=verify, algorithmName=RSA, algorithmFamily=RSA, library=openssl, algorithmPrimitive=signature
fn test_rsa_public_decrypt() {
    use openssl::bn::BigNum;
    use openssl::rsa::{Padding, Rsa};
    let n = BigNum::from_slice(&[0u8; 256]).unwrap();
    let e = BigNum::from_slice(&[1, 0, 1]).unwrap();
    let rsa = Rsa::from_public_components(n, e).unwrap();
    let signature = [0u8; 256];
    let mut data = [0u8; 256];
    let _ = rsa.public_decrypt(&signature, &mut data, Padding::PKCS1);
}

// TEST-RULE: rust.openssl.rsa.encrypt-high-level
// TEST-METADATA: assetType=algorithm, findingType=pke, operation=encrypt, algorithmName=RSA, algorithmFamily=RSA, library=openssl, algorithmPrimitive=pke
fn test_rsa_encrypter() {
    use openssl::encrypt::Encrypter;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    let mut encrypter = Encrypter::new(&pkey).unwrap();
    let plaintext = b"hello";
    let mut ciphertext = vec![0u8; 256];
    let _ = encrypter.encrypt(plaintext, &mut ciphertext);
}

// TEST-RULE: rust.openssl.rsa.decrypt-high-level
// TEST-METADATA: assetType=algorithm, findingType=pke, operation=decrypt, algorithmName=RSA, algorithmFamily=RSA, library=openssl, algorithmPrimitive=pke
fn test_rsa_decrypter() {
    use openssl::encrypt::Decrypter;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    let mut decrypter = Decrypter::new(&pkey).unwrap();
    let ciphertext = [0u8; 256];
    let mut plaintext = vec![0u8; 256];
    let _ = decrypter.decrypt(&ciphertext, &mut plaintext);
}
