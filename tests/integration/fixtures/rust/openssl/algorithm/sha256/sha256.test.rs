// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, algorithmName=SHA-256, algorithmFamily=SHA-2, library=openssl, algorithmPrimitive=hash, algorithmParameterSetIdentifier=256
fn test_sha256_direct_function_single_import() {
    use openssl::sha;
    let data = b"test data";
    let hash = sha::sha256(data);
    _ = hash;
}

// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, algorithmName=SHA-256, algorithmFamily=SHA-2, library=openssl, algorithmPrimitive=hash, algorithmParameterSetIdentifier=256
fn test_sha256_direct_function_grouped_import() {
    use {openssl::sha, std::io};
    let data = b"test data";
    let hash = sha::sha256(data);
    _ = hash;
}

// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, algorithmName=SHA-256, algorithmFamily=SHA-2, library=openssl, algorithmPrimitive=hash, algorithmParameterSetIdentifier=256
fn test_sha256_fully_qualified() {
    let data = b"test data";
    let hash = openssl::sha::sha256(data);
    _ = hash;
}

// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, algorithmName=SHA-256, algorithmFamily=SHA-2, library=openssl, algorithmPrimitive=hash, algorithmParameterSetIdentifier=256
fn test_sha256_hasher_new() {
    use openssl::sha;
    let mut hasher = sha::Sha256::new();
    hasher.update(b"test");
    let hash = hasher.finish();
    _ = hash;
}

// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, algorithmName=SHA-256, algorithmFamily=SHA-2, library=openssl, algorithmPrimitive=hash, algorithmParameterSetIdentifier=256
fn test_sha256_hasher_new_grouped_import() {
    use {openssl::sha, std::io};
    let mut hasher = sha::Sha256::new();
    hasher.update(b"test");
    let hash = hasher.finish();
    _ = hash;
}

// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, algorithmName=SHA-256, algorithmFamily=SHA-2, library=openssl, algorithmPrimitive=hash, algorithmParameterSetIdentifier=256
fn test_sha256_hasher_new_fully_qualified() {
    let mut hasher = openssl::sha::Sha256::new();
    hasher.update(b"test");
    let hash = hasher.finish();
    _ = hash;
}

// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, algorithmName=SHA-256, algorithmFamily=SHA-2, library=openssl, algorithmPrimitive=hash, algorithmParameterSetIdentifier=256
fn test_sha256_hasher_with_messagedigest() {
    use openssl::hash::{Hasher, MessageDigest};
    let mut hasher = Hasher::new(MessageDigest::sha256()).unwrap();
    hasher.update(b"test").unwrap();
    let hash = hasher.finish().unwrap();
    _ = hash;
}

// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, algorithmName=SHA-256, algorithmFamily=SHA-2, library=openssl, algorithmPrimitive=hash, algorithmParameterSetIdentifier=256
fn test_sha256_hasher_with_messagedigest_grouped_import() {
    use {
        openssl::hash::{Hasher, MessageDigest},
        std::io,
    };
    let mut hasher = Hasher::new(MessageDigest::sha256()).unwrap();
    hasher.update(b"test").unwrap();
    let hash = hasher.finish().unwrap();
    _ = hash;
}

// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, algorithmName=SHA-256, algorithmFamily=SHA-2, library=openssl, algorithmPrimitive=hash, algorithmParameterSetIdentifier=256
fn test_sha256_hasher_with_messagedigest_fully_qualified() {
    let mut hasher = openssl::hash::Hasher::new(openssl::hash::MessageDigest::sha256()).unwrap();
    hasher.update(b"test").unwrap();
    let hash = hasher.finish().unwrap();
    _ = hash;
}

// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, algorithmName=SHA-256, algorithmFamily=SHA-2, library=openssl, algorithmPrimitive=hash, algorithmParameterSetIdentifier=256
fn test_sha256_hash_function_with_messagedigest() {
    use openssl::hash::{hash, MessageDigest};
    let data = b"test data";
    let hash_result = hash(MessageDigest::sha256(), data).unwrap();
    _ = hash_result;
}

// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, algorithmName=SHA-256, algorithmFamily=SHA-2, library=openssl, algorithmPrimitive=hash, algorithmParameterSetIdentifier=256
fn test_sha256_hash_function_with_messagedigest_grouped_import() {
    use {
        openssl::hash::{hash, MessageDigest},
        std::io,
    };
    let data = b"test data";
    let hash_result = hash(MessageDigest::sha256(), data).unwrap();
    _ = hash_result;
}

// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, algorithmName=SHA-256, algorithmFamily=SHA-2, library=openssl, algorithmPrimitive=hash, algorithmParameterSetIdentifier=256
fn test_sha256_hash_function_with_messagedigest_fully_qualified() {
    let data = b"test data";
    let hash_result = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), data).unwrap();
    _ = hash_result;
}

// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, algorithmName=SHA-256, algorithmFamily=SHA-2, library=openssl, algorithmPrimitive=hash, algorithmParameterSetIdentifier=256
fn test_sha256_md_single_import() {
    use openssl::md::Md;
    let md = Md::sha256();
    _ = md;
}

// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, algorithmName=SHA-256, algorithmFamily=SHA-2, library=openssl, algorithmPrimitive=hash, algorithmParameterSetIdentifier=256
fn test_sha256_md_module_import() {
    use openssl::md;
    let md = md::Md::sha256();
    _ = md;
}

// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, algorithmName=SHA-256, algorithmFamily=SHA-2, library=openssl, algorithmPrimitive=hash, algorithmParameterSetIdentifier=256
fn test_sha256_md_fully_qualified() {
    let md = openssl::md::Md::sha256();
    _ = md;
}

// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, algorithmName=SHA-256, algorithmFamily=SHA-2, library=openssl, algorithmPrimitive=hash, algorithmParameterSetIdentifier=256
fn test_sha256_messagedigest_from_nid_single_import() {
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    let md = MessageDigest::from_nid(Nid::SHA256);
    _ = md;
}

// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, algorithmName=SHA-256, algorithmFamily=SHA-2, library=openssl, algorithmPrimitive=hash, algorithmParameterSetIdentifier=256
fn test_sha256_messagedigest_from_nid_grouped_import() {
    use {openssl::hash::MessageDigest, openssl::nid::Nid, std::io};
    let md = MessageDigest::from_nid(Nid::SHA256);
    _ = md;
}

// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, algorithmName=SHA-256, algorithmFamily=SHA-2, library=openssl, algorithmPrimitive=hash, algorithmParameterSetIdentifier=256
fn test_sha256_messagedigest_from_nid_fully_qualified() {
    let md = openssl::hash::MessageDigest::from_nid(openssl::nid::Nid::SHA256);
    _ = md;
}

// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, algorithmName=SHA-256, algorithmFamily=SHA-2, library=openssl, algorithmPrimitive=hash, algorithmParameterSetIdentifier=256
fn test_sha256_md_from_nid_single_import() {
    use openssl::md::Md;
    use openssl::nid::Nid;
    let md = Md::from_nid(Nid::SHA256);
    _ = md;
}

// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, algorithmName=SHA-256, algorithmFamily=SHA-2, library=openssl, algorithmPrimitive=hash, algorithmParameterSetIdentifier=256
fn test_sha256_md_from_nid_grouped_import() {
    use {openssl::md::Md, openssl::nid::Nid, std::io};
    let md = Md::from_nid(Nid::SHA256);
    _ = md;
}

// TEST-METADATA: assetType=algorithm, findingType=hash, operation=digest, algorithmName=SHA-256, algorithmFamily=SHA-2, library=openssl, algorithmPrimitive=hash, algorithmParameterSetIdentifier=256
fn test_sha256_md_from_nid_fully_qualified() {
    let md = openssl::md::Md::from_nid(openssl::nid::Nid::SHA256);
    _ = md;
}
