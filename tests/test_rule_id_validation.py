from lib.fixture_parser import parse_test_expectations
from lib.validator import find_matching_result


def _make_result(check_id, crypto_metadata):
    return {
        "check_id": check_id,
        "extra": {
            "metadata": {
                "crypto": crypto_metadata,
            },
            "metavars": {},
        },
    }


def test_parse_test_rule_applies_to_next_metadata_block(tmp_path):
    fixture = tmp_path / "example.test.rs"
    fixture.write_text(
        "\n".join(
            [
                "// TEST-RULE: rust.crypto.rule1",
                "// TEST-METADATA: algorithmName=AES-GCM-SIV",
                "use aes_gcm_siv::Aes256GcmSiv;",
                "",
                "// TEST-RULE: rust.crypto.rule2",
                "// TEST-METADATA: algorithmName=ChaCha20-Poly1305",
                "use chacha20poly1305::ChaCha20Poly1305;",
            ]
        ),
        encoding="utf-8",
    )

    expectations = parse_test_expectations(str(fixture))

    assert [expectation.rule_id for expectation in expectations] == [
        "rust.crypto.rule1",
        "rust.crypto.rule2",
    ]


def test_find_matching_result_rejects_metadata_match_from_wrong_rule():
    results = [
        _make_result(
            "rust.crypto.rule1",
            {
                "algorithmName": "AES-GCM-SIV",
                "library": "RustCrypto",
            },
        ),
    ]

    match = find_matching_result(
        results,
        {
            "algorithmName": "AES-GCM-SIV",
            "library": "RustCrypto",
        },
        "rust.crypto.rule2",
    )

    assert match is None


def test_find_matching_result_accepts_expected_rule_when_present():
    results = [
        _make_result(
            "rust.crypto.rule1",
            {
                "algorithmName": "AES-GCM-SIV",
                "library": "RustCrypto",
            },
        ),
        _make_result(
            "rust.crypto.rule2",
            {
                "algorithmName": "ChaCha20-Poly1305",
                "library": "RustCrypto",
            },
        ),
    ]

    match = find_matching_result(
        results,
        {
            "algorithmName": "ChaCha20-Poly1305",
            "library": "RustCrypto",
        },
        "rust.crypto.rule2",
    )

    assert match is not None
    result, resolved_metadata = match
    assert result["check_id"] == "rust.crypto.rule2"
    assert resolved_metadata["algorithmName"] == "ChaCha20-Poly1305"
