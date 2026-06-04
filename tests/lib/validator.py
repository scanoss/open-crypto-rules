"""
Validator for checking that extracted metadata matches test expectations.
"""

from typing import Dict, List, Tuple, Optional


class ValidationResult:
    """
    Result of a validation check.

    Attributes:
        success: Whether validation passed
        message: Human-readable message (error details or success)
        errors: List of specific error messages
    """

    def __init__(self, success: bool, message: str, errors: List[str] = None):
        self.success = success
        self.message = message
        self.errors = errors or []

    def __bool__(self):
        return self.success

    def __repr__(self):
        status = "PASS" if self.success else "FAIL"
        return f"<ValidationResult({status}: {self.message})>"


def validate_metadata(
    expected: Dict[str, str],
    actual: Dict[str, str],
    rule_id: Optional[str] = None
) -> ValidationResult:
    """
    Validate that actual metadata matches expected metadata.

    Checks that:
    1. All expected metadata fields exist in actual
    2. All expected values match actual values exactly

    Note: Actual metadata may contain additional fields not in expected - this is OK.
    Only the fields specified in expected are validated.

    Args:
        expected: Dict of expected metadata (from TEST-METADATA comment)
        actual: Dict of actual metadata (resolved from opengrep output)
        rule_id: Optional rule ID for better error messages

    Returns:
        ValidationResult with success status and detailed message

    Example:
        >>> expected = {"algorithmName": "AES", "keySize": "256"}
        >>> actual = {"algorithmName": "AES", "keySize": "256", "library": "crypto/aes"}
        >>> result = validate_metadata(expected, actual)
        >>> result.success
        True

        >>> actual = {"algorithmName": "AES", "keySize": "128"}  # Wrong key size
        >>> result = validate_metadata(expected, actual)
        >>> result.success
        False
        >>> print(result.message)
        Metadata validation failed:
          keySize: expected '256', got '128'
    """
    errors = []

    # Check each expected field
    for key, expected_value in expected.items():
        if key not in actual:
            errors.append(f"Missing field '{key}' (expected: '{expected_value}')")
            continue

        actual_value = actual[key]

        if actual_value != expected_value:
            errors.append(
                f"Field '{key}': expected '{expected_value}', got '{actual_value}'"
            )

    if errors:
        rule_info = f" for rule '{rule_id}'" if rule_id else ""
        message = f"Metadata validation failed{rule_info}:\n  " + "\n  ".join(errors)
        return ValidationResult(success=False, message=message, errors=errors)

    # Success!
    field_count = len(expected)
    rule_info = f" for rule '{rule_id}'" if rule_id else ""
    message = f"All {field_count} metadata field(s) matched{rule_info}"
    return ValidationResult(success=True, message=message)


def find_matching_result(
    results: List[Dict],
    expected_metadata: Dict[str, str],
    expected_rule_id: Optional[str] = None
) -> Optional[Tuple[Dict, Dict[str, str]]]:
    """
    Find a result that matches the expected metadata and optional rule ID.

    Iterates through opengrep results to find one where:
    1. Rule ID matches (if specified)
    2. Resolved metadata matches expected metadata

    Args:
        results: List of result dicts from opengrep output
        expected_metadata: Expected metadata to match
        expected_rule_id: Optional rule ID to filter by

    Returns:
        Tuple of (matching result dict, resolved metadata dict) if found, None otherwise

    Example:
        >>> results = [
        ...     {
        ...         "check_id": "go.crypto.aes",
        ...         "extra": {
        ...             "metadata": {"crypto": {"algorithmName": "AES"}},
        ...             "metavars": {}
        ...         }
        ...     }
        ... ]
        >>> expected = {"algorithmName": "AES"}
        >>> result, metadata = find_matching_result(results, expected)
        >>> result["check_id"]
        'go.crypto.aes'
    """
    from .metavar_resolver import extract_metadata_from_result

    for result in results:
        # Check rule ID if specified
        if expected_rule_id:
            actual_rule_id = result.get('check_id', '')
            if not rule_id_matches(actual_rule_id, expected_rule_id):
                continue

        # Extract and resolve metadata
        resolved_metadata = extract_metadata_from_result(result)

        # Check if metadata matches
        validation = validate_metadata(expected_metadata, resolved_metadata)
        if validation.success:
            return result, resolved_metadata

    return None


def rule_id_matches(actual_rule_id: str, expected_rule_id: str) -> bool:
    """
    Check if an actual rule ID matches an expected rule ID.

    Handles various formats:
    - Exact match: "go.crypto.aes" == "go.crypto.aes"
    - Suffix match: "semgrep-rules.go.crypto.aes" ends with "go.crypto.aes"
    - Prefix tolerant: Allows path prefixes from semgrep

    Args:
        actual_rule_id: Rule ID from opengrep output
        expected_rule_id: Rule ID from TEST-RULE comment

    Returns:
        True if IDs match (exact or suffix match)

    Example:
        >>> rule_id_matches("go.crypto.aes", "go.crypto.aes")
        True
        >>> rule_id_matches("semgrep-rules.go.crypto.aes", "go.crypto.aes")
        True
        >>> rule_id_matches("java.jca.cipher", "go.crypto.aes")
        False
    """
    if actual_rule_id == expected_rule_id:
        return True

    # Check if expected is a suffix of actual (handles path prefixes)
    if actual_rule_id.endswith(f".{expected_rule_id}"):
        return True

    if actual_rule_id.endswith(expected_rule_id):
        return True

    return False


def format_expectation_error(
    expectation_index: int,
    expected_metadata: Dict[str, str],
    expected_rule_id: Optional[str],
    results: List[Dict],
    fixture_name: str
) -> str:
    """
    Format a detailed error message when an expectation is not met.

    Args:
        expectation_index: Index of the failed expectation
        expected_metadata: Metadata that was expected
        expected_rule_id: Rule ID that was expected (if any)
        results: All results from opengrep
        fixture_name: Name of the fixture file

    Returns:
        Formatted multi-line error message

    Example output:
        Expectation #1 not satisfied in test.go

        Expected:
          Rule: go.crypto.aes (optional)
          Metadata: algorithmName=AES, keySize=256

        Triggered rules:
          - go.crypto.aes (metadata mismatch: keySize expected '256' got '128')
          - go.crypto.sha

        No matching result found.
    """
    from .metavar_resolver import extract_metadata_from_result

    lines = [
        f"Expectation #{expectation_index + 1} not satisfied in {fixture_name}",
        "",
        "Expected:"
    ]

    if expected_rule_id:
        lines.append(f"  Rule: {expected_rule_id}")

    metadata_str = ", ".join(f"{k}={v}" for k, v in expected_metadata.items())
    lines.append(f"  Metadata: {metadata_str}")
    lines.append("")

    if results:
        lines.append("Triggered rules:")
        for result in results:
            rule_id = result.get('check_id', 'unknown')
            resolved = extract_metadata_from_result(result)

            # Show why this rule didn't match
            validation = validate_metadata(expected_metadata, resolved)
            if validation.success:
                lines.append(f"  - {rule_id} (matched but shouldn't be here?)")
            else:
                # Show first error
                error_summary = validation.errors[0] if validation.errors else "metadata mismatch"
                lines.append(f"  - {rule_id} ({error_summary})")

        lines.append("")
        lines.append("No matching result found.")
    else:
        lines.append("No rules were triggered by opengrep.")
        lines.append("")
        lines.append("Possible causes:")
        lines.append("  - Rule file path is incorrect")
        lines.append("  - Rule pattern doesn't match the code")
        lines.append("  - Code doesn't contain cryptographic usage")

    return "\n".join(lines)
