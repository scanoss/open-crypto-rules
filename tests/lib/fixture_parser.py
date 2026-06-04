"""
Parser for test expectations embedded in fixture files.

Extracts TEST-RULE and TEST-METADATA comments from code fixtures
to determine what cryptographic properties should be detected.
"""

import re
from pathlib import Path
from typing import List, Dict, Optional, Tuple


class FixtureExpectation:
    """
    Represents a single test expectation from a fixture file.

    Attributes:
        rule_id: Optional specific rule ID that should trigger
        metadata: Dict of expected metadata key-value pairs
        line_number: Line where the expectation was defined (for debugging)
    """

    def __init__(self, rule_id: Optional[str], metadata: Dict[str, str], line_number: int):
        self.rule_id = rule_id
        self.metadata = metadata
        self.line_number = line_number

    def __repr__(self):
        rule_part = f"rule={self.rule_id}" if self.rule_id else "any rule"
        return f"<FixtureExpectation({rule_part}, {len(self.metadata)} metadata fields, line {self.line_number})>"


def parse_test_expectations(fixture_path: str) -> List[FixtureExpectation]:
    """
    Parse TEST-RULE and TEST-METADATA comments from a fixture file.

    Supports various comment styles:
    - // for Go, Java, C, Rust, JavaScript
    - # for Python, Shell
    - /* */ and <!-- --> are not supported (not used in fixtures)

    Format:
        // TEST-RULE: rule.id.optional
        // TEST-METADATA: key1=value1, key2=value2, ...

    Multiple expectations can be in one file (one per TEST-METADATA comment).
    TEST-RULE is optional and applies to the next TEST-METADATA.

    Args:
        fixture_path: Path to fixture file

    Returns:
        List of FixtureExpectation objects

    Raises:
        FileNotFoundError: If fixture file doesn't exist
        ValueError: If TEST-METADATA format is invalid

    Example fixture content:
        // TEST-RULE: go.crypto.aes.gcm
        // TEST-METADATA: algorithmName=AES-GCM, mode=GCM

        func main() {
            cipher.NewGCM(block)
        }

        // TEST-METADATA: algorithmName=AES, keySize=256

        func test() {
            aes.NewCipher(make([]byte, 32))
        }
    """
    path = Path(fixture_path)
    if not path.exists():
        raise FileNotFoundError(f"Fixture file not found: {fixture_path}")

    content = path.read_text(encoding='utf-8', errors='ignore')

    # Patterns for different comment styles
    # Matches: // TEST-RULE: rule.id  OR  # TEST-RULE: rule.id
    rule_pattern = r'(?://|#)\s*TEST-RULE:\s*([^\s\n]+)'

    # Matches: // TEST-METADATA: k1=v1, k2=v2  OR  # TEST-METADATA: k1=v1, k2=v2
    metadata_pattern = r'(?://|#)\s*TEST-METADATA:\s*([^\n]+)'

    expectations = []
    pending_rule_id: Optional[str] = None

    # Process line by line to maintain order and associate rules with metadata
    for line_num, line in enumerate(content.split('\n'), start=1):
        # Check for TEST-RULE
        rule_match = re.match(rule_pattern, line.strip())
        if rule_match:
            pending_rule_id = rule_match.group(1).strip()
            continue

        # Check for TEST-METADATA
        metadata_match = re.match(metadata_pattern, line.strip())
        if metadata_match:
            metadata_str = metadata_match.group(1).strip()

            # Parse metadata: "key1=value1, key2=value2, ..."
            metadata = parse_metadata_string(metadata_str, fixture_path, line_num)

            # Create expectation
            expectation = FixtureExpectation(
                rule_id=pending_rule_id,
                metadata=metadata,
                line_number=line_num
            )
            expectations.append(expectation)

            # Reset pending rule (it's been consumed)
            pending_rule_id = None

    if not expectations:
        raise ValueError(
            f"No TEST-METADATA found in {fixture_path}. "
            f"Add comments like: // TEST-METADATA: algorithmName=AES"
        )

    return expectations


def parse_metadata_string(metadata_str: str, fixture_path: str, line_num: int) -> Dict[str, str]:
    """
    Parse a metadata string into a dict.

    Supports two formats:
    1. Comma-separated with '=': "key1=value1, key2=value2"
    2. Space-separated with ':': "key1:value1 key2:value2"

    Args:
        metadata_str: Metadata string in either format
        fixture_path: Path to fixture (for error messages)
        line_num: Line number (for error messages)

    Returns:
        Dict of metadata key-value pairs

    Raises:
        ValueError: If format is invalid

    Example:
        >>> parse_metadata_string("algorithmName=AES, keySize=256", "test.go", 1)
        {'algorithmName': 'AES', 'keySize': '256'}

        >>> parse_metadata_string("algorithmName:AES keySize:256", "test.go", 1)
        {'algorithmName': 'AES', 'keySize': '256'}
    """
    metadata = {}

    # Detect format by looking for separators
    # Format 1: Uses '=' and usually commas
    # Format 2: Uses ':' and spaces

    if '=' in metadata_str:
        # Format 1: key1=value1, key2=value2
        separator = '='
        pairs = [p.strip() for p in metadata_str.split(',')]
    elif ':' in metadata_str:
        # Format 2: key1:value1 key2:value2
        separator = ':'
        pairs = [p.strip() for p in metadata_str.split()]
    else:
        raise ValueError(
            f"Invalid TEST-METADATA format at {fixture_path}:{line_num}\n"
            f"Expected 'key=value' or 'key:value' format\n"
            f"Got: {metadata_str}"
        )

    for pair in pairs:
        if not pair:
            continue  # Skip empty strings

        if separator not in pair:
            raise ValueError(
                f"Invalid TEST-METADATA format at {fixture_path}:{line_num}\n"
                f"Expected '{separator}' separator but got: '{pair}'\n"
                f"Full metadata: {metadata_str}"
            )

        # Split on first separator only (values might contain separator)
        key, value = pair.split(separator, 1)
        key = key.strip()
        value = value.strip()

        if not key:
            raise ValueError(
                f"Empty key in TEST-METADATA at {fixture_path}:{line_num}: '{pair}'"
            )

        # Store in dict
        metadata[key] = value

    if not metadata:
        raise ValueError(
            f"No metadata pairs found at {fixture_path}:{line_num}\n"
            f"Got: {metadata_str}"
        )

    return metadata


def get_test_name(fixture_path: str, expectation_index: int = 0) -> str:
    """
    Generate a readable test name from fixture path and expectation index.

    Args:
        fixture_path: Path to fixture file
        expectation_index: Index of expectation in file (for multi-expectation fixtures)

    Returns:
        Human-readable test name

    Example:
        >>> get_test_name("fixtures/go/crypto/aes/test.test.go", 0)
        'go/crypto/aes/test[0]'

        >>> get_test_name("fixtures/java/jca/cipher.test.java", 2)
        'java/jca/cipher[2]'
    """
    path = Path(fixture_path)

    # Get relative path from fixtures directory
    parts = path.parts
    try:
        fixtures_idx = parts.index('fixtures')
        rel_parts = parts[fixtures_idx + 1:]  # Everything after 'fixtures/'
    except ValueError:
        # 'fixtures' not in path, use full path
        rel_parts = parts

    # Remove extension and .test. marker
    name_parts = list(rel_parts[:-1]) + [path.stem.replace('.test', '')]

    # Join with / and add index if multiple expectations
    base_name = '/'.join(name_parts)

    if expectation_index > 0:
        return f"{base_name}[{expectation_index}]"

    return base_name
