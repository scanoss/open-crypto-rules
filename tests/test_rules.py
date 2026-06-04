"""
Pytest test runner for SCANOSS open crypto detection rules.

This test suite:
1. Discovers all .test.* fixture files
2. Parses TEST-METADATA expectations from each fixture
3. Runs opengrep with --taint-intrafile on each fixture
4. Validates that extracted metadata matches expectations

Run with:
    pytest tests/ -v                    # Run all tests
    pytest tests/ -v -n auto            # Parallel execution
    pytest tests/ -k "java"             # Run only Java tests
    pytest tests/ -v --tb=short         # Shorter tracebacks
"""

import pytest
from pathlib import Path
from typing import List, Tuple

from lib.opengrep_runner import run_opengrep, check_opengrep_version, OpenGrepError
from lib.fixture_parser import parse_test_expectations, get_test_name, FixtureExpectation
from lib.validator import find_matching_result, format_expectation_error

# Paths
REPO_ROOT = Path(__file__).parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "integration" / "fixtures"
RULES_DIR = REPO_ROOT / "semgrep-rules"


def discover_fixtures() -> List[Path]:
    """
    Discover all test fixture files.

    Returns:
        List of paths to .test.* files
    """
    if not FIXTURES_DIR.exists():
        pytest.skip(f"Fixtures directory not found: {FIXTURES_DIR}")

    fixtures = list(FIXTURES_DIR.rglob("*.test.*"))

    if not fixtures:
        pytest.skip(f"No fixtures found in {FIXTURES_DIR}")

    return sorted(fixtures)


def get_language_from_fixture(fixture_path: Path) -> str:
    """
    Detect programming language from fixture file extension.

    Args:
        fixture_path: Path to fixture file

    Returns:
        Language name matching semgrep-rules directory structure

    Example:
        >>> get_language_from_fixture(Path("test.test.java"))
        'java'
        >>> get_language_from_fixture(Path("test.test.go"))
        'go'
    """
    # Get the actual file extension (not .test. part)
    # For "foo.test.java", we want "java"
    suffix = fixture_path.suffix.lstrip('.')

    # Map file extensions to rule directory names
    lang_map = {
        'cs': 'csharp',
        'go': 'go',
        'java': 'java',
        'py': 'python',
        'c': 'c',
        'cpp': 'c',  # C++ uses same rules as C
        'h': 'c',    # C headers
        'rs': 'rust',
        'rb': 'ruby',
        'js': 'javascript',
        'ts': 'typescript',
    }

    language = lang_map.get(suffix)
    if not language:
        # Fallback: use the extension as-is
        language = suffix

    return language


def get_rules_path(fixture_path: Path) -> Path:
    """
    Get rules directory for a fixture's programming language.

    Instead of complex path mirroring, this simply:
    1. Detects language from file extension
    2. Returns the rules directory for that language
    3. Lets opengrep find matching rules automatically

    This is simpler, more robust, and aligns with how semgrep works.

    Args:
        fixture_path: Path to fixture file

    Returns:
        Path to language rules directory

    Raises:
        FileNotFoundError: If no rules directory exists for the language

    Example:
        >>> get_rules_path(Path("fixtures/java/jca/test.test.java"))
        Path("semgrep-rules/java/")

        >>> get_rules_path(Path("fixtures/go/crypto/sha/sha1.test.go"))
        Path("semgrep-rules/go/")
    """
    language = get_language_from_fixture(fixture_path)
    rules_path = RULES_DIR / language

    if not rules_path.exists():
        raise FileNotFoundError(
            f"No rules directory found for language: {language}\n"
            f"Expected: {rules_path}\n"
            f"Fixture: {fixture_path}\n"
            f"Detected language from extension: .{fixture_path.suffix}"
        )

    return rules_path


# Pytest fixtures (setup/teardown)


@pytest.fixture(scope="session", autouse=True)
def check_opengrep():
    """
    Session-scoped fixture to verify opengrep is installed.

    Runs once before all tests.
    """
    try:
        check_opengrep_version(min_version="1.12.1")
    except OpenGrepError as e:
        pytest.exit(f"OpenGrep check failed: {e}")


# Test generation


def pytest_generate_tests(metafunc):
    """
    Pytest hook to generate parametrized tests for each fixture.

    This dynamically creates a test for each (fixture, expectation) pair.
    Multiple expectations in one fixture become multiple tests.
    """
    if "fixture_path" in metafunc.fixturenames and "expectation" in metafunc.fixturenames:
        # Discover all fixtures
        fixtures = discover_fixtures()

        # Generate test parameters: [(fixture_path, expectation, test_id), ...]
        test_params = []

        for fixture_path in fixtures:
            try:
                expectations = parse_test_expectations(str(fixture_path))

                for idx, expectation in enumerate(expectations):
                    test_id = get_test_name(str(fixture_path), idx)
                    test_params.append((fixture_path, expectation, idx, test_id))

            except Exception as e:
                # If fixture parsing fails, create a failing test for it
                test_id = get_test_name(str(fixture_path), 0)
                # Create a dummy expectation that will fail in the test
                pytest.fail(f"Failed to parse fixture {fixture_path}: {e}")

        # Parametrize the test
        metafunc.parametrize(
            "fixture_path,expectation,expectation_index,test_id",
            test_params,
            ids=[params[3] for params in test_params]  # Use test_id for test names
        )


# Main test function


@pytest.mark.timeout(60)  # 60 second timeout per test
def test_fixture(fixture_path: Path, expectation: FixtureExpectation, expectation_index: int, test_id: str, batch_scanner):
    """
    Test a single expectation from a fixture file.

    Steps:
    1. Get cached opengrep results from batch scanner (or run per-file if batch mode disabled)
    2. Find result matching expectation
    3. Validate metadata

    Args:
        fixture_path: Path to fixture file
        expectation: FixtureExpectation with rule_id and metadata
        expectation_index: Index of expectation in fixture
        test_id: Human-readable test identifier
        batch_scanner: Session-scoped BatchScanner fixture with cached results
    """
    # Get cached results from batch scanner (or run per-file if batch mode disabled)
    try:
        results = batch_scanner.get_results_for_fixture(fixture_path)
    except OpenGrepError as e:
        pytest.fail(f"OpenGrep execution failed: {e}")
    except Exception as e:
        pytest.fail(f"Unexpected error getting results: {e}")

    # Note: batch_scanner.get_results_for_fixture() returns the list of results directly,
    # whereas run_opengrep() returned a dict with 'results' and 'errors' keys.
    # In batch mode, errors are handled at scan time, not per-test time.

    # Find matching result
    match = find_matching_result(
        results,
        expectation.metadata,
        expectation.rule_id
    )

    if match is None:
        # No matching result found - format detailed error
        error_msg = format_expectation_error(
            expectation_index,
            expectation.metadata,
            expectation.rule_id,
            results,
            fixture_path.name
        )
        pytest.fail(error_msg)

    # Success! Matching result found
    result, resolved_metadata = match

    # Log success details (visible with -v or -s)
    rule_id = result.get('check_id', 'unknown')
    line = result.get('start', {}).get('line', '?')
    print(f"\n  ✓ Matched rule '{rule_id}' at line {line}")
    print(f"  ✓ Metadata: {resolved_metadata}")


# Additional helper tests


def test_fixtures_directory_exists():
    """Sanity check that fixtures directory exists."""
    assert FIXTURES_DIR.exists(), f"Fixtures directory not found: {FIXTURES_DIR}"


def test_rules_directory_exists():
    """Sanity check that rules directory exists."""
    assert RULES_DIR.exists(), f"Rules directory not found: {RULES_DIR}"


def test_at_least_one_fixture_exists():
    """Sanity check that at least one fixture exists."""
    fixtures = list(FIXTURES_DIR.rglob("*.test.*"))
    assert len(fixtures) > 0, f"No fixtures found in {FIXTURES_DIR}"


if __name__ == "__main__":
    # Allow running directly: python tests/test_rules.py
    pytest.main([__file__, "-v"])
