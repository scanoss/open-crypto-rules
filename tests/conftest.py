"""
Pytest configuration and fixtures for crypto detection rule tests.

This module provides:
1. Session-scoped batch scanner for performance optimization
2. CLI options for controlling test behavior
3. Performance timing and statistics
"""

import pytest
from pathlib import Path

from lib.batch_scanner import BatchScanner


# Paths
REPO_ROOT = Path(__file__).parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "integration" / "fixtures"
RULES_DIR = REPO_ROOT / "semgrep-rules"


@pytest.fixture(scope="session")
def batch_scanner():
    """
    Session-scoped batch scanner that runs opengrep once per language.

    This is the main performance optimization:
    - Old approach: 648 opengrep invocations (one per test)
    - New approach: 5 opengrep invocations (one per language)

    The scanner caches all results and tests look up their results from cache.

    Returns:
        BatchScanner instance with cached results
    """
    scanner = BatchScanner(
        fixtures_root=FIXTURES_DIR,
        rules_root=RULES_DIR
    )

    # Run batch scans at session startup
    try:
        scanner.scan_all_languages()
    except Exception as e:
        pytest.exit(f"Batch scanning failed at session startup: {e}")

    return scanner


def pytest_sessionfinish(session, exitstatus):
    """
    Hook called after all tests finish.

    Displays performance statistics if batch mode was used.
    """
    # Try to get batch_scanner from session
    # Note: This is a bit hacky but pytest doesn't make it easy to access fixtures in hooks
    if hasattr(session, 'batch_scanner_stats'):
        stats = session.batch_scanner_stats
        print("\n" + "="*70)
        print("BATCH SCANNING PERFORMANCE SUMMARY")
        print("="*70)
        print(f"  Total scan time: {stats['total_scan_time']:.2f}s")
        print(f"  Languages scanned: {', '.join(stats['languages_scanned'])}")
        print(f"  Total results cached: {stats['total_results_cached']}")
        print(f"  Unique cache keys: {stats['unique_cache_keys']}")
        print("\n  Scan times by language:")
        for lang, time in stats['scan_times_by_language'].items():
            print(f"    {lang}: {time:.2f}s")
        print("="*70)


@pytest.fixture(scope="function", autouse=True)
def store_batch_scanner_stats(request, batch_scanner):
    """
    Store batch scanner stats in session for later display.

    This fixture runs for every test but only stores stats once.
    """
    if not hasattr(request.session, 'batch_scanner_stats'):
        # Store stats in session for pytest_sessionfinish hook
        request.session.batch_scanner_stats = batch_scanner.get_stats()

    yield  # Test runs here
