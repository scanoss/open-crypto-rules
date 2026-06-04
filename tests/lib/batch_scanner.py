"""
Batch scanner for running opengrep on all fixtures at once.

This module provides significant performance improvements by:
1. Running opengrep once per language (5 invocations) instead of per-file (648 invocations)
2. Caching all results at test session startup
3. Looking up cached results during individual test execution

Expected speedup: 50-70% faster test execution.
"""

import time
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
from collections import defaultdict

from .opengrep_runner import run_opengrep, run_opengrep_batch, OpenGrepError


class BatchScanner:
    """
    Session-scoped batch scanner that runs opengrep once per language.

    This replaces 648 individual opengrep invocations with 5 batch scans.
    Results are cached and looked up during test execution.
    """

    # Language mappings: language -> (fixtures_dir, rules_dir)
    LANGUAGE_MAPPINGS = {
        'c': ('c', 'c'),
        'csharp': ('csharp', 'csharp'),
        'go': ('go', 'go'),
        'java': ('java', 'java'),
        'javascript': ('javascript', 'javascript'),
        'python': ('python', 'python'),
        'ruby': ('ruby', 'ruby'),
        'rust': ('rust', 'rust'),
        'typescript': ('typescript', 'typescript'),
    }

    def __init__(self, fixtures_root: Path, rules_root: Path):
        """
        Initialize batch scanner.

        Args:
            fixtures_root: Path to tests/integration/fixtures/
            rules_root: Path to semgrep-rules/
        """
        self.fixtures_root = fixtures_root
        self.rules_root = rules_root

        # Result cache: (normalized_path, rule_id) -> List[result_dict]
        # Multiple results possible if same file has multiple matches for same rule
        self._result_cache: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)

        # Track which languages have been scanned
        self._scanned_languages = set()

        # Performance tracking
        self.scan_times: Dict[str, float] = {}
        self.total_scan_time = 0.0

    def _normalize_path(self, path: str) -> str:
        """
        Normalize a file path for consistent cache lookup.

        Converts both absolute and relative paths to a consistent format.

        Args:
            path: File path from opengrep result or test fixture

        Returns:
            Normalized path string for cache key
        """
        p = Path(path)

        # If it's absolute, try to make it relative to fixtures_root
        if p.is_absolute():
            try:
                p = p.relative_to(self.fixtures_root.parent.parent)
            except ValueError:
                # Can't make relative, use as-is
                pass

        return str(p)

    def scan_language(self, language: str) -> int:
        """
        Scan all fixtures for a specific language.

        Args:
            language: Language identifier (c, go, java, python, rust)

        Returns:
            Number of results found

        Raises:
            OpenGrepError: If batch scan fails
            ValueError: If language is not configured
        """
        if language not in self.LANGUAGE_MAPPINGS:
            raise ValueError(f"Unknown language: {language}")

        if language in self._scanned_languages:
            # Already scanned
            return 0

        fixtures_dir, rules_dir = self.LANGUAGE_MAPPINGS[language]
        fixtures_path = self.fixtures_root / fixtures_dir
        rules_path = self.rules_root / rules_dir

        # Check if paths exist
        if not fixtures_path.exists():
            # No fixtures for this language, skip silently
            self._scanned_languages.add(language)
            return 0

        if not rules_path.exists():
            raise OpenGrepError(f"Rules directory not found: {rules_path}")

        # Run batch opengrep scan
        start_time = time.time()
        print(f"\n  Batch scanning {language} fixtures: {fixtures_path}")

        try:
            output = run_opengrep_batch(str(rules_path), str(fixtures_path), timeout=120)
        except OpenGrepError as e:
            # Batch scan failed - this will fail all tests for this language
            raise OpenGrepError(
                f"Batch scan failed for {language} fixtures.\n"
                f"All {language} tests will fail.\n"
                f"Error: {e}"
            )

        elapsed = time.time() - start_time
        self.scan_times[language] = elapsed
        self.total_scan_time += elapsed

        # Index results by (path, rule_id)
        results = output.get('results', [])
        for result in results:
            path = self._normalize_path(result.get('path', ''))
            rule_id = result.get('check_id', '')

            if path and rule_id:
                self._result_cache[(path, rule_id)].append(result)

        self._scanned_languages.add(language)

        print(f"    Found {len(results)} results in {elapsed:.2f}s")

        return len(results)

    def scan_all_languages(self) -> Dict[str, int]:
        """
        Scan all languages at once (called at session startup).

        Returns:
            Dict mapping language -> number of results found
        """
        print("\n" + "="*70)
        print("BATCH SCANNING MODE: Scanning all fixtures at session startup")
        print("="*70)

        results_per_language = {}

        for language in self.LANGUAGE_MAPPINGS.keys():
            try:
                count = self.scan_language(language)
                results_per_language[language] = count
            except OpenGrepError as e:
                print(f"  ERROR scanning {language}: {e}")
                # Re-raise to fail fast
                raise

        print(f"\n  Total scan time: {self.total_scan_time:.2f}s")
        print(f"  Total results cached: {sum(len(v) for v in self._result_cache.values())}")
        print("="*70 + "\n")

        return results_per_language

    def get_results_for_fixture(
        self,
        fixture_path: Path,
        rule_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get cached opengrep results for a specific fixture file.

        Args:
            fixture_path: Path to fixture file
            rule_id: Optional rule ID to filter by

        Returns:
            List of opengrep result dicts matching the fixture (and rule if specified)
        """
        # Lookup from cache
        normalized = self._normalize_path(str(fixture_path))

        if rule_id:
            # Specific rule requested
            return self._result_cache.get((normalized, rule_id), [])
        else:
            # All results for this file
            all_results = []
            for (cached_path, cached_rule), results in self._result_cache.items():
                if cached_path == normalized:
                    all_results.extend(results)
            return all_results

    def get_stats(self) -> Dict[str, Any]:
        """
        Get performance statistics.

        Returns:
            Dict with timing and cache statistics
        """
        return {
            'total_scan_time': self.total_scan_time,
            'scan_times_by_language': self.scan_times,
            'languages_scanned': list(self._scanned_languages),
            'total_results_cached': sum(len(v) for v in self._result_cache.values()),
            'unique_cache_keys': len(self._result_cache),
        }
