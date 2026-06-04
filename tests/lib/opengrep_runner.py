"""
OpenGrep runner for executing scans and parsing results.
"""

import subprocess
import json
from pathlib import Path
from typing import Dict, Any


class OpenGrepError(Exception):
    """Raised when opengrep execution fails."""
    pass


def run_opengrep(rules_path: str, fixture_path: str, timeout: int = 60) -> Dict[str, Any]:
    """
    Execute opengrep with taint analysis and return parsed JSON output.

    Args:
        rules_path: Path to semgrep rule file or directory
        fixture_path: Path to code fixture to scan
        timeout: Maximum execution time in seconds (default: 60)

    Returns:
        Dict containing opengrep JSON output with 'results' and 'errors' keys

    Raises:
        OpenGrepError: If opengrep execution fails
        FileNotFoundError: If rules or fixture path doesn't exist
        subprocess.TimeoutExpired: If execution exceeds timeout
    """
    # Validate inputs
    if not Path(rules_path).exists():
        raise FileNotFoundError(f"Rules path not found: {rules_path}")

    if not Path(fixture_path).exists():
        raise FileNotFoundError(f"Fixture path not found: {fixture_path}")

    # Build command
    cmd = [
        "opengrep",
        "--json",                # JSON output format
        "--no-git-ignore",       # Scan all files
        "--taint-intrafile",     # CRITICAL: Enable taint analysis for metavar propagation
        "--config", rules_path,
        fixture_path
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False  # Don't raise on non-zero exit (opengrep returns 1 if findings found)
        )

        # Parse JSON output first
        if not result.stdout.strip():
            # No output - check if it's a real error
            if result.returncode >= 2:
                raise OpenGrepError(
                    f"opengrep failed with exit code {result.returncode}\n"
                    f"stderr: {result.stderr}\n"
                    f"No JSON output produced"
                )
            # No output means no results
            return {"results": [], "errors": []}

        try:
            output = json.loads(result.stdout)
            return output
        except json.JSONDecodeError as e:
            raise OpenGrepError(
                f"Failed to parse opengrep JSON output: {e}\n"
                f"stdout: {result.stdout[:500]}"
            )

    except subprocess.TimeoutExpired:
        raise OpenGrepError(f"opengrep timed out after {timeout} seconds")


def run_opengrep_batch(rules_path: str, fixtures_dir: str, timeout: int = 120) -> Dict[str, Any]:
    """
    Execute opengrep on an entire directory for batch scanning.

    This is optimized for scanning multiple files at once, reducing
    process spawn overhead from 648 invocations to ~5 (one per language).

    Args:
        rules_path: Path to semgrep rule file or directory
        fixtures_dir: Path to directory containing fixtures to scan
        timeout: Maximum execution time in seconds (default: 120 for batch)

    Returns:
        Dict containing opengrep JSON output with 'results' and 'errors' keys.
        Results will include 'path' field for each match to map back to files.

    Raises:
        OpenGrepError: If opengrep execution fails
        FileNotFoundError: If rules or fixtures directory doesn't exist
        subprocess.TimeoutExpired: If execution exceeds timeout

    Note:
        Uses same flags as run_opengrep() including --taint-intrafile.
        The only difference is scanning a directory instead of a single file.
    """
    # Validate inputs
    if not Path(rules_path).exists():
        raise FileNotFoundError(f"Rules path not found: {rules_path}")

    if not Path(fixtures_dir).exists():
        raise FileNotFoundError(f"Fixtures directory not found: {fixtures_dir}")

    if not Path(fixtures_dir).is_dir():
        raise ValueError(f"Expected directory, got file: {fixtures_dir}")

    # Build command - identical to run_opengrep() except target is a directory
    cmd = [
        "opengrep",
        "--json",                # JSON output format
        "--no-git-ignore",       # Scan all files
        "--taint-intrafile",     # CRITICAL: Enable taint analysis for metavar propagation
        "--config", rules_path,
        fixtures_dir             # Scan entire directory
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False  # Don't raise on non-zero exit (opengrep returns 1 if findings found)
        )

        # Parse JSON output
        if not result.stdout.strip():
            # No output - check if it's a real error
            if result.returncode >= 2:
                raise OpenGrepError(
                    f"opengrep batch scan failed with exit code {result.returncode}\n"
                    f"stderr: {result.stderr}\n"
                    f"No JSON output produced"
                )
            # No output means no results
            return {"results": [], "errors": []}

        try:
            output = json.loads(result.stdout)
            return output
        except json.JSONDecodeError as e:
            raise OpenGrepError(
                f"Failed to parse opengrep JSON output: {e}\n"
                f"stdout: {result.stdout[:500]}"
            )

    except subprocess.TimeoutExpired:
        raise OpenGrepError(
            f"opengrep batch scan timed out after {timeout} seconds\n"
            f"Consider increasing timeout or scanning smaller batches"
        )


def check_opengrep_version(min_version: str = "1.12.1") -> bool:
    """
    Check if opengrep is installed and meets minimum version requirement.

    Args:
        min_version: Minimum required version (default: 1.12.1 for taint support)

    Returns:
        True if version requirement is met

    Raises:
        OpenGrepError: If opengrep is not installed or version check fails
    """
    try:
        result = subprocess.run(
            ["opengrep", "--version"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10
        )

        # Parse version from output (format can be "1.12.1" or "semgrep 1.12.1")
        version_line = result.stdout.strip()

        # Extract version number - try different formats
        parts = version_line.split()

        # Case 1: Just the version number "1.12.1"
        if len(parts) == 1 and parts[0][0].isdigit():
            version_str = parts[0]
        # Case 2: "semgrep 1.12.1" or similar
        elif len(parts) >= 2:
            version_str = parts[1]
        else:
            raise OpenGrepError(f"Could not parse opengrep version from: {version_line}")

        # Compare versions (simple string comparison works for semver)
        if version_str >= min_version:
            return True
        else:
            raise OpenGrepError(
                f"opengrep version {version_str} is too old. "
                f"Minimum required: {min_version} (for --taint-intrafile support)"
            )

    except FileNotFoundError:
        raise OpenGrepError(
            "opengrep not found. Install with: pip install semgrep"
        )
    except subprocess.CalledProcessError as e:
        raise OpenGrepError(f"Failed to check opengrep version: {e}")
