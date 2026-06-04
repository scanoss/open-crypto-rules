"""
Metavariable resolver for replacing $VAR references in rule metadata.

This module handles the resolution of metavariables captured by opengrep
(with --taint-intrafile) into actual values from the scanned code.
"""

import re
from typing import Dict, Any, Union


def get_metavar_value(metavar_info: Dict[str, Any]) -> str:
    """
    Extract the actual value from a metavar info dict.

    Prefers propagated_value (from taint analysis) over abstract_content,
    as propagated values are more accurate for tracking data flow.

    Args:
        metavar_info: Metavar info dict from opengrep output with keys:
            - abstract_content: Original syntactic match
            - propagated_value: Value from taint tracking (optional, preferred)

    Returns:
        Resolved string value with quotes stripped

    Example:
        >>> metavar = {
        ...     "abstract_content": "\"SHA-256\"",
        ...     "propagated_value": {
        ...         "svalue_abstract_content": "\"SHA-256\""
        ...     }
        ... }
        >>> get_metavar_value(metavar)
        'SHA-256'
    """
    # Prefer taint-tracked propagated value
    if isinstance(metavar_info, dict):
        propagated = metavar_info.get('propagated_value')
        if propagated and isinstance(propagated, dict):
            content = propagated.get('svalue_abstract_content', '')
            if content:
                return content.strip('"').strip("'")

        # Fall back to abstract content
        content = metavar_info.get('abstract_content', '')
        if content:
            return content.strip('"').strip("'")

    # Handle case where metavar_info is already a string
    if isinstance(metavar_info, str):
        return metavar_info.strip('"').strip("'")

    return ''


def resolve_metavars(template: str, metavars: Dict[str, Any]) -> str:
    """
    Replace $VAR references in a template string with actual values.

    Searches for patterns like $algorithm, $mode, $variant in the template
    and replaces them with values from the metavars dict.

    Args:
        template: String potentially containing $VAR references
        metavars: Dict mapping variable names to metavar info dicts

    Returns:
        String with all $VAR references replaced with actual values

    Example:
        >>> template = "SHA-$variant"
        >>> metavars = {"$variant": {"abstract_content": "256"}}
        >>> resolve_metavars(template, metavars)
        'SHA-256'

        >>> template = "AES-$keysize-$mode"
        >>> metavars = {
        ...     "$keysize": {"abstract_content": "256"},
        ...     "$mode": {"abstract_content": "GCM"}
        ... }
        >>> resolve_metavars(template, metavars)
        'AES-256-GCM'
    """
    # Fast path: no variables to resolve
    if '$' not in template:
        return template

    # Pattern matches $WORD (alphanumeric + underscore)
    pattern = r'\$[a-zA-Z_][a-zA-Z0-9_]*'

    def replace_var(match):
        """Replace a single $VAR match"""
        var_name = match.group(0)  # e.g., "$variant"

        # Try with $ prefix first (common format)
        if var_name in metavars:
            value = get_metavar_value(metavars[var_name])
            if value:
                return value

        # Try without $ prefix (alternate format)
        key_without_dollar = var_name.lstrip('$')
        if key_without_dollar in metavars:
            value = get_metavar_value(metavars[key_without_dollar])
            if value:
                return value

        # If not found, keep original $VAR
        # This allows debugging - you can see which vars weren't resolved
        return var_name

    return re.sub(pattern, replace_var, template)


def resolve_metadata(rule_metadata: Dict[str, Any], metavars: Dict[str, Any]) -> Dict[str, str]:
    """
    Resolve all metavariable references in a metadata dict.

    Processes all metadata fields from a semgrep/opengrep rule,
    resolving any $VAR references and converting values to strings.

    Args:
        rule_metadata: Dict of metadata from rule (e.g., crypto metadata)
        metavars: Dict of metavariables captured by opengrep

    Returns:
        Dict with all values as resolved strings

    Example:
        >>> rule_metadata = {
        ...     "algorithmName": "SHA-$variant",
        ...     "algorithmFamily": "SHA-2",
        ...     "keySize": 256
        ... }
        >>> metavars = {"$variant": {"abstract_content": "256"}}
        >>> resolve_metadata(rule_metadata, metavars)
        {'algorithmName': 'SHA-256', 'algorithmFamily': 'SHA-2', 'keySize': '256'}
    """
    resolved = {}

    for key, value in rule_metadata.items():
        if isinstance(value, str):
            # Resolve any $VAR references in string values
            resolved[key] = resolve_metavars(value, metavars)
        elif isinstance(value, bool):
            # Convert boolean to string
            resolved[key] = str(value).lower()  # true/false (lowercase)
        elif isinstance(value, (int, float)):
            # Convert numbers to strings
            resolved[key] = str(value)
        elif isinstance(value, dict):
            # Nested dict - recursively resolve
            resolved[key] = str(resolve_metadata(value, metavars))
        elif isinstance(value, list):
            # List - resolve each item and join
            resolved_items = [
                resolve_metavars(str(item), metavars) if isinstance(item, str) else str(item)
                for item in value
            ]
            resolved[key] = ','.join(resolved_items)
        else:
            # Fallback: convert to string
            resolved[key] = str(value)

    return resolved


def extract_metadata_from_result(result: Dict[str, Any]) -> Dict[str, str]:
    """
    Extract and resolve metadata from an opengrep result.

    Combines metadata extraction, metavariable resolution, and
    flattening into a single convenient function.

    Args:
        result: Single result dict from opengrep output

    Returns:
        Resolved metadata dict (all string values)

    Example:
        >>> result = {
        ...     "check_id": "go.crypto.sha",
        ...     "extra": {
        ...         "metadata": {
        ...             "crypto": {
        ...                 "algorithmName": "SHA-$variant"
        ...             }
        ...         },
        ...         "metavars": {
        ...             "$variant": {"abstract_content": "256"}
        ...         }
        ...     }
        ... }
        >>> extract_metadata_from_result(result)
        {'algorithmName': 'SHA-256'}
    """
    extra = result.get('extra', {})

    # Extract crypto metadata from rule
    metadata = extra.get('metadata', {})
    crypto_metadata = metadata.get('crypto', {})

    # Get metavariables captured by opengrep
    metavars = extra.get('metavars', {})

    # Resolve and return
    return resolve_metadata(crypto_metadata, metavars)
