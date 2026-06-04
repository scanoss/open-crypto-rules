# Testing Guide for Semgrep Crypto Rules

This document describes the testing infrastructure for validating Semgrep cryptographic detection rules.

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Test Structure](#test-structure)
- [Writing Tests](#writing-tests)
- [Running Tests](#running-tests)
- [Adding New Tests](#adding-new-tests)
- [Troubleshooting](#troubleshooting)

---

## Overview

We use **self-describing test fixtures** that embed expectations directly in the test code as comments. The test framework runs opengrep directly with taint analysis enabled, parses the output, resolves metavariables, and validates metadata.

### Key Features

✅ **Fast execution** - Batch opengrep invocation (one scan per language), with results cached for the session
✅ **Multiple tests per file** - Group related tests together for better organization
✅ **Auto-discovery** - Just drop in a `.test.*` file and it runs automatically
✅ **Self-documenting** - Test expectations are right in the code
✅ **Scalable** - Works for any language/framework (Java, Python, Go, C, Rust, etc.)
✅ **Parallel execution** - Run tests in parallel for even faster execution
✅ **Metavar resolution** - Full support for `$variable` replacement in metadata
✅ **Flexible validation** - TEST-RULE is optional, focus on metadata validation
✅ **Dual format support** - Handles both `key=value` and `key:value` metadata formats

### How It Works

1. Write test fixtures with `TEST-METADATA` comment blocks (one per test case)
2. Optionally add `TEST-RULE` to validate specific rule IDs
3. Place them in `tests/integration/fixtures/<language>/<framework>/`
4. Run `make test`
5. Test runner:
   - Auto-discovers all `.test.*` files
   - Executes opengrep with `--taint-intrafile` on each fixture
   - Parses JSON output and resolves metavariables
   - Validates metadata matches expectations
   - Runs tests in parallel for speed

---

## Quick Start

### Prerequisites

**Required:**
- Python 3.9+
- OpenGrep/Semgrep >= 1.12.1 (for taint analysis support)

**Installation:**
```bash
# Install opengrep (if not already installed)
pip install semgrep

# Verify installation
opengrep --version  # Should be >= 1.12.1
```

### Run All Tests

```bash
make test
```

This will:
- Install Python test dependencies (pytest, etc.)
- Auto-discover all `.test.*` files
- Run opengrep on each fixture with taint analysis
- Validate metadata extraction
- Report results

### Run Tests in Parallel (Faster!)

```bash
make test-parallel
```

Uses all available CPU cores for maximum speed.

### Run Quick Test Subset

```bash
make test-quick
```

Runs just AES tests to verify the framework is working.

### Add a New Test

```bash
# Option 1: Add to existing fixture file
# Edit tests/integration/fixtures/java/jca/jca-crypto-operations.test.java
# Add new TEST-METADATA block with test code

# Option 2: Create new fixture file
touch tests/integration/fixtures/java/jca/my-new-test.test.java

# Add test expectations and code
cat > tests/integration/fixtures/java/jca/my-new-test.test.java << 'EOF'
// TEST-METADATA: algorithmFamily=AES, library=JCA/JCE
import javax.crypto.Cipher;
class Test {
    void test() throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
    }
}
EOF

# Run tests
make test
```

No need to modify test code or configuration! Each `TEST-METADATA` block becomes a separate test case.

---

## Test Structure

```
open-crypto-rules/
├── tests/
│   ├── lib/                       # Test library (Python)
│   │   ├── __init__.py
│   │   ├── opengrep_runner.py     # Execute opengrep, parse JSON
│   │   ├── batch_scanner.py       # Batch-scan one invocation per language
│   │   ├── metavar_resolver.py    # Resolve $variables in metadata
│   │   ├── fixture_parser.py      # Parse TEST-METADATA comments
│   │   └── validator.py           # Validate metadata matches
│   ├── integration/
│   │   └── fixtures/              # Self-describing test fixtures
│   │       ├── go/
│   │       │   └── crypto/
│   │       │       └── algorithm/
│   │       │           └── md5/
│   │       │               └── md5.test.go
│   │       ├── c/
│   │       └── rust/
│   ├── test_rules.py              # Main pytest test runner
│   ├── pytest.ini                 # Pytest configuration
│   └── requirements.txt           # Python dependencies
├── semgrep-rules/                 # Rules being tested
│   ├── go/
│   │   └── crypto/
│   │       └── algorithm/
│   │           └── md5/
│   │               └── rules.yaml
│   ├── c/
│   └── rust/
└── Makefile
```

### Fixture Path → Rules File Mapping

The test runner automatically maps fixture paths to rule files by walking up the directory tree:

```
Fixture: tests/integration/fixtures/go/crypto/algorithm/aes/key-generation/128-bit/test.test.go
Rules:   semgrep-rules/go/crypto/algorithm/aes/rules.yaml  (found by walking up)

Fixture: tests/integration/fixtures/java/jca/test.test.java
Rules:   semgrep-rules/java/jca/rules.yaml OR semgrep-rules/java/jca/

Fixture: tests/integration/fixtures/python/cryptography/test.test.py
Rules:   semgrep-rules/python/cryptography.yaml OR semgrep-rules/python/cryptography/
```

The test runner tries multiple levels, so deeply nested fixtures work automatically.

---

## Writing Tests

### Test Fixture Format

A test fixture is a source code file with `TEST-METADATA` comment blocks that define test expectations. Each `TEST-METADATA` block represents one test case.

### Metadata Format Options

The parser supports **two metadata formats**:

#### Format 1: Comma-separated with `=` (Recommended)
```java
// TEST-METADATA: algorithmFamily=AES, mode=GCM, library=JCA/JCE
```

#### Format 2: Space-separated with `:`
```go
// TEST-METADATA: algorithmName:AES keySize:256 library:crypto/aes
```

Both formats work identically - use whichever is more convenient.

### Multiple Tests in One File (Java)

```java
// TEST-METADATA: algorithmFamily=AES/GCM/NoPadding, algorithmPrimitive=block-cipher, library=JCA/JCE

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class Test1_AesGcm {
    void test() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] key = new byte[16];
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
    }
}

// TEST-METADATA: algorithmFamily=HMAC, algorithmPrimitive=mac, library=JCA/JCE

import javax.crypto.Mac;

class Test2_HmacSha256 {
    void test() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        byte[] keyBytes = new byte[32];
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "HmacSHA256");
        mac.init(keySpec);
    }
}

// TEST-RULE: java.crypto.jca.keygenerator-symmetric-key-init
// TEST-METADATA: algorithmFamily=AES, library=JCA/JCE

import javax.crypto.KeyGenerator;

class Test3_AesKeyGeneration {
    void test() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
    }
}
```

### Python Example (Multiple Tests)

```python
# TEST-METADATA: algorithmFamily=HMAC, algorithmPrimitive=mac, algorithmParameterSetIdentifier=256

import hmac

h1 = hmac.new(b"key", b"msg", digestmod="sha256")

# TEST-METADATA: algorithmFamily=HMAC, algorithmPrimitive=mac, algorithmParameterSetIdentifier=512

import hashlib

h2 = hmac.new(b"key", b"msg", digestmod=hashlib.sha512)
```

### Go Example (Space-separated format)

```go
// TEST-RULE: go.crypto.aes.key-generation
// TEST-METADATA: algorithmName:AES keySize:128 library:crypto/aes

package main

import "crypto/aes"

func main() {
    key := make([]byte, 16)
    block, _ := aes.NewCipher(key)
    _ = block
}
```

### TEST-* Comment Syntax

#### TEST-METADATA (Required)

Each test case **must** have a `TEST-METADATA` comment block that specifies expected metadata key-value pairs.

**Format Options:**
```java
// Format 1 (comma-separated)
// TEST-METADATA: algorithmName=DES, mode=ECB, padding=PKCS5Padding

// Format 2 (space-separated)
// TEST-METADATA: algorithmName:DES mode:ECB padding:PKCS5Padding
```

**Rules:**
- Each `TEST-METADATA` starts a new test case
- Only validates fields that are specified (other fields are ignored)
- If a field is omitted, it's not validated (supports optional metadata)
- Whitespace is trimmed automatically

#### TEST-RULE (Optional)

Optionally specifies which specific rule ID should be triggered. If omitted, the test validates that **any rule** with matching metadata is found.

```java
// TEST-RULE: java.security.crypto.cipher-weak-algorithm
// TEST-METADATA: algorithmName=DES, mode=ECB
```

**Format**: `TEST-RULE: <rule-id>`

**When to use**:
- Use `TEST-RULE` when you want to validate a specific rule triggers
- Omit `TEST-RULE` when you only care about metadata being extracted correctly
- `TEST-RULE` applies to the next `TEST-METADATA` block only

### Metavariable Support

The test framework fully supports metavariable resolution via opengrep's taint analysis:

**Rule with metavariables:**
```yaml
rules:
  - id: go.crypto.sha
    patterns:
      - pattern: sha$VARIANT.New()
      - metavariable-regex:
          metavariable: $VARIANT
          regex: "(?<variant>1|256|512)"
    metadata:
      crypto:
        algorithmName: SHA-$variant  # $variant will be resolved
        algorithmFamily: SHA
```

**Test fixture:**
```go
// TEST-METADATA: algorithmName=SHA-256, algorithmFamily=SHA

import "crypto/sha256"

func main() {
    h := sha256.New()  // $variant captures "256"
    _ = h              // Metadata becomes algorithmName=SHA-256
}
```

The framework automatically:
1. Runs opengrep with `--taint-intrafile` to enable taint tracking
2. Extracts metavariable values from the `metavars` field
3. Resolves `$variable` references in metadata
4. Validates the final resolved metadata

### Comment Prefix by Language

The parser supports different comment styles:

| Language   | Comment Prefix | Example                |
|------------|----------------|------------------------|
| Java       | `//`           | `// TEST-METADATA: ...`|
| Python     | `#`            | `# TEST-METADATA: ...` |
| Go         | `//`           | `// TEST-METADATA: ...`|
| C/C++      | `//`           | `// TEST-METADATA: ...`|
| Rust       | `//`           | `// TEST-METADATA: ...`|
| JavaScript | `//`           | `// TEST-METADATA: ...`|

### Naming Convention

**Format**: `<descriptive-name>.test.<extension>`

Examples:
- `jca-crypto-operations.test.java` - Multiple JCA crypto tests
- `hmac-operations.test.py` - Multiple HMAC-related tests
- `aes-gcm-mode.test.go` - AES GCM mode tests
- `openssl-ciphers.test.c` - OpenSSL cipher tests

---

## Running Tests

### Run All Tests

```bash
make test
```

### Run Tests in Parallel (Recommended)

```bash
make test-parallel
```

Uses pytest-xdist to run tests on all available CPU cores.

### Run Quick Subset

```bash
make test-quick
```

Runs just AES tests to verify everything works.

### Run Specific Tests

```bash
# Run tests matching a keyword
cd tests && pytest -v -k "aes"
cd tests && pytest -v -k "java"
cd tests && pytest -v -k "128-bit"

# Run a specific test file
cd tests && pytest -v test_rules.py

# Run with more verbose output
cd tests && pytest -v -s --tb=long
```

### Debug Test Failures

```bash
# Run with full tracebacks and output
make test-debug

# Or use pytest directly
cd tests && pytest -v -s --tb=long -k "failing-test-name"
```

### Performance Benchmarking

```bash
# Time the test suite
time make test

# Run with pytest timing info
cd tests && pytest -v --durations=10
```

---

## Adding New Tests

### Workflow for New Rules

When you create a new rule file (e.g., `semgrep-rules/python/cryptography/rules.yaml`):

#### Step 1: Create Fixture Directory (if needed)

```bash
mkdir -p tests/integration/fixtures/python/cryptography
```

#### Step 2: Create Test Fixture

```bash
touch tests/integration/fixtures/python/cryptography/weak-cipher.test.py
```

#### Step 3: Write Test with Expectations

```python
# TEST-RULE: python.crypto.cryptography.weak-cipher
# TEST-METADATA: algorithm=DES, library=cryptography

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

cipher = Cipher(algorithms.TripleDES(key), modes.ECB())
```

#### Step 4: Run Tests

```bash
make test
```

That's it! The test will be automatically discovered and run.

### Adding Multiple Tests

You can add multiple test cases to the same file:

```python
# TEST-METADATA: algorithm=DES, mode=ECB
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
cipher1 = Cipher(algorithms.TripleDES(key), modes.ECB())

# TEST-METADATA: algorithm=DES, mode=CBC
cipher2 = Cipher(algorithms.TripleDES(key), modes.CBC(iv))

# TEST-METADATA: algorithm=AES, mode=GCM
cipher3 = Cipher(algorithms.AES(key), modes.GCM(nonce))
```

Each `TEST-METADATA` block becomes a separate test case.

---

## CI/CD Integration

### GitHub Actions

Tests run automatically on pull requests via GitHub Actions.

**Workflow file:** `.github/workflows/test.yml`

The workflow should use Python tests:
```yaml
steps:
  - uses: actions/checkout@v4

  - uses: actions/setup-python@v4
    with:
      python-version: '3.11'

  - name: Install dependencies
    run: |
      pip install semgrep pytest pytest-xdist pytest-timeout

  - name: Run tests
    run: make test-parallel
```

**Testing locally before pushing:**

```bash
# Ensure tests pass
make test

# Or run in parallel
make test-parallel
```

---

## Troubleshooting

### Test Fails: "Expected rule X was not triggered"

**Problem**: Rule doesn't match the fixture code, or metadata doesn't match.

**Debug steps**:

1. Run opengrep manually on the fixture:
   ```bash
   opengrep --json --taint-intrafile \
           --config semgrep-rules/java/jca/rules.yaml \
           tests/integration/fixtures/java/jca/your-test.test.java
   ```

2. Check what rules actually triggered:
   ```bash
   opengrep --json --taint-intrafile \
           --config semgrep-rules/java/jca/rules.yaml \
           tests/integration/fixtures/java/jca/your-test.test.java \
           | jq '.results[].check_id'
   ```

3. Check actual metadata extracted:
   ```bash
   opengrep --json --taint-intrafile \
           --config semgrep-rules/java/jca/rules.yaml \
           tests/integration/fixtures/java/jca/your-test.test.java \
           | jq '.results[].extra.metadata.crypto'
   ```

4. Verify metavariables are captured:
   ```bash
   opengrep --json --taint-intrafile \
           --config semgrep-rules/java/jca/rules.yaml \
           tests/integration/fixtures/java/jca/your-test.test.java \
           | jq '.results[].extra.metavars'
   ```

### Test Fails: "Invalid TEST-METADATA format"

**Problem**: Metadata format doesn't match either `key=value` or `key:value` format.

**Solution**: Ensure you use one of these formats:

```java
// Format 1 (comma-separated)
// TEST-METADATA: key1=value1, key2=value2

// Format 2 (space-separated)
// TEST-METADATA: key1:value1 key2:value2
```

### Test Fails: "No rules found for fixture"

**Problem**: Rules file path doesn't exist.

**Debug steps**:

1. Check what paths were tried:
   ```bash
   cd tests && pytest -v -k "your-test-name" --tb=short
   ```

2. The error message shows all paths tried. Create rules at one of those locations:
   ```bash
   # If error says it tried semgrep-rules/go/crypto/aes/rules.yaml
   mkdir -p semgrep-rules/go/crypto/aes
   touch semgrep-rules/go/crypto/aes/rules.yaml
   ```

### Test Fails: "OpenGrep not found"

**Problem**: OpenGrep/Semgrep not installed.

**Solution**:
```bash
pip install semgrep
opengrep --version  # Should show >= 1.12.1
```

### Test Fails: "OpenGrep version too old"

**Problem**: OpenGrep version < 1.12.1 (required for `--taint-intrafile`).

**Solution**:
```bash
pip install --upgrade semgrep
opengrep --version
```

### Metavariables Not Resolved

**Problem**: Metadata contains `$variable` instead of actual value.

**Causes:**
1. OpenGrep not run with `--taint-intrafile` flag
2. Metavariable not captured in the rule
3. Named regex group doesn't match

**Solution**:
1. Verify rule has metavariable patterns:
   ```yaml
   patterns:
     - pattern: algo.$FUNC(...)
     - metavariable-regex:
         metavariable: $FUNC
         regex: "(?<func>New|Sum)"  # Named group
   ```

2. Check metavars are captured:
   ```bash
   opengrep --json --taint-intrafile --config rules.yaml test.go \
     | jq '.results[].extra.metavars'
   ```

### Tests Slow / Hanging

**Problem**: Some tests take too long.

**Solutions:**
1. Use parallel execution:
   ```bash
   make test-parallel
   ```

2. Increase timeout (default 80s per test):
   ```bash
   cd tests && pytest -v --timeout=120
   ```

3. Find slow tests:
   ```bash
   cd tests && pytest -v --durations=20
   ```

---

## Best Practices

### 1. Group Related Tests

Put multiple related test cases in one file:

```java
// Multiple cipher tests in jca-ciphers.test.java
// TEST-METADATA: algorithm=DES
// ... test code ...

// TEST-METADATA: algorithm=AES, mode=ECB
// ... test code ...

// TEST-METADATA: algorithm=AES, mode=GCM
// ... test code ...
```

### 2. Use Descriptive Names

```
✓ cipher-weak-algorithms.test.java
✓ hash-md5-usage.test.py
✗ test1.test.java
✗ temp.test.go
```

### 3. Validate Key Metadata Only

Only specify metadata fields that are critical:

```java
// Good - validates important fields
// TEST-METADATA: algorithmName=DES, library=JCA/JCE

// Overkill - too many fields
// TEST-METADATA: algorithmName=DES, mode=ECB, padding=PKCS5Padding, library=JCA/JCE, api=Cipher.getInstance, assetType=algorithm, findingType=cipher, ...
```

### 4. Keep Fixtures Simple

Focus on the pattern being tested:

```java
// Good - minimal, focused
class Test {
    void test() throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
    }
}

// Too complex
class ComplexBusinessLogic {
    private DataService service;

    public void processPayment(Payment p) {
        service.validate(p);
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        // ... 50 more lines ...
    }
}
```

### 5. Test Edge Cases

```java
// TEST-METADATA: algorithmName=DES

// This tests case-insensitive algorithm detection
Cipher cipher = Cipher.getInstance("des/ecb/pkcs5padding");
```

### 6. Use Comments for Complex Tests

```python
# TEST-METADATA: algorithmName=SHA-256

# This test verifies that metavariable $variant is resolved correctly
# The rule should capture "256" from "sha256" and replace $variant in metadata
import hashlib
h = hashlib.sha256()
```

---

## Performance Tips

### Parallel Execution

Always use parallel execution for full test runs:
```bash
make test-parallel  # Uses all CPU cores
```

### Selective Testing

Test only what you're working on:
```bash
cd tests && pytest -v -k "java"     # Just Java tests
cd tests && pytest -v -k "aes"      # Just AES tests
cd tests && pytest -v -k "weak"     # Just tests with "weak" in name
```

### Quick Feedback Loop

```bash
# Quick test (just AES, fail fast)
make test-quick

# Or custom quick test
cd tests && pytest -v -k "your-feature" --maxfail=3
```

---

## Examples

### Minimal Test (Just Metadata)

```java
// TEST-METADATA: library=JCA/JCE

import javax.crypto.Cipher;

class Test {
    void test() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    }
}
```

### Test with Rule ID

```java
// TEST-RULE: java.security.crypto.cipher-weak-algorithm
// TEST-METADATA: algorithmName=DES, mode=ECB, library=JCA/JCE

import javax.crypto.Cipher;

class WeakCipher {
    void test() throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
    }
}
```

### Test with Metavariable Resolution

```go
// TEST-RULE: go.crypto.aes.key-generation
// TEST-METADATA: algorithmName=AES, keySize=256

package main

import "crypto/aes"

func main() {
    // Rule captures $BYTESIZE=32, resolves to keySize=256 (32*8=256)
    key := make([]byte, 32)
    block, _ := aes.NewCipher(key)
    _ = block
}
```

### Multiple Tests Per File

```python
# TEST-METADATA: algorithmFamily=MD5
import hashlib
h1 = hashlib.md5()

# TEST-METADATA: algorithmFamily=SHA-1
h2 = hashlib.sha1()

# TEST-METADATA: algorithmFamily=SHA-256
h3 = hashlib.sha256()
```

---

## Summary

The Python-based test framework provides:
- ⚡ **Fast execution** via batch scanning (one opengrep invocation per language)
- 🐍 **Simple Python code** (small, dependency-light core)
- 🔄 **Full metavar support** with taint analysis
- 🎯 **Flexible validation** (partial metadata, optional rule IDs)
- ⚙️ **Easy to extend** (pure Python, no binary deps)
- 📦 **Auto-discovery** (just add `.test.*` files)

For questions or issues, check the [Troubleshooting](#troubleshooting) section or open an issue.
