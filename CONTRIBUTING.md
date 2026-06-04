# Contributing

Thanks for your interest in improving SCANOSS Open Crypto Rules! This guide
covers how the repository is organized and how to test your changes.

By contributing, you agree that your contributions are licensed under the
project's [GPL-2.0 license](LICENSE).

## Ways to contribute

- **New rules** for libraries or algorithms not yet covered
- **Test fixtures** that improve detection coverage or guard against regressions
- **Bug fixes** for false positives / false negatives
- **Test framework** and documentation improvements

## Repository layout

```
semgrep-rules/<language>/<library>/...      # detection rules (rules.yaml)
tests/integration/fixtures/<language>/...   # self-describing test fixtures
tests/lib/                                  # the Python test framework
```

Rules live under a path that reflects their language and library, and each rule
file has matching fixtures under `tests/integration/fixtures/`. The test runner
maps a fixture to the rules for its language automatically by file extension —
see [TESTING.md](TESTING.md#fixture-path--rules-file-mapping) for details.

## Prerequisites

- Python 3.9+
- [OpenGrep](https://github.com/opengrep/opengrep) (or Semgrep) >= 1.12.1

```bash
pip install -r tests/requirements.txt
pip install semgrep
opengrep --version   # >= 1.12.1
```

## Adding or changing a rule

1. Add or edit the rule under `semgrep-rules/<language>/<library>/...`, following
   the structure and style of the existing rules.
2. Validate the rule file before committing:
   ```bash
   opengrep --validate --config semgrep-rules/<language>/<library>/rules.yaml
   ```
3. Add at least one **test fixture** that exercises the rule (see below). Every
   rule change should be covered by a fixture.
4. Run the test suite and make sure it passes.

## Writing tests

Tests are self-describing source files named `*.test.<ext>`. Each test case is a
`TEST-METADATA` comment block (optionally preceded by `TEST-RULE`) followed by
the code that should trigger detection:

```go
// TEST-RULE: go.crypto.md5.hash-usage
// TEST-METADATA: algorithmName=MD5, algorithmFamily=MD5, library=crypto/md5

package main

import "crypto/md5"

func main() {
    _ = md5.New()
}
```

Only the metadata fields you list are validated, so assert on what matters. The
[Testing Guide](TESTING.md) documents the full fixture format, both metadata
syntaxes, and metavariable resolution.

## Running tests

```bash
make test            # all tests
make test-parallel   # all CPU cores
make test-quick      # fast subset
make docker-test     # run inside the test container
```

To debug a single failing test:

```bash
cd tests && pytest -v -s --tb=long -k "your-test-name"
```

The [Troubleshooting](TESTING.md#troubleshooting) section explains how to inspect
what a rule actually matched and what metadata it produced.

## Pull request checklist

- [ ] New / changed rules have matching test fixtures
- [ ] `make test` passes locally
- [ ] Rule files validate with `opengrep --validate`
- [ ] Commits follow [Conventional Commits](https://www.conventionalcommits.org/)
- [ ] The change is focused and the PR description explains the motivation

## Reporting issues

Use the issue templates to report a false positive/negative, request a new rule,
or file a bug in the test framework. For security-sensitive reports, follow
[SECURITY.md](SECURITY.md) instead of opening a public issue.
