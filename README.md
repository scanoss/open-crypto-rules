# SCANOSS Open Crypto Rules

[![License: GPL v2](https://img.shields.io/badge/License-GPLv2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![Tests](https://github.com/scanoss/open-crypto-rules/actions/workflows/test.yml/badge.svg)](https://github.com/scanoss/open-crypto-rules/actions/workflows/test.yml)

Open source [Semgrep](https://semgrep.dev/) / [OpenGrep](https://github.com/opengrep/opengrep)
rules for detecting **cryptographic usage in source code**.

These rules statically inventory where cryptography is used across a codebase —
algorithms, hashes, MACs, key material, certificates, and protocols — and attach
structured metadata to each finding. The metadata is designed to feed downstream
tooling such as a **Cryptographic Bill of Materials (CBOM)**.

The rules surface evidence; they do not enforce policy. Whether a given algorithm
or configuration is acceptable is left to the systems and people consuming the
findings.

## What's here

| Path | Description |
|------|-------------|
| `semgrep-rules/` | The detection rules, organized as `<language>/<library>/...` |
| `tests/` | Python + OpenGrep test framework and self-describing fixtures |
| `TESTING.md` | Full guide to writing and running tests |
| `Dockerfile.test` | Reproducible test environment |
| `Makefile` | Common test commands |

## Quick start

### Prerequisites

- Python 3.9+
- [OpenGrep](https://github.com/opengrep/opengrep) (or Semgrep) >= 1.12.1 — required for taint analysis

```bash
pip install semgrep        # provides the opengrep-compatible engine
opengrep --version         # should be >= 1.12.1
```

### Run a scan

Point the engine at the rules and your code:

```bash
opengrep --config semgrep-rules/ --taint-intrafile path/to/your/code
```

### Run the tests

```bash
make test            # run all tests
make test-parallel   # run across all CPU cores
make test-quick      # fast subset
```

Or in a container, with no local Python/OpenGrep setup:

```bash
make docker-test
```

See [TESTING.md](TESTING.md) for the complete testing guide.

## Coverage

Rules are grouped by language and library under `semgrep-rules/`. Each rule file
is paired with self-describing test fixtures under
`tests/integration/fixtures/` that document and verify the expected detections.

## Contributing

Contributions are welcome — new rules, additional fixtures, and improvements to
the test framework. Please read [CONTRIBUTING.md](CONTRIBUTING.md) and our
[Code of Conduct](CODE_OF_CONDUCT.md) before opening a pull request.

## Security

To report a security issue, please follow the process in [SECURITY.md](SECURITY.md).

## License

This project is licensed under the **GNU General Public License v2.0**.
See [LICENSE](LICENSE) for the full text.

---

Maintained by [SCANOSS](https://www.scanoss.com/).
