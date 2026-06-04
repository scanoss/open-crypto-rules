---
name: Bug report
about: Report a false positive, false negative, or a problem with the test framework
title: "[bug] "
labels: bug
---

## Summary

<!-- A clear and concise description of the problem. -->

## Type

- [ ] False positive (rule matched code that is not the target crypto usage)
- [ ] False negative (rule did not match code it should have)
- [ ] Test framework / tooling issue

## Rule and language

- Rule ID (if known):
- Language / library:

## Reproduction

<!-- Minimal code sample that demonstrates the issue. -->

```text
// paste a minimal snippet here
```

Command used:

```bash
opengrep --config semgrep-rules/ --taint-intrafile <file>
```

## Expected vs. actual

- **Expected:**
- **Actual:**

## Environment

- OpenGrep / Semgrep version (`opengrep --version`):
- OS / platform:
