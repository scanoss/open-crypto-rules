# Security Policy

## Reporting a Vulnerability

We take security seriously. If you believe you have found a security
vulnerability in this project, please report it privately so we can address it
before it is publicly disclosed.

**Please do not open a public issue for security reports.**

Preferred reporting channels:

1. **GitHub private vulnerability reporting** — use the
   [Security Advisories](https://github.com/scanoss/open-crypto-rules/security/advisories/new)
   "Report a vulnerability" form for this repository.
2. **Email** — contact **security@scanoss.com** with the details.

Please include, where possible:

- A clear description of the issue and its impact
- Steps to reproduce (rule, fixture, or command)
- The OpenGrep/Semgrep version and platform
- Any suggested remediation

## Scope

This repository contains static detection rules and a test framework. Relevant
security concerns include, for example:

- Rules that could cause the scanning engine to crash, hang, or consume
  excessive resources on crafted input
- Test framework code that executes untrusted input unsafely

Vulnerabilities in OpenGrep/Semgrep themselves should be reported to their
respective projects.

## Response

We aim to acknowledge reports within a reasonable timeframe, keep you informed
of progress, and credit reporters who wish to be acknowledged once a fix is
released.
