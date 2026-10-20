# Security Policy

stash stores secrets, so we take security reports seriously and fix them before anything else.

## Reporting a vulnerability

**Please don't report security issues in public issues, discussions, or pull requests.**

Report them privately with GitHub's [private vulnerability reporting](https://github.com/Mrlopez62/stash/security/advisories/new). Go to the **Security** tab and click **Report a vulnerability**.

Please include:
- what an attacker could do, and what they'd need to start with (for example, local access or read access to the vault file)
- steps to reproduce, or a proof of concept
- the version or commit you tested

What to expect:
- We'll confirm we received your report within **3 days**.
- We'll aim to ship a fix or a mitigation plan within **30 days**.
- We'll credit you in the advisory, unless you'd rather stay anonymous.

## Supported versions

stash is pre-1.0. Only the latest release and the `main` branch get security fixes.

## Scope

[docs/threat-model.md](threat-model.md) lists what stash is designed to protect against and what it isn't. Reports about the documented non-goals are still welcome, but we'll treat them as hardening work rather than vulnerabilities.
