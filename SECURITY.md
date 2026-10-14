# Security policy

## Reporting a vulnerability

Please report vulnerabilities in CipherGuard privately through GitHub's
[private vulnerability reporting](https://github.com/NicholasDarwin/CipherGuard/security/advisories/new).
Do not open a public issue.

Include what you found, how to reproduce it, and the impact you expect. You
should get a response within 7 days.

## Scope

In scope: the scanner, the API, the web app, and the deployment configuration
in this repository.

Out of scope: findings that CipherGuard reports about *other* repositories.
Those belong to the owners of those repositories.

## How CipherGuard handles secrets it finds

Detected secret values are masked before they are stored, exported, shared,
or sent to the AI model. See "Secrets and privacy" in the README.
