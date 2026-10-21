# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through [GitHub's advisory form](https://github.com/heavyblanketpizza/blacksite/security/advisories/new), not in a public issue. Include the version, how to reproduce the problem, and what an attacker gains. You should hear back within a week. Fixes ship as a new release, and the advisory is published once the release is out.

Only the latest release receives fixes.

## What Blacksite defends against

Blacksite runs disconnected, so the threat model is a person, a file, or a model answer on the local computer:

- The web app listens only on 127.0.0.1. Only accounts an admin created can sign in, with optional two-step sign-in, and every state-changing request carries a CSRF token.
- Evidence is untrusted. Logs can carry prompt injection, so indexing flags instruction-like text, tool output neutralizes tool-call markup, and every guide is checked before anyone sees it: citations are verified against the evidence, risky commands are labeled, and commands that pipe a download into a shell are blocked.
- Secrets recognized in evidence are redacted when it is indexed.
- The audit ledger is hash-chained and signed, and exported guides carry signed provenance.

In scope: anything that lets evidence or a signed-in member make the agent act outside its instructions, reach another person's data, run a command, or forge an audit or provenance record. Out of scope: a wrong diagnosis from the model, which the checks and the person reviewing the guide exist for, and attacks that already control the OS account running Blacksite.
