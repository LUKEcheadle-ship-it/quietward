# Security policy

This repository is a non-destructive validation harness for QuietWard and QuietWard Response.

## Scope

The v0.1 harness is intentionally restricted to loopback targets and test-owned state. It does not perform shell execution, malware deployment, persistence changes, process termination, firewall changes, file quarantine/deletion, or host isolation.

## Reporting findings

Security findings discovered by this harness should be reported against the affected QuietWard or QuietWard Response project rather than expanded into destructive proof-of-concept code here.

Do not include live credentials, enrollment secrets, HMAC secrets, private host data, or production evidence in issues or test fixtures.
