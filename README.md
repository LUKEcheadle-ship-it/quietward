# QuietWard Adversarial Validation

A separate, non-destructive security validation harness for the released **QuietWard + QuietWard Response v1** trust boundary.

This project independently challenges security claims already made by the v1 threat model and acceptance suite and reports evidence as `PASS`, `FAIL`, `KNOWN_LIMITATION`, or `SKIP`. It does not expand QuietWard Response and it is not RedLab.

## Current status

- **Version:** `0.1.0`
- **Harness tests:** `20/20` passing
- **Attack matrix:** `38` cases across nine trust-boundary categories
- **Live probes:** six stateless HMAC/authentication probes plus optional nonce-replay and event-ID-conflict probes
- **Target scope:** loopback HTTP/HTTPS only

## Safety boundary

The v0.1 harness is deliberately non-destructive:

- loopback targets only
- test-owned state only
- no malware deployment
- no persistence creation
- no shell, PowerShell, cmd, or bash execution
- no process termination
- no firewall modification
- no file quarantine/deletion
- no host isolation
- documented unsupported behavior is classified as `KNOWN_LIMITATION`, not a regression

## Attack matrix

The initial 38-case matrix covers:

1. protocol and authentication
2. agent lifecycle and credential boundaries
3. approval and policy enforcement
4. result forgery and lifecycle substitution
5. malicious-Response-to-QuietWard attempts
6. corrupt endpoint response state
7. audit integrity
8. concurrency and unsupported runtime shapes
9. data and deployment hardening

Use `qw-adversary --list` to inspect every case.

## Implemented live probes

The first live pack checks that Response rejects:

- missing authentication headers
- wrong key IDs
- body tampering after signing
- target/path-query tampering after signing
- stale signed timestamps
- future signed timestamps

An optional stateful pack creates only synthetic test-owned events to prove:

- nonce replay rejection
- event UUID reuse with changed content rejection

No enrollment or credential creation is automated. Supply a dedicated test agent through environment variables so the harness never prints or persists the secret itself.

```bash
export QWA_AGENT_ID='...'
export QWA_KEY_ID='...'
export QWA_SECRET='...'
export QWA_HOST_ID='...'
qw-adversary --target http://127.0.0.1:8002 --auth-probes

# Optional test-owned event creation:
qw-adversary --target http://127.0.0.1:8002 --auth-probes --stateful-auth-probes
```

The target validator refuses non-loopback hosts before any request is sent.

## Development

Requires Python 3.12+.

```bash
python -m pip install -e '.[test]'
pytest
qw-adversary --list
```

For a source-tree-only check without installation:

```bash
PYTHONPATH=src pytest -q
```

## Relationship to the QuietWard system

- **QuietWard** observes endpoint state and enforces the endpoint-side action allowlist.
- **QuietWard Response** correlates incidents, manages approval/policy, coordinates actions, and records audit evidence.
- **QuietWard Adversarial Validation** independently tests the claimed trust boundaries between them.
- **RedLab** is reserved for a later, broader authorized lab-testing project and is intentionally not part of this repository.

## License

MIT License. See `LICENSE`.
