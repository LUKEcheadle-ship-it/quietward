# QuietWard v0.6 Response handoff preview

Status: **development / not yet release-qualified**

This branch adds a one-way, privacy-preserving handoff from QuietWard findings to QuietWard Response while preserving QuietWard's observation-only contract.

## Design

QuietWard does **not** connect to the Response action API and does not poll for, approve, or execute Response actions.

The flow is:

```text
QuietWard observations
        |
        v
local deterministic analysis
        |
        v
privacy-preserving handoff builder
        |
        v
private local JSON handoff file
        |
        +----> separate Response-owned importer / endpoint agent
```

The handoff deliberately keeps the trust boundary one-way. Response execution authority never enters the QuietWard process.

## Data that crosses the boundary

For each correlated finding, QuietWard may export:

- deterministic Response event ID
- QuietWard finding ID
- host ID required for host-bound Response authentication
- coarse OS family: Windows, Linux, Darwin, or Unknown
- severity, score, confidence, and event count
- coarse event-kind codes and sanitized correlation-signal codes
- installation-keyed HMAC-SHA256 subject identity
- bounded non-executable investigation hints

The handoff does **not** include:

- raw finding subjects
- raw process command lines
- executable paths from event attributes
- raw file paths as subject identity
- raw source or destination addresses
- QuietWard action targets
- executable proposals or execution authority

## Fail-closed rules

Handoff creation fails if:

- QuietWard reports any executed action
- any QuietWard proposal claims executable authority
- a host ID is incompatible with the Response host-ID contract
- the installation privacy identity key is unavailable
- one handoff file would contain findings for multiple hosts

## Local export

From a development checkout:

```bash
python scripts/export_response_handoff.py EVENTS.jsonl \
  --config ~/.config/quietward/config.json \
  --output ~/.local/state/quietward/response-handoff.json
```

The output file is created with private permissions where the platform supports them. The exporter itself performs no network request.

## Focused qualification

```bash
python scripts/verify_v06_response_handoff.py
```

Final v0.6 release qualification must additionally run the complete QuietWard platform/release gate on the exact candidate SHA.

## Explicitly out of scope

This preview does not add quarantine, process termination, service control, firewall modification, host isolation, arbitrary shell execution, cloud upload, or autonomous remediation to QuietWard.
