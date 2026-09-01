# QuietWard v0.6 Response handoff preview

Status: **development / not yet release-qualified**

This branch turns QuietWard and QuietWard Response into a more useful joint system without weakening QuietWard's observation-only contract. QuietWard produces privacy-preserving local handoff artifacts; a separate Response-owned process is responsible for authenticated transport and every response action.

## Joint architecture

```text
QuietWard observations
        |
        v
local deterministic analysis
        |
        v
tamper-evident QuietWard evidence-chain cycle
        |
        v
privacy-preserving handoff builder
        |
        v
private local handoff outbox
        |
        +----> Response-owned watcher
                    |
                    v
              authenticated Response incident
                    |
                    v
              analyst approval + policy
                    |
                    v
              Response endpoint agent
```

QuietWard does **not** connect to the Response API, hold a Response credential, poll for actions, approve actions, or execute actions. Response execution authority never enters the QuietWard process.

## Continuous local outbox

`scripts/run_response_handoff_outbox.py` can continuously follow QuietWard's persisted evidence chain using a read-only SQLite connection.

For each new cycle it:

1. reads the exact stored cycle payload from `evidence_chain`;
2. reconstructs the observation-only events/report;
3. builds sanitized Response events;
4. binds each event to the source QuietWard `cycle_id` and `chain_hash`;
5. writes a private deterministic `cycle-*.json` handoff file;
6. advances a private local outbox ledger.

The outbox never modifies the QuietWard database and performs no network request.

Backpressure is bounded. If the configured pending-file limit is reached, the exporter fails closed rather than silently dropping findings or growing indefinitely.

Run once:

```bash
python scripts/run_response_handoff_outbox.py --once
```

Run continuously:

```bash
python scripts/run_response_handoff_outbox.py --interval 5
```

The default outbox is:

```text
~/.local/state/quietward/response-handoff-outbox
```

## Linux user service

Install the outbox as a systemd user service:

```bash
bash scripts/install_response_handoff_user_service.sh
```

Optional explicit paths:

```bash
bash scripts/install_response_handoff_user_service.sh \
  /ABSOLUTE/PATH/config.json \
  /ABSOLUTE/PATH/response-handoff-outbox
```

The unit uses a private umask, `NoNewPrivileges`, and `PrivateTmp`. It still has no Response credential and no network client.

## Data that crosses the boundary

For each correlated finding, QuietWard may export:

- deterministic Response event ID;
- QuietWard finding ID;
- host ID required for host-bound Response authentication;
- coarse OS family: Windows, Linux, Darwin, or Unknown;
- severity, score, confidence, and event count;
- coarse event-kind codes and sanitized correlation-signal codes;
- installation-keyed HMAC-SHA256 subject identity;
- bounded non-executable investigation hints;
- for automated outbox delivery, the exact QuietWard evidence-chain cycle ID and 64-hex chain hash.

The handoff does **not** include:

- raw finding subjects;
- raw process command lines;
- executable paths from event attributes;
- raw file paths as subject identity;
- raw source or destination addresses;
- QuietWard action targets;
- executable proposals or execution authority.

## Provenance

Automated handoff events are traceable back to the tamper-evident QuietWard evidence chain:

```text
Response event metadata
  quietward_source_cycle_id
  quietward_source_chain_hash
            |
            v
QuietWard evidence_chain row
```

The Response watcher validates that the document-level provenance and each embedded event's provenance match exactly before transmitting anything.

## Manual export

A manual one-shot sanitized export is still available for development and inspection:

```bash
python scripts/export_response_handoff.py EVENTS.jsonl \
  --config ~/.config/quietward/config.json \
  --output ~/.local/state/quietward/response-handoff.json
```

Manual exports are not required to carry evidence-chain provenance because they are built directly from supplied event input rather than a persisted evidence-chain cycle.

## Fail-closed rules

Handoff creation fails if:

- QuietWard reports any executed action;
- any QuietWard proposal claims executable authority;
- a host ID is incompatible with the Response host-ID contract;
- the installation privacy identity key is unavailable;
- one handoff file would contain findings for multiple hosts;
- evidence-chain provenance is partial or malformed;
- an existing deterministic cycle file changes unexpectedly;
- the pending outbox capacity is exhausted.

## Qualification

Focused handoff/outbox gate:

```bash
python scripts/verify_v06_response_handoff.py
```

The Response companion branch adds a joint acceptance test that starts the real Response API and proves:

```text
QuietWard analysis
-> sanitized local handoff
-> Response ingestion
-> incident creation
-> analyst approval
-> read-only endpoint diagnostic
-> signed result
-> Response audit verification
```

The joint Response gate is:

```bash
python ../quietward-response/scripts/verify_v11_diagnostics.py \
  --quietward-repo .
```

Final v0.6 release qualification must run the complete QuietWard platform/release gate and the joint Response gate on the exact candidate SHAs.

## Explicitly out of scope

This preview does not add quarantine, process termination, service control, firewall modification, host isolation, arbitrary shell execution, cloud upload, or autonomous remediation to QuietWard.
