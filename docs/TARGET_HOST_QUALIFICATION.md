# Target-host read-only qualification

This stage proves that QuietWard can observe a target computer without modifying it. It is performed before enabling scanner execution or making support claims for a new host type.

## Debian command

```bash
PYTHONPATH=src python -m quietward.cli qualify \
  --cycles 5 \
  --interval-seconds 2 \
  --pretty
```

The command prints one JSON report to standard output. QuietWard does not create or update a report file; redirecting output is an explicit operator choice.

## Mandatory gates

The report must show:

- `decision: PASS`;
- exactly the requested number of cycles;
- the same pseudonymous host ID in every cycle;
- zero actions executed;
- zero executable action proposals;
- zero baseline change events on cycle 1;
- all persisted privacy flags set to false;
- cycle duration, snapshot size and event count below configured limits;
- no required collector errors.

Missing optional Docker or journal access is recorded as a warning. QuietWard must not use `sudo` or broaden permissions to hide that warning.

## Resource defaults

The conservative qualification ceilings are:

- 5,000 ms maximum per collection cycle;
- 2,000,000 bytes maximum serialized snapshot;
- 512 MiB maximum Python-process peak RSS;
- 500 events maximum per cycle;
- 3 cycles by default, with 1 second between cycles.

These are qualification ceilings, not expected steady-state usage. Final service limits should be tightened from evidence on the actual host.

## Privacy review

Before sharing a report, verify that it contains no raw process arguments, source addresses, Docker container IDs, raw log messages, credentials, malware samples or private network inventories. Qualification reports still describe host counts and should remain private.

## Failure handling

A failed gate does not authorize remediation. Preserve the report privately, investigate the blocker, change the code or configuration in a review branch, rerun the same qualification and compare the evidence. Do not bypass a gate by enabling root access or weakening the observation-only policy.
