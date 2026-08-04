## What changed

Describe the focused change and why it is needed.

## Security and privacy boundary

- Data read:
- Data persisted:
- Commands executed:
- Permissions required:
- Network behavior:
- Action authority:

## Validation

List the exact tests, compilation checks, release audit, restart checks, and target-host evidence completed for this change.

## Checklist

- [ ] The change remains observation-only.
- [ ] No shell, `sudo`, package installation, updater, cloud telemetry, public listener, or executable containment path was added.
- [ ] Raw sensitive data is not persisted or included in fixtures.
- [ ] First-run baseline and backward compatibility were considered.
- [ ] Resource and event volume are bounded.
- [ ] Tests cover failure behavior and zero executed actions.
- [ ] Security-sensitive details were reported privately rather than included here.
