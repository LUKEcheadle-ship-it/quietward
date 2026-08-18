# QuietWard

QuietWard is an offline-first, observation-only cybersecurity monitor that explains suspicious host activity without silently changing the computer.

## Release status

`v0.4.0-alpha.2` is an **experimental open-source alpha**. The qualified platforms are:

- **Windows 11**
- **Debian 12**

Windows 10, macOS, and other Linux distributions have not completed independent qualification and are not listed as supported. QuietWard is not a replacement for Microsoft Defender or professional endpoint protection.

## What it does

QuietWard monitors processes, listening ports, persistence, selected sensitive files, local security evidence, containers when available, and its own integrity. It correlates changes into findings, stores bounded local evidence, and presents the result in a read-only localhost dashboard.

On Windows, it also displays read-only Microsoft Defender status. Defender evidence is labeled separately and QuietWard does not start scans or change Defender settings.

![QuietWard read-only dashboard on Windows](docs/assets/quietward-windows-dashboard.png)

## Windows quick start

Requirements:

- Windows 11
- Python 3.11 or newer
- PowerShell

Extract the release archive, open PowerShell in the extracted folder, and run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\install_windows.ps1
```

The installer is user-scoped and creates:

- a private local virtual environment;
- private configuration, state, and evidence-signing keys;
- one limited current-user startup task;
- a desktop shortcut to the dashboard.

Open the dashboard at `http://127.0.0.1:8765/` or run:

```powershell
quietward open-dashboard --pretty
quietward diagnose --pretty
```

Run the bounded host check with:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\qualify_windows.ps1
```

See `docs/FIRST_RUN.md` and `docs/WINDOWS.md` for operating and troubleshooting guidance.

## Debian quick start

```bash
./scripts/install_user_service.sh
quietward doctor --config ~/.config/quietward/config.json --pretty
```

The Debian path remains the corrected and qualified observation-only alpha.

## What users see

The local dashboard answers five practical questions:

1. Is QuietWard running normally?
2. When did monitoring last complete?
3. Which findings need attention?
4. Why was each finding raised?
5. Are there collector, database, privacy, or evidence-integrity problems?

Findings are grouped by semantic family so repeated hash-specific observations do not overwhelm the page. Each accessible disclosure preserves every original finding and incident link. Groups show their raw child count, highest severity, newest observation, review-state summary, and explanation. Filters retain only matching children, while the count line distinguishes groups, matching raw findings, displayed raw findings, and the database total.

Finding details include severity, score, allowlisted plain-language reason explanations, escaped raw technical details, supporting evidence, review state, and any non-executable remediation proposal. Exact UTC timestamps remain available in tooltips and accessible labels. Optional collector limitations are shown as warnings rather than being presented as confirmed threats.

## Safety boundary

QuietWard does not quarantine or delete files, stop arbitrary processes or services, change firewall rules, isolate a host, install packages during monitoring, upload telemetry by default, expose a public listener, execute arbitrary commands, or perform automatic remediation.

Release invariants for the public alpha remain:

```text
actions_executed == 0
executable_proposals == 0
dashboard_bind == 127.0.0.1
cloud_upload == false
public_listener == false
```

Outbound connection monitoring is disabled by default. Enable it only when you are ready to establish and review a real-host baseline.

## Experimental QuietWard Response integration

The `feature/response-platform-integration` branch contains an **optional** integration with the separate QuietWard Response control-plane project. It is not part of the current public alpha release.

When explicitly enabled, QuietWard can:

- send its own event observations to QuietWard Response using HMAC-SHA256 authenticated requests;
- queue delivery locally if Response is temporarily unavailable;
- poll outbound for actions that Response has already stored, approved, and policy-validated;
- validate the target, action type, and parameters again on the endpoint;
- return a signed typed result;
- keep a durable local action ledger so a completed action ID is not executed twice.

Enablement is environment-driven and off by default:

```text
QUIETWARD_RESPONSE_ENABLED=true
QUIETWARD_RESPONSE_URL=http://127.0.0.1:8002
QUIETWARD_RESPONSE_AGENT_ID=...
QUIETWARD_RESPONSE_KEY_ID=...
QUIETWARD_RESPONSE_SECRET=...
```

The Phase 2 branch deliberately recognizes only one executable response action: `restart_quietward_demo_service`. Despite the name, it does **not** control a real operating-system service. It changes only the dedicated QuietWard-owned state file `quietward-response-demo.json`. It accepts no service name, command, path, process ID, or other arbitrary target.

For a safe end-to-end demo after enrollment:

```bash
python scripts/quietward_response_demo.py init-unhealthy --host-id YOUR_HOST_ID
python scripts/quietward_response_demo.py sync --host-id YOUR_HOST_ID
```

The first sync sends an authenticated synthetic health event for that dedicated fixture. After an analyst prepares and approves the allowlisted response in the QuietWard Response incident console, run `sync` again to poll, execute the demo-only state transition, and return the result.

If Response is disabled or unreachable, QuietWard continues its local monitoring path. The main service catches optional integration failures rather than converting them into local service failure. No shell, PowerShell, `cmd`, service manager, process kill, firewall, file deletion, quarantine, or host isolation capability is introduced by this Phase 2 bridge.

## Build and verify a release candidate

On Windows:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\build_release_candidate.ps1
```

This runs tests, compilation, the public-release audit, two deterministic builds, archive-hash comparison, and archive verification. It writes the source archive and SHA-256 checksum under `dist\`.

Verify an extracted or downloaded archive with:

```powershell
py -3 .\scripts\verify_release_bundle.py .\dist\quietward-v0.4.0-alpha.2-source.zip
```

Linux validation remains available through:

```bash
./scripts/validate_release.sh
```

## Export a redacted incident

```bash
quietward export FINDING_ID incident.json --format json --pretty
quietward export FINDING_ID incident.md --format markdown
```

Exports remain local and exclude raw sensitive identities and analyst notes.

## Documentation

Start with:

- `docs/FIRST_RUN.md`
- `docs/WINDOWS.md`
- `docs/releases/v0.4.0-alpha.2.md`
- `docs/INTERN_UX_ACCEPTANCE_2026_08.md`
- `docs/PRIVACY.md`
- `docs/SECURITY_MODEL.md`
- `docs/EVIDENCE_INTEGRITY.md`
- `docs/RELEASE_CHECKLIST.md`

## License

MIT. See `LICENSE`.

## Repository policy

Never commit malware samples, private host logs, credentials, runtime databases, scanner databases, private network inventories, raw persistence files, signing keys, or production model inputs.
