# QuietWard v0.5 detection regression matrix

This matrix covers the observation-only v0.5 detection candidate. Cases use synthetic parser input or in-memory `SecurityEvent` objects and never perform remediation or host mutation.

A case is release-qualified only when its mapped regression actually runs successfully in the complete v0.5 gate on the candidate SHA.

| ID | Detection / false-positive case | Expected result | Primary regression |
|---|---|---|---|
| AUTH-01 | Large single source targets many account identities | credential-spray context, HIGH review priority | `test_detection_hardening_v05.py` / `test_detection_adversarial_v05.py` |
| AUTH-02 | Small failure burst against one account | no spray HIGH floor | `test_detection_adversarial_v05.py` |
| AUTH-03 | Raw username/source address in persisted spray event | never persisted | `test_detection_hardening_v05.py` |
| PROC-01 | Windows reverse-shell process pattern | `reverse_shell`, HIGH+ | `test_detection_hardening_v05.py` |
| PROC-02 | Windows credential-dumping command | `credential_dumping`, HIGH+ | `test_detection_hardening_v05.py` |
| PROC-03 | Office/PDF parent spawns interpreter/LOLBin | `document_spawned_interpreter`, HIGH+ | `test_parent_child_detection_v05.py` |
| PROC-04 | Normal Office child process | no document→interpreter marker | `test_parent_child_detection_v05.py` |
| PROC-05 | Interpreter launched from non-document parent | no document→interpreter marker | `test_parent_child_detection_v05.py` |
| PROC-06 | Linux relay or `/dev/tcp` reverse shell | `reverse_shell`, HIGH+ | `test_detection_hardening_v05.py` |
| PROC-07 | Linux download→shell / encoded-shell chain | bounded high-signal marker | `test_detection_hardening_v05.py` |
| PROC-08 | Web/server parent spawns already-suspicious shell child | `web_server_spawned_suspicious_shell`, HIGH+ | `test_linux_parent_child_parser_v05.py` |
| PROC-09 | Web/server parent spawns normal maintenance shell | no ancestry marker by itself | `test_linux_parent_child_parser_v05.py` |
| IMPACT-01 | `vssadmin(.exe) delete shadows` | recovery-inhibition marker, HIGH+ | `test_windows_impact_evasion_v05.py` / `test_detection_adversarial_v05.py` |
| IMPACT-02 | `wmic(.exe) shadowcopy delete` | recovery-inhibition marker, HIGH+ | `test_windows_impact_evasion_v05.py` / `test_detection_adversarial_v05.py` |
| IMPACT-03 | `wbadmin(.exe) delete catalog` | recovery-inhibition marker, HIGH+ | `test_windows_impact_evasion_v05.py` |
| IMPACT-04 | recovery-disabling `bcdedit` | recovery-inhibition marker, HIGH+ | `test_windows_impact_evasion_v05.py` |
| IMPACT-05 | `vssadmin list shadows` / normal backup query | no recovery-inhibition marker | `test_detection_adversarial_v05.py` |
| EVADE-01 | explicit event-log clearing | `event_log_clearing`, HIGH+ | `test_windows_impact_evasion_v05.py` / `test_detection_adversarial_v05.py` |
| EVADE-02 | event-log query/read | no clearing marker | `test_detection_adversarial_v05.py` |
| EVADE-03 | Defender real-time preference disable | lower-weight contextual tamper marker | `test_windows_impact_evasion_v05.py` |
| EVADE-04 | Defender status query | no tamper marker | `test_detection_adversarial_v05.py` |
| CONT-01 | Docker socket or host-root exposure | high-confidence container security evidence | `test_detection_adversarial_v05.py` |
| CONT-02 | weak but common container context such as missing no-new-privileges alone | no automatic HIGH behavior floor | `test_detection_adversarial_v05.py` |
| CHAIN-01 | spray → privilege → persistence → outbound across subjects | one bounded same-host chain | `test_detection_hardening.py` / `test_detection_hardening_v05.py` |
| CHAIN-02 | reverse shell + persistence across subjects | two-phase high-signal chain | `test_high_signal_marker_correlation_v05.py` |
| CHAIN-03 | recovery inhibition + file-integrity evidence | two-phase high-signal chain | `test_high_signal_marker_correlation_v05.py` |
| CHAIN-04 | log clearing + identity attack | two-phase high-signal chain | `test_high_signal_marker_correlation_v05.py` |
| CHAIN-05 | low-specificity suspicious process + unrelated network | no two-phase chain | `test_high_signal_marker_correlation_v05.py` |
| CHAIN-06 | high-signal event with no second attack phase | no chain | `test_high_signal_marker_correlation_v05.py` |
| CHAIN-07 | same subject only | no cross-subject host-chain duplicate | `test_high_signal_marker_correlation_v05.py` |
| CHAIN-08 | events outside 15-minute chain window | no chain | `test_detection_adversarial_v05.py` |
| CHAIN-09 | suspicious process name aligns with adjacent network process | process/network corroboration bonus | `test_process_network_corroboration_v05.py` |
| PRIV-01 | command arguments persisted raw | forbidden; only hashes + bounded markers | `test_detection_hardening_v05.py` / `test_parent_child_detection_v05.py` |
| SAFE-01 | any finding proposes an executable action | forbidden by observation-only release invariant | full existing suite / release gate |
| SAFE-02 | monitoring executes remediation | forbidden (`actions_executed == 0`) | full existing suite / release gate |
| SAFE-03 | dashboard becomes public listener | forbidden | existing qualification/release audit |

## Release interpretation

- High-confidence behavior floors affect **review priority only**; they never authorize an action.
- Lower-specificity administrative/context markers remain below HIGH unless additional typed evidence increases the score.
- Multi-stage chains require bounded time, multiple phases and cross-subject evidence; a single scary marker does not create a host-chain by itself.
- Raw authentication identities and raw Windows/Linux process arguments remain outside durable event evidence.
- A test file existing is not a PASS. The complete v0.5 gate and platform qualification must execute successfully on the exact candidate SHA.

## Platform release gate

Before publication:

```text
python scripts/verify_v05_detection.py
```

must pass, followed by the existing qualified Windows 11 and Debian 12 platform checks. Any detection, privacy, safety, public-release-audit or platform failure blocks publication.
