# QuietWard v0.5 release-correction record

This document records qualification-driven corrections made after a full code/function review of the v0.5 detection-hardening candidate. These corrections do not change QuietWard's observation-only product boundary.

Status: **candidate corrections — full exact-SHA tests and Windows 11/Debian 12 qualification still required**.

## Windows collector/parser repairs

The review found several source-contract regressions in the Windows path. The candidate now:

- imports and uses the regex module required by ransomware/evasion process markers;
- aligns outbound-connection parser arguments with the Windows collector;
- uses the private installation identity for outbound destination pseudonyms;
- uses the private installation identity for failed-logon source/account pseudonyms;
- aligns persistence parsing with the PowerShell collector's actual `Category/Name/Command/State/Account` wire format;
- stores pseudonymous persistence identities/fingerprints rather than raw name/command/account values;
- retains deterministic risk markers such as user-writable target, unexpected interpreter and privileged service without persisting the sensitive source strings.

These contracts are enforced by the v0.5 gate and cross-platform regression tests.

## Installation-keyed network/authentication privacy

Previous code represented source/destination addresses with a public deterministic SHA-256 namespace. Although raw addresses were absent, low-entropy IPv4 addresses could be dictionary-tested and linked across installations.

v0.5 now uses the existing private installation `PrivacyIdentity` HMAC key for:

- Linux SSH authentication source addresses — `linux-auth-source-v1`;
- Linux optional outbound destinations — `linux-outbound-address-v1`;
- Windows failed-logon source addresses — `windows-auth-source-v1`;
- Windows optional outbound destinations — `windows-outbound-address-v1`.

The same raw IP therefore produces a different durable pseudonym under different installation keys. If the private identity is unavailable, authentication/outbound collection fails closed rather than persisting a weaker public address digest.

## High-signal suppression safety

Expected/suppressed review rules remain important for ordinary recurring noise. The review identified a problem where a later high-confidence process behavior could inherit an old subject suppression before scoring/correlation.

The service now bypasses ordinary suppression for explicit high-signal security evidence, including:

- malware/YARA and self/evidence-integrity failures;
- credential spray;
- reverse/web shells;
- credential dumping/theft;
- process injection;
- suspicious document/server child execution;
- ransomware recovery inhibition;
- event-log clearing;
- dangerous container/Docker-socket/host-root evidence.

Lower-specificity context such as `encoded_command` alone remains suppressible. The bypass is intentionally narrow and affects review visibility only; QuietWard still executes zero response actions.

## Release-gate changes

`scripts/verify_v05_detection.py` now requires source/test evidence for:

- installation-keyed address privacy;
- corrected Windows connection/auth/persistence contracts;
- high-signal suppression bypass;
- the existing cross-subject chain, process/network, scoring, ancestry and ransomware/evasion controls;
- full pytest with warnings as errors;
- public-release audit;
- observation-only invariants.

The candidate must still pass Windows 11 and Debian 12 qualification plus deterministic packaging on the final SHA before publication.

## Unchanged safety boundary

The corrections add no quarantine, process/service termination, firewall change, host isolation, cloud upload, generic command execution or automatic remediation path.

Required release invariants remain:

```text
actions_executed == 0
executable_proposals == 0
dashboard_bind == 127.0.0.1
cloud_upload == false
public_listener == false
```
