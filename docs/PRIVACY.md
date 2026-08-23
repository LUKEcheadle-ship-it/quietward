# Privacy model

QuietWard is local-first and does not upload telemetry. The default dashboard binds only to loopback. Scanner and model integrations are disabled by default.

## Stored data

QuietWard stores normalized events, findings, non-executable proposals, private alerts, bounded snapshots, scanner-run metadata, review states and tamper-evident chain records in local private state files.

Authentication usernames and sensitive Windows process/persistence identities use installation-specific HMAC-SHA256 pseudonyms derived from a private local privacy-identity key. SSH source addresses and optional outbound destinations on Linux/Windows now use installation-keyed scoped HMAC pseudonyms as well, so the same raw IP does not produce a globally reusable public digest across installations. If that private identity is unavailable, affected authentication/outbound records fail closed instead of persisting a weaker address identifier.

Raw process arguments are not persisted. Linux parser logic derives behavioral markers in memory and retains only a bounded argument digest in the current v0.5 format; Windows command lines use the installation privacy identity. Raw journal messages, authorized keys, cron contents, service-unit contents, scanner output, YARA strings and vulnerability descriptions are not persisted.

Docker container IDs remain represented by a namespaced digest rather than the raw identifier; these identifiers are already high-entropy machine-generated values and are not treated as human identity or network-address pseudonyms.

Early, uncorrected pre-rename alpha state could contain raw authentication usernames. Current releases prevent new raw username persistence. The supported migration accepts only the corrected signed schema-v4 format, keeps its established pseudonym namespace, and verifies the complete retained evidence chain before committing new paths. Older or ambiguous state must be archived privately and start with a fresh database.

Outbound connection monitoring is opt-in. When enabled, QuietWard stores only protocol, destination port, destination scope, installation-keyed destination pseudonym, process name when available and privacy flags. It does not store the raw local or remote address.

## Suppression privacy/safety interaction

Suppression rules remain local. High-signal events such as malware/YARA/integrity failures, credential spray, reverse shells, credential dumping, process injection, explicit ransomware recovery inhibition and event-log clearing bypass ordinary subject suppression so an earlier expected-state rule cannot hide a newly dangerous observation. This affects local review visibility only and never authorizes remediation.

## Sharing diagnostics

Do not publish the SQLite database, alerts, health reports, qualification reports, scanner data, host inventories or model inputs from a real machine. Public bug reports should use synthetic fixtures and redact identifying data.

## Deletion

The uninstall workflows preserve evidence by default. Explicit data deletion removes QuietWard-owned configuration and local state. Review `docs/OPERATIONS.md` before deletion.
