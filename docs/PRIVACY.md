# Privacy model

QuietWard is local-first and does not upload telemetry. The default dashboard binds only to loopback. Scanner and model integrations are disabled by default.

## Stored data

QuietWard stores normalized events, findings, non-executable proposals, private alerts, bounded snapshots, scanner-run metadata, review states and tamper-evident chain records in local private state files.

Process arguments are hashed after in-memory marker extraction. SSH source addresses, Docker container IDs and outbound destinations are namespaced hashes. Authentication usernames are represented by installation-specific HMAC-SHA256 pseudonyms using a private local privacy-identity key; raw usernames are never persisted. Raw journal messages, authorized keys, cron contents, service-unit contents, scanner output, YARA strings and vulnerability descriptions are not persisted.

Early, uncorrected pre-rename alpha state could contain raw authentication usernames. Current releases prevent new raw username persistence. The supported migration accepts only the corrected signed schema-v4 format, keeps its established pseudonym namespace, and verifies the complete retained evidence chain before committing new paths. Older or ambiguous state must be archived privately and start with a fresh database.

Outbound connection monitoring is opt-in. When enabled, QuietWard stores only protocol, destination port, destination scope, destination hash, process name when available and privacy flags. It does not store the raw local or remote address.

## Sharing diagnostics

Do not publish the SQLite database, alerts, health reports, qualification reports, scanner data, host inventories or model inputs from a real machine. Public bug reports should use synthetic fixtures and redact identifying data.

## Deletion

The uninstall workflows preserve evidence by default. Explicit data deletion removes QuietWard-owned configuration and local state. Review `docs/OPERATIONS.md` before deletion.
