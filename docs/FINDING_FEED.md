# Finding feed v1

`quietward findings export --after CURSOR --limit 500` emits one redacted JSON record per line.
Records are ordered by their opaque cursor.  `--after` is exclusive; omit it for
the beginning.  A malformed cursor fails without emitting data.  The command is
read-only: it does not acknowledge, suppress, delete, or deliver findings.

The contract is `schema_version: "1.0"` and contains finding ID, opaque cursor,
timestamp, pseudonymous host ID, event type, severity, confidence, summary, and
redacted evidence.  It contains no database path, raw command arguments,
addresses, usernames, findings-review notes, or delivery configuration.
