# Evidence integrity and redacted exports

QuietWard stores a hash-linked evidence chain for retained service cycles and can optionally authenticate new chain entries with a local HMAC-SHA256 key.

## Optional evidence signing

QuietWard never downloads, rotates or uploads signing keys. The installers create and protect the local key for supported deployments. For a manual Debian deployment, an administrator may create one with:

```bash
umask 077
head -c 32 /dev/urandom > ~/.config/quietward/evidence-signing.key
```

Then set an absolute path in the storage configuration:

```json
{
  "storage": {
    "evidence_signing_key_path": "/home/USER/.config/quietward/evidence-signing.key"
  }
}
```

The key file must be a regular non-symlink file, contain 32–4096 bytes and have no group or world permissions. QuietWard stores only a derived key identifier and HMAC signatures; key bytes never enter the database, logs, health report, dashboard or exports.

Signing can be enabled on an existing database. Earlier retained cycles remain valid unsigned history, and every subsequent cycle must be signed. Removing or changing the configured key causes verification and new-cycle persistence to fail rather than silently falling back to unsigned operation. Key rotation remains intentionally unsupported in the current alpha.

## Bounded retained chain

Cycle and scanner-run histories have explicit count limits in addition to age retention. Before old cycles are removed, QuietWard records the last removed cycle and chain hash as a retained-chain anchor. Verification starts from that anchor and validates every retained payload, chain hash and required signature.

The anchor is local metadata, not an external transparency log. Signed chains make post-anchor rewriting detectable without the private key; unsigned chains remain locally tamper-evident only.

## Redacted incident exports

```bash
quietward export FINDING_ID ~/incident.json --format json --pretty
quietward export FINDING_ID ~/incident.md --format markdown
```

Exports are private files, are written atomically, reject symlink targets and refuse overwrite unless `--force` is supplied. Subjects, paths, usernames, process names, target values and proposal targets are replaced with stable export-only hashes. Analyst notes are excluded. Normalized scanner identifiers and already-hashed fields may remain.

Review every export before controlled sharing; no redaction system can guarantee that arbitrary future attributes contain no sensitive context.
