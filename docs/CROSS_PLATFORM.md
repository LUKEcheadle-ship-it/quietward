# Cross-platform architecture

QuietWard keeps one platform-neutral analysis, storage, privacy, evidence,
alert, dashboard, and incident-export core. Operating-system integrations are
read-only collector adapters selected at runtime.

## Support tiers

| Platform | Current tier | Notes |
| --- | --- | --- |
| Debian 12 | Qualified experimental alpha | Existing real-host evidence applies. |
| Windows 11 | Qualified experimental alpha | User-scoped offline installer and read-only collector are available. |
| Windows 10 | Unqualified | Separate validation is required before support is claimed. |
| Windows Server 2019+ | Development preview | Uses related APIs but requires independent server qualification. |
| Other Linux distributions | Compatibility preview | Each distribution needs its own command, init, authentication, packaging and service matrix. |
| macOS | Planned | Requires Unified Log, launchd, Endpoint Security/XProtect and native service integration. |

“Linux support” is stated by tested distribution and version. QuietWard does
not claim every Linux environment works until its combinations have been
qualified.

## Runtime selection

`auto` selects:

- the established Debian collector on Debian;
- the capability-tolerant Linux collector on other Linux distributions;
- the Windows collector on Windows;
- a clear unsupported-platform failure elsewhere.

The common service receives the selected collector through a factory. Windows
uses a compatibility lock layer so importing the service does not require the
Unix-only `fcntl` module.

## Windows collector

The Windows lane uses fixed, exact PowerShell command tuples with
`subprocess(..., shell=False)`. Arbitrary PowerShell, `cmd.exe`, script hosts,
privilege escalation and dynamic command construction are not allowed.

It covers:

- process inventory, with command lines hashed immediately and account names
  replaced by installation-specific keyed identifiers;
- TCP listening sockets, with interface addresses reduced to coarse scopes;
- opt-in established outbound connections, with destination addresses hashed;
- Run/RunOnce keys, enabled scheduled tasks and automatic services;
- optional Docker Desktop/container inventory;
- optional failed-logon events from the Windows Security log;
- configured sensitive-file integrity.

Security-log access can require additional permission. Failed-logon collection
is disabled by default until the operator explicitly enables it.

## Safety direction

Cross-platform collection remains observation-only. Any future remediation must
be bounded, reversible, catalogued, explicitly approved and independently
verified. Arbitrary commands, silent quarantine, firewall mutation, registry
editing, process termination and service changes are not automatic defaults.
