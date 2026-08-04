# QuietWard deployment

## Supported initial targets

QuietWard currently targets Windows 11 and Debian 12. Monitoring is observation-only and does not require automatic remediation authority.

## Debian installation

```bash
./scripts/install_user_service.sh
```

The installer copies the standard-library runtime into `~/.local/share/quietward`, creates the `quietward` launcher, preserves existing configuration, installs a hardened user-level `quietward.service`, runs diagnostics and starts the service.

## Windows installation

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\install_windows.ps1
```

The installer creates a private user-scoped environment under `%LOCALAPPDATA%\QuietWard`, one limited current-user startup task, private keys and state, and a local dashboard shortcut.

## Configure scanners

All scanner jobs are disabled by default. Enable only scanners already installed and supplied with trusted local data:

- ClamAV uses the local signature database already maintained by the host.
- YARA requires an absolute trusted rules file.
- Trivy is forced into offline mode and all database/check updates are disabled.
- debsecan requires an explicit local `data_source`; QuietWard refuses its default remote source.

QuietWard never invokes a scanner updater. Signature and database updates remain a separately governed host-administration responsibility.

## Dashboard

The dashboard binds to `127.0.0.1` by default. Access it locally or through an authenticated tunnel. Private-network binding requires `allow_private_network_bind: true` and a private token file containing at least 24 characters. Public binding is rejected.

Authentication-event collection requires the private `collector.privacy_identity_key_path` key. Installers create this key once without network access and never replace a valid existing key. If it is missing or invalid, identity persistence fails closed rather than storing usernames.

## Acceptance

Debian:

```bash
./scripts/qualify_target_host.sh
```

Windows:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\qualify_windows.ps1
```

Do not enable containment. QuietWard’s released safety boundary remains observation-only with zero executable remediation proposals.
