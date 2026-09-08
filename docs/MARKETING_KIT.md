# QuietWard marketing kit

## One-line pitch

**QuietWard is a local-first, observation-only endpoint security monitor that explains suspicious host activity and preserves tamper-evident evidence without silently changing the machine.**

## Short GitHub / portfolio description

QuietWard monitors host behavior, correlates security signals into explainable findings, tracks incident lifecycle, and stores local tamper-evident evidence. The project deliberately stays observation-only: no automatic quarantine, process termination, firewall changes, host isolation, cloud telemetry, or generic remote-command surface.

## Current call to action

Try the real scoring/correlation path safely before installing the monitor:

```bash
python scripts/quick_demo.py
```

The demo uses synthetic data only and performs no host scan, network request, system change, or action execution.

## Social post

I’ve been building **QuietWard**, an open-source endpoint security project focused on a different tradeoff: useful host visibility without automatically giving the monitoring agent broad control of the machine.

QuietWard watches processes, network activity, persistence, authentication evidence, file integrity, container state, and its own integrity. It correlates those signals into explainable findings and keeps local tamper-evident evidence.

The core boundary is intentional: QuietWard is **observation-only**. It does not automatically quarantine files, kill processes, change firewall rules, isolate the host, or expose a generic remote-command surface.

I also added a safe synthetic demo so anyone can see the actual scoring and correlation path before installing anything:

`python scripts/quick_demo.py`

QuietWard can optionally pair with **QuietWard Response**, where investigation, approval, policy, and controlled diagnostics live as a separate system.

Project: https://github.com/LUKEcheadle-ship-it/quietward

#Cybersecurity #OpenSource #Python #SecurityEngineering #Homelab

## Resume / portfolio bullet

**QuietWard — Creator / Developer:** Built and qualified a local-first endpoint security monitor with deterministic multi-signal detection, privacy-preserving identity handling, incident lifecycle tracking, read-only Windows/Linux collection, tamper-evident evidence chains, and an explicit zero-action security boundary; integrated it with a separate controlled-response system through a sanitized provenance-preserving handoff.

## Claims to avoid

Do not market QuietWard as:

- a replacement for enterprise EDR/MDR;
- guaranteed malware prevention;
- autonomous remediation;
- an Internet-facing production security service;
- universally qualified across all operating systems.
