# QuietWard community roadmap

QuietWard is building toward a local-first endpoint security tool that is useful to individual defenders, homelab users, students, and security engineers without becoming an unrestricted endpoint control product.

This roadmap is intentionally public so users can see where the project is going and contributors can pick work with a clear product purpose.

## Near term: make the first 10 minutes excellent

- ship the safe synthetic `scripts/quick_demo.py` path;
- simplify first-run validation and explain failures in plain language;
- make Windows and Debian installation paths easier to verify and recover;
- add clearer sample findings and screenshots for common detection categories;
- document the QuietWard -> QuietWard Response pairing path end to end.

## Detection quality

- expand regression coverage for common living-off-the-land behavior;
- improve multi-stage correlation without increasing false-positive noise;
- add clearer reason strings for correlated findings;
- improve suppression guidance and review workflows;
- publish small sanitized detection examples contributors can extend.

## Daily usability

- richer finding search/filtering in the local dashboard;
- clearer health and coverage indicators;
- easier export of sanitized incident evidence;
- better install/upgrade diagnostics;
- predictable resource-use reporting on supported platforms.

## Platform coverage

Current focus remains Windows and Debian. Expansion should happen only when the platform can be qualified honestly rather than being listed as nominally supported.

Potential future work:

- additional mainstream Linux distributions;
- macOS collector research;
- stronger native Windows collection paths;
- platform-specific privacy and evidence-integrity tests.

## QuietWard + Response

QuietWard stays observation-only. The joint system should improve through:

- easier local pairing and bridge health checks;
- stronger provenance visibility;
- better handoff failure diagnostics;
- more useful sanitized investigation context;
- no Response credential or execution authority inside QuietWard.

## Good contribution areas

Contributors do not need to work on security-sensitive execution code. Useful areas include:

- documentation and screenshots;
- parser fixtures and sanitized examples;
- dashboard usability;
- platform diagnostics;
- test coverage;
- performance measurement;
- detection reason clarity;
- installer ergonomics.

Before contributing, read `CONTRIBUTING.md`, `SECURITY.md`, and the observation-only boundary in the main README.
