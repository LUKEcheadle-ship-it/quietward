# August 2026 intern UX acceptance

This record paraphrases the August 13 report. It contains no intern document, host data, logs, network inventory, or production evidence.

| Report item | Decision | Evidence |
|---|---|---|
| Repeated hash-specific rows | Implemented and verified | Semantic groups preserve all children; a 250-finding mixed fixture is covered by `tests/test_dashboard.py`. |
| Severity order | Implemented and verified | Critical, high, medium/mid, low, info, then unknown; urgent states and newest timestamps break ties. |
| Onboarding placement | Implemented and verified | Welcome content precedes findings, can be dismissed in local storage, and is restored by Help. |
| Human-readable timestamps | Implemented and verified | A single injected-clock-capable formatter handles missing, invalid, future, offset, relative, and local display while retaining exact UTC. |
| Developer-heavy reasons | Implemented and verified | Only allowlisted formats are translated; escaped raw values remain under Raw Event Log. |
| Refresh appeared inert | Implemented and verified | Requests disable the control, expose progress/success/failure, reject overlap, preserve prior data, filters, and disclosure state, and use one timer. |
| macOS support | Rejected with evidence | No Darwin collector, installer, LaunchAgent qualification host, or native runner exists. The platform check remains intact; macOS is not advertised as supported. |

## Exact grouping identity

The key is `normalized title | subject category | detector family`. Title normalization lowercases, removes long hash tokens and standalone numbers, and collapses punctuation/whitespace. Subject category uses an explicit prefix (for example `service:`), or the coarse categories `path`, `hash`, and `generic`. Detector family recognizes only `tiny_model_probability`, `base:<rule>`, and `rule:<rule>` forms. The unique finding hash is never a grouping input. Similar titles with different subject or detector categories remain separate.

The dashboard fetches at most 500 newest findings. It always shows displayed raw, matching raw, grouped, and total raw counts, and explicitly labels truncation and the limit.

## Platform and safety decision

Windows 11 and Debian 12 behavior is unchanged. The dashboard remains GET-only: mutation verbs return 405, and no UI control writes review state or executes proposals. Required invariants remain `actions_executed == 0`, `executable_proposals == 0`, loopback binding, no cloud upload, and no public listener.

The private archive's only newer-looking qualification changes referenced event kinds absent from the canonical public contract, so they were rejected as incompatible. Its remaining path differences revive retired branding and were also rejected.
