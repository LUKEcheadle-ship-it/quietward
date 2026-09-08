# Try QuietWard before installing it

If you are evaluating QuietWard, start with the synthetic demo. It does not inspect the host, make a network request, or modify system state.

```bash
python scripts/quick_demo.py
```

For the complete structured payload:

```bash
python scripts/quick_demo.py --json
```

The demo feeds three synthetic security signals through the real deterministic scoring, correlation, finding, proposal, and observation-only policy path. It is intended to show what QuietWard output looks like without asking a new user to configure endpoint monitoring first.

Expected safety properties:

```text
synthetic_data_only == true
host_observation_performed == false
host_state_changed == false
network_request_performed == false
actions_executed == 0
```

## Then try the real monitor

Run the prerequisite doctor before installation or service startup:

```bash
quietward doctor --pretty
```

See `docs/FIRST_RUN.md` for the supported installation flow.

## Want the response side too?

QuietWard can pair with [QuietWard Response](https://github.com/LUKEcheadle-ship-it/quietward-response) through a sanitized local handoff while QuietWard itself remains observation-only.
