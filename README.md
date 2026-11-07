# incident-replay-lab

A dependency-free, deterministic incident-replay engine. It accepts login-success/login-failure events with timezone-aware ISO 8601 timestamps, sorts events stably, and alerts when a user reaches a configurable number of failures within a sliding window. Successful login resets the user's failure history. The alert fires once at the threshold, not on every subsequent failure. This is a simulation, not a live intrusion detector.

## Run tests

Python 3.10+ with no third-party packages:

```sh
python -m unittest discover -s tests -v
```

## Example

```python
from incident_replay import replay
print(replay([{"user":"alice","action":"login_failure","timestamp":"2026-01-01T00:00:00Z"}]))
```

GitHub Actions is configured to run tests for Python 3.10, 3.12 and 3.13. CI results must be checked separately.
