"""Deterministic security event replay and alert correlation."""
from datetime import datetime, timezone

def replay(events, threshold=3, window_seconds=300):
    if type(threshold) is not int or threshold < 1 or type(window_seconds) is not int or window_seconds < 1:
        raise ValueError("threshold and window_seconds must be positive integers")
    ordered = []
    for i, event in enumerate(events):
        if not isinstance(event, dict) or not isinstance(event.get("user"), str) or not event["user"]:
            raise ValueError("event user required")
        if event.get("action") not in ("login_success", "login_failure"):
            raise ValueError("unsupported action")
        timestamp = event.get("timestamp")
        if not isinstance(timestamp, str):
            raise ValueError("timestamp required")
        try:
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("invalid timestamp") from exc
        if dt.tzinfo is None:
            raise ValueError("timezone required")
        ordered.append((dt.astimezone(timezone.utc), i, event))
    ordered.sort(key=lambda x: (x[0], x[1]))
    failures = {}
    alerts = []
    for dt, _, event in ordered:
        user = event["user"]
        if event["action"] == "login_success":
            failures.pop(user, None)
            continue
        recent = [t for t in failures.get(user, []) if (dt - t).total_seconds() < window_seconds]
        recent.append(dt)
        failures[user] = recent
        if len(recent) == threshold:
            alerts.append({"user": user, "type": "repeated_login_failures",
                           "count": len(recent), "timestamp": dt.isoformat()})
    return alerts
