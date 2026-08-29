from datetime import datetime, timezone

def event(action: str, actor: str, details: str):
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "actor": actor,
        "details": details,
    }
