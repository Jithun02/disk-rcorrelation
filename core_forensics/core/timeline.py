from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _safe_dt(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def build_timeline(
    processes: list[dict[str, Any]],
    files: list[dict[str, Any]],
    connections: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []

    for proc in processes:
        events.append(
            {
                "timestamp": proc.get("create_time"),
                "event": "process_start",
                "pid": proc.get("pid"),
                "name": proc.get("name"),
            }
        )

    for file_item in files:
        if file_item.get("mtime"):
            events.append(
                {
                    "timestamp": file_item.get("mtime"),
                    "event": "file_modified",
                    "path": file_item.get("path"),
                    "deleted": file_item.get("is_deleted", False),
                }
            )

    for conn in connections:
        if conn.get("created"):
            events.append(
                {
                    "timestamp": conn.get("created"),
                    "event": "network_connection",
                    "pid": conn.get("pid"),
                    "remote": f"{conn.get('remote_address')}:{conn.get('remote_port')}",
                }
            )

    events.sort(
        key=lambda item: _safe_dt(item.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc),
        reverse=False,
    )

    return events
