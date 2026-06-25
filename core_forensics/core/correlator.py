from __future__ import annotations

from collections import defaultdict
from pathlib import PureWindowsPath
from typing import Any

SUSPICIOUS_EXEC_PATH_PARTS = [
    r"\\temp\\",
    r"\\users\\public\\",
    r"\\appdata\\local\\temp\\",
    r"\\programdata\\",
]


def _basename(path: str) -> str:
    try:
        return PureWindowsPath(path).name.lower()
    except Exception:
        return path.lower().split("/")[-1]


def correlate(
    processes: list[dict[str, Any]],
    files: list[dict[str, Any]],
    dlls: list[dict[str, Any]] | None = None,
    connections: list[dict[str, Any]] | None = None,
    psxview_processes: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    dlls = dlls or []
    connections = connections or []
    psxview_processes = psxview_processes or []

    all_file_paths = [str(item.get("path", "")).lower() for item in files]
    non_deleted_paths = [str(item.get("path", "")).lower() for item in files if not item.get("is_deleted", False)]

    file_basenames = {_basename(path) for path in non_deleted_paths}

    dll_by_pid: dict[int, list[str]] = defaultdict(list)
    for dll in dlls:
        pid = int(dll.get("pid", -1))
        if pid < 0:
            continue
        dll_by_pid[pid].append(str(dll.get("path", "")))

    conn_by_pid: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for conn in connections:
        pid = int(conn.get("pid", -1))
        if pid < 0:
            continue
        conn_by_pid[pid].append(conn)

    psxview_by_pid: dict[int, dict[str, Any]] = {}
    for item in psxview_processes:
        pid = int(item.get("pid", -1) or -1)
        if pid < 0:
            continue
        psxview_by_pid[pid] = item

    correlated: list[dict[str, Any]] = []

    for proc in processes:
        process_name = str(proc.get("name", "")).strip()
        proc_name_lower = process_name.lower()

        image_path = str(proc.get("image_path_name") or proc.get("path") or "")
        image_path_lower = image_path.lower()
        process_basename = _basename(process_name)

        found_on_disk = process_basename in file_basenames

        path_suspicious = any(marker in image_path_lower for marker in SUSPICIOUS_EXEC_PATH_PARTS) if image_path else False
        path_missing = bool(image_path and image_path_lower not in all_file_paths and image_path_lower not in non_deleted_paths)
        psxview = psxview_by_pid.get(int(proc.get("pid", 0) or 0), {})

        correlated.append(
            {
                "process": process_name,
                "pid": int(proc.get("pid", 0) or 0),
                "ppid": int(proc.get("ppid", 0) or 0),
                "create_time": proc.get("create_time"),
                "image_path": image_path or None,
                "found_on_disk": found_on_disk,
                "path_suspicious": path_suspicious,
                "path_missing": path_missing,
                "dll_count": len(dll_by_pid.get(int(proc.get("pid", 0) or 0), [])),
                "connection_count": len(conn_by_pid.get(int(proc.get("pid", 0) or 0), [])),
                "cross_view_mismatch": bool(psxview.get("cross_view_mismatch", False)),
                "cross_view_visible_count": int(psxview.get("visible_count", 0) or 0),
            }
        )

    summary = {
        "process_count": len(processes),
        "disk_file_count": len(files),
        "deleted_file_count": sum(1 for item in files if item.get("is_deleted", False)),
        "network_connection_count": len(connections),
    }

    return {"summary": summary, "correlated": correlated}
