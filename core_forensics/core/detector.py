from __future__ import annotations

import re
from typing import Any

KNOWN_SYSTEM_PROCESSES = {
    "system",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "explorer.exe",
}

SUSPICIOUS_NAME_RE = re.compile(r"^[a-z]{8,}[0-9]{2,}\.exe$")


def _severity(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def detect_anomalies(correlated_data: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []

    pids = {item.get("pid") for item in correlated_data}

    for item in correlated_data:
        name = str(item.get("process", "")).lower()
        pid = int(item.get("pid", 0) or 0)
        ppid = int(item.get("ppid", 0) or 0)

        if not item.get("found_on_disk") and name not in KNOWN_SYSTEM_PROCESSES:
            score = 70 + min(int(item.get("connection_count", 0)) * 2, 15)
            alerts.append(
                {
                    "type": "fileless_malware_candidate",
                    "severity": _severity(score),
                    "score": score,
                    "process": item.get("process"),
                    "pid": pid,
                    "reason": "Running process does not map to a disk executable.",
                }
            )

        if item.get("path_suspicious"):
            score = 55 + min(int(item.get("dll_count", 0)), 20)
            alerts.append(
                {
                    "type": "suspicious_execution_path",
                    "severity": _severity(score),
                    "score": score,
                    "process": item.get("process"),
                    "pid": pid,
                    "reason": "Process image path is in a high-risk user-writable location.",
                }
            )

        if item.get("path_missing"):
            score = 60
            alerts.append(
                {
                    "type": "path_missing_on_disk",
                    "severity": _severity(score),
                    "score": score,
                    "process": item.get("process"),
                    "pid": pid,
                    "reason": "Process image path from memory was not present in parsed disk files.",
                }
            )

        if SUSPICIOUS_NAME_RE.match(name):
            alerts.append(
                {
                    "type": "suspicious_process_name",
                    "severity": "medium",
                    "score": 40,
                    "process": item.get("process"),
                    "pid": pid,
                    "reason": "Process name matches random-looking malware naming pattern.",
                }
            )

        # A simple hidden-process heuristic: parent process missing from pslist snapshot.
        if ppid > 0 and ppid not in pids and name not in KNOWN_SYSTEM_PROCESSES:
            alerts.append(
                {
                    "type": "hidden_process_candidate",
                    "severity": "high",
                    "score": 65,
                    "process": item.get("process"),
                    "pid": pid,
                    "reason": "Parent PID not visible in process list snapshot.",
                }
            )

        # Injection heuristic: high DLL count + active network + missing binary.
        if (
            int(item.get("dll_count", 0)) > 80
            and int(item.get("connection_count", 0)) > 0
            and not item.get("found_on_disk")
        ):
            alerts.append(
                {
                    "type": "process_injection_candidate",
                    "severity": "critical",
                    "score": 90,
                    "process": item.get("process"),
                    "pid": pid,
                    "reason": "High DLL load and network activity from process without mapped executable.",
                }
            )

        if item.get("cross_view_mismatch"):
            alerts.append(
                {
                    "type": "cross_view_process_mismatch",
                    "severity": "high",
                    "score": 72,
                    "process": item.get("process"),
                    "pid": pid,
                    "reason": "Process visibility differs across kernel process views.",
                }
            )

    alerts.sort(key=lambda item: item.get("score", 0), reverse=True)
    return alerts


def detect_hidden_processes(
    pslist_processes: list[dict[str, Any]],
    psscan_processes: list[dict[str, Any]],
    psxview_processes: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []

    pslist_pids = {int(item.get("pid", 0) or 0) for item in pslist_processes}

    for item in psscan_processes:
        pid = int(item.get("pid", 0) or 0)
        if pid <= 0 or pid in pslist_pids:
            continue
        alerts.append(
            {
                "type": "hidden_process_psscan_only",
                "severity": "high",
                "score": 75,
                "process": item.get("name"),
                "pid": pid,
                "reason": "Process appears in psscan but not in pslist.",
            }
        )

    for item in psxview_processes:
        pid = int(item.get("pid", 0) or 0)
        if pid <= 0:
            continue
        if not item.get("cross_view_mismatch"):
            continue
        visible_count = int(item.get("visible_count", 0) or 0)
        alerts.append(
            {
                "type": "hidden_process_psxview_mismatch",
                "severity": "high" if visible_count <= 3 else "medium",
                "score": 78 if visible_count <= 3 else 62,
                "process": item.get("name"),
                "pid": pid,
                "reason": "Process has inconsistent visibility in psxview checks.",
                "checks": item.get("checks", {}),
            }
        )

    alerts.sort(key=lambda item: item.get("score", 0), reverse=True)
    return alerts
