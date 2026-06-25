from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from typing import Any


@dataclass
class VolatilityConfig:
    volatility_bin: str = "vol"
    timeout_seconds: int = 120


class VolatilityError(RuntimeError):
    pass


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        return lowered in {"true", "1", "yes", "y"}
    return False


def _normalize_process_row(row: dict[str, Any]) -> dict[str, Any] | None:
    name = row.get("imagefilename") or row.get("image_file_name") or row.get("name")
    pid = row.get("pid")
    if not name or pid is None:
        return None

    return {
        "name": str(name),
        "pid": _coerce_int(pid),
        "ppid": _coerce_int(row.get("ppid", 0)),
        "create_time": row.get("createtime") or row.get("create_time"),
        "offset": row.get("offsetv") or row.get("offset"),
        "source": row.get("source"),
    }


def _normalize_record(record: dict[str, Any]) -> dict[str, Any]:
    normalized: dict[str, Any] = {}
    for key, value in record.items():
        clean = key.lower().replace(" ", "_").replace("(", "").replace(")", "")
        normalized[clean] = value
    return normalized


def _parse_renderer_json(stdout: str) -> list[dict[str, Any]]:
    payload = json.loads(stdout)

    if isinstance(payload, dict) and "rows" in payload and "columns" in payload:
        columns = [str(col) for col in payload.get("columns", [])]
        rows = payload.get("rows", [])
        parsed = [dict(zip(columns, row)) for row in rows if isinstance(row, list)]
        return [_normalize_record(item) for item in parsed]

    if isinstance(payload, list):
        items = [item for item in payload if isinstance(item, dict)]
        return [_normalize_record(item) for item in items]

    return []


def _run_volatility(memory_file: str, plugin: str, config: VolatilityConfig) -> list[dict[str, Any]]:
    cmd = [config.volatility_bin, "-f", memory_file, "-r", "json", plugin]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=config.timeout_seconds)

    if proc.returncode != 0:
        raise VolatilityError(proc.stderr.strip() or "Volatility command failed")

    if not proc.stdout.strip():
        return []

    return _parse_renderer_json(proc.stdout)


def _run_volatility_text(memory_file: str, plugin: str, config: VolatilityConfig) -> str:
    cmd = [config.volatility_bin, "-f", memory_file, plugin]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=config.timeout_seconds)

    if proc.returncode != 0:
        raise VolatilityError(proc.stderr.strip() or "Volatility text command failed")

    return proc.stdout


def extract_processes(memory_file: str, config: VolatilityConfig | None = None) -> list[dict[str, Any]]:
    config = config or VolatilityConfig()

    try:
        rows = _run_volatility(memory_file, "windows.pslist", config)
    except (VolatilityError, json.JSONDecodeError, subprocess.TimeoutExpired):
        rows = []

    processes: list[dict[str, Any]] = []

    if rows:
        for row in rows:
            parsed = _normalize_process_row(row)
            if parsed:
                processes.append(parsed)
        return processes

    try:
        text = _run_volatility_text(memory_file, "windows.pslist", config)
    except (VolatilityError, subprocess.TimeoutExpired):
        return []
    row_pattern = re.compile(r"^\s*(\S+\.exe)\s+(\d+)\s+(\d+)")

    for line in text.splitlines():
        match = row_pattern.search(line)
        if not match:
            continue
        processes.append(
            {
                "name": match.group(1),
                "pid": int(match.group(2)),
                "ppid": int(match.group(3)),
                "create_time": None,
                "offset": None,
            }
        )

    return processes


def extract_psscan_processes(memory_file: str, config: VolatilityConfig | None = None) -> list[dict[str, Any]]:
    config = config or VolatilityConfig()
    try:
        rows = _run_volatility(memory_file, "windows.psscan", config)
    except (VolatilityError, json.JSONDecodeError, subprocess.TimeoutExpired):
        return []

    processes: list[dict[str, Any]] = []
    for row in rows:
        parsed = _normalize_process_row(row)
        if not parsed:
            continue
        parsed["source"] = "psscan"
        processes.append(parsed)

    return processes


def extract_psxview(memory_file: str, config: VolatilityConfig | None = None) -> list[dict[str, Any]]:
    config = config or VolatilityConfig()
    try:
        rows = _run_volatility(memory_file, "windows.psxview", config)
    except (VolatilityError, json.JSONDecodeError, subprocess.TimeoutExpired):
        return []

    output: list[dict[str, Any]] = []
    for row in rows:
        parsed = _normalize_process_row(row)
        if not parsed:
            continue

        checks = {
            "pslist": _coerce_bool(row.get("pslist")),
            "psscan": _coerce_bool(row.get("psscan")),
            "thrdproc": _coerce_bool(row.get("thrdproc")),
            "csrss": _coerce_bool(row.get("csrss")),
            "session": _coerce_bool(row.get("session")),
            "deskthrd": _coerce_bool(row.get("deskthrd")),
        }
        visible_count = sum(1 for present in checks.values() if present)
        parsed.update(
            {
                "source": "psxview",
                "checks": checks,
                "visible_count": visible_count,
                "cross_view_mismatch": 0 < visible_count < len(checks),
            }
        )
        output.append(parsed)

    return output


def extract_dlls(memory_file: str, config: VolatilityConfig | None = None) -> list[dict[str, Any]]:
    config = config or VolatilityConfig()
    try:
        rows = _run_volatility(memory_file, "windows.dlllist", config)
    except (VolatilityError, json.JSONDecodeError, subprocess.TimeoutExpired):
        return []

    dlls: list[dict[str, Any]] = []
    for row in rows:
        pid = row.get("pid")
        base = row.get("base")
        path = row.get("path") or row.get("fullpath") or row.get("name")
        if pid is None or not path:
            continue
        dlls.append(
            {
                "pid": int(pid),
                "base": base,
                "path": str(path),
            }
        )

    return dlls


def extract_network_connections(memory_file: str, config: VolatilityConfig | None = None) -> list[dict[str, Any]]:
    config = config or VolatilityConfig()
    try:
        rows = _run_volatility(memory_file, "windows.netscan", config)
    except (VolatilityError, json.JSONDecodeError, subprocess.TimeoutExpired):
        return []

    connections: list[dict[str, Any]] = []
    for row in rows:
        pid = row.get("pid")
        local_addr = row.get("localaddr") or row.get("local_address")
        local_port = row.get("localport") or row.get("local_port")
        remote_addr = row.get("foreignaddr") or row.get("remoteaddr") or row.get("remote_address")
        remote_port = row.get("foreignport") or row.get("remoteport") or row.get("remote_port")
        protocol = row.get("proto") or row.get("protocol")

        if pid is None:
            continue

        connections.append(
            {
                "pid": int(pid),
                "protocol": protocol,
                "local_address": local_addr,
                "local_port": local_port,
                "remote_address": remote_addr,
                "remote_port": remote_port,
                "state": row.get("state"),
                "created": row.get("created"),
            }
        )

    return connections
