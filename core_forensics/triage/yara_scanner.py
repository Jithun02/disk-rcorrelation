from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any

import pytsk3

class YaraScannerError(RuntimeError):
    pass


def _load_yara_module() -> Any:
    try:
        return importlib.import_module("yara")
    except ImportError as exc:  # pragma: no cover
        raise YaraScannerError("yara-python is not installed") from exc


def _compile_rules(rules_path: str):
    yara_module = _load_yara_module()
    try:
        return yara_module.compile(filepath=rules_path)
    except Exception as exc:  # pragma: no cover
        raise YaraScannerError(f"Failed to compile YARA rules: {exc}") from exc


def _extract_strings(match: Any) -> list[str]:
    strings: list[str] = []
    for item in getattr(match, "strings", []):
        identifier = getattr(item, "identifier", None)
        matched_data = getattr(item, "matched_data", b"")
        if isinstance(matched_data, bytes):
            snippet = matched_data[:48].decode("utf-8", errors="replace")
        else:
            snippet = str(matched_data)[:48]
        if identifier:
            strings.append(f"{identifier}:{snippet}")
    return strings


def _iter_file_systems(img: pytsk3.Img_Info):
    try:
        volume = pytsk3.Volume_Info(img)
        for partition in volume:
            if partition.len <= 0:
                continue
            try:
                yield pytsk3.FS_Info(img, offset=partition.start * 512)
            except OSError:
                continue
    except OSError:
        yield pytsk3.FS_Info(img)


def _read_file_bytes_from_fs(fs: pytsk3.FS_Info, path: str, inode: int | None, max_size: int) -> bytes:
    file_obj = None

    if inode:
        try:
            file_obj = fs.open_meta(inode=inode)
        except OSError:
            file_obj = None

    if file_obj is None:
        try:
            file_obj = fs.open(path=path)
        except OSError:
            return b""

    if not file_obj.info or not file_obj.info.meta or file_obj.info.meta.size is None:
        return b""

    size = int(file_obj.info.meta.size)
    if size <= 0:
        return b""

    size = min(size, max_size)
    try:
        return file_obj.read_random(0, size)
    except OSError:
        return b""


def scan_disk_files_with_yara(
    image_path: str,
    files: list[dict[str, Any]],
    rules_path: str,
    max_files: int = 300,
    max_file_size_bytes: int = 5_000_000,
) -> dict[str, Any]:
    if not rules_path:
        return {"enabled": False, "matches": [], "errors": ["No YARA rules path provided."]}

    rule_file = Path(rules_path)
    if not rule_file.exists():
        return {
            "enabled": False,
            "matches": [],
            "errors": [f"YARA rules file not found: {rules_path}"],
        }

    try:
        compiled = _compile_rules(rules_path)
    except YaraScannerError as exc:
        return {"enabled": False, "matches": [], "errors": [str(exc)]}

    if not Path(image_path).exists():
        return {
            "enabled": False,
            "matches": [],
            "errors": [f"Disk image not found: {image_path}"],
        }

    candidates = [
        item
        for item in files
        if item.get("is_deleted", False) and isinstance(item.get("size"), int)
    ]
    if not candidates:
        candidates = [item for item in files if isinstance(item.get("size"), int)]

    candidates.sort(key=lambda item: int(item.get("size", 0)), reverse=True)

    img = pytsk3.Img_Info(image_path)
    file_systems = list(_iter_file_systems(img))

    matches: list[dict[str, Any]] = []
    errors: list[str] = []

    for item in candidates[: max(1, max_files)]:
        size = int(item.get("size", 0) or 0)
        if size <= 0 or size > max_file_size_bytes:
            continue

        path = str(item.get("path", ""))
        inode = item.get("inode")

        chunk = b""
        for fs in file_systems:
            chunk = _read_file_bytes_from_fs(fs, path=path, inode=inode, max_size=max_file_size_bytes)
            if chunk:
                break

        if not chunk:
            errors.append(f"Could not extract bytes for {path}")
            continue

        try:
            hit_list = compiled.match(data=chunk)
        except Exception as exc:  # pragma: no cover
            errors.append(f"YARA scan failure for {item.get('path')}: {exc}")
            continue

        for hit in hit_list:
            matches.append(
                {
                    "rule": hit.rule,
                    "namespace": hit.namespace,
                    "tags": list(hit.tags),
                    "meta": dict(hit.meta),
                    "path": item.get("path"),
                    "is_deleted": bool(item.get("is_deleted", False)),
                    "matched_strings": _extract_strings(hit),
                }
            )

    return {
        "enabled": True,
        "rules_path": rules_path,
        "scanned_candidates": min(len(candidates), max(1, max_files)),
        "matches": matches,
        "errors": errors,
    }
