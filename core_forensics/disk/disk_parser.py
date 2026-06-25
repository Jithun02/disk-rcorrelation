from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import pytsk3


@dataclass
class FileRecord:
    path: str
    size: int | None
    inode: int | None
    is_deleted: bool
    mtime: str | None
    atime: str | None
    ctime: str | None
    crtime: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "size": self.size,
            "inode": self.inode,
            "is_deleted": self.is_deleted,
            "mtime": self.mtime,
            "atime": self.atime,
            "ctime": self.ctime,
            "crtime": self.crtime,
        }


def _safe_decode(name: bytes) -> str:
    return name.decode("utf-8", errors="replace")


def _ts_to_iso(ts: int | None) -> str | None:
    if not ts:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except (ValueError, OSError, OverflowError):
        return None


def _meta_from_entry(path: str, entry: pytsk3.File) -> FileRecord | None:
    if not entry.info or not entry.info.meta:
        return None

    meta = entry.info.meta
    name = entry.info.name

    is_deleted = False
    if name and name.flags is not None:
        is_deleted = bool(name.flags & pytsk3.TSK_FS_NAME_FLAG_UNALLOC)

    return FileRecord(
        path=path,
        size=int(meta.size) if meta.size is not None else None,
        inode=int(meta.addr) if meta.addr is not None else None,
        is_deleted=is_deleted,
        mtime=_ts_to_iso(meta.mtime),
        atime=_ts_to_iso(meta.atime),
        ctime=_ts_to_iso(meta.ctime),
        crtime=_ts_to_iso(meta.crtime),
    )


def _iter_file_systems(img: pytsk3.Img_Info) -> Iterator[pytsk3.FS_Info]:
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


def _scan_directory(directory: pytsk3.Directory, prefix: str, collector: list[FileRecord], depth: int = 0) -> None:
    if depth > 128:
        return

    for entry in directory:
        if not entry.info or not entry.info.name:
            continue

        raw_name = entry.info.name.name
        if raw_name in (b".", b".."):
            continue

        name = _safe_decode(raw_name)
        full_path = f"{prefix}/{name}" if prefix else f"/{name}"

        record = _meta_from_entry(full_path, entry)
        meta = entry.info.meta
        if not meta:
            continue

        if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
            try:
                sub_dir = entry.as_directory()
                _scan_directory(sub_dir, full_path, collector, depth=depth + 1)
            except OSError:
                continue
        else:
            if record:
                collector.append(record)


def extract_files(image_path: str) -> list[dict[str, Any]]:
    files: list[FileRecord] = []
    img = pytsk3.Img_Info(image_path)

    for fs in _iter_file_systems(img):
        try:
            root = fs.open_dir(path="/")
            _scan_directory(root, "", files)
        except OSError:
            continue

    return [f.to_dict() for f in files]
