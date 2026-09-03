"""Hermes Security Workbench — file analysis modules.

Local file hashing and metadata extraction. All PASSIVE, stdlib-only, no
network activity. Matches the MODULES registry contract in plugin_api.py.
Target is a local file path (input_types ["file"]).
"""
from __future__ import annotations

import hashlib
import os
from typing import Any, Dict, List


def _sha256(path: str, chunk: int = 65536) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def _sha1(path: str) -> str:
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def _md5(path: str) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def _err(t: str, msg: str) -> Dict[str, Any]:
    return {
        "finding_type": f"{t}_error",
        "value": msg,
        "confidence": 0.1,
        "severity": "info",
        "source": "file",
        "evidence": {},
        "raw": {},
    }


async def _run_file_hash(target: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
    path = os.path.expanduser(target)
    if not os.path.isfile(path):
        return [_err("file", f"not a file: {target}")]
    try:
        size = os.path.getsize(path)
        sha256 = _sha256(path)
        sha1 = _sha1(path)
        md5 = _md5(path)
    except (OSError, Exception) as exc:  # noqa: BLE001
        return [_err("file", f"hash failed: {exc}")]
    return [
        {
            "finding_type": "hash_sha256",
            "value": sha256,
            "confidence": 1.0,
            "severity": "info",
            "source": "hashlib",
            "evidence": {"path": path, "size": size},
            "raw": {},
        },
        {
            "finding_type": "hash_sha1",
            "value": sha1,
            "confidence": 1.0,
            "severity": "info",
            "source": "hashlib",
            "evidence": {"path": path},
            "raw": {},
        },
        {
            "finding_type": "hash_md5",
            "value": md5,
            "confidence": 1.0,
            "severity": "info",
            "source": "hashlib",
            "evidence": {"path": path},
            "raw": {},
        },
    ]


async def _run_file_metadata(target: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
    path = os.path.expanduser(target)
    if not os.path.isfile(path):
        return [_err("file", f"not a file: {target}")]
    try:
        st = os.stat(path)
        size = st.st_size
        mtime = st.st_mtime
    except (OSError, Exception) as exc:  # noqa: BLE001
        return [_err("file", f"stat failed: {exc}")]

    from datetime import datetime, timezone
    mtime_iso = datetime.fromtimestamp(mtime, timezone.utc).isoformat(timespec="seconds")
    return [
        {
            "finding_type": "file_size",
            "value": str(size),
            "confidence": 1.0,
            "severity": "info",
            "source": "os.stat",
            "evidence": {"path": path, "bytes": size},
            "raw": {},
        },
        {
            "finding_type": "file_mtime",
            "value": mtime_iso,
            "confidence": 1.0,
            "severity": "info",
            "source": "os.stat",
            "evidence": {"path": path, "mtime_iso": mtime_iso},
            "raw": {},
        },
    ]


MODULES: List[Dict[str, Any]] = [
    {
        "name": "file_hash",
        "category": "files",
        "description": "Compute SHA-256, SHA-1, and MD5 hashes of a local file.",
        "risk_level": "PASSIVE",
        "network_activity": False,
        "input_types": ["file"],
        "output_types": ["finding"],
        "runner": _run_file_hash,
    },
    {
        "name": "file_metadata",
        "category": "files",
        "description": "Local file metadata: size and modified time.",
        "risk_level": "PASSIVE",
        "network_activity": False,
        "input_types": ["file"],
        "output_types": ["finding"],
        "runner": _run_file_metadata,
    },
]
