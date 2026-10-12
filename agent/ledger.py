"""BƯỚC 3d — audit ledger append-only, tamper-evident (10')."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _calc_hash(record_without_hash: dict) -> str:
    canonical = json.dumps(record_without_hash, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def append(entry: dict, path: Path) -> dict:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    prev_hash = "0" * 64
    if path.exists() and path.stat().st_size > 0:
        lines = path.read_text(encoding="utf-8").splitlines()
        # Bỏ dòng trống cuối (nếu có).
        lines = [ln for ln in lines if ln.strip()]
        if lines:
            try:
                last = json.loads(lines[-1])
                prev_hash = last.get("hash", "0" * 64)
            except Exception:
                prev_hash = "0" * 64
    record = dict(entry)
    record.pop("hash", None)
    record["prev_hash"] = prev_hash
    record["hash"] = _calc_hash(record)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record


def verify(path: Path) -> bool:
    path = Path(path)
    if not path.exists():
        return True
    text = path.read_text(encoding="utf-8")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return True
    prev = "0" * 64
    for ln in lines:
        try:
            rec = json.loads(ln)
        except Exception:
            return False
        # Mọi dòng phải có reason non-empty.
        if not rec.get("reason"):
            return False
        stored_hash = rec.get("hash")
        stored_prev = rec.get("prev_hash")
        if not stored_hash or stored_prev != prev:
            return False
        rec_no_hash = dict(rec)
        rec_no_hash.pop("hash", None)
        if _calc_hash(rec_no_hash) != stored_hash:
            return False
        prev = stored_hash
    return True
