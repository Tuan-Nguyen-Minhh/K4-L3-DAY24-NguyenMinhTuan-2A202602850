"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15')."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PRINCIPALS_FILE = Path(__file__).resolve().parent.parent / "data" / "principals.json"

_VALID_CLASSIFICATIONS = ("public", "internal", "restricted")


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals() -> dict:
    try:
        return json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _parse_expiry(raw: str) -> datetime | None:
    if not raw or not isinstance(raw, str):
        return None
    s = raw.strip()
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def check(context: PolicyContext) -> tuple[bool, str]:
    # 1. Classification phải thuộc tập cho phép.
    if context.data_classification not in _VALID_CLASSIFICATIONS:
        return False, f"deny: unknown data_classification {context.data_classification!r}"

    # 2. Rule tối thiểu: restricted + egress luôn deny, kể cả DPO.
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "deny: restricted data cannot egress (restricted+egress)"

    # 3. Principal phải tồn tại trong fixture mô phỏng.
    principals = _load_principals()
    principal = principals.get(context.principal_id) if context.principal_id else None
    if principal is None:
        return False, f"deny: unknown principal {context.principal_id!r}"

    # 4. TTL: expires_at phải là thời điểm UTC trong tương lai.
    exp = _parse_expiry(context.expires_at)
    if exp is None:
        return False, f"deny: missing or invalid expires_at {context.expires_at!r}"
    now = datetime.now(timezone.utc)
    if exp <= now:
        return False, f"deny: credential expired at {context.expires_at!r}"

    # 5. Purpose phải thuộc danh sách được phép của principal.
    allowed_purposes = principal.get("purposes", [])
    if not context.request_purpose or context.request_purpose not in allowed_purposes:
        return (
            False,
            f"deny: purpose {context.request_purpose!r} not allowed for {context.principal_id!r}",
        )

    # 6. Tool phải nằm trong giao các scope.
    if not context.requested_tool:
        return False, "deny: missing requested_tool"
    allowed_tools = set(principal.get("allowed_tools", []))
    effective = allowed_tools.intersection(set(context.agent_scopes or ()))
    if context.delegation_depth and context.delegation_depth > 0:
        effective = effective.intersection(set(context.parent_scopes or ()))
    if context.requested_tool not in effective:
        return (
            False,
            f"deny: tool {context.requested_tool!r} not in effective scopes for "
            f"{context.principal_id!r} (depth={context.delegation_depth})",
        )

    return True, (
        f"allow: {context.principal_id!r} may call {context.requested_tool!r} "
        f"for {context.request_purpose!r} on {context.data_classification}"
    )
