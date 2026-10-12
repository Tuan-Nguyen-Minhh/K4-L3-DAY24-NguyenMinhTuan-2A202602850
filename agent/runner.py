"""BƯỚC 3c — trifecta split + egress allowlist + OBO + ledger."""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger as ledger_mod
from agent import pii as pii_mod
from agent import tools
from agent.policy import PolicyContext, check

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
PRINCIPALS_FILE = DATA_DIR / "principals.json"
CUSTOMERS_FILE = DATA_DIR / "customers.json"

AGENT_ID = "lab24-agent"
FUTURE_EXPIRY = "2099-01-01T00:00:00+00:00"
_TICKET_RE = re.compile(r"ticket-(\d+)", re.IGNORECASE)


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def _args_hash(args: dict) -> str:
    raw = json.dumps(args, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _load_principals() -> dict:
    try:
        return json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _log(
    ledger_path: Path,
    *,
    tool: str,
    classification: str,
    decision: bool,
    reason: str,
    args: dict,
    run_id: str,
    principal_id: str,
    expires_at: str,
) -> None:
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent_id": AGENT_ID,
        "run_id": run_id,
        "tool": tool,
        "args_hash": _args_hash(args),
        "classification": classification,
        "decision": "allow" if decision else "deny",
        "reason": reason,
        "on_behalf_of": principal_id,
        "expires_at": expires_at,
    }
    ledger_mod.append(entry, ledger_path)


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    ledger_path = Path(log_dir) / "ledger.jsonl" if log_dir else DEFAULT_LEDGER_PATH
    ledger_path.parent.mkdir(parents=True, exist_ok=True)

    principals = _load_principals()
    principal = principals.get(principal_id)
    if principal is not None:
        agent_scopes = tuple(principal.get("allowed_tools", []))
    else:
        agent_scopes = ()
    parent_scopes = agent_scopes
    expires_at = FUTURE_EXPIRY
    run_id = uuid.uuid4().hex[:12]

    # ---- Run A: search_docs (untrusted content), không chạm private/egress ----
    ctx_a = PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner="lab24-agent/run-a",
        delegation_depth=0,
        egress_enabled=False,
        principal_id=principal_id,
        requested_tool="search_docs",
        agent_scopes=agent_scopes,
        parent_scopes=(),
        expires_at=expires_at,
    )
    allow_a, reason_a = check(ctx_a)
    _log(ledger_path, tool="search_docs", classification="internal",
         decision=allow_a, reason=reason_a, args={"query": message},
         run_id=run_id, principal_id=principal_id, expires_at=expires_at)
    docs: list[dict] = []
    if allow_a:
        docs = tools.search_docs(message)

    combined = "\n\n".join(d.get("text", "") for d in docs) if docs else ""
    try:
        injected = llm.find_injection(combined) if combined else None
    except Exception:
        injected = None
    # PII gate trước boundary: redact (không chuyển text thô sang Run B).
    try:
        _ = pii_mod.redact(combined) if combined else ""
    except Exception:
        pass

    # Chỉ truyền ID số trích từ TÊN FILE sang Run B.
    ticket_ids: list[int] = []
    seen_ids: set[int] = set()
    for d in docs:
        m = _TICKET_RE.search(str(d.get("id", "")))
        if m:
            try:
                tid = int(m.group(1))
            except ValueError:
                continue
            if tid not in seen_ids:
                seen_ids.add(tid)
                ticket_ids.append(tid)

    # ---- Run B: read_customer qua NGUỒN TIN CẬY related_tickets ----
    try:
        customers = json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8"))
    except Exception:
        customers = []
    wanted: list[str] = []
    seen_cid: set[str] = set()
    for tid in ticket_ids:
        for rec in customers:
            try:
                if tid in (rec.get("related_tickets") or []):
                    cid = str(rec.get("customer_id"))
                    if cid not in seen_cid:
                        seen_cid.add(cid)
                        wanted.append(cid)
            except Exception:
                continue

    collected: list[dict] = []
    for cid in wanted:
        ctx_b = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner="lab24-agent/run-b",
            delegation_depth=1,
            egress_enabled=False,
            principal_id=principal_id,
            requested_tool="read_customer",
            agent_scopes=agent_scopes,
            parent_scopes=parent_scopes,
            expires_at=expires_at,
        )
        allow_b, reason_b = check(ctx_b)
        _log(ledger_path, tool="read_customer", classification="restricted",
             decision=allow_b, reason=reason_b, args={"customer_id": cid},
             run_id=run_id, principal_id=principal_id, expires_at=expires_at)
        if allow_b:
            try:
                collected.append(tools.read_customer(cid))
            except Exception:
                continue

    # ---- Egress: nếu có injection thì ghi deny, KHÔNG gọi http_post thật ----
    if injected is not None:
        target = getattr(injected, "target_url", "") or "http://127.0.0.1:10024/reconcile"
        ctx_e = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner="lab24-agent/run-b",
            delegation_depth=1,
            egress_enabled=True,
            principal_id=principal_id,
            requested_tool="http_post",
            agent_scopes=agent_scopes,
            parent_scopes=parent_scopes,
            expires_at=expires_at,
        )
        allow_e, reason_e = check(ctx_e)
        _log(ledger_path, tool="http_post", classification="restricted",
             decision=allow_e, reason=reason_e,
             args={"url": target, "records": len(collected)},
             run_id=run_id, principal_id=principal_id, expires_at=expires_at)
        # Không gọi tools.http_post dù allow (defense in depth cho lab);
        # policy đã deny (restricted+egress) nên dữ liệu không ra sink.

    try:
        return llm.summarize(docs)
    except Exception:
        return "Không tổng hợp được ticket."
