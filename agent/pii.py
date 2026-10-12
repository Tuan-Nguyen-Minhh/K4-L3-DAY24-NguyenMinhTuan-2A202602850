"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Regex recognizer cho tiếng Việt tổng hợp. Không dùng Presidio/spaCy.
"""
from __future__ import annotations

import re

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

# CCCD: đúng 12 chữ số, ranh giới không phải chữ số hai đầu.
CCCD_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")

# SĐT: số 0 + 9-10 chữ số, cho phép cách/gạch/chấm giữa các số để bắt
# dạng "0912 345 678" mà vẫn bắt đúng dạng plain "0912345678".
PHONE_RE = re.compile(r"(?<!\d)0(?:[\s.\-]*\d){9,10}(?!\d)")

# STK: bắt buộc có nhãn để phân biệt với SĐT/CCCD cùng độ dài.
# Nhãn: STK / số tài khoản / tai khoan (có/không dấu).
BANK_LABEL_RE = re.compile(
    r"(?:STK|số\s*tài\s*khoản|Số\s*tài\s*khoản|SỐ\s*TÀI\s*KHOẢN"
    r"|tai\s*khoan|Tai\s*Khoan|so\s*tai\s*khoan)"
    r"\s*[:#\-]?\s*(?P<num>\d(?:[\s\-]*\d){7,15})"
)

# Fallback cho STK trần dài 13-16 số (dài hơn CCCD/SĐT nên ít nhầm).
# Chỉ dùng khi không có nhãn; testset hiện tại mọi STK đều có nhãn.
BARE_LONG_RE = re.compile(r"(?<!\d)\d{13,16}(?!\d)")


def _spans(pattern: re.Pattern, text: str, typ: str) -> list[dict]:
    out: list[dict] = []
    for m in pattern.finditer(text):
        s, e = m.span()
        # BANK_LABEL_RE có group num: chỉ lấy vùng số, bỏ nhãn.
        if typ == "VN_BANK_ACCOUNT" and "num" in m.groupdict():
            s, e = m.span("num")
        # Chuẩn hoá: vùng số có thể lẫn space/gạch — cắt đúng span đã khớp.
        # Kiểm tra số chữ số thực tế để loại nhiễu (vd phone lẫn quá nhiều space).
        digits = re.sub(r"\D", "", text[s:e])
        if typ == "VN_CCCD" and len(digits) != 12:
            continue
        if typ == "VN_PHONE" and len(digits) not in (10, 11):
            continue
        if typ == "VN_BANK_ACCOUNT" and not (8 <= len(digits) <= 16):
            continue
        out.append({"type": typ, "start": s, "end": e})
    return out


def detect(text: str) -> list[dict]:
    """Tìm 4 loại PII, xử lý trùng để không báo hai lần."""
    cands: list[dict] = []
    cands.extend(_spans(EMAIL_RE, text, "EMAIL"))
    cands.extend(_spans(BANK_LABEL_RE, text, "VN_BANK_ACCOUNT"))
    cands.extend(_spans(CCCD_RE, text, "VN_CCCD"))
    cands.extend(_spans(PHONE_RE, text, "VN_PHONE"))

    # BARE_LONG chỉ khi chưa có gì đè lên vùng đó (tránh đè CCCD/phone).
    bare = _spans(BARE_LONG_RE, text, "VN_BANK_ACCOUNT")
    cands.extend(bare)

    # Ưu tiên khi trùng: EMAIL > BANK > CCCD > PHONE; span dài hơn trước.
    prio = {"EMAIL": 0, "VN_BANK_ACCOUNT": 1, "VN_CCCD": 2, "VN_PHONE": 3}
    cands.sort(key=lambda d: (d["start"], -(d["end"] - d["start"]), prio[d["type"]]))

    kept: list[dict] = []
    for c in cands:
        overlap = False
        for k in kept:
            if c["start"] < k["end"] and k["start"] < c["end"]:
                overlap = True
                break
        if not overlap:
            kept.append(c)
    kept.sort(key=lambda d: (d["start"], d["end"]))
    return kept


def redact(text: str) -> str:
    """Thay mọi entity bằng [REDACTED_<TYPE>], từ cuối về đầu."""
    ents = detect(text)
    for e in sorted(ents, key=lambda d: d["start"], reverse=True):
        text = text[: e["start"]] + f"[REDACTED_{e['type']}]" + text[e["end"] :]
    return text
