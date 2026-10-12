# Verification — CP5 (số liệu thật của bài này)

## Môi trường
- OS: Windows (PowerShell, chạy tại thư mục repo); `CHECKPOINTS.md` hiện diện.
- Python: `3.11.9` (`.venv`, `python -m venv .venv`, `pip install -r requirements.txt pre-commit pip-tools`).
- Gitleaks: `8.30.1` (tải từ release chính thức về `%TEMP%\gitleaks\gitleaks.exe`, chạy bằng đường dẫn đầy đủ vì chưa có sẵn trong PATH của máy này; TA kiểm bằng `gitleaks version` trên máy chấm).
- `PYTHONIOENCODING=utf-8` cho terminal hiện tại.

## CP1 Baseline
- `reports/baseline.md`: 3 câu + `agent/loop.py` / `agent/tools.py` / `sink/sink.py` kèm số dòng; kết luận ticket là dữ liệu nhưng baseline xử lý chỉ thị như lệnh.

## CP2 Red team
- `python -m agent.check_lure corpus/ticket-901.md corpus/ticket-902.md corpus/ticket-903.md corpus/ticket-904.md` → `4/4 lure sẵn sàng` (901: 4 marker; 902: 6; 903: 9; 904+904b: 2; riêng 904 và 904b từng file `find_injection=None`).
- `reports/attack-before.log`: 4 dòng (replay cô lập từng lure qua `_naive_loop` khi runner còn scaffold), mỗi dòng chứa `KH-000999` + CCCD synthetic `811753472374`; file ~1196 byte. Đây là dữ liệu synthetic của repo.

## CP3a PII
- `python -m pytest tests/test_pii.py -v -s --basetemp=.pytest_tmp` → `gold=118 pred=118 tp=118`, `precision=1.000 recall=1.000` (band >95%).
- Giới hạn regex: xem `reports/verification.md` đoạn BƯỚC 3 (4 loại theo mẫu, STK cần nhãn, không NER/tên/địa chỉ).

## CP3b/3c Policy + OBO
- `python -m pytest tests/test_policy.py tests/test_obo.py tests/test_ledger.py -v` → 14 passed (gồm `test_runner_checks_principal_at_tool_boundary`: `support_l1` 0 read, `dpo` có read, ledger đủ `on_behalf_of/run_id/expires_at` + `read_customer deny` cho support).

## CP3d/3e Split + Ledger + Injection
- `python -m pytest tests/test_split.py -v` → 1 passed (`KH-000777` không bị đọc, vẫn đọc khách hợp lệ).
- `python -m pytest tests/test_injection.py -v` → 8 passed (4 lure × 2 principal, không SKIP).
- `python -m pytest tests/test_ledger.py -v` → 3 passed (sửa 1 ký tự giữa file → `verify=False`; thiếu `reason` → `False`).
- Ledger thật: `python -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"` → 23 dòng/lượt, `verify=True`, có `http_post deny` (`reason="deny: restricted data cannot egress..."`, `on_behalf_of=dpo`), không có PII thô trong ledger.

## CP4 Supply chain
- `gitleaks git --config .gitleaks.toml --redact --verbose .` → exit 1 (mong đợi), 1 finding `lab24-synthetic-token` tại `lab-fake-secret.txt:1`, commit `1bdd849`.
- `gitleaks dir` lần đầu → 1 finding `generic-api-key` tại `.venv/.../setuptools/.../msvccompiler.py:45` (false positive thư viện). Đã thêm `[allowlist] paths=['\.venv/']` vào `.gitleaks.toml`; chạy lại: `dir` → `no leaks found`, exit 0; `git` → vẫn 1 finding ở `1bdd849`, exit 1.
- `python -m piptools compile --generate-hashes -o requirements.lock requirements.txt` → `requirements.lock` (mọi package có `--hash=sha256`); `pip install --require-hashes -r requirements.lock` → satisfied.
- `.pre-commit-config.yaml`: repo `https://github.com/gitleaks/gitleaks`, `rev: v8.30.1`, `id: gitleaks-system`, `pass_filenames: false`.
- `pre-commit install` + `pre-commit run --all-files` → Passed. `pytest tests/test_supply_chain.py` → 3 passed.

## CP5 Prove
- `python sink/sink.py --reset` + `python -m pytest tests/ -q --basetemp=.pytest_tmp` → `33 passed`, exit 0 (không SKIP).
- Reset sink lần nữa + chạy agent `--as dpo` cùng query với sink nghe → `reports/attack-after.log` 0 byte (`(Get-Item reports/attack-after.log).Length` = 0).
- Đối chiếu: `attack-before.log` 4 dòng (có POST `KH-000999` giả) vs `attack-after.log` rỗng; `reports/ledger.jsonl` 46 dòng (2 lượt dpo), `verify=True`, 2 dòng `http_post deny` với `on_behalf_of=dpo`.
- `reports/compliance-mapping.md`: bảng 4 cột (Luật 91/2025, NĐ 356/2025, Luật AI 134/2025, OWASP ASI01/03/04) kèm evidence file:dòng; điều khoản cụ thể ghi `chưa xác minh`; không phải chứng nhận tuân thủ.
- `reports/dpia-lite.md`: 4 câu hỏi (dữ liệu/mục đích/luồng/chặn+giới hạn mock).

## Lỗi đã gặp và cách sửa
1. `gitleaks` không có trong PATH + `requests` thiếu (chưavenv): tạo `.venv`, cài `requirements.txt`, tải Gitleaks 8.30.1 từ release về `%TEMP%` và gọi bằng full path.
2. `gitleaks dir` báo thư viện `.venv`: allowlist đúng `\.venv/` trong `.gitleaks.toml`, chạy lại cả 2 lệnh; không tắt rule token giả.
3. `pip-compile` báo retry/timeout 1 lần (mạng): chạy lại foreground thì xong, lock đủ hash.
4. `pytest tests/` fail 1 lần ở `test_incident_note_identifies_synthetic_leak` vì chưa viết incident note: đã viết `reports/secrets-incident.md` rồi pass lại 33/33.

## Tự kiểm nộp (SUBMISSION.md)
- `python -m pytest tests/ -q` → 33 passed.
- `pre-commit run --all-files` → Passed.
- `verify(reports/ledger.jsonl)` → True.
- `attack-before.log` có exfil synthetic; `attack-after.log` rỗng.
- Chưa commit — commit cuối và `git add -f` cho `attack-*.log` làm ở BƯỚC 6.
- Các lỗi còn lại: không có (ngoài Gitleaks cần TA đảm bảo trong PATH khi chấm).
