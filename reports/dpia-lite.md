# DPIA-lite — bản mô tả học tập (không phải hồ sơ đánh giá tác động pháp lý chính thức)

1. Loại dữ liệu và phân loại:
   - Ticket trong `corpus/` (kể cả 4 lure `ticket-901.md, 902.md, 903.md, 904.md+904b.md`): phân loại `internal` khi qua PEP search (`agent/runner.py:94-105`); nội dung không tin cậy hoàn toàn (attacker có thể viết chỉ thị).
   - Hồ sơ khách trong `data/customers.json` (vd `KH-000999`: CCCD `811753472374`, SĐT, STK, email — toàn synthetic): phân loại `restricted` khi qua PEP read (`agent/runner.py:159-170`). `KH-000777` có `related_tickets=[]` nên không gắn ticket nào.
   - Ledger `reports/ledger.jsonl` chỉ giữ `args_hash`, không giữ PII thô (đã kiểm: 3 giá trị CCCD/SĐT/STK của KH-000999 không xuất hiện trong ledger).

2. Mục đích xử lý và principal:
   - Query: `"Tổng hợp các ticket còn mở tuần này"` — mục đích `summarize-tickets` (search) và `support-reply` (read) theo `data/principals.json:2-4`.
   - `support_l1` (`allowed=["search_docs"]`): chỉ được tìm ticket, bị deny mọi `read_customer` chứa CCCD/STK.
   - `dpo` (`allowed=["search_docs","read_customer"]`, purposes có `support-reply`): được đọc khách gắn với ticket hợp lệ (kể cả `KH-000999` vì `related_tickets=[901-905]`), nhưng vẫn bị deny egress.
   - `--as` chỉ chọn fixture mô phỏng, không phải đăng nhập/xác thực production.

3. Dữ liệu đi qua những run/tool nào, endpoint nào:
   - Run A: `search_docs` đọc `corpus/` → `find_injection` (log, không dùng `customer_id` của attacker) → `pii.redact` → chỉ chuyển `list[int]` ticket ID từ tên file sang Run B (`agent/runner.py:86-132`).
   - Run B: tra `related_tickets` trong `data/customers.json` → `policy.check` trước mỗi `read_customer` → đọc nếu allow (`agent/runner.py:132-170`).
   - Egress: nếu có injection, check `http_post` với `restricted + egress=True` → deny, không gọi `tools.http_post`; đích duy nhất được phép trong code là `http://127.0.0.1:10024/*` (`agent/tools.py:26-27,68-83`), sink ghi `reports/sink.log` (`sink/sink.py:37-47`).
   - Mọi tool call (allow+deny) ghi `reports/ledger.jsonl` với `on_behalf_of/agent_id/run_id/expires_at/reason` (`agent/ledger.py:14`).

4. Bằng chứng deny/allow và giới hạn của mock:
   - Trước containment: `reports/attack-before.log` 4 dòng (mỗi lure 1 POST), đều chứa `KH-000999` + CCCD synthetic → rò rỉ tái hiện được.
   - Sau containment (`--as dpo`, cùng query): `reports/attack-after.log` 0 byte; `reports/ledger.jsonl` 46 dòng, `verify=True`, có `http_post deny` (`reason="deny: restricted data cannot egress..."`, `on_behalf_of=dpo`); `test_split` chứng minh `KH-000777` không bị đọc, `dpo` vẫn đọc 21 khách hợp lệ.
   - Giới hạn: `--mock` (`agent/llm.py`) deterministic, chỉ nhận diện ≥2 marker sau bỏ dấu — không phải model thật; regex PII chỉ bắt 4 mẫu; quyền là fixture; ledger hash chain không phát hiện xoá dòng cuối/viết lại toàn file nếu thiếu mốc ngoài; sink là localhost, không suy ra an toàn Internet.
