# Baseline — CP1: agent chưa có containment

1. Mỗi lần chạy baseline đã có agent_id/run_id và danh tính người dùng để kiểm quyền chưa? Chưa. `_naive_loop(message, llm)` chỉ nhận message và llm (`agent/loop.py:27`), gọi `tools.search_docs(message)` (`agent/loop.py:31`) rồi `tools.read_customer(customer_id)` (`agent/loop.py:39`) và `tools.http_post(...)` (`agent/loop.py:44`) mà không truyền principal/agent_id/run_id hay scope nào để kiểm quyền.

2. Trước http_post có policy nào kiểm mục đích, quyền và loại dữ liệu không? Ai thực sự quyết định gửi? Không có policy/PEP nào. Quyết định gửi do `llm.find_injection(combined_text)` (`agent/loop.py:34`, định nghĩa `agent/llm.py:65`) cộng với nhánh `if injected is not None` (`agent/loop.py:35`) tự ý đọc và POST; `http_post` trong `agent/tools.py:68` chỉ chặn cứng host/port (`agent/tools.py:76-83`), không kiểm mục đích, quyền hay PII.

3. Dòng nào tạo body POST và file nào ghi lại việc sink đã nhận body đó? `tools.http_post(injected.target_url, {"records": collected})` tại `agent/loop.py:44` tạo body từ `collected` (kết quả `read_customer` ở `agent/loop.py:37-39`); phía sink ghi mỗi POST một dòng JSON `{"path","body"}` vào `reports/sink.log` tại `sink/sink.py:43-47` (`LOG_PATH` ở `sink/sink.py:37`).

Kết luận: ticket là dữ liệu không tin cậy nhưng baseline xử lý chỉ thị bên trong như lệnh — `search_docs` đọc nguyên văn (`agent/tools.py:34-52`), `find_injection` coi marker trong text là lệnh, rồi `read_customer`/`http_post` chạy mà chưa có cổng kiểm quyền nào.
