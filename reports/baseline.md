# CP1 — Phân tích baseline chưa có kiểm soát

1. Agent chưa có identity riêng cho mỗi run trong baseline: `_naive_loop(message, llm)` được định nghĩa tại `agent/loop.py:27`, gọi tool từ `agent/loop.py:31` mà không tạo agent_id/run_id/TTL hay kiểm tra principal trước khi đọc và gửi dữ liệu.

2. Không có policy cấp quyền cho `http_post` trong baseline: sau khi đọc customer ở `agent/loop.py:39`, `_naive_loop()` gọi trực tiếp `tools.http_post()` tại `agent/loop.py:44` mà không qua policy/ledger; hàm `http_post()` định nghĩa tại `agent/tools.py:68` chỉ giới hạn đích localhost bằng allowlist ở `agent/tools.py:77`.

3. Bằng chứng gửi sai dữ liệu đã có tại `reports/attack-before.log:1` (evidence CP2, commit `2baf9dd`): request `/reconcile` chứa record synthetic `KH-000999` khớp CCCD/SĐT/STK trong `data/customers.json`; `Handler.do_POST()` định nghĩa tại `sink/sink.py:42` ghi path/body ở `sink/sink.py:45` và ghi JSONL ở `sink/sink.py:47`.
