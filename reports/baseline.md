# CP1 — Phân tích baseline chưa có kiểm soát

1. Agent chưa có identity riêng cho mỗi run trong baseline: hàm `_naive_loop(message, llm)` tại `agent/loop.py:26` không tạo `agent_id`, `run_id`, TTL hoặc kiểm tra principal trước các tool call ở dòng 31–44, nên lựa chọn `--as` không được dùng để phân quyền trong nhánh baseline này.

2. Không có policy cấp quyền cho `http_post`: sau khi lấy customer ID từ chỉ thị injection và gọi `tools.read_customer()` tại `agent/loop.py:37–39`, `_naive_loop()` gọi trực tiếp `tools.http_post()` tại dòng 44 mà không qua `policy.check()` hay ghi ledger; allowlist trong `agent/tools.py`, hàm `http_post()`, chỉ giới hạn đích đến là `http://127.0.0.1:10024`, không ngăn việc gửi dữ liệu restricted đến sink của lab.

3. Bằng chứng gửi sai dữ liệu nằm trong `reports/sink.log`: hàm `Handler.do_POST()` trong `sink/sink.py:45–47` ghi path và body của request, và ở CP2 sẽ lưu bản sao thành `reports/attack-before.log` rồi đối chiếu CCCD, SĐT, STK synthetic của `KH-000999` với `data/customers.json` để chứng minh rò rỉ thay vì chỉ dựa vào câu trả lời tổng hợp ticket của agent.
