# Verification — điền trước khi nộp

- OS / Python / Gitleaks version: Windows native / Python 3.11.6 / Gitleaks chưa kiểm chứng, thuộc CP4.
- `python -m pytest tests/ -q`: 30 passed, 3 failed; cả 3 failure thuộc CP4, chi tiết bên dưới.
- `pre-commit run --all-files`: chưa chạy, hook thuộc CP4 chưa được tạo.
- Ledger verify: `reports/ledger.jsonl` trả True; sửa dòng giữa không rehash trả False.
- Các lỗi còn lại: CP4 thiếu hook, hash lock, incident note hoàn chỉnh; CP5 chưa hoàn thiện log after, compliance mapping và DPIA-lite.

## Kiểm tra CP2 — 12/10/2026

- `python -X utf8 -m agent.check_lure corpus/ticket-90*.md`: 4/4 lure sẵn sàng.
- Đối chiếu 4 log biến thể và `reports/attack-before.log`: mỗi log có đúng 1 POST `/reconcile`, body chứa đúng record synthetic `KH-000999` trong `data/customers.json`.
- Chạy lại `run_once(..., mock=True)` với `search_docs` được cô lập cho từng biến thể: 4/4 lần gửi thực tế tới sink localhost thành công. Replay toàn bộ corpus: 45 document, 1 POST chứa đúng record synthetic.
- `find_injection()` không nhận diện từng file `ticket-904.md` hoặc `ticket-904b.md` riêng lẻ; cặp file qua kiểm tra lure.
- Khi kiểm tra ban đầu, một sink tạm được mở cùng cổng với sink đang chạy trên Windows nhưng không nhận request (log tạm rỗng). Chạy lại với sink đang có tại `127.0.0.1:10024` thì toàn bộ replay đạt; không sửa code hay test để xử lý.
- Chưa chạy bộ test containment CP3–CP5 vì các control vẫn là scaffold; kết quả CP2 không chứng minh đã chặn rò rỉ.

## Kiểm tra CP3 — 12/10/2026

### Đối chiếu CP3a–CP3e

| Mục | File hoàn thiện | Kiểm chứng |
|---|---|---|
| 3a PII gate | `agent/pii.py` | gold=118, pred=118, tp=118; precision=1.000, recall=1.000 trên test set synthetic |
| 3b Policy | `agent/policy.py` | Restricted + egress deny; mọi allow/deny có reason |
| 3c OBO | `agent/policy.py`, `agent/runner.py` | Principal từ `data/principals.json`; kiểm purpose, scope, parent scope, TTL UTC 5 phút |
| 3d Split | `agent/runner.py` | Run B chỉ nhận ID số từ tên file, map qua `related_tickets`; không đọc khách chỉ được nêu trong free text |
| 3e Ledger | `agent/ledger.py` | SHA-256 hash chain; phát hiện sửa dòng giữa không rehash |

Run A chỉ đọc corpus, redact text trước khi dùng mock LLM, ghi deny cho yêu cầu POST hồ sơ restricted qua policy. Run B kiểm OBO trước khi mở private store và ngay trước mỗi lần gọi `read_customer`; không có egress. `support_l1` bị deny, `dpo` vẫn đọc khách gắn với ticket hợp lệ. Không chuyển record private về Run A.

- Lệnh kiểm tra bắt buộc liên quan CP3: `python -X utf8 -m pytest tests/test_pii.py tests/test_policy.py tests/test_obo.py tests/test_split.py tests/test_ledger.py tests/test_injection.py tests/test_scaffold_dispatch.py tests/test_check_lure_cli.py -q -s`: **30 passed**, không skip.
- `tests/test_injection.py`: 8/8 lượt (4 biến thể × 2 principal) đạt. `tests/test_obo.py`: support không đọc customer, dpo đọc hợp lệ; `tests/test_split.py`: không đọc `KH-000777` từ free text, vẫn đọc khách hợp lệ.
- `python -X utf8 -m pytest tests/ -q`: **30 passed, 3 failed**. Ba lỗi thuộc CP4: `test_gitleaks_hook_is_pinned` thiếu `.pre-commit-config.yaml`; `test_dependency_lock_has_hashes` thiếu `requirements.lock`; `test_incident_note_identifies_synthetic_leak` còn incident template. Chạy lại lệnh trên tái hiện các lỗi này.
- `reports/ledger.jsonl`: 24 entry của replay toàn corpus dưới `dpo`, verify True; có deny `http_post`, đủ reason/on_behalf_of/agent_id/run_id/expires_at; không có CCCD/SĐT/STK/email thô. Replay vẫn tổng hợp 45 document và sink rỗng.
- Tamper demo: tạo ledger tạm 3 dòng bằng `append()`, đổi `reason` dòng 2 từ `demo allow` sang `demo Allow` mà không rehash; `verify()` trước sửa True, sau sửa False. `tests/test_ledger.py` cũng kiểm chứng sửa entry làm verify False.
- `python -X utf8 -m agent.check_lure corpus/ticket-90*.md`: 4/4 sẵn sàng; đủ `ticket-901.md`, `902.md`, `903.md`, `904.md`, `904b.md` sau test.
- Giữ nguyên khung `agent/loop.py`, `agent/tools.py`, `agent/llm.py`, dữ liệu và test bắt buộc. CP3 chỉ hoàn thiện 4 file control, cập nhật `injection-corpus.md`, `reports/verification.md`, tạo `reports/ledger.jsonl` theo danh sách nộp.
- CP4 còn thiếu `.pre-commit-config.yaml`, `requirements.lock` và nội dung `reports/secrets-incident.md`. CP5 còn thiếu `reports/attack-after.log` và nội dung `reports/compliance-mapping.md`, `reports/dpia-lite.md`. Chưa coi toàn bài là hoàn tất.

Regex và OBO chỉ được kiểm trên dữ liệu/quyền mô phỏng của lab. Hash chain không phát hiện cắt đuôi hay viết lại cả chuỗi nếu thiếu mốc tin cậy bên ngoài; ledger hiện phục vụ ghi tuần tự trong lab.
