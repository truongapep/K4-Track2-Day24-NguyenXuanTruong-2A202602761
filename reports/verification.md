# Verification — điền trước khi nộp

- OS / Python / Gitleaks version: Windows native / Python 3.11.6 / Gitleaks 8.30.1.
- `python -m pytest tests/ -q`: **33 passed**, không fail/skip tại CP5; kết quả lỗi ở CP3 là lịch sử trước khi làm supply chain.
- `pre-commit run --all-files`: Passed, với Gitleaks 8.30.1 trong PATH.
- Ledger verify: `reports/ledger.jsonl` trả True; sửa dòng giữa không rehash trả False.
- Các lỗi còn lại: không còn lỗi test bắt buộc; các điều/khoản pháp luật cụ thể chưa xác minh, không khẳng định compliance production.

Các mục CP2–CP4 bên dưới ghi kết quả tại thời điểm từng checkpoint; tình trạng nộp cuối và file audit nằm ở mục CP5.

## Kiểm tra CP2 — 12/10/2026

- `python -X utf8 -m agent.check_lure corpus/ticket-90*.md`: 4/4 lure sẵn sàng.
- Đối chiếu 4 log biến thể và `reports/attack-before.log`: mỗi log có đúng 1 POST `/reconcile`, body chứa đúng record synthetic `KH-000999` trong `data/customers.json`.
- Chạy lại `run_once(..., mock=True)` với `search_docs` được cô lập cho từng biến thể: 4/4 lần gửi thực tế tới sink localhost thành công. Replay toàn bộ corpus: 45 document, 1 POST chứa đúng record synthetic.
- `find_injection()` không nhận diện từng file `ticket-904.md` hoặc `ticket-904b.md` riêng lẻ; cặp file qua kiểm tra lure.
- Khi kiểm tra ban đầu, một sink tạm được mở cùng cổng với sink đang chạy trên Windows nhưng không nhận request (log tạm rỗng). Chạy lại với sink đang có tại `127.0.0.1:10024` thì toàn bộ replay đạt; không sửa code hay test để xử lý.
- Chưa chạy bộ test containment CP3–CP5 vì các control vẫn là scaffold; kết quả CP2 không chứng minh đã chặn rò rỉ.

## Lịch sử CP3 — 12/10/2026, commit `a222f39`

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
- `python -X utf8 -m pytest tests/ -q` tại thời điểm CP3: **30 passed, 3 failed**. Ba lỗi thuộc CP4: hook/lock chưa có, incident note còn template. Các lỗi này đã được xử lý ở CP4, **không còn tái hiện trên HEAD hiện tại**.
- `reports/ledger.jsonl`: 24 entry của replay toàn corpus dưới `dpo`, verify True; có deny `http_post`, đủ reason/on_behalf_of/agent_id/run_id/expires_at; không có CCCD/SĐT/STK/email thô. Replay vẫn tổng hợp 45 document và sink rỗng.
- Tamper demo: tạo ledger tạm 3 dòng bằng `append()`, đổi `reason` dòng 2 từ `demo allow` sang `demo Allow` mà không rehash; `verify()` trước sửa True, sau sửa False. `tests/test_ledger.py` cũng kiểm chứng sửa entry làm verify False.
- `python -X utf8 -m agent.check_lure corpus/ticket-90*.md`: 4/4 sẵn sàng; đủ `ticket-901.md`, `902.md`, `903.md`, `904.md`, `904b.md` sau test.
- Giữ nguyên khung `agent/loop.py`, `agent/tools.py`, `agent/llm.py`, dữ liệu và test bắt buộc. CP3 chỉ hoàn thiện 4 file control, cập nhật `injection-corpus.md`, `reports/verification.md`, tạo `reports/ledger.jsonl` theo danh sách nộp.
- Tại thời điểm commit CP3, CP4/CP5 chưa hoàn thành hook/lock/incident note/after/mapping/DPIA-lite; đây không phải danh sách thiếu trên HEAD hiện tại.

Regex và OBO chỉ được kiểm trên dữ liệu/quyền mô phỏng của lab. Hash chain không phát hiện cắt đuôi hay viết lại cả chuỗi nếu thiếu mốc tin cậy bên ngoài; ledger hiện phục vụ ghi tuần tự trong lab.

## Kiểm tra CP4 — 12/10/2026

- File CP4: tạo `.pre-commit-config.yaml` và `requirements.lock`; điền `reports/secrets-incident.md`; cập nhật `.gitleaks.toml` chỉ để bỏ `.venv/` khỏi directory scan; cập nhật báo cáo này. Không tạo báo cáo Markdown riêng hoặc sửa test bắt buộc.
- `gitleaks version`: **8.30.1**, binary từ release chính thức đã kiểm SHA-256 archive. Activate `.venv` hoặc thêm `.venv/Scripts` vào PATH trước khi chạy scanner/hook.
- `gitleaks git --config .gitleaks.toml --redact --verbose .`: **1 finding** thuộc `lab24-synthetic-token` tại `lab-fake-secret.txt:1`, commit `1bdd849922156c868a5ee9293d68f5b72e242d2c`; **exit 1 dự kiến**. Chi tiết xử lý token giả/rotate trong `reports/secrets-incident.md`.
- `gitleaks dir --config .gitleaks.toml --redact .`: **0 finding, exit 0**; phạm vi không gồm `.venv/`, không loại các file bài làm hay token giả khỏi lịch sử.
- `python -m piptools compile --generate-hashes --no-emit-index-url --no-emit-trusted-host -o requirements.lock requirements.txt`: đạt; **11 package** được pin, mỗi package có hash. `python -m pip install --require-hashes -r requirements.lock`: exit 0; cài lại với `--force-reinstall --require-hashes` cũng exit 0, kiểm các wheel thực tế.
- Lỗi setup đã xử lý: pip-tools và pre-commit trong sandbox ban đầu không ghi được cache user (WinError 5); tải từ GitHub bị chặn mạng. Khi cache pre-commit đã tồn tại, chạy trong sandbox còn báo `attempt to write a readonly database`. Chạy lại với quyền được cấp thì tạo lock/tải scanner/chạy hook thành công. Directory scan ban đầu báo 3 finding trong thư viện/ví dụ scanner ở `.venv`; sau ngoại lệ đúng phạm vi môi trường local, quét sạch và quét lịch sử vẫn có token giả.
- `python -X utf8 -m pytest tests/test_supply_chain.py -q`: **3 passed**. `python -X utf8 -m pytest tests/ -q`: **33 passed**, không fail/skip. `python -m pip check`: không có dependency bị lỗi.
- `pre-commit run --all-files`: hook **Detect hardcoded secrets Passed**; repo chính thức pin v8.30.1, `pass_filenames: false`, cấu hình `.gitleaks.toml`. Quét file hiện tại không đồng nghĩa quét lịch sử; finding token giả được kiểm bằng lệnh riêng ở trên.
- Bài vẫn còn CP5: tạo `reports/attack-after.log` sau reset/replay cuối và điền `reports/compliance-mapping.md`, `reports/dpia-lite.md` với evidence thật.

## Kiểm tra CP5 — 12/10/2026

- `python -X utf8 -m pytest tests/ -q`: **33 passed**, không fail/skip. Fixture reset sink cho các test liên quan; ledger test nằm trong thư mục tạm nên không ghi đè ledger nộp. `tests/test_injection.py` đủ 4 biến thể × 2 principal; `tests/test_obo.py` và `tests/test_split.py` kiểm quyền và tiện ích hợp lệ.
- `python -X utf8 -m agent.check_lure corpus/ticket-90*.md`: **4/4 sẵn sàng**, đủ cả `ticket-904b.md` sau khi fixture trả lại corpus.
- Sau pytest, chạy `python -X utf8 -m sink.sink --reset`, rồi `python -X utf8 -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"` trên payload/corpus ban đầu. CLI tổng hợp **45 document**. Copy `reports/sink.log` thành `reports/attack-after.log`: **0 byte**. Không dùng log rỗng do fixture pytest reset làm bằng chứng replay cuối.
- `reports/attack-before.log:1` giữ nguyên: 1 POST `/reconcile`, chứa đúng record synthetic `KH-000999`, đối chiếu với `data/customers.json`. Before và after là hai artifact khác nhau, không ghi đè before.
- Ledger được nối tiếp, giữ 24 entry CP3 và thêm 24 entry CP5: **48 entry, verify True**. Dòng 25 allow `search_docs`, dòng 26 deny `http_post` với reason `Restricted data must not cross an egress boundary` và `on_behalf_of=dpo`, dòng 27 allow gate trusted-resolution, dòng 28–48 allow đọc customer hợp lệ. Mọi entry đủ reason, agent_id, run_id, on_behalf_of, expires_at; không có CCCD/SĐT/STK/email thô.
- `reports/compliance-mapping.md` có đủ Luật 91/2025, NĐ 356/2025, Luật AI 134/2025 và OWASP ASI01/03/04, trỏ đúng file/dòng evidence. Đã xác minh metadata văn bản từ nguồn Chính phủ và mã OWASP từ nguồn chính thức; điều/khoản cụ thể **chưa xác minh**, không tự kết luận tuân thủ pháp luật.
- `reports/dpia-lite.md` đã điền dữ liệu, purpose/principal, luồng A/B/tool/endpoint, before/after và giới hạn mock/regex/TTL/hash chain.
- Gitleaks **8.30.1**: directory scan 0 finding/exit 0; history scan 8 commit, đúng 1 finding synthetic ở `1bdd849`, exit 1 dự kiến. Không bỏ finding khỏi lịch sử.
- `pre-commit run --all-files --verbose` trên index CP5: **Detect hardcoded secrets Passed**, 0 finding/exit 0. Cache user cần quyền ghi ngoài sandbox như đã ghi ở CP4; không dùng `--no-verify`.
- Rà theo `SUBMISSION.md`: đủ 4 file control; 5 file lure gồm mẫu 901 và cặp 904/904b; `.pre-commit-config.yaml`, `requirements.lock`, `reports/secrets-incident.md`; `injection-corpus.md`, `reports/baseline.md`, before/after, ledger, compliance mapping, DPIA-lite và báo cáo này. Log after/ledger được stage đích danh bằng `git add -f`. Không nộp `.venv/` hay `reports/sink.log`; không tạo báo cáo riêng CP5.
