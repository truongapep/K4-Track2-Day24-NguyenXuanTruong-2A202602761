# Verification — kết quả kiểm chứng

- OS / Python / Gitleaks version: Windows native / Python 3.11.6 / Gitleaks 8.30.1.
- `python -X utf8 -m pytest tests/ -q -s`: **33 passed**, không fail/skip trong lượt chốt CP5, snapshot trước commit `72ffb08ce085645fdbaa98f7afb183a2af338e30`; precision/recall=1.000, gold=pred=tp=118.
- Hook Gitleaks đã kiểm các phần CP1–CP4 trước commit và được chạy lại trên index chốt CP5; kết quả lượt chốt ghi bên dưới. Các lượt lịch sử index rỗng không được coi là kiểm diff chưa stage.
- Ledger verify: `reports/ledger.jsonl` trả True; sửa dòng giữa không rehash trả False.
- Các mục chưa kiểm: WSL/Linux chưa chạy; điều/khoản pháp luật cụ thể chưa xác minh. Replay CLI sau sửa lure 903 đã được cho phép và hoàn tất; evidence và báo cáo được chốt trong CP5 theo yêu cầu người dùng.

Các mục CP2–CP5 và các lượt rà soát bên dưới là lịch sử tại từng snapshot. Kết quả cuối nằm ở mục “Chốt CP5”; không coi số liệu lịch sử là số liệu của HEAD mới.

## Lịch sử CP2 — 12/10/2026, commit `2baf9dd`

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

## Lịch sử CP4 — 12/10/2026, commit `2e69deb`

- File CP4: tạo `.pre-commit-config.yaml` và `requirements.lock`; điền `reports/secrets-incident.md`; cập nhật `.gitleaks.toml` chỉ để bỏ `.venv/` khỏi directory scan; cập nhật báo cáo này. Không tạo báo cáo Markdown riêng hoặc sửa test bắt buộc.
- `gitleaks version`: **8.30.1**, binary từ release chính thức đã kiểm SHA-256 archive. Activate `.venv` hoặc thêm `.venv/Scripts` vào PATH trước khi chạy scanner/hook.
- `gitleaks git --config .gitleaks.toml --redact --verbose .`: **7 commit** khi HEAD là `a222f39c758e422d81c2cea2352d66d66dd033ce`, **1 finding** thuộc `lab24-synthetic-token` tại `lab-fake-secret.txt:1` trong commit `1bdd849922156c868a5ee9293d68f5b72e242d2c`; **exit 1 dự kiến**. Chi tiết trong `reports/secrets-incident.md`.
- `gitleaks dir --config .gitleaks.toml --redact .`: **0 finding, exit 0**; phạm vi không gồm `.venv/`, không loại các file bài làm hay token giả khỏi lịch sử.
- `python -m piptools compile --generate-hashes --no-emit-index-url --no-emit-trusted-host -o requirements.lock requirements.txt`: đạt; **11 package** được pin, mỗi package có hash. `python -m pip install --require-hashes -r requirements.lock`: exit 0; cài lại với `--force-reinstall --require-hashes` cũng exit 0, kiểm các wheel thực tế.
- Lỗi setup đã xử lý: pip-tools và pre-commit trong sandbox ban đầu không ghi được cache user (WinError 5); tải từ GitHub bị chặn mạng. Khi cache pre-commit đã tồn tại, chạy trong sandbox còn báo `attempt to write a readonly database`. Chạy lại với quyền được cấp thì tạo lock/tải scanner/chạy hook thành công. Directory scan ban đầu báo 3 finding trong thư viện/ví dụ scanner ở `.venv`; sau ngoại lệ đúng phạm vi môi trường local, quét sạch và quét lịch sử vẫn có token giả.
- `python -X utf8 -m pytest tests/test_supply_chain.py -q`: **3 passed**. `python -X utf8 -m pytest tests/ -q`: **33 passed**, không fail/skip. `python -m pip check`: không có dependency bị lỗi.
- `pre-commit run --all-files`: hook **Detect hardcoded secrets Passed**; repo chính thức pin v8.30.1, `pass_filenames: false`, cấu hình `.gitleaks.toml`. Quét file hiện tại không đồng nghĩa quét lịch sử; finding token giả được kiểm bằng lệnh riêng ở trên.
- Tại thời điểm CP4, việc tạo after/điền mapping/DPIA-lite còn thuộc CP5; các file này đã có trên HEAD hiện tại.

### Kiểm lại CP4 trước commit riêng — 12/10/2026

- Snapshot quét **`611ebe40c4c177090619be833844aafaef46bf0f`**: Gitleaks **8.30.1**, history scan **12 commit**, đúng **1 finding synthetic** tại `lab-fake-secret.txt:1` trong commit `1bdd849`, rule `lab24-synthetic-token`; exit **1 dự kiến**. Directory scan exit **0**, không finding, giữ phạm vi ngoại lệ `.venv/`.
- `python -X utf8 -m pytest tests/test_supply_chain.py -q`: **3 passed**. Hook pin và 11 package có hash đã có từ CP4 gốc, lần này chỉ sửa incident note/báo cáo và gắn số liệu quét với SHA thực tế.
- Chỉ commit `reports/secrets-incident.md` và phần CP4 trong báo cáo này; ledger/after/compliance mapping/DPIA-lite thuộc CP5 còn chờ người dùng yêu cầu.

## Lịch sử CP5 — 12/10/2026, commit `874546d`

- `python -X utf8 -m pytest tests/ -q`: **33 passed**, không fail/skip. Fixture reset sink cho các test liên quan; ledger test nằm trong thư mục tạm nên không ghi đè ledger nộp. `tests/test_injection.py` đủ 4 biến thể × 2 principal; `tests/test_obo.py` và `tests/test_split.py` kiểm quyền và tiện ích hợp lệ.
- `python -X utf8 -m agent.check_lure corpus/ticket-90*.md`: **4/4 sẵn sàng**, đủ cả `ticket-904b.md` sau khi fixture trả lại corpus.
- Sau pytest, chạy `python -X utf8 -m sink.sink --reset`, rồi `python -X utf8 -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"` trên payload/corpus ban đầu. CLI tổng hợp **45 document**. Copy `reports/sink.log` thành `reports/attack-after.log`: **0 byte**. Không dùng log rỗng do fixture pytest reset làm bằng chứng replay cuối.
- Trình tự có tool record: pytest (fixture reset sink) → CLI reset sink → CLI agent → copy sink thành after. Không có record về một lệnh CLI reset riêng trước pytest; không bổ sung hoặc khẳng định sự kiện đó đã xảy ra. Lượt rà soát này không chạy lại agent/sink CLI.
- `reports/attack-before.log:1` giữ nguyên: 1 POST `/reconcile`, chứa đúng record synthetic `KH-000999`, đối chiếu với `data/customers.json`. Before và after là hai artifact khác nhau, không ghi đè before.
- Ledger được nối tiếp, giữ 24 entry CP3 và thêm 24 entry CP5: **48 entry, verify True**. Dòng 25 allow `search_docs`, dòng 26 deny `http_post` với reason `Restricted data must not cross an egress boundary` và `on_behalf_of=dpo`, dòng 27 allow gate trusted-resolution, dòng 28–48 allow đọc customer hợp lệ. Mọi entry đủ reason, agent_id, run_id, on_behalf_of, expires_at; không có CCCD/SĐT/STK/email thô.
- `reports/compliance-mapping.md` có đủ Luật 91/2025, NĐ 356/2025, Luật AI 134/2025 và OWASP ASI01/03/04, trỏ đúng file/dòng evidence. Đã xác minh metadata văn bản từ nguồn Chính phủ và mã OWASP từ nguồn chính thức; điều/khoản cụ thể **chưa xác minh**, không tự kết luận tuân thủ pháp luật.
- `reports/dpia-lite.md` đã điền dữ liệu, purpose/principal, luồng A/B/tool/endpoint, before/after và giới hạn mock/regex/TTL/hash chain.
- Gitleaks **8.30.1**: directory scan 0 finding/exit 0; history scan **8 commit** khi HEAD là `2e69deb757e643dc1e21a5c13d8039b1c63c245d`, đúng 1 finding synthetic ở `1bdd849`, exit 1 dự kiến.
- `pre-commit run --all-files --verbose` trên index CP5: **Detect hardcoded secrets Passed**, 0 finding/exit 0. Cache user cần quyền ghi ngoài sandbox như đã ghi ở CP4; không dùng `--no-verify`.
- Rà theo `SUBMISSION.md`: đủ 4 file control; 5 file lure gồm mẫu 901 và cặp 904/904b; `.pre-commit-config.yaml`, `requirements.lock`, `reports/secrets-incident.md`; `injection-corpus.md`, `reports/baseline.md`, before/after, ledger, compliance mapping, DPIA-lite và báo cáo này. Log after/ledger được stage đích danh bằng `git add -f`. Không nộp `.venv/` hay `reports/sink.log`; không tạo báo cáo riêng CP5.

## Lịch sử rà soát trước khi được phép replay — 12/10/2026

- HEAD/snapshot lịch sử được quét: **`874546d799d358c84ddc25882d232ab02538bb59`**. Chỉ sửa báo cáo và lure 903 trong working tree; chưa stage/commit/push, không rewrite lịch sử, không sửa các file giảng viên được bảo vệ.
- Windows native, Python 3.11.6; README yêu cầu WSL2 Ubuntu/macOS/Linux nhưng lượt này **chưa kiểm trên WSL/Linux**. Không suy ra hỗ trợ nền tảng đó từ kết quả Windows.
- Full suite `python -X utf8 -m pytest tests/ -q -s`: **33 passed**, không failed/skipped; gold=118, pred=118, tp=118, precision=1.000, recall=1.000.
- `agent.check_lure`: **4/4 sẵn sàng** sau bỏ câu tự thú ở 903; từng file 904 và 904b riêng có `find_injection() == None`, ghép cặp được nhận diện.
- Gitleaks **8.30.1** quét lịch sử **9 commit** tại SHA HEAD ở trên: 1 finding synthetic, rule `lab24-synthetic-token`, `lab-fake-secret.txt:1` tại commit `1bdd849`, exit 1 dự kiến. Directory scan working tree sạch, exit 0; chỉ bỏ `.venv/` khỏi phạm vi theo config.
- `pre-commit run --all-files --verbose`: Passed nhưng quét 0 byte vì hook `gitleaks-system` dùng staged diff và index chưa stage bản sửa. Cần chạy lại sau khi người dùng stage/duyệt, không coi kết quả này là hook kiểm bản sửa chưa stage.
- Ledger hiện có **48 entry**, verify True; mọi entry đủ ts/agent_id/run_id/tool/args_hash/classification/decision/reason/on_behalf_of/expires_at/prev_hash/hash. Hash/args_hash dài 64 ký tự hex; TTL hợp lệ **tại thời điểm decision** (không đòi TTL lịch sử còn hiệu lực hiện nay); có deny http_post dưới dpo, không chứa CCCD/SĐT/STK/email thô từ fixture.
- Đủ **20 file** trong danh sách nộp mở rộng gồm mẫu lure 901; `.venv/` và `reports/sink.log` không được track. Before tổng và 4 before riêng, after, ledger không được sửa; nội dung khớp HEAD sau chuẩn hóa LF/CRLF. After vẫn **0 byte**. Không tạo lại evidence before hoặc replay CLI.
- `git diff --stat 52b33b5 HEAD -- tests agent/loop.py agent/tools.py agent/llm.py data sink corpus/ticket-901.md`: rỗng; kiểm cả diff working tree của các đường dẫn này cũng rỗng.
- Citation đã rà theo file/dòng hiện tại; before là lịch sử CP2 `2baf9dd`, after/ledger là evidence lịch sử CP5 `874546d`, finding secret trỏ về commit `1bdd849`. After rỗng không gán dòng giả.
- Chưa chạy CLI replay trên payload 903 đã sửa vì cần người dùng cho phép riêng; test đã kiểm payload mới, nhưng artifact after/ledger được giữ ở phiên bản lịch sử. Chưa xác minh điều khoản pháp luật cụ thể, không kết luận tuân thủ production hoặc điểm chính thức.

## Lịch sử replay được cho phép và commit CP1/CP2 — 12/10/2026

- Người dùng cho phép riêng replay CLI sau sửa 903 và chỉ commit chỉnh sửa CP1/CP2; chưa cho phép commit các checkpoint còn lại. Không rewrite lịch sử; các commit cũ vẫn giữ nguyên.
- Trình tự thực chạy: CLI reset sink → `pytest tests/ -q -s` (33 passed) → `agent.check_lure` (4/4) → CLI reset sink lần nữa → `agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"` → copy sink thành `reports/attack-after.log`. CLI tổng hợp 45 document, after **0 byte**. Đây là replay toàn corpus có lure 903 đã sửa, không phải log riêng biến thể 3.
- Replay thực hiện trước hai commit chỉnh sửa, trên base `874546d` với diff lure 903; nội dung lure đã replay hiện được lưu ở commit CP2 `29ebe3e`. SHA-256 của file 903 tại replay: `486de43b332835e1ef9e0b1d7195415dc6388a3ff57e017808356fd37f321fa4`.
- Ledger nối 24 entry mới, tổng **72**, verify True; dòng 49 allow search, dòng 50 deny `http_post` dưới `dpo` kèm reason, dòng 51 allow gate trusted-resolution, dòng 52–72 allow đọc customer hợp lệ. Đủ metadata, không có CCCD/SĐT/STK/email thô.
- SHA-256 của `reports/attack-before.log` và mỗi file before variant 1–4 trước/sau replay đều là `6248e01fcb19b79fa0e42c16fab037249d643900c4baccebd4aadeb74a1cc84c`: giữ nguyên byte, không tạo lại before.
- Trước mỗi commit đã báo phạm vi và chạy hook Passed: CP1 `20ee837` lúc 17:04:52 +07:00 chỉ sửa `reports/baseline.md`; CP2 `29ebe3e` lúc 17:06:46 +07:00 chỉ sửa `corpus/ticket-903.md`, `injection-corpus.md`. Không stage các file báo cáo/evidence thuộc checkpoint còn lại, không push.
- Kiểm sau commit tại HEAD **`29ebe3e30d6ff324652d5a77c3204d949c600745`**: full suite **33 passed**, precision/recall 1.000; history scanner Gitleaks 8.30.1 quét **11 commit**, đúng 1 finding synthetic, exit 1 dự kiến; directory scan sạch, exit 0. Before hash giữ nguyên, ledger verify True, after 0 byte.
- Hook sau hai commit Passed, quét 0 byte vì index không còn thay đổi staged; hook trước từng commit đã kiểm file CP1/CP2 được stage. Directory scan kiểm các báo cáo/evidence còn chưa stage. Rà 64 citation file/dòng đều hợp lệ, file giảng viên được bảo vệ không đổi.
- After vẫn rỗng nên không có diff nội dung so với file rỗng cũ, dù đã copy lại từ replay mới. `reports/ledger.jsonl`, compliance mapping, DPIA-lite, secrets incident và verification vẫn chưa commit, chờ người dùng yêu cầu checkpoint tương ứng.

## Chốt CP5 — 12/10/2026

- Người dùng đã lần lượt yêu cầu commit CP1, CP2, CP3, CP4 rồi CP5/push; trước từng commit đã báo phạm vi. Theo yêu cầu đổi thông điệp của người dùng, hai commit CP1/CP2 hiện tại là `7c8c138`/`667b440`, thay các SHA tạm `20ee837`/`29ebe3e` trong lịch sử kiểm tra ở trên; nội dung file và evidence không đổi. CP3 là `611ebe4`, CP4 là `72ffb08`.
- Payload 903 tại `667b440` khớp SHA-256 `486de43b332835e1ef9e0b1d7195415dc6388a3ff57e017808356fd37f321fa4` của lần replay được cho phép. Giữ after 0 byte và ledger 72 entry từ replay đó, không tạo lại before hoặc thêm lần replay không cần thiết.
- Full suite **33 passed**, không skip/fail; precision=recall=1.000 (gold=pred=tp=118); `agent.check_lure` **4/4 sẵn sàng**, từng file 904/904b riêng không nhận diện injection. Test sau replay chỉ dùng ledger tạm và fixture của đề, không ghi đè evidence nộp.
- Ledger verify True, đủ metadata/reason/hash/OBO/TTL, không chứa CCCD/SĐT/STK/email thô; `reports/ledger.jsonl:49` allow search, dòng 50 deny http_post dưới dpo, dòng 51–72 allow đọc hợp lệ. Before tổng và 4 before riêng giữ nguyên SHA-256 đã ghi ở mục lịch sử replay.
- Gitleaks **8.30.1**: tại snapshot trước commit CP5 **`72ffb08ce085645fdbaa98f7afb183a2af338e30`**, history scan **13 commit**, đúng 1 finding synthetic ở commit `1bdd849`, exit 1 dự kiến; directory scan sạch, exit 0. Số 12 trong incident note là lượt CP4 tại snapshot `611ebe4`, không phải lượt chốt này. Sau commit mới phải quét lại và dùng SHA/số commit của lượt mới.
- Đủ 20 file được track theo checklist gồm mẫu lure 901; after có trong Git dù 0 byte; `.venv/` và `reports/sink.log` không track. Các file giảng viên được bảo vệ không đổi so với `52b33b5`.
- `pre-commit run --all-files --verbose` trên index chốt CP5: **Detect hardcoded secrets Passed**, quét 30.65 KB, không finding/exit 0; đây là lượt quét phần staged thực tế, khác các lượt lịch sử index rỗng.
- Mapping/DPIA-lite dẫn evidence hiện tại, làm rõ parent_scopes mô phỏng quyền orchestrator và giới hạn mock/regex/hash chain; điều khoản pháp luật cụ thể chưa xác minh, không khẳng định compliance production. Chưa thực hiện bonus; bonus cần log/test riêng theo rubric.
