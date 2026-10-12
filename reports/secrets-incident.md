# Secret giả trong lịch sử Git — kết quả kiểm chứng

- Scanner và phiên bản: Gitleaks **8.30.1**, tải binary Windows x64 từ [release chính thức](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1). SHA-256 archive `gitleaks_8.30.1_windows_x64.zip` là `d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e`, khớp file checksum của release. Binary đặt trong `.venv/Scripts/gitleaks.exe`, có trong PATH khi activate venv; không đưa binary vào bài nộp.
- Commit chứa token giả: `1bdd849922156c868a5ee9293d68f5b72e242d2c` (`1bdd849`). Token được cài sẵn cho lab, có định dạng `LAB24-DEMO`, vô hiệu và là dữ liệu synthetic; finding này không chứng minh đã lộ credential thật.
- File, rule và kết quả quét lịch sử hiện tại ngày 12/10/2026: tại commit `1bdd849922156c868a5ee9293d68f5b72e242d2c`, file `lab-fake-secret.txt:1`, rule **`lab24-synthetic-token`**. Chạy `gitleaks git --config .gitleaks.toml --redact --verbose .` khi HEAD là **`611ebe40c4c177090619be833844aafaef46bf0f`**: **12 commit được quét, 1 finding, exit code 1 dự kiến**. Fingerprint: `1bdd849922156c868a5ee9293d68f5b72e242d2c:lab-fake-secret.txt:lab24-synthetic-token:1`. File đã bị xoá tại commit `ece6ca4` nhưng finding vẫn hiện; không chép nguyên token hay rewrite lịch sử.
- Kết quả quét file hiện tại: `gitleaks dir --config .gitleaks.toml --redact .`: **0 finding, exit code 0**. `.gitleaks.toml` giữ default rules và rule lab, chỉ loại `.venv/` khỏi phạm vi vì dependency/tooling local không được nộp. Lịch sử CP4 trước ngoại lệ này: scanner báo `generic-api-key` ở `.venv/Lib/site-packages/setuptools/_distutils/msvccompiler.py:45` (gán `RegEnumKey`) và 2 ví dụ trong README scanner; đã kiểm lại đường dẫn thư viện thực có trên máy. Không loại `corpus/`, `data/`, `reports/` hay token giả khỏi lịch sử.
- Nếu đây là credential thật, cần xử lý thế nào: thu hồi/rotate ngay tại bên cấp credential, kiểm tra việc sử dụng trái phép và phạm vi ảnh hưởng, thay credential trong hệ thống liên quan, rà các bản sao/log và xử lý lịch sử theo quy trình incident. Lab không tạo hoặc sử dụng secret thật.
- Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ: credential đã lộ có thể còn trong lịch sử Git hoặc bản sao và vẫn dùng được cho đến khi bị thu hồi. Dependency pin/hash và scanner/hook giảm rủi ro supply chain hoặc phát hiện secret được commit, không vô hiệu hoá credential đã phát hành; vì vậy không thay thế rotate.

## Hook và dependency lock

- `.pre-commit-config.yaml` dùng repo chính thức `https://github.com/gitleaks/gitleaks`, pin `rev: v8.30.1`, hook `gitleaks-system`, `pass_filenames: false`, args trỏ `.gitleaks.toml`. [Định nghĩa hook tại tag v8.30.1](https://github.com/gitleaks/gitleaks/blob/v8.30.1/.pre-commit-hooks.yaml) chạy staged Git diff; hook không thay thế quét toàn bộ lịch sử bằng lệnh riêng ở trên.
- `requirements.lock` được sinh từ `requirements.txt` bằng `python -m piptools compile --generate-hashes --no-emit-index-url --no-emit-trusted-host -o requirements.lock requirements.txt` (pip-tools 7.6.2, Python 3.11.6). Pin đầy đủ **11 package**, mỗi package có SHA-256 hash, không ghi URL registry hoặc credential vào lock.
- `python -m pip install --require-hashes -r requirements.lock` đạt. Chạy thêm `--force-reinstall --require-hashes` để kiểm hash của các wheel thực tế khi cài lại trong `.venv`: exit code 0.
- Kết quả hook và test cuối CP4 ghi trong `reports/verification.md`. Bài dùng dữ liệu tổng hợp; kết quả scanner không bảo đảm phát hiện mọi loại secret.

## Lịch sử số liệu checkpoint

- Lượt CP4 quét 7 commit khi HEAD là `a222f39c758e422d81c2cea2352d66d66dd033ce`, trước commit CP4.
- Lượt CP5 quét 8 commit khi HEAD là `2e69deb757e643dc1e21a5c13d8039b1c63c245d`, trước commit CP5.
- Lượt rà soát trước hai commit chỉnh sửa quét 9 commit khi HEAD là `874546d799d358c84ddc25882d232ab02538bb59`; lượt sau hai commit CP1/CP2 quét 11 commit khi HEAD là `29ebe3e30d6ff324652d5a77c3204d949c600745`, đều có đúng 1 finding synthetic. Sau một commit mới, phải chạy lại scanner và ghi số commit cùng SHA của lượt mới, không dùng số cũ cho HEAD mới.
- SHA `29ebe3e` ở trên là lượt quét trước khi người dùng yêu cầu đổi thông điệp CP1/CP2; không phải HEAD hiện tại. Lượt kiểm CP4 trước commit mới tại `611ebe40c4c177090619be833844aafaef46bf0f` quét 12 commit, 1 finding synthetic, exit 1; directory scan sạch và 3 test supply chain đạt.
