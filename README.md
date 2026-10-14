# xmproxy

Proxy kiểm tra HTTP/HTTPS và WebSocket, viết bằng Python với lõi mitmproxy.
Giao diện xem/chỉnh sửa request, response, tìm kiếm, replay và xem WebSocket
sử dụng mitmweb. Upstream HTTP/HTTPS được hỗ trợ; SOCKS upstream chưa hỗ trợ.

## Cài đặt

Python 3.12 trở lên và uv:

```sh
UV_CACHE_DIR=/workspace/.cache/uv uv sync --frozen
```

## Chạy

```sh
.venv/bin/xmproxy
.venv/bin/xmproxy --upstream http://proxy.example:3128
.venv/bin/xmproxy --intercept '~u example.com' --record .xmproxy/flows.mitm
```

Proxy mặc định bind `127.0.0.1:8080`. Web UI bind `127.0.0.1:8081` và yêu cầu
token trong URL mà tiến trình in khi khởi động. Môi trường onboarding không cung
cấp web preview; các địa chỉ này dành cho client chạy trong cùng máy.

Cấu hình HTTP và HTTPS proxy của client trỏ vào cổng 8080. Với HTTPS/WSS,
cài `.xmproxy/mitmproxy-ca-cert.pem` vào trust store của client, hoặc chỉ định
CA riêng cho request. Ví dụ kiểm tra từ cùng máy:

```sh
curl --proxy http://127.0.0.1:8080 --cacert .xmproxy/mitmproxy-ca-cert.pem https://example.com
```

Không tắt xác minh TLS. Client dùng certificate pinning cần cấu hình riêng và
không được bảo đảm hoạt động. CA và private key được tạo trong `.xmproxy`,
không commit thư mục này.

`--intercept` dùng filter của mitmproxy để giữ request/response. Trong UI, xem và
chỉnh sửa flow rồi Resume. WebSocket được giám sát và lưu message; phiên bản này
không cung cấp breakpoint/chỉnh sửa tương tác từng WebSocket message.

Upstream yêu cầu Basic authentication: đặt biến `XMPROXY_UPSTREAM_AUTH` theo dạng
`username:password` trong môi trường chạy, không nhúng credentials vào URL.
Lõi mitmproxy nhận giá trị này qua argv, nên tiến trình cùng tài khoản có thể đọc
được. Upstream có CA riêng: dùng `--trusted-ca /path/to/ca-bundle.pem`.

File `--record` có thể chứa cookies, tokens và nội dung nhạy cảm. Đặt file trong
thư mục riêng như `.xmproxy`. Xem lại bằng `.venv/bin/mitmweb -r .xmproxy/flows.mitm`.
Chỉ mở `--listen-host 0.0.0.0` khi cần client bên ngoài và có kiểm soát truy cập
mạng phù hợp; proxy hiện không yêu cầu xác thực client.

## Kiểm thử

```sh
.venv/bin/python -m unittest discover -s tests
.venv/bin/python tests/smoke.py
```

Smoke test dùng cổng 18080, 18081, 18082, 18443 và 19090. Nó tạo hai proxy, origin
HTTP/TLS cục bộ và CA tạm; xác minh UI có token, HTTP, HTTPS, WebSocket và WebSocket
qua TLS qua upstream, cùng file ghi bốn flow. Tiến trình và dữ liệu tạm được dọn
sau kiểm thử. Không cần dịch vụ bên ngoài hay credentials để chạy các test này.

## Chỉ chuyển qua upstream, vẫn giải mã

```sh
.venv/bin/xmproxy --upstream-only --upstream http://proxy.example:3128
```

`--upstream-only` yêu cầu khai báo upstream. Mọi request được chuyển qua upstream;
xmproxy vẫn giải mã HTTPS/WSS, giữ web UI, intercept HTTP và recording.
Không có fallback kết nối trực tiếp khi upstream hỏng. Client vẫn cần tin cậy CA
của xmproxy. Có thể kết hợp `--intercept`, `--record`, `--trusted-ca` và upstream
authentication như chế độ thông thường. `--upstream` cũng sử dụng cùng cơ chế;
`--upstream-only` làm rõ và kiểm tra yêu cầu bắt buộc dùng upstream.

## Truy cập web UI từ máy khác

```sh
uv run xmproxy --web-host 0.0.0.0 --web-port 8081 --upstream http://brd.superproxy.io:44445
```

Mở TCP 8081 trong firewall/security group của máy chủ. Dùng địa chỉ public của
máy chủ và token được in khi khởi động để đăng nhập. UI cho phép đọc và chỉnh sửa
lưu lượng nhạy cảm; giữ token kín. HTTP không mã hóa token/lưu lượng UI trên mạng,
nên dùng reverse proxy HTTPS khi truy cập qua Internet và ưu tiên giới hạn IP
trong firewall. Proxy lưu lượng ở cổng 8080 vẫn mặc định bind localhost.
