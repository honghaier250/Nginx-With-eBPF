# nginx_with_ebpf
基于eBPF技术探测Nginx并拓展其能力。

## 依赖

```shell
rustup install stable
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
cargo install cargo-generate                                                                                                                                          │
# https://aya-rs.dev/book/start/development/#starting-a-new-project
cargo generate --name nginx-with-ebpf -d program_type=uprobe https://github.com/aya-rs/aya-template

# 生成bindings.rs
git clone https://github.com/nginxinc/ngx-rust.git
cd ngx-rust
cargo build --release
find . -name "bindings.rs"

# 拷贝bindings.rs
cp xxx/bindings.rs nginx-with-ebpf/nginx_with_ebpf-ebpf/src/bindings.rs

# bindings.rs适配ebpf
sed -i -r 's/std::fmt/core::fmt/g' nginx-with-ebpf/nginx_with_ebpf-ebpf/src/bindings.rs
sed -i -r 's/std::default/core::default/g' nginx-with-ebpf/nginx_with_ebpf-ebpf/src/bindings.rs
sed -i -r 's/std::marker/core::marker/g' nginx-with-ebpf/nginx_with_ebpf-ebpf/src/bindings.rs
sed -i -r 's/std::cmp/core::cmp/g' nginx-with-ebpf/nginx_with_ebpf-ebpf/src/bindings.rs
sed -i -r 's/std::option/core::option/g' nginx-with-ebpf/nginx_with_ebpf-ebpf/src/bindings.rs
sed -i -r 's/std::clone/core::clone/g' nginx-with-ebpf/nginx_with_ebpf-ebpf/src/bindings.rs
sed -i -r 's/std::slice/core::slice/g' nginx-with-ebpf/nginx_with_ebpf-ebpf/src/bindings.rs
sed -i -r 's/std::mem/core::mem/g' nginx-with-ebpf/nginx_with_ebpf-ebpf/src/bindings.rs
sed -i -r 's/std::hash/core::hash/g' nginx-with-ebpf/nginx_with_ebpf-ebpf/src/bindings.rs
sed -i -r 's/std::os::raw/aya_ebpf::cty/g' nginx-with-ebpf/nginx_with_ebpf-ebpf/src/bindings.rs
```

## 构建

```shell
# Build eBPF
cargo xtask build-ebpf

# Build Userspace
cargo build
```

## 运行

```shell
RUST_LOG=info cargo xtask run -- --pid $(pgrep -f "nginx: worker")

[2024-05-22T07:48:36Z INFO  nginx_with_ebpf] Waiting for Ctrl-C...
[2024-05-22T07:48:41Z INFO  nginx_with_ebpf] 4751821449717830,10.0.209.200:57281=>10.0.229.81:80, /1kb.html, 404, request_size=83, response_size=375, downstream_request_first_byte_time=6567704, downstream_request_last_byte_time=6585816, upstream_connect_time=6800342, upstream_request_first_byte_time=7116383, upstream_request_last_byte_time=7116383, upstream_response_first_byte_time=7713408, upstream_response_last_byte_time=7901449, downstream_response_first_byte_time=7754475, downstream_response_last_byte_time=8064774

# 输出字段含义
客户端地址=>应用地址: 10.0.209.200:57281=>10.0.229.81:80
请求URL: /1kb.html
请求大小: request_size=83
响应码: 404
响应大小: response_size=375
阶段耗时:

   |- Accept接收时间(纳秒): 4751821449717830
   |
   |- Accept到接收请求首字节花费时长(纳秒): downstream_request_first_byte_time=6567704
   |
   |- Accept到请求头接收完成花费时长(纳秒): downstream_request_last_byte_time=6585816
   |
   |- Accept到开始连接Upstream花费时长(纳秒): upstream_connect_time=6800342
   |
   |- Accept到向Upstream转发请求首字节花费时长(纳秒): upstream_request_first_byte_time=7116383
   |
   |- Accept到向Upstream转发请求头完成花费时长(纳秒): upstream_request_last_byte_time=7116383
   |
   |- Accept到接收Upstream响应首字节花费时长(纳秒): upstream_response_first_byte_time=7713408
   |
   |- Accept到接收Upstream响应完成花费时长(纳秒): upstream_response_last_byte_time=7901449
   |
   |- Accept到向客户端转发响应首字节花费时长(纳秒): downstream_response_first_byte_time=7754475
   |
   |- Accept到向客户端转发响应完成花费时长(纳秒): downstream_response_last_byte_time=8064774
   v
```

## 拓展
- [Aya is an eBPF library for the Rust](https://github.com/aya-rs/aya)
- [Grafana Beyla](https://github.com/grafana/beyla)
- [BPF driven auto-tuning](https://github.com/oracle/bpftune)
- [MyBee](https://github.com/elbaro/mybee)
