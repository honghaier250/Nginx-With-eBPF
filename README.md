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
sed -i -r 's/std::os::raw/aya_bpf::cty/g' nginx-with-ebpf/nginx_with_ebpf-ebpf/src/bindings.rs
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
RUST_LOG=info cargo xtask run -- --pid $(pgrep -f "nginx: worker") --uprobe ngx_http_read_request_header

[2024-01-17T06:39:18Z INFO  nginx_with_ebpf] Waiting for Ctrl-C...
[2024-01-17T06:39:21Z INFO  nginx_with_ebpf] uprobe function called for request: GET /1kb.html HTTP/1.1
^C[2024-01-17T06:39:24Z INFO  nginx_with_ebpf] Received Ctrl-C

[2024-01-17T06:39:24Z INFO  nginx_with_ebpf] stack 0x555fc13e1524 ngx_http_read_request_header@:0
[2024-01-17T06:39:24Z INFO  nginx_with_ebpf] stack 0x555fc13deef8 ngx_http_wait_request_handler@:0
[2024-01-17T06:39:24Z INFO  nginx_with_ebpf] stack 0x555fc13b1df8 ngx_epoll_process_events@:0
[2024-01-17T06:39:24Z INFO  nginx_with_ebpf] stack 0x555fc139d8ff ngx_process_events_and_timers@:0
[2024-01-17T06:39:24Z INFO  nginx_with_ebpf] stack 0x555fc13aeef9 ngx_worker_process_cycle@:0
[2024-01-17T06:39:24Z INFO  nginx_with_ebpf] stack 0x555fc13ab06d ngx_spawn_process@:0
[2024-01-17T06:39:24Z INFO  nginx_with_ebpf] stack 0x555fc13ada3f ngx_start_worker_processes@:0
[2024-01-17T06:39:24Z INFO  nginx_with_ebpf] stack 0x555fc13ace82 ngx_master_process_cycle@:0
[2024-01-17T06:39:24Z INFO  nginx_with_ebpf] stack 0x555fc13659d4 main@:0
[2024-01-17T06:39:24Z INFO  nginx_with_ebpf] stack 0x7f80c36266ca __libc_init_first@:0
[2024-01-17T06:39:24Z INFO  nginx_with_ebpf] Exiting...
```

## 拓展
- [Aya is an eBPF library for the Rust](https://github.com/aya-rs/aya)
- [Grafana Beyla](https://github.com/grafana/beyla)
- [BPF driven auto-tuning](https://github.com/oracle/bpftune)
- [MyBee](https://github.com/elbaro/mybee)
