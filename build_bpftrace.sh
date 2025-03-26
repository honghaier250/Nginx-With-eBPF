#/bin/bash

# 安装依赖
apt install systemtap-sdt-dev binutils-dev lldb liblldb-dev

gcl https://github.com/libbpf/blazesym.git
cd blazesym/capi
cargo build --release
sudo install include/blazesym.h /usr/local/include
cd ../
sudo install ./target/release/libblazesym_c.so /usr/local/lib/


# 开始构建
cd ..
mkdir -p bpftrace/build
cd bpftrace/build
cmake ..
make -j$(nproc)
sudo install src/bpftrace /usr/local/bin
