#!/bin/bash

sed -i -r 's/std::fmt/core::fmt/g' nginx_with_ebpf-ebpf/src/bindings.rs
sed -i -r 's/std::default/core::default/g' nginx_with_ebpf-ebpf/src/bindings.rs
sed -i -r 's/std::marker/core::marker/g' nginx_with_ebpf-ebpf/src/bindings.rs
sed -i -r 's/std::cmp/core::cmp/g' nginx_with_ebpf-ebpf/src/bindings.rs
sed -i -r 's/std::option/core::option/g' nginx_with_ebpf-ebpf/src/bindings.rs
sed -i -r 's/std::clone/core::clone/g' nginx_with_ebpf-ebpf/src/bindings.rs
sed -i -r 's/std::slice/core::slice/g' nginx_with_ebpf-ebpf/src/bindings.rs
sed -i -r 's/std::mem/core::mem/g' nginx_with_ebpf-ebpf/src/bindings.rs
sed -i -r 's/std::hash/core::hash/g' nginx_with_ebpf-ebpf/src/bindings.rs
sed -i -r 's/std::os::raw/aya_bpf::cty/g' nginx_with_ebpf-ebpf/src/bindings.rs
