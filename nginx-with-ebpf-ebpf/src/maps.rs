use aya_ebpf::{macros::map, maps::PerfEventArray, maps::HashMap};
use nginx_with_ebpf_common::Connection;
use nginx_with_ebpf_common::Request;

#[map(name = "EVENTS")]
pub static mut EVENTS: PerfEventArray<Connection> = PerfEventArray::with_max_entries(1024, 0);

#[map(name = "LATENCY")]
pub static mut LATENCY: HashMap<Connection, Request> = HashMap::with_max_entries(1024, 0);
