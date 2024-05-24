#![no_std]

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Connection {
    pub start_time: usize,
    pub pid: u32,
    pub fd: i32,
    pub src_ip: u32,
    pub src_port: u16,
    pub magic: u16,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Request {
    pub downstream_accept_time: u64,
    pub downstream_request_first_byte_time: u64,
    pub downstream_request_last_byte_time: u64,
    pub downstream_response_first_byte_time: u64,
    pub downstream_response_last_byte_time: u64,
    pub upstream_connect_time: u64,
    pub upstream_request_first_byte_time: u64,
    pub upstream_request_last_byte_time: u64,
    pub upstream_response_first_byte_time: u64,
    pub upstream_response_last_byte_time: u64,
    pub response_status: usize,
    pub response_size: i64,
    pub request_size: i64,
    pub request_uri: [u8; 25],
    pub upstream_ip: u32,
    pub upstream_port: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Connection {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Request {}