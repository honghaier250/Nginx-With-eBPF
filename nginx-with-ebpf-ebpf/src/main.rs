#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings;
mod maps;

use aya_log_ebpf::{debug, info};
use core::cmp;
use maps::LATENCY;
use nginx_with_ebpf_common::Connection;
use nginx_with_ebpf_common::Request;

use bindings::{
    ngx_connection_t, ngx_http_request_t, ngx_http_upstream_t, ngx_socket_t, sockaddr, sockaddr_in,
    sockaddr_in6, NGX_AGAIN, NGX_HTTP_MODULE, NGX_OK,
};

use aya_ebpf::{
    bindings::BPF_F_USER_STACK,
    helpers::*,
    macros::{map, uprobe, uretprobe},
    maps::*,
    programs::ProbeContext,
};

#[inline]
pub(crate) fn ntohs(value: u16) -> u16 {
    u16::from_be(value)
}

#[inline]
pub(crate) fn ntohl(value: u32) -> u32 {
    u32::from_be(value)
}

fn get_info_from_connection(
    connection: *const ngx_connection_t,
) -> Result<(usize, ngx_socket_t, u32, u16), i64> {
    unsafe {
        let fd: ngx_socket_t = bpf_probe_read_user(&(*connection).fd)?;

        let sockaddr: *const sockaddr = bpf_probe_read_user(&(*connection).sockaddr)?;

        let sa_family = bpf_probe_read_user(&(*sockaddr).sa_family)?;

        let mut src_ip: u32 = 0;
        let mut src_port: u16 = 0;

        if sa_family == 2 {
            let socket: sockaddr_in = bpf_probe_read_user(sockaddr as *const sockaddr_in)?;
            src_ip = ntohl(socket.sin_addr.s_addr as u32);
            src_port = ntohs(socket.sin_port as u16);
        } else {
            let socket: sockaddr_in6 = bpf_probe_read_user(sockaddr as *const sockaddr_in6)?;
            //dst_ip = ntohs(socket.sin6_addr[0]);
            src_port = ntohs(socket.sin6_port as u16);
        };

        // let family =
        // unsafe { ((bpf_probe_read_user(&*sockaddr)).map_err(|_e| 5i64)? as sockaddr).sa_family };
        // First we need to get the family, then we can use it to cast the sockaddr to a more specific type
        // Also, it helps filter out UDS and IPv6 connections.
        // if family != AF_INET as sa_family_t {
        //     return Ok(None);
        // }
        // let sock_in_addr: *const sockaddr_in = unsafe { core::mem::transmute(sockaddr) };
        // let sock_in: sockaddr_in = unsafe { bpf_probe_read_user(sock_in_addr)? };
        // let ip = u32::from_be(sock_in.sin_addr.s_addr);
        // let port = u16::from_be(sock_in.sin_port);
        // let local = 0x7f << 6 * 4 | 0xff; // 127.0.0.x
        //                                   // skip 127.0.0.x (for example, 53 might be used for DNS)
        // if ip & local == ip {
        //     return Ok(None);
        // }

        let start_time = bpf_probe_read_user(&(*connection).start_msec)?;

        Ok((start_time, fd, src_ip, src_port))
    }
}

#[uprobe]
pub fn uprobe_ngx_http_init_connection(ctx: ProbeContext) -> u32 {
    fn try_ngx_http_init_connection(ctx: ProbeContext) -> Result<u32, i64> {
        unsafe {
            let connection: *const ngx_connection_t = ctx.arg(0).ok_or(0)?;

            let (start_time, fd, src_ip, src_port) = match get_info_from_connection(connection) {
                Ok(v) => v,
                Err(e) => return Err(e),
            };

            let pid = bpf_get_current_pid_tgid() as u32;

            debug!(&ctx, "uprobe_ngx_http_init_connection find connection: pid: {}, fd: {}, ip: {}, port: {}, start_time: {}", pid, fd, src_ip, src_port, start_time);

            let connection = Connection {
                start_time: start_time,
                pid: pid,
                fd: fd,
                src_ip: src_ip,
                src_port: src_port,
                magic: 00000,
            };

            let downstream_accept_time = bpf_ktime_get_ns() as u64;

            let request = Request {
                downstream_accept_time: downstream_accept_time,
                downstream_request_first_byte_time: 0,
                downstream_request_last_byte_time: 0,
                downstream_response_first_byte_time: 0,
                downstream_response_last_byte_time: 0,
                upstream_connect_time: 0,
                upstream_request_first_byte_time: 0,
                upstream_request_last_byte_time: 0,
                upstream_response_first_byte_time: 0,
                upstream_response_last_byte_time: 0,
                response_status: 0,
                response_size: 0,
                request_size: 0,
                request_uri: [0; 25],
                upstream_ip: 0,
                upstream_port: 0,
                upstream_name: [0; 25],
            };

            LATENCY
                .insert(&connection, &request, 0)
                .map_err(|e| e as i64)?;
        };

        Ok(0)
    }

    match try_ngx_http_init_connection(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

#[uretprobe]
pub fn uretprobe_ngx_http_alloc_request(ctx: ProbeContext) -> u32 {
    fn try_ngx_http_alloc_request(ctx: ProbeContext) -> Result<u32, i64> {
        unsafe {
            let request: *const ngx_http_request_t = ctx.ret().ok_or(1i64)?;
            let connection: *const ngx_connection_t = bpf_probe_read_user(&(*request).connection)?;

            let (start_time, fd, src_ip, src_port) = match get_info_from_connection(connection) {
                Ok(v) => v,
                Err(e) => return Err(e),
            };

            let pid = bpf_get_current_pid_tgid() as u32;

            let connection = Connection {
                start_time: start_time,
                pid: pid,
                fd: fd,
                src_ip: src_ip,
                src_port: src_port,
                magic: 00000,
            };

            let downstream_request_first_byte_time = bpf_ktime_get_ns() as u64;

            if let Some(request) = LATENCY.get_ptr_mut(&connection) {
                let request = &mut (*request);
                request.downstream_request_first_byte_time = downstream_request_first_byte_time;
                LATENCY
                    .insert(&connection, &request, 2)
                    .map_err(|e| e as i64)?;
            } else {
                debug!(&ctx, "uretprobe_ngx_http_alloc_request no found connection pid: {}, fd: {}, ip: {}, port: {}, start_time: {}", pid, fd, src_ip, src_port, start_time);
            }
        };
        Ok(0)
    }

    match try_ngx_http_alloc_request(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

#[uretprobe]
pub fn uretprobe_ngx_http_read_request_header(ctx: ProbeContext) -> u32 {
    fn try_ngx_http_read_request_header(ctx: ProbeContext) -> Result<u32, i64> {
        let pid = bpf_get_current_pid_tgid() as u32;

        unsafe {
            let request: *const ngx_http_request_t = ctx.arg(0).ok_or(1i64)?;
            let connection: *const ngx_connection_t = bpf_probe_read_user(&(*request).connection)?;

            let (start_time, fd, src_ip, src_port) = match get_info_from_connection(connection) {
                Ok(v) => v,
                Err(e) => return Err(e),
            };

            let connection = Connection {
                start_time: start_time,
                pid: pid,
                fd: fd,
                src_ip: src_ip,
                src_port: src_port,
                magic: 00000,
            };

            let uri = bpf_probe_read_user(&(*request).uri)?;

            if let Some(request) = LATENCY.get_ptr_mut(&connection) {
                let request = &mut (*request);

                if uri.len > 1 {
                    let mut buf = [0u8; 25];
                    let len = cmp::min(uri.len as usize, buf.len());
                    bpf_probe_read_user_buf(uri.data as *const u8, &mut buf[..len])?;
                    request.request_uri = buf;
                    let uri = core::str::from_utf8_unchecked(&request.request_uri);
                }

                LATENCY
                    .insert(&connection, &request, 2)
                    .map_err(|e| e as i64)?;
            } else {
                debug!(&ctx, "uretprobe_ngx_http_read_request_header no found connection pid: {}, fd: {}, ip: {}, port: {}, start_time: {}", pid, fd, src_ip, src_port, start_time);
            }
        };
        Ok(0)
    }

    match try_ngx_http_read_request_header(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

#[uretprobe]
pub fn uretprobe_ngx_http_parse_request_line(ctx: ProbeContext) -> u32 {
    fn try_ngx_http_parse_request_line(ctx: ProbeContext) -> Result<u32, i64> {
        let pid = bpf_get_current_pid_tgid() as u32;

        unsafe {
            let rc: u32 = ctx.ret().ok_or(1i64)?;

            if rc != NGX_OK {
                return Ok(0);
            }

            let downstream_request_last_byte_time = bpf_ktime_get_ns() as u64;
            let request: *const ngx_http_request_t = ctx.arg(0).ok_or(1i64)?;
            let connection: *const ngx_connection_t = bpf_probe_read_user(&(*request).connection)?;

            let (start_time, fd, src_ip, src_port) = match get_info_from_connection(connection) {
                Ok(v) => v,
                Err(e) => return Err(e),
            };

            let connection = Connection {
                start_time: start_time,
                pid: pid,
                fd: fd,
                src_ip: src_ip,
                src_port: src_port,
                magic: 00000,
            };

            if let Some(request) = LATENCY.get_ptr_mut(&connection) {
                let request = &mut (*request);
                request.downstream_request_last_byte_time = downstream_request_last_byte_time;
                LATENCY
                    .insert(&connection, &request, 2)
                    .map_err(|e| e as i64)?;
            } else {
                debug!(&ctx, "uretprobe_ngx_http_parse_request_line no found connection pid: {}, fd: {}, ip: {}, port: {}, start_time: {}", pid, fd, src_ip, src_port, start_time);
            }
        };
        Ok(0)
    }

    match try_ngx_http_parse_request_line(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

#[uprobe]
pub fn uprobe_ngx_http_upstream_connect(ctx: ProbeContext) -> u32 {
    fn try_ngx_http_upstream_connect(ctx: ProbeContext) -> Result<u32, i64> {
        let pid = bpf_get_current_pid_tgid() as u32;

        unsafe {
            let upstream_connect_time = bpf_ktime_get_ns() as u64;
            let request: *const ngx_http_request_t = ctx.arg(0).ok_or(1i64)?;
            let connection: *const ngx_connection_t = bpf_probe_read_user(&(*request).connection)?;

            let (start_time, fd, src_ip, src_port) = match get_info_from_connection(connection) {
                Ok(v) => v,
                Err(e) => return Err(e),
            };

            let connection = Connection {
                start_time: start_time,
                pid: pid,
                fd: fd,
                src_ip: src_ip,
                src_port: src_port,
                magic: 00000,
            };

            if let Some(request) = LATENCY.get_ptr_mut(&connection) {
                let request = &mut (*request);
                request.upstream_connect_time = upstream_connect_time;
                LATENCY
                    .insert(&connection, &request, 2)
                    .map_err(|e| e as i64)?;
            } else {
                debug!(&ctx, "uprobe_ngx_http_upstream_connect no found connection pid: {}, fd: {}, ip: {}, port: {}, start_time: {}", pid, fd, src_ip, src_port, start_time);
            }
        };
        Ok(0)
    }

    match try_ngx_http_upstream_connect(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

#[uprobe]
pub fn uprobe_ngx_http_upstream_send_request_body(ctx: ProbeContext) -> u32 {
    fn try_ngx_http_upstream_send_request_body(ctx: ProbeContext) -> Result<u32, i64> {
        unsafe {
            let pid = bpf_get_current_pid_tgid() as u32;
            let upstream_request_first_byte_time = bpf_ktime_get_ns() as u64;

            let request: *const ngx_http_request_t = ctx.arg(0).ok_or(1i64)?;
            let upstream: *const ngx_http_upstream_t = ctx.arg(1).ok_or(1i64)?;
            let connection: *const ngx_connection_t = bpf_probe_read_user(&(*request).connection)?;

            let (start_time, fd, src_ip, src_port) = match get_info_from_connection(connection) {
                Ok(v) => v,
                Err(e) => return Err(e),
            };

            let connection = Connection {
                start_time: start_time,
                pid: pid,
                fd: fd,
                src_ip: src_ip,
                src_port: src_port,
                magic: 00000,
            };

            let sockaddr: *const sockaddr = bpf_probe_read_user(&(*upstream).peer.sockaddr)?;

            let sa_family = bpf_probe_read_user(&(*sockaddr).sa_family)?;

            let mut upstream_ip: u32 = 0;
            let mut upstream_port: u16 = 0;

            if sa_family == 2 {
                let socket: sockaddr_in = bpf_probe_read_user(sockaddr as *const sockaddr_in)?;
                upstream_ip = ntohl(socket.sin_addr.s_addr as u32);
                upstream_port = ntohs(socket.sin_port as u16);
            } else {
                let socket: sockaddr_in6 = bpf_probe_read_user(sockaddr as *const sockaddr_in6)?;
                upstream_port = ntohs(socket.sin6_port as u16);
            };

            if let Some(request) = LATENCY.get_ptr_mut(&connection) {
                let request = &mut (*request);
                request.upstream_ip = upstream_ip;
                request.upstream_port = upstream_port;
                request.upstream_request_first_byte_time = upstream_request_first_byte_time;
                request.upstream_request_last_byte_time = upstream_request_first_byte_time;

                LATENCY
                    .insert(&connection, &request, 2)
                    .map_err(|e| e as i64)?;
            } else {
                debug!(&ctx, "uprobe_ngx_http_upstream_send_request_body no found connection pid: {}, fd: {}, ip: {}, port: {}, start_time: {}", pid, fd, src_ip, src_port, start_time);
            }
        };
        Ok(0)
    }

    match try_ngx_http_upstream_send_request_body(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

#[uprobe]
pub fn uprobe_ngx_http_proxy_process_status_line(ctx: ProbeContext) -> u32 {
    fn try_ngx_http_proxy_process_status_line(ctx: ProbeContext) -> Result<u32, i64> {
        unsafe {
            let pid = bpf_get_current_pid_tgid() as u32;
            let upstream_response_first_byte_time = bpf_ktime_get_ns() as u64;
            let request: *const ngx_http_request_t = ctx.arg(0).ok_or(1i64)?;
            let connection: *const ngx_connection_t = bpf_probe_read_user(&(*request).connection)?;

            let (start_time, fd, src_ip, src_port) = match get_info_from_connection(connection) {
                Ok(v) => v,
                Err(e) => return Err(e),
            };

            let connection = Connection {
                start_time: start_time,
                pid: pid,
                fd: fd,
                src_ip: src_ip,
                src_port: src_port,
                magic: 00000,
            };

            if let Some(request) = LATENCY.get_ptr_mut(&connection) {
                let request = &mut (*request);
                request.upstream_response_first_byte_time = upstream_response_first_byte_time;
                LATENCY
                    .insert(&connection, &request, 2)
                    .map_err(|e| e as i64)?;
            } else {
                debug!(&ctx, "uprobe_ngx_http_proxy_process_status_line no found connection pid: {}, fd: {}, ip: {}, port: {}, start_time: {}", pid, fd, src_ip, src_port, start_time);
            }
        };
        Ok(0)
    }

    match try_ngx_http_proxy_process_status_line(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

#[uprobe]
pub fn uprobe_ngx_http_upstream_send_response(ctx: ProbeContext) -> u32 {
    fn try_ngx_http_upstream_send_response(ctx: ProbeContext) -> Result<u32, i64> {
        unsafe {
            let pid = bpf_get_current_pid_tgid() as u32;
            let downstream_response_first_byte_time = bpf_ktime_get_ns() as u64;
            let request: *const ngx_http_request_t = ctx.arg(0).ok_or(1i64)?;
            let connection: *const ngx_connection_t = bpf_probe_read_user(&(*request).connection)?;

            let (start_time, fd, src_ip, src_port) = match get_info_from_connection(connection) {
                Ok(v) => v,
                Err(e) => return Err(e),
            };

            let connection = Connection {
                start_time: start_time,
                pid: pid,
                fd: fd,
                src_ip: src_ip,
                src_port: src_port,
                magic: 00000,
            };

            if let Some(request) = LATENCY.get_ptr_mut(&connection) {
                let request = &mut (*request);
                request.downstream_response_first_byte_time = downstream_response_first_byte_time;
                LATENCY
                    .insert(&connection, &request, 2)
                    .map_err(|e| e as i64)?;
            } else {
                debug!(&ctx, "uprobe_ngx_http_upstream_send_response no found connection pid: {}, fd: {}, ip: {}, port: {}, start_time: {}", pid, fd, src_ip, src_port, start_time);
            }
        };
        Ok(0)
    }

    match try_ngx_http_upstream_send_response(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

#[uprobe]
pub fn uprobe_ngx_http_proxy_finalize_request(ctx: ProbeContext) -> u32 {
    fn try_ngx_http_proxy_finalize_request(ctx: ProbeContext) -> Result<u32, i64> {
        unsafe {
            let pid = bpf_get_current_pid_tgid() as u32;
            let upstream_response_last_byte_time = bpf_ktime_get_ns() as u64;
            let request: *const ngx_http_request_t = ctx.arg(0).ok_or(1i64)?;
            let connection: *const ngx_connection_t = bpf_probe_read_user(&(*request).connection)?;

            let (start_time, fd, src_ip, src_port) = match get_info_from_connection(connection) {
                Ok(v) => v,
                Err(e) => return Err(e),
            };

            let connection = Connection {
                start_time: start_time,
                pid: pid,
                fd: fd,
                src_ip: src_ip,
                src_port: src_port,
                magic: 00000,
            };

            if let Some(request) = LATENCY.get_ptr_mut(&connection) {
                let request = &mut (*request);
                request.upstream_response_last_byte_time = upstream_response_last_byte_time;
                LATENCY
                    .insert(&connection, &request, 2)
                    .map_err(|e| e as i64)?;
            } else {
                debug!(&ctx, "uprobe_ngx_http_proxy_finalize_request no found connection pid: {}, fd: {}, ip: {}, port: {}, start_time: {}", pid, fd, src_ip, src_port, start_time);
            }
        };
        Ok(0)
    }

    match try_ngx_http_proxy_finalize_request(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

#[uprobe]
pub fn uprobe_ngx_http_free_request(ctx: ProbeContext) -> u32 {
    fn try_ngx_http_free_request(ctx: ProbeContext) -> Result<u32, i64> {
        unsafe {
            let pid = bpf_get_current_pid_tgid() as u32;
            let downstream_response_last_byte_time = bpf_ktime_get_ns() as u64;
            let request: *const ngx_http_request_t = ctx.arg(0).ok_or(1i64)?;
            let connection: *const ngx_connection_t = bpf_probe_read_user(&(*request).connection)?;

            let (start_time, fd, src_ip, src_port) = match get_info_from_connection(connection) {
                Ok(v) => v,
                Err(e) => return Err(e),
            };
            
            let mut status = bpf_probe_read_user(&(*request).err_status)?;
            if status == 0 {
                status = bpf_probe_read_user(&(*request).headers_out.status)?;
            }         
            let request_size = bpf_probe_read_user(&(*request).request_length)?;
            let response_size = bpf_probe_read_user(&(*connection).sent)?;

            let connection = Connection {
                start_time: start_time,
                pid: pid,
                fd: fd,
                src_ip: src_ip,
                src_port: src_port,
                magic: 00000,
            };   

            if let Some(request) = LATENCY.get_ptr_mut(&connection) {
                let request = &mut (*request);
                request.response_status = status;
                request.request_size = request_size;
                request.response_size = response_size;
                request.downstream_response_last_byte_time = downstream_response_last_byte_time;
                LATENCY
                    .insert(&connection, &request, 2)
                    .map_err(|e| e as i64)?;
            } else {
                debug!(&ctx, "uprobe_ngx_http_free_request no found connection pid: {}, fd: {}, ip: {}, port: {}, start_time: {}", pid, fd, src_ip, src_port, start_time);
            }
        };
        Ok(0)
    }

    match try_ngx_http_free_request(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
