#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings;

use core::{cmp};
use aya_log_ebpf::info;

use bindings::{
    ngx_http_request_t,
    NGX_HTTP_MODULE
};

use aya_ebpf::{
    macros::{uprobe, map},
    programs::ProbeContext,
    helpers::*,
    bindings::{BPF_F_USER_STACK},
    maps::*,
};

#[map]
static STACK_TRACES: StackTrace = StackTrace::with_max_entries(127, 0);

#[map]
static STACKS: Queue<[u64; 1]> = Queue::with_max_entries(1024, 0);

#[uprobe]
pub fn nginx_with_ebpf(ctx: ProbeContext) -> u32 {
    match try_nginx_with_ebpf(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

fn try_nginx_with_ebpf(ctx: ProbeContext) -> Result<u32, i64> {
    let request: *const ngx_http_request_t = ctx.arg(0).ok_or(1i64)?;
    let signature = unsafe {
        bpf_probe_read_user(&(*request).signature).map_err(|e| e)?
    };

    if signature != NGX_HTTP_MODULE {
        return Ok(0);
    }

    unsafe {
        let uri = bpf_probe_read_user(&(*request).uri)?;
        if uri.len > 1 {
            let mut buf = [0u8; 128];
            let len = cmp::min(uri.len as usize, buf.len());
            bpf_probe_read_user_buf(uri.data as *const u8, &mut buf[..len])?;
            let uri = core::str::from_utf8_unchecked(&buf);
            info!(&ctx, "uprobe function called for request: {}", uri);

            //let s = core::str::from_utf8_unchecked(slice::from_raw_parts(uri.data, uri.len as usize));
            //let s = core::str::from_utf8_unchecked(bpf_probe_read_user_buf(
                        //uri.data as *const u8,
                        //&mut buf));
        }

        if let Ok(ustack) = STACK_TRACES.get_stackid(&ctx, BPF_F_USER_STACK.into()) {
            if let Err(e) = STACKS.push(&[ustack as _], 0) {
                info!(&ctx, "Error pushing stack: {}", e);
            }
        }
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
