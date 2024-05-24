#[allow(unused_imports)]
use aya::programs::UProbe;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use color_eyre::Result;
use log::{info, warn, debug};
use sysinfo::{PidExt, ProcessExt, SystemExt};

use crate::Opts;

pub fn attach_bpf(opts: &Opts) -> Result<Bpf> {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };

    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/nginx-with-ebpf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/nginx-with-ebpf"
    ))?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let pid = {
        if let Some(pid) = opts.pid {
            pid
        } else {
            let mut system = sysinfo::System::new();
            system.refresh_all();
            let procs: Vec<_> = system.processes_by_name("nginx").collect();
            if procs.len() != 1 {
                log::warn!("There is more than 1 nginx processes");
                for p in procs {
                    log::warn!("{} {}", p.pid(), p.name());
                }
                return Err(color_eyre::eyre::eyre!(
                    "There is 0 more than 1 nginx processes"
                ));
            }
            procs[0].pid().as_u32() as i32
        }
    };

    let target = format!("/proc/{}/exe", pid);

    let program: &mut UProbe = bpf
        .program_mut("uprobe_ngx_http_init_connection")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach(Some("ngx_http_init_connection"), 0, &target, opts.pid)?;

    let program: &mut UProbe = bpf
        .program_mut("uretprobe_ngx_http_alloc_request")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach(Some("ngx_http_alloc_request"), 0, &target, opts.pid)?;

    let program: &mut UProbe = bpf
        .program_mut("uretprobe_ngx_http_parse_request_line")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach(Some("ngx_http_parse_request_line"), 0, &target, opts.pid)?;

    let program: &mut UProbe = bpf
    .program_mut("uretprobe_ngx_http_read_request_header")
    .unwrap()
    .try_into()?;
    program.load()?;
    program.attach(Some("ngx_http_read_request_header"), 0, &target, opts.pid)?;

    let program: &mut UProbe = bpf
        .program_mut("uprobe_ngx_http_upstream_connect")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach(Some("ngx_http_upstream_connect"), 0, &target, opts.pid)?;

    let program: &mut UProbe = bpf
        .program_mut("uprobe_ngx_http_upstream_send_request_body")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach(Some("ngx_http_upstream_send_request_body"), 0, &target, opts.pid)?;

    let program: &mut UProbe = bpf
        .program_mut("uprobe_ngx_http_upstream_send_response")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach(Some("ngx_http_upstream_send_response"), 0, &target, opts.pid)?;

    let program: &mut UProbe = bpf
        .program_mut("uprobe_ngx_http_proxy_process_status_line")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach(Some("ngx_http_proxy_process_status_line"), 0, &target, opts.pid)?;

    let program: &mut UProbe = bpf
        .program_mut("uprobe_ngx_http_proxy_finalize_request")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach(Some("ngx_http_proxy_finalize_request"), 0, &target, opts.pid)?;

    let program: &mut UProbe = bpf
        .program_mut("uprobe_ngx_http_free_request")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach(Some("ngx_http_free_request"), 0, &target, opts.pid)?;

    Ok(bpf)
}
