mod symbol;

use aya::programs::UProbe;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::{signal};
use aya::maps::{Queue,StackTraceMap};
use std::{thread, time};
use symbol::Resolver;


#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, value_name = "pid", help = "nginx worker pid to uprobe", required = true)]
    pid: Option<i32>,
    #[clap(short, long, value_name = "uprobe", help = "http function to uprobe", required = true)]
    uprobe: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/nginx_with_ebpf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/nginx_with_ebpf"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut UProbe = bpf.program_mut("nginx_with_ebpf").unwrap().try_into()?;

    let pid = opt.pid.unwrap() as u32;
    let path = format!("/proc/{}/exe", pid);

    program.load()?;
    program.attach(opt.uprobe.as_ref().map(String::as_ref), 0, path, opt.pid.try_into()?)?;

    let mut stacks = Queue::<_, [u64; 1]>::try_from(bpf.map_mut("STACKS")?)?;
    let stack_traces = StackTraceMap::try_from(bpf.map_mut("STACK_TRACES")?)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Received Ctrl-C\n");

    let symbol_resolver = Resolver::new();

    match stacks.pop(0) {
        Ok([utrace_id]) => {
            let user_stack = stack_traces.get(&(utrace_id as u32), 0)?;
            let user_frames = symbol_resolver.resolve(
                pid,
                &user_stack
                    .frames()
                    .iter()
                    .map(|f| f.ip as usize)
                    .collect::<Vec<_>>(),
            )?;
            for (addr, symbol) in user_frames {
                info!("stack {:#x} {}", addr, symbol.unwrap_or("[unknown symbol name]".to_string()));
            }
        }
        Err(_) => {
            thread::sleep(time::Duration::from_millis(1000));
        }
    }

    info!("Exiting...");

    Ok(())
}
