mod ebpf;
mod symbol;

use aya::maps::{HashMap, MapData, Queue};
use aya::programs::UProbe;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::Parser;
use color_eyre::eyre::ContextCompat;
use color_eyre::Result;
use log::{debug, info, warn};
#[allow(unused_imports)]
use nginx_with_ebpf_common::Connection;
use nginx_with_ebpf_common::Request;
use std::convert::TryFrom;
use std::{net, str, thread, time};
use symbol::Resolver;
use tokio::{signal, task};

#[derive(Debug, Parser)]
struct Opts {
    #[clap(
        short,
        long,
        value_name = "pid",
        help = "nginx worker pid to uprobe",
        required = true
    )]
    pid: Option<i32>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    color_eyre::install()?;

    let opt = Opts::parse();

    let mut bpf = ebpf::attach_bpf(&opt)?;

    tokio::task::spawn(async move {
        loop {
            let mut latency: HashMap<_, Connection, Request> =
                HashMap::try_from(bpf.map_mut("LATENCY").unwrap()).unwrap();

            for entry in latency.iter() {
                match entry {
                    Ok((connection, request)) => {
                        let client_ip = net::Ipv4Addr::from(connection.src_ip);
                        let client_port = connection.src_port;
                        let upstream_ip = net::Ipv4Addr::from(request.upstream_ip);
                        let upstream_port = request.upstream_port;
                        let request_uri = str::from_utf8(&request.request_uri).unwrap();
                        let status = request.response_status;
                        let request_size = request.request_size;
                        let response_size = request.response_size;
                        let accept_time = request.downstream_accept_time;
                        let downstream_request_first_byte_time = request
                            .downstream_request_first_byte_time
                            - request.downstream_accept_time;
                        let downstream_request_last_byte_time = request
                            .downstream_request_last_byte_time
                            - request.downstream_accept_time;
                        let upstream_connect_time =
                            request.upstream_connect_time - request.downstream_accept_time;
                        let upstream_request_first_byte_time = request
                            .upstream_request_first_byte_time
                            - request.downstream_accept_time;
                        let upstream_request_last_byte_time = request
                            .upstream_request_last_byte_time
                            - request.downstream_accept_time;
                        let upstream_response_first_byte_time = request
                            .upstream_response_first_byte_time
                            - request.downstream_accept_time;
                        let upstream_response_last_byte_time = request
                            .upstream_response_last_byte_time
                            - request.downstream_accept_time;
                        let downstream_response_first_byte_time = request
                            .downstream_response_first_byte_time
                            - request.downstream_accept_time;
                        let downstream_response_last_byte_time = request
                            .downstream_response_last_byte_time
                            - request.downstream_accept_time;

                        info!("{}, {}:{}=>{}:{}, {}, {}, request_size={}, response_size={}, downstream_request_first_byte_time={}, downstream_request_last_byte_time={}, upstream_connect_time={}, upstream_request_first_byte_time={}, upstream_request_last_byte_time={}, upstream_response_first_byte_time={}, upstream_response_last_byte_time={}, downstream_response_first_byte_time={}, downstream_response_last_byte_time={}", accept_time, client_ip, client_port, upstream_ip, upstream_port, request_uri, status, request_size, response_size, downstream_request_first_byte_time, downstream_request_last_byte_time, upstream_connect_time, upstream_request_first_byte_time, upstream_request_last_byte_time, upstream_response_first_byte_time, upstream_response_last_byte_time, downstream_response_first_byte_time, downstream_response_last_byte_time);
                    }
                    Err(e) => warn!("Error: {}", e),
                }
            }

            let connections = latency.keys().flatten().collect::<Vec<_>>();
            for connection in connections {
                let _ = latency.remove(&connection);
            }

            tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        }
    });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
