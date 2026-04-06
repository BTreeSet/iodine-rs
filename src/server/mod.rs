use clap::Args;
use std::net::{Ipv4Addr, SocketAddr};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tracing::{debug, warn};

pub mod pool;
pub mod state;
use state::ServerState;

const DNS_HEADER_LEN: usize = 12;
const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV4_DST_OFFSET: usize = 16;

#[derive(Debug, Clone, Args)]
pub struct ServerArgs {
    #[arg(long)]
    pub topdomain: Option<String>,
    #[arg(long)]
    pub bind_addr: Option<String>,
}

pub async fn run(args: ServerArgs) {
    let bind_addr: SocketAddr = args
        .bind_addr
        .as_deref()
        .unwrap_or("0.0.0.0:53")
        .parse()
        .expect("bind_addr must be a valid socket address");

    let state = ServerState::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(255, 255, 255, 0));
    let mut tun_device = crate::tun::create_tun_device(
        "iodine0",
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(255, 255, 255, 0),
        1500,
    )
    .expect("failed to create tun device");
    let socket = UdpSocket::bind(bind_addr)
        .await
        .expect("failed to bind UDP socket");

    let mut udp_buf = [0u8; 2048];
    let mut tun_buf = [0u8; 2048];

    loop {
        tokio::select! {
            recv = socket.recv_from(&mut udp_buf) => {
                let (len, peer) = match recv {
                    Ok(v) => v,
                    Err(err) => {
                        warn!(error = %err, "udp recv_from failed");
                        continue;
                    }
                };
                let packet = &udp_buf[..len];
                let _validation_header = {
                    let mut cur = std::io::Cursor::new(packet);
                    match crate::dns::DnsHeader::parse(&mut cur) {
                        Ok(header) => header,
                        Err(err) => {
                            debug!(error = %err, "invalid dns header");
                            continue;
                        }
                    }
                };

                if let Some(cached_response) = state.check_cache(packet) {
                    if let Err(err) = socket.send_to(&cached_response, peer).await {
                        warn!(error = %err, "udp send_to cached response failed");
                    }
                    continue;
                }

                let query_key = packet.to_vec();
                let response = Bytes::copy_from_slice(packet);
                state.put_cache(query_key, response.clone());
                if let Err(err) = socket.send_to(&response, peer).await {
                    warn!(error = %err, "udp send_to response failed");
                    continue;
                }

                // Placeholder tunnel payload extraction starts immediately after DNS header.
                if packet.len() > DNS_HEADER_LEN {
                    let payload = &packet[DNS_HEADER_LEN..];
                    if !payload.is_empty() {
                        if let Err(err) = tun_device.write_all(payload).await {
                            warn!(error = %err, "tun write_all failed");
                        }
                    }
                }
            }
            tun_read = tun_device.read(&mut tun_buf) => {
                let len = match tun_read {
                    Ok(v) => v,
                    Err(err) => {
                        warn!(error = %err, "tun read failed");
                        continue;
                    }
                };
                // IPv4 minimum header is 20 bytes; destination address is at bytes 16..20.
                if len < IPV4_MIN_HEADER_LEN {
                    continue;
                }
                let dst_ip = Ipv4Addr::new(
                    tun_buf[IPV4_DST_OFFSET],
                    tun_buf[IPV4_DST_OFFSET + 1],
                    tun_buf[IPV4_DST_OFFSET + 2],
                    tun_buf[IPV4_DST_OFFSET + 3],
                );
                let packet = Bytes::copy_from_slice(&tun_buf[..len]);
                if let Some(session_id) = state.find_session_id_by_virtual_ip(dst_ip) {
                    let _ = state.queue_downstream_packet(session_id, packet);
                }
            }
        }
    }
}
