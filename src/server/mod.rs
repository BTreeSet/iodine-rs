use clap::Args;
use std::io::Cursor;
use std::net::{Ipv4Addr, SocketAddr};

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tracing::warn;

pub mod pool;
pub mod state;
use state::{ServerError, ServerState};

use crate::dns::{
    DnsHeader, DnsQuestion, DnsRdata, DnsResourceRecord, DNS_CLASS_IN, DNS_TYPE_NULL, DNS_TYPE_TXT,
};

const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV4_DST_OFFSET: usize = 16;

#[derive(Debug, Clone, Args)]
pub struct ServerArgs {
    #[arg(long)]
    pub topdomain: Option<String>,
    #[arg(long)]
    pub bind_addr: Option<String>,
    #[arg(long, default_value = "10.0.0.1")]
    pub tun_ip: String,
    #[arg(long, default_value = "10.0.0.0")]
    pub tun_network: String,
    #[arg(long, default_value = "255.255.255.0")]
    pub tun_netmask: String,
}

pub async fn run(args: ServerArgs) {
    let bind_addr: SocketAddr = args
        .bind_addr
        .as_deref()
        .unwrap_or("0.0.0.0:53")
        .parse()
        .expect("bind_addr must be a valid socket address");
    let tun_ip: Ipv4Addr = args
        .tun_ip
        .parse()
        .expect("tun_ip must be a valid IPv4 address");
    let tun_network: Ipv4Addr = args
        .tun_network
        .parse()
        .expect("tun_network must be a valid IPv4 address");
    let tun_netmask: Ipv4Addr = args
        .tun_netmask
        .parse()
        .expect("tun_netmask must be a valid IPv4 address");

    let state = ServerState::new(tun_network, tun_netmask);
    let mut tun_device = crate::tun::create_tun_device("iodine0", tun_ip, tun_netmask, 1500)
        .expect("failed to create tun device");
    let bootstrap_user = "default";
    let bootstrap_hash = [0u8; 16];
    let bootstrap_session_id = state.add_user(bootstrap_user.to_string(), bootstrap_hash);
    if let Err(err) = state.create_session(bootstrap_user, bootstrap_hash) {
        warn!(error = %err, "failed to create bootstrap session");
    }
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
                let mut cur = Cursor::new(packet);
                let header = match DnsHeader::parse(&mut cur) {
                    Ok(header) => header,
                    Err(err) => {
                        warn!(error = %err, "invalid dns header");
                        continue;
                    }
                };
                let question = match DnsQuestion::parse(&mut cur) {
                    Ok(question) => question,
                    Err(err) => {
                        warn!(error = %err, "invalid dns question");
                        continue;
                    }
                };

                let first_label = match first_label_bytes(question.qname_wire) {
                    Some(label) => label,
                    None => {
                        warn!("dns question missing first label");
                        continue;
                    }
                };
                let upstream_packet = match crate::encoding::base32::decode_bytes(first_label) {
                    Ok(data) => data,
                    Err(err) => {
                        warn!(error = %err, "failed to decode upstream base32 payload");
                        continue;
                    }
                };
                if !upstream_packet.is_empty() {
                    if let Err(err) = tun_device.write_all(&upstream_packet).await {
                        warn!(error = %err, "tun write_all failed");
                        continue;
                    }
                }

                let downstream = match state.pop_downstream_packet(bootstrap_session_id) {
                    Ok(packet) => packet,
                    Err(ServerError::SessionNotFound) => {
                        warn!("session not found while dequeuing downstream packet");
                        continue;
                    }
                    Err(err) => {
                        warn!(error = %err, "failed to dequeue downstream packet");
                        continue;
                    }
                };

                let mut response = BytesMut::with_capacity(2048);
                let answer_count = if downstream.is_some() { 1 } else { 0 };
                let response_header = DnsHeader {
                    id: header.id,
                    flags: (header.flags | 0x8000 | 0x0080) & !0x0200,
                    qdcount: 1,
                    ancount: answer_count,
                    nscount: 0,
                    arcount: 0,
                };
                response_header.write_to(&mut response);
                question.write_to(&mut response);

                if let Some(downstream_packet) = downstream {
                    let encoded = crate::encoding::base64::encode(&downstream_packet);
                    let rr_type = if question.qtype == DNS_TYPE_TXT {
                        DNS_TYPE_TXT
                    } else {
                        DNS_TYPE_NULL
                    };
                    let rr = DnsResourceRecord {
                        name_wire: question.qname_wire,
                        rr_type,
                        class: DNS_CLASS_IN,
                        ttl: 0,
                        rdata: if rr_type == DNS_TYPE_TXT {
                            DnsRdata::Txt(encoded.as_bytes())
                        } else {
                            DnsRdata::Null(encoded.as_bytes())
                        },
                    };
                    rr.write_to(&mut response);
                }

                if let Err(err) = socket.send_to(&response, peer).await {
                    warn!(error = %err, "udp send_to response failed");
                    continue;
                }

                state.put_cache(packet.to_vec(), Bytes::copy_from_slice(&response));
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
                    if let Err(err) = state.queue_downstream_packet(session_id, packet) {
                        warn!(error = %err, session_id, "failed to queue downstream packet");
                    }
                }
            }
        }
    }
}

fn first_label_bytes(qname_wire: &[u8]) -> Option<&[u8]> {
    let len = *qname_wire.first()? as usize;
    if len == 0 || qname_wire.len() < len + 1 {
        return None;
    }
    Some(&qname_wire[1..=len])
}
