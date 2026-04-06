use clap::Args;
use std::io::Cursor;
use std::net::{Ipv4Addr, SocketAddr};

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

pub mod pool;
pub mod state;
use state::{Codec, ServerError, ServerState};

use crate::dns::{
    DnsHeader, DnsQuestion, DnsRdata, DnsResourceRecord, DNS_CLASS_IN, DNS_TYPE_NULL, DNS_TYPE_TXT,
};

const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV4_DST_OFFSET: usize = 16;
const DNS_FLAGS_RESPONSE_RA: u16 = 0x8000 | 0x0080;
const DNS_FLAGS_CLEAR_AA_MASK: u16 = !0x0200;

const PACKET_TYPE_DATA: u8 = 0;
const PACKET_TYPE_CODEC: u8 = 4;

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
    let topdomain = args
        .topdomain
        .unwrap_or_else(|| "testdomain.com".to_string())
        .trim_matches('.')
        .to_ascii_lowercase();

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
    let socket = UdpSocket::bind(bind_addr)
        .await
        .expect("failed to bind UDP socket");
    info!(%bind_addr, %topdomain, "Server listening on UDP DNS socket");

    let bootstrap_user = "default";
    let bootstrap_hash = [0u8; 16];
    let bootstrap_session_id = state.add_user(bootstrap_user.to_string(), bootstrap_hash);
    if let Err(err) = state.create_session(bootstrap_user, bootstrap_hash) {
        warn!(error = %err, "failed to create bootstrap session");
    }
    if let Err(err) = state.set_user_codec(bootstrap_session_id, Codec::Base32) {
        warn!(error = %err, "failed to set bootstrap codec");
    }

    let mut udp_buf = [0u8; 2048];
    let mut tun_buf = [0u8; 2048];
    loop {
        tokio::select! {
            recv = socket.recv_from(&mut udp_buf) => {
                match recv {
                    Ok((len, peer)) => {
                        if let Err(err) = handle_udp_packet(
                            &state,
                            &socket,
                            &mut tun_device,
                            &udp_buf[..len],
                            peer,
                            &topdomain,
                            bootstrap_session_id,
                        ).await {
                            error!(error = %err, "udp packet handler error");
                        }
                    }
                    Err(err) => error!(error = %err, "udp recv_from failed"),
                }
            }
            tun_read = tun_device.read(&mut tun_buf) => {
                match tun_read {
                    Ok(len) => {
                        if let Err(err) = handle_tun_packet(&state, &tun_buf[..len]) {
                            error!(error = %err, "tun packet handler error");
                        }
                    }
                    Err(err) => error!(error = %err, "tun read failed"),
                }
            }
        }
    }
}

async fn handle_udp_packet(
    state: &ServerState,
    socket: &UdpSocket,
    tun: &mut tun::AsyncDevice,
    packet: &[u8],
    peer: SocketAddr,
    topdomain: &str,
    fallback_session_id: u32,
) -> Result<(), ServerError> {
    debug!(bytes = packet.len(), ?peer, "Received packet");
    let mut cur = Cursor::new(packet);
    let header = DnsHeader::parse(&mut cur)
        .map_err(|e| ServerError::InvalidPacket(format!("invalid dns header: {e}")))?;
    let question = DnsQuestion::parse(&mut cur)
        .map_err(|e| ServerError::InvalidPacket(format!("invalid dns question: {e}")))?;
    if !qname_matches_topdomain(question.qname_wire, topdomain) {
        return Err(ServerError::InvalidPacket(
            "qname outside configured topdomain".to_string(),
        ));
    }

    let first_label = first_label_bytes(question.qname_wire).ok_or_else(|| {
        ServerError::InvalidPacket("dns question missing first label".to_string())
    })?;
    let (packet_type, user_id, payload_bytes) = parse_packet_type(first_label)
        .ok_or_else(|| ServerError::InvalidPacket("invalid upstream packet label".to_string()))?;

    match packet_type {
        PACKET_TYPE_CODEC => {
            let current_codec = state.user_codec_or_default(user_id, Codec::Base32);
            let decoded = crate::encoding::decode_upstream(current_codec, payload_bytes)
                .map_err(|e| ServerError::Encoding(e.to_string()))?;
            let requested = *decoded.first().ok_or_else(|| {
                ServerError::InvalidPacket("codec packet missing requested codec byte".to_string())
            })?;
            let next_codec = Codec::try_from(requested).map_err(|_| {
                ServerError::InvalidPacket("invalid requested codec id".to_string())
            })?;
            state.set_user_codec(user_id, next_codec)?;
            send_simple_txt_response(socket, peer, &header, question, b"OK").await?;
        }
        PACKET_TYPE_DATA => {
            let codec = state.user_codec_or_default(user_id, Codec::Base32);
            let decoded = crate::encoding::decode_upstream(codec, payload_bytes)
                .map_err(|e| ServerError::Encoding(e.to_string()))?;
            if decoded.len() < 2 {
                return Err(ServerError::InvalidPacket(
                    "decoded data packet too short".to_string(),
                ));
            }
            let ip_packet = &decoded[1..];
            tun.write_all(ip_packet)
                .await
                .map_err(|e| ServerError::Io(format!("tun write failed: {e}")))?;

            let downstream = state.pop_downstream_packet(fallback_session_id)?;
            send_data_response(socket, peer, &header, question, downstream).await?;
        }
        _ => {
            let downstream = state.pop_downstream_packet(fallback_session_id)?;
            send_data_response(socket, peer, &header, question, downstream).await?;
        }
    }

    Ok(())
}

fn handle_tun_packet(state: &ServerState, packet: &[u8]) -> Result<(), ServerError> {
    if packet.len() < IPV4_MIN_HEADER_LEN {
        return Ok(());
    }
    let dst_ip = Ipv4Addr::new(
        packet[IPV4_DST_OFFSET],
        packet[IPV4_DST_OFFSET + 1],
        packet[IPV4_DST_OFFSET + 2],
        packet[IPV4_DST_OFFSET + 3],
    );
    if let Some(session_id) = state.find_session_id_by_virtual_ip(dst_ip) {
        state.queue_downstream_packet(session_id, Bytes::copy_from_slice(packet))?;
    }
    Ok(())
}

async fn send_simple_txt_response(
    socket: &UdpSocket,
    peer: SocketAddr,
    header: &DnsHeader,
    question: DnsQuestion<'_>,
    payload: &[u8],
) -> Result<(), ServerError> {
    let mut response = BytesMut::with_capacity(512);
    DnsHeader {
        id: header.id,
        flags: (header.flags | DNS_FLAGS_RESPONSE_RA) & DNS_FLAGS_CLEAR_AA_MASK,
        qdcount: 1,
        ancount: 1,
        nscount: 0,
        arcount: 0,
    }
    .write_to(&mut response);
    question.write_to(&mut response);
    DnsResourceRecord {
        name_wire: question.qname_wire,
        rr_type: DNS_TYPE_TXT,
        class: DNS_CLASS_IN,
        ttl: 0,
        rdata: DnsRdata::Txt(payload),
    }
    .write_to(&mut response);
    socket
        .send_to(&response, peer)
        .await
        .map_err(|e| ServerError::Io(format!("udp send failed: {e}")))?;
    Ok(())
}

async fn send_data_response(
    socket: &UdpSocket,
    peer: SocketAddr,
    header: &DnsHeader,
    question: DnsQuestion<'_>,
    downstream: Option<Bytes>,
) -> Result<(), ServerError> {
    let mut response = BytesMut::with_capacity(2048);
    let answer_count = if downstream.is_some() { 1 } else { 0 };
    DnsHeader {
        id: header.id,
        flags: (header.flags | DNS_FLAGS_RESPONSE_RA) & DNS_FLAGS_CLEAR_AA_MASK,
        qdcount: 1,
        ancount: answer_count,
        nscount: 0,
        arcount: 0,
    }
    .write_to(&mut response);
    question.write_to(&mut response);
    if let Some(downstream_packet) = downstream {
        let encoded = crate::encoding::base64::encode(&downstream_packet);
        let rr_type = if question.qtype == DNS_TYPE_TXT {
            DNS_TYPE_TXT
        } else {
            DNS_TYPE_NULL
        };
        DnsResourceRecord {
            name_wire: question.qname_wire,
            rr_type,
            class: DNS_CLASS_IN,
            ttl: 0,
            rdata: if rr_type == DNS_TYPE_TXT {
                DnsRdata::Txt(encoded.as_bytes())
            } else {
                DnsRdata::Null(encoded.as_bytes())
            },
        }
        .write_to(&mut response);
    }
    socket
        .send_to(&response, peer)
        .await
        .map_err(|e| ServerError::Io(format!("udp send failed: {e}")))?;
    Ok(())
}

fn parse_packet_type(first_label: &[u8]) -> Option<(u8, u32, &[u8])> {
    let (&lead, payload) = first_label.split_first()?;
    let packet_type = (lead >> 4) & 0x0f;
    let user_id = (lead & 0x0f) as u32;
    Some((packet_type, user_id, payload))
}

fn first_label_bytes(qname_wire: &[u8]) -> Option<&[u8]> {
    let len = *qname_wire.first()? as usize;
    if len == 0 || qname_wire.len() < len + 1 {
        return None;
    }
    Some(&qname_wire[1..=len])
}

fn qname_matches_topdomain(qname_wire: &[u8], topdomain: &str) -> bool {
    let qname = qname_to_string(qname_wire);
    if qname.is_empty() {
        return false;
    }
    let qname = qname.to_ascii_lowercase();
    qname == topdomain || qname.ends_with(&format!(".{topdomain}"))
}

fn qname_to_string(qname_wire: &[u8]) -> String {
    let mut labels = Vec::new();
    let mut pos = 0usize;
    while pos < qname_wire.len() {
        let len = qname_wire[pos] as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if pos + len > qname_wire.len() {
            break;
        }
        labels.push(String::from_utf8_lossy(&qname_wire[pos..pos + len]).to_string());
        pos += len;
    }
    labels.join(".")
}
