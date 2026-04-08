//! Protocol 0x00000502 compatibility notes (derived from upstream `common.h` + `iodined.c`):
//! - Raw command nibble values in the framed header are:
//!   - LOGIN: `0x10` (`RAW_HDR_CMD_LOGIN`)
//!   - DATA:  `0x20` (`RAW_HDR_CMD_DATA`)
//!   - PING:  `0x30` (`RAW_HDR_CMD_PING`)
//!   - userid is low nibble of the command byte (`RAW_HDR_USR_MASK`).
//! - For DNS query handling under the tunnel topdomain, upstream first dispatches control/handshake probes
//!   (`Y`, `V`, `L`, `P`, etc.) before attempting regular upstream payload processing.
//! - During autodetect, client sends probe names (e.g. `y<codec><variant><cmc>.topdomain`) and expects a
//!   syntactically valid answer RR in the same qtype family, never silence/empty-answer.
//! - Upstream favors “answer something valid” for topdomain-matching traffic (including duplicate/illegal
//!   query memory fallback replying `"x"`), because silence causes resolver/client retries and autodetect failure.
//! - Version/login flow:
//!   - `V<base32(version)>` => `VACK<seed><userid>` when version matches, otherwise `VNAK<protocol><0>`.
//!   - `L<base32(userid|md5(password,seed)|...)>` verifies login hash and then returns `serverip-clientip-mtu-prefix`.
//! - Ping flow:
//!   - `P<...>` acts as keepalive + downstream ACK carrier and must return a valid response packet.
//!   - Minimal compatibility for this server is to parse + acknowledge with a valid downstream response RR.
use clap::Args;
use flate2::read::ZlibDecoder;
use std::collections::HashMap;
use std::io::Cursor;
use std::io::Read;
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
use crate::encoding::framing::UpstreamHeader;
use crate::protocol::{
    DNS_PACKET_BUFFER_SIZE, PACKET_TYPE_CODEC, PACKET_TYPE_CODEC_CHECK, PACKET_TYPE_ECHO,
    PACKET_TYPE_ENCODING, PACKET_TYPE_FRAG_ACK, PACKET_TYPE_FRAG_SIZE, PACKET_TYPE_IP,
    PACKET_PREFIX_VACK, PACKET_TYPE_LOGIN, PACKET_TYPE_PING, PACKET_TYPE_VERSION,
    PROTOCOL_VERSION,
};

const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV4_DST_OFFSET: usize = 16;
const DNS_FLAGS_RESPONSE_RA: u16 = 0x8000 | 0x0080;
const DNS_FLAGS_CLEAR_AA_MASK: u16 = !0x0200;
const CONTROL_BADLEN: &[u8] = b"BADLEN";
const MAX_HANDSHAKE_USERID: u8 = 15;
const DOWNCODECCHECK1: &[u8] = b"\x00\x00\x00\x00\xFF\xFF\xFF\xFF\x55\x55\x55\x55\xAA\xAA\xAA\xAA\
\x81\x63\xC8\xD2\xC7\x7C\xB2\x17\x5F\x4F\xCE\xC9\x49\x2D\x52\x21\
\x61\xA9\x71\x20\x25\xB3\x06\x73\xE6\xD8\x44\x30\x79\x50\x57\xBF";

const DOWNSTREAM_FRAGMENT_SIZE: usize = 360;

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
    let password = std::env::var("IODINE_PASSWORD")
        .expect("IODINE_PASSWORD must be set for protocol-compatible login handling");

    let state = ServerState::new(tun_network, tun_netmask);
    let mut tun_device = crate::tun::create_tun_device("iodine0", tun_ip, tun_netmask, 1500)
        .expect("failed to create tun device");
    let socket = UdpSocket::bind(bind_addr)
        .await
        .expect("failed to bind UDP socket");
    info!(%bind_addr, %topdomain, "Server listening on UDP DNS socket");

    let mut udp_buf = [0u8; DNS_PACKET_BUFFER_SIZE];
    let mut tun_buf = [0u8; DNS_PACKET_BUFFER_SIZE];
    let mut handshake = HandshakeState::default();
    let udp_ctx = UdpContext {
        topdomain_labels: split_topdomain_labels(&topdomain),
        password,
        tun_ip,
        tun_netmask,
    };

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
                            &udp_ctx,
                            &mut handshake,
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
                        if let Err(err) = handle_tun_packet(&state, &tun_buf[..len]).await {
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
    ctx: &UdpContext,
    handshake: &mut HandshakeState,
) -> Result<(), ServerError> {
    debug!(bytes = packet.len(), ?peer, "Received packet");
    let mut cur = Cursor::new(packet);
    let header = DnsHeader::parse(&mut cur)
        .map_err(|e| ServerError::InvalidPacket(format!("invalid dns header: {e}")))?;
    let question = DnsQuestion::parse(&mut cur)
        .map_err(|e| ServerError::InvalidPacket(format!("invalid dns question: {e}")))?;

    if !qname_matches_topdomain(question.qname_wire, &ctx.topdomain_labels) {
        return Ok(());
    }
    let query_prefix =
        qname_data_prefix(question.qname_wire, &ctx.topdomain_labels).unwrap_or_default();

    let first_label = first_label_bytes(question.qname_wire).ok_or_else(|| {
        ServerError::InvalidPacket("dns question missing first label".to_string())
    })?;

    if let Some(control_response) = handle_control_request(
        ControlQuery {
            first_label,
            query_data_prefix: &query_prefix,
            request_qtype: question.qtype,
        },
        state,
        handshake,
        &ctx.password,
        ctx.tun_ip,
        ctx.tun_netmask,
    )
    .await
    {
        send_rr_response(
            socket,
            peer,
            &header,
            question,
            control_response.rr_type,
            &control_response.payload,
        )
        .await?;
        return Ok(());
    }

    let Some(packet) = parse_upstream_query(&query_prefix) else {
        send_probe_fallback_response(socket, peer, &header, question).await?;
        return Ok(());
    };

    match packet {
        UpstreamQuery::Ping {
            user_id,
            down_seq,
            down_frag,
        } => {
            handle_ping_packet(
                state, socket, peer, &header, question, handshake, user_id, down_seq, down_frag,
            )
            .await?;
        }
        UpstreamQuery::Data {
            user_id,
            up_seq,
            up_frag,
            down_seq,
            down_frag,
            last_frag,
            encoded_payload,
        } => {
            handle_data_packet(
                state,
                socket,
                tun,
                peer,
                &header,
                question,
                handshake,
                user_id,
                up_seq,
                up_frag,
                down_seq,
                down_frag,
                last_frag,
                encoded_payload,
            )
            .await?;
        }
    }

    Ok(())
}

fn session_id_for(handshake: &HandshakeState, user_id: u32) -> u32 {
    handshake
        .session_id_by_handshake_user
        .get(&user_id)
        .copied()
        .unwrap_or(user_id)
}

#[allow(clippy::too_many_arguments)]
async fn handle_ping_packet(
    state: &ServerState,
    socket: &UdpSocket,
    peer: SocketAddr,
    header: &DnsHeader,
    question: DnsQuestion<'_>,
    handshake: &HandshakeState,
    user_id: u32,
    down_seq: u8,
    down_frag: u8,
) -> Result<(), ServerError> {
    let session_id = session_id_for(handshake, user_id);
    let _ = state.process_downstream_ack(session_id, down_seq, down_frag);
    send_data_response(socket, peer, header, question, state, session_id).await
}

#[allow(clippy::too_many_arguments)]
async fn handle_data_packet(
    state: &ServerState,
    socket: &UdpSocket,
    tun: &mut tun::AsyncDevice,
    peer: SocketAddr,
    header: &DnsHeader,
    question: DnsQuestion<'_>,
    handshake: &HandshakeState,
    user_id: u32,
    up_seq: u8,
    up_frag: u8,
    down_seq: u8,
    down_frag: u8,
    last_frag: bool,
    encoded_payload: &[u8],
) -> Result<(), ServerError> {
    let session_id = session_id_for(handshake, user_id);
    let codec = state.user_codec_or_default(session_id, Codec::Base32);
    let decoded =
        decode_upstream_payload(codec, encoded_payload).map_err(|e| ServerError::Encoding(e.to_string()))?;
    let _ = state.process_downstream_ack(session_id, down_seq, down_frag);
    let assembled = state.push_upstream_fragment(session_id, up_seq, up_frag, &decoded, last_frag);
    let Ok(Some(compressed_packet)) = assembled else {
        send_data_response(socket, peer, header, question, state, session_id).await?;
        return Ok(());
    };
    let mut decoder = ZlibDecoder::new(&compressed_packet[..]);
    let mut inflated = Vec::new();
    decoder
        .read_to_end(&mut inflated)
        .map_err(|e| ServerError::InvalidPacket(format!("zlib decode failed: {e}")))?;
    let packet = strip_tun_pi_if_present(&inflated);
    let ip_version = packet.first().map(|b| b >> 4).unwrap_or(0);
    if ip_version != 4 {
        debug!(session_id, ip_version, "dropping non-ipv4 upstream packet");
        send_data_response(socket, peer, header, question, state, session_id).await?;
        return Ok(());
    }
    tun.write_all(packet)
        .await
        .map_err(|e| ServerError::Io(format!("tun write failed: {e}")))?;
    send_data_response(socket, peer, header, question, state, session_id).await
}

async fn handle_tun_packet(state: &ServerState, packet: &[u8]) -> Result<(), ServerError> {
    if packet.len() < IPV4_MIN_HEADER_LEN {
        debug!(len = packet.len(), "ignoring short tun packet");
        return Ok(());
    }
    if (packet[0] >> 4) != 4 {
        debug!(len = packet.len(), "ignoring non-ipv4 tun packet");
        return Ok(());
    }
    let dst_ip = Ipv4Addr::new(
        packet[IPV4_DST_OFFSET],
        packet[IPV4_DST_OFFSET + 1],
        packet[IPV4_DST_OFFSET + 2],
        packet[IPV4_DST_OFFSET + 3],
    );
    if let Some(session_id) = state.find_session_id_by_virtual_ip(dst_ip) {
        let out_packet = if state.use_tun_pi(session_id).unwrap_or(false) {
            let mut with_pi = Vec::with_capacity(packet.len() + 4);
            with_pi.extend_from_slice(&[0x00, 0x00, 0x08, 0x00]);
            with_pi.extend_from_slice(packet);
            with_pi
        } else {
            packet.to_vec()
        };
        state.queue_downstream_packet(session_id, Bytes::from(out_packet))?;
    }
    Ok(())
}

async fn send_probe_fallback_response(
    socket: &UdpSocket,
    peer: SocketAddr,
    header: &DnsHeader,
    question: DnsQuestion<'_>,
) -> Result<(), ServerError> {
    let rr_type = if question.qtype == DNS_TYPE_TXT {
        DNS_TYPE_TXT
    } else {
        DNS_TYPE_NULL
    };
    send_rr_response(socket, peer, header, question, rr_type, b"x").await
}

async fn send_rr_response(
    socket: &UdpSocket,
    peer: SocketAddr,
    header: &DnsHeader,
    question: DnsQuestion<'_>,
    rr_type: u16,
    payload: &[u8],
) -> Result<(), ServerError> {
    let mut response = BytesMut::with_capacity(1024);
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
        rr_type,
        class: DNS_CLASS_IN,
        ttl: 0,
        rdata: control_rdata(rr_type, payload),
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
    state: &ServerState,
    user_id: u32,
) -> Result<(), ServerError> {
    let (up_ack_seq, up_ack_frag) = state.upstream_ack(user_id).unwrap_or((0, 0));
    let payload = state
        .build_downstream_packet(user_id, DOWNSTREAM_FRAGMENT_SIZE, up_ack_seq, up_ack_frag)
        .unwrap_or_else(|_| vec![0x80, 0x00]);
    if question.qtype == DNS_TYPE_TXT {
        let encoded = crate::encoding::base32::encode(&payload);
        let mut txt_payload = Vec::with_capacity(encoded.len() + 1);
        txt_payload.push(b't');
        txt_payload.extend_from_slice(encoded.as_bytes());
        send_rr_response(socket, peer, header, question, DNS_TYPE_TXT, &txt_payload).await
    } else {
        send_rr_response(socket, peer, header, question, DNS_TYPE_NULL, &payload).await
    }
}

#[derive(Debug)]
enum UpstreamQuery<'a> {
    Ping {
        user_id: u32,
        down_seq: u8,
        down_frag: u8,
    },
    Data {
        user_id: u32,
        up_seq: u8,
        up_frag: u8,
        down_seq: u8,
        down_frag: u8,
        last_frag: bool,
        encoded_payload: &'a [u8],
    },
}

fn parse_upstream_query(data: &[u8]) -> Option<UpstreamQuery<'_>> {
    let (&first, rest) = data.split_first()?;
    if first.eq_ignore_ascii_case(&PACKET_TYPE_PING) {
        let decoded = decode_upstream_payload(Codec::Base32, rest).ok()?;
        if decoded.len() < 2 {
            return None;
        }
        let user_id = decoded[0] as u32;
        let (down_seq, down_frag) = UpstreamHeader::parse_ack_byte(decoded[1]);
        return Some(UpstreamQuery::Ping {
            user_id,
            down_seq,
            down_frag,
        });
    }
    let user_id = hex_nibble(first)? as u32;
    if data.len() < 6 {
        return None;
    }
    let packed = UpstreamHeader::parse_encoded([data[1], data[2], data[3]])?;
    Some(UpstreamQuery::Data {
        user_id,
        up_seq: packed.up_seq,
        up_frag: packed.up_frag,
        down_seq: packed.down_seq,
        down_frag: packed.down_frag,
        last_frag: packed.last_frag,
        encoded_payload: &data[5..],
    })
}

fn decode_upstream_payload(
    codec: Codec,
    payload: &[u8],
) -> Result<Bytes, crate::encoding::EncodingError> {
    let non_dot_len = payload.iter().filter(|b| **b != b'.').count();
    let mut undotified = BytesMut::with_capacity(non_dot_len);
    undotified.extend(payload.iter().copied().filter(|b| *b != b'.'));
    crate::encoding::decode_upstream(codec, &undotified)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn strip_tun_pi_if_present(packet: &[u8]) -> &[u8] {
    if packet.len() >= 5
        && packet[0] == 0x00
        && packet[1] == 0x00
        // EtherType values in TUN_PI: 0x0800 (IPv4), 0x86DD (IPv6).
        && ((packet[2] == 0x08 && packet[3] == 0x00) || (packet[2] == 0x86 && packet[3] == 0xdd))
        && ((packet[4] >> 4) == 4 || (packet[4] >> 4) == 6)
    {
        &packet[4..]
    } else {
        packet
    }
}

fn first_label_bytes(qname_wire: &[u8]) -> Option<&[u8]> {
    let len = *qname_wire.first()? as usize;
    if len == 0 || qname_wire.len() < len + 1 {
        return None;
    }
    Some(&qname_wire[1..=len])
}

fn parse_qname_labels(qname_wire: &[u8]) -> Option<Vec<&[u8]>> {
    let mut labels = Vec::new();
    let mut pos = 0usize;
    loop {
        let len = *qname_wire.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            return Some(labels);
        }
        if len > 63 || pos + len > qname_wire.len() {
            return None;
        }
        labels.push(&qname_wire[pos..pos + len]);
        pos += len;
    }
}

fn split_topdomain_labels(topdomain: &str) -> Vec<Vec<u8>> {
    topdomain
        .split('.')
        .filter(|label| !label.is_empty())
        .map(|label| label.as_bytes().to_vec())
        .collect()
}

fn qname_matches_topdomain(qname_wire: &[u8], topdomain_labels: &[Vec<u8>]) -> bool {
    let Some(labels) = parse_qname_labels(qname_wire) else {
        return false;
    };
    labels.len() >= topdomain_labels.len()
        && labels[labels.len() - topdomain_labels.len()..]
            .iter()
            .zip(topdomain_labels)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn qname_data_prefix(qname_wire: &[u8], topdomain_labels: &[Vec<u8>]) -> Option<Vec<u8>> {
    let labels = parse_qname_labels(qname_wire)?;
    if labels.len() < topdomain_labels.len() {
        return None;
    }
    let suffix = &labels[labels.len() - topdomain_labels.len()..];
    if !suffix
        .iter()
        .zip(topdomain_labels)
        .all(|(left, right)| left.eq_ignore_ascii_case(right))
    {
        return None;
    }
    let prefix_count = labels.len() - topdomain_labels.len();
    if prefix_count == 0 {
        return Some(Vec::new());
    }
    let total_len: usize = labels[..prefix_count]
        .iter()
        .map(|label| label.len())
        .sum::<usize>()
        + (prefix_count - 1);
    let mut prefix = Vec::with_capacity(total_len);
    for (idx, label) in labels[..prefix_count].iter().enumerate() {
        if idx > 0 {
            prefix.push(b'.');
        }
        prefix.extend_from_slice(label);
    }
    Some(prefix)
}

fn response_rr_type(request_qtype: u16) -> u16 {
    if request_qtype == DNS_TYPE_TXT {
        DNS_TYPE_TXT
    } else {
        DNS_TYPE_NULL
    }
}

struct ControlResponse {
    rr_type: u16,
    payload: Vec<u8>,
}

#[derive(Clone)]
struct UdpContext {
    topdomain_labels: Vec<Vec<u8>>,
    password: String,
    tun_ip: Ipv4Addr,
    tun_netmask: Ipv4Addr,
}

struct HandshakeState {
    next_handshake_userid: u8,
    login_challenge_seed: u32,
    pending_login_challenges: HashMap<u8, u32>,
    session_id_by_handshake_user: HashMap<u32, u32>,
}

struct ControlQuery<'a> {
    first_label: &'a [u8],
    query_data_prefix: &'a [u8],
    request_qtype: u16,
}

impl Default for HandshakeState {
    fn default() -> Self {
        Self {
            next_handshake_userid: 1,
            login_challenge_seed: 0x0102_0304,
            pending_login_challenges: HashMap::new(),
            session_id_by_handshake_user: HashMap::new(),
        }
    }
}

async fn handle_control_request(
    query: ControlQuery<'_>,
    state: &ServerState,
    handshake: &mut HandshakeState,
    password: &str,
    tun_ip: Ipv4Addr,
    tun_netmask: Ipv4Addr,
) -> Option<ControlResponse> {
    let first_char = *query.first_label.first()?;
    let rr_type = response_rr_type(query.request_qtype);
    match first_char.to_ascii_lowercase() {
        PACKET_TYPE_CODEC_CHECK => {
            if query.first_label.len() < 3 {
                return Some(ControlResponse {
                    rr_type,
                    payload: CONTROL_BADLEN.to_vec(),
                });
            }
            let requested_codec = query.first_label[1].to_ascii_uppercase();
            let supports_codec = match requested_codec {
                b'R' => query.request_qtype == DNS_TYPE_NULL || query.request_qtype == DNS_TYPE_TXT,
                b'T' | b'S' | b'U' | b'V' => true,
                _ => false,
            };
            if !supports_codec {
                return Some(ControlResponse {
                    rr_type,
                    payload: b"BADCODEC".to_vec(),
                });
            }
            let variant = decode_base32_char(query.first_label[2]).unwrap_or(0);
            if variant != 1 {
                return Some(ControlResponse {
                    rr_type,
                    payload: CONTROL_BADLEN.to_vec(),
                });
            }
            Some(ControlResponse {
                rr_type,
                payload: DOWNCODECCHECK1.to_vec(),
            })
        }
        PACKET_TYPE_VERSION => {
            let decoded = crate::encoding::base32::decode_bytes(&query.first_label[1..]).ok()?;
            if decoded.len() < 4 {
                return Some(ControlResponse {
                    rr_type,
                    payload: b"VNAK\0\0\0\0\0".to_vec(),
                });
            }
            let version = u32::from_be_bytes([decoded[0], decoded[1], decoded[2], decoded[3]]);
            if version == PROTOCOL_VERSION {
                let userid = handshake.next_handshake_userid;
                handshake.next_handshake_userid = if userid >= MAX_HANDSHAKE_USERID {
                    1
                } else {
                    userid + 1
                };
                let seed = handshake.login_challenge_seed;
                handshake.login_challenge_seed =
                    handshake.login_challenge_seed.wrapping_add(0x1021);
                handshake.pending_login_challenges.insert(userid, seed);
                let mut out = Vec::with_capacity(9);
                out.extend_from_slice(PACKET_PREFIX_VACK);
                out.extend_from_slice(&seed.to_be_bytes());
                out.push(userid);
                return Some(ControlResponse {
                    rr_type,
                    payload: out,
                });
            }
            let mut out = Vec::with_capacity(9);
            out.extend_from_slice(b"VNAK");
            out.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
            out.push(0);
            Some(ControlResponse {
                rr_type,
                payload: out,
            })
        }
        PACKET_TYPE_LOGIN => {
            handle_login_packet(query, state, handshake, password, tun_ip, tun_netmask, rr_type)
                .await
        }
        PACKET_TYPE_IP => {
            let mut payload = Vec::with_capacity(5);
            payload.push(b'I');
            payload.extend_from_slice(&tun_ip.octets());
            Some(ControlResponse { rr_type, payload })
        }
        PACKET_TYPE_ECHO => Some(ControlResponse {
            rr_type,
            payload: query.query_data_prefix.to_vec(),
        }),
        PACKET_TYPE_CODEC => handle_codec_packet(query, state, handshake, rr_type).await,
        PACKET_TYPE_ENCODING => {
            if query.first_label.len() < 3 {
                return Some(ControlResponse {
                    rr_type,
                    payload: CONTROL_BADLEN.to_vec(),
                });
            }
            let payload = match query.first_label[2].to_ascii_lowercase() {
                b't' => b"Base32".to_vec(),
                b's' => b"Base64".to_vec(),
                b'u' => b"Base64u".to_vec(),
                b'v' => b"Base128".to_vec(),
                b'r' => b"Raw".to_vec(),
                b'l' => b"Lazy".to_vec(),
                b'i' => b"Immediate".to_vec(),
                _ => b"BADCODEC".to_vec(),
            };
            Some(ControlResponse { rr_type, payload })
        }
        PACKET_TYPE_FRAG_SIZE => {
            if query.first_label.len() < 4 {
                return Some(ControlResponse {
                    rr_type,
                    payload: CONTROL_BADLEN.to_vec(),
                });
            }
            let c1 = decode_base32_char(query.first_label[1]).unwrap_or(0);
            let c2 = decode_base32_char(query.first_label[2]).unwrap_or(0);
            let c3 = decode_base32_char(query.first_label[3]).unwrap_or(0);
            let req_frag_size = (((c1 & 1) as usize) << 10) | ((c2 as usize) << 5) | (c3 as usize);
            if !(2..=2047).contains(&req_frag_size) {
                return Some(ControlResponse {
                    rr_type,
                    payload: b"BADFRAG".to_vec(),
                });
            }
            let mut payload = vec![0u8; req_frag_size];
            payload[0] = ((req_frag_size >> 8) & 0xff) as u8;
            payload[1] = (req_frag_size & 0xff) as u8;
            if req_frag_size > 2 {
                payload[2] = 107;
                let mut v: u8 = 0x42;
                for b in payload.iter_mut().skip(3) {
                    *b = v;
                    v = v.wrapping_add(107);
                }
            }
            Some(ControlResponse { rr_type, payload })
        }
        PACKET_TYPE_FRAG_ACK => {
            let decoded = crate::encoding::base32::decode_bytes(&query.first_label[1..]).ok()?;
            if decoded.len() < 3 {
                return Some(ControlResponse {
                    rr_type,
                    payload: CONTROL_BADLEN.to_vec(),
                });
            }
            let frag = u16::from_be_bytes([decoded[1], decoded[2]]);
            Some(ControlResponse {
                rr_type,
                payload: vec![(frag >> 8) as u8, (frag & 0xff) as u8],
            })
        }
        _ => None,
    }
}

async fn handle_login_packet(
    query: ControlQuery<'_>,
    state: &ServerState,
    handshake: &mut HandshakeState,
    password: &str,
    tun_ip: Ipv4Addr,
    tun_netmask: Ipv4Addr,
    rr_type: u16,
) -> Option<ControlResponse> {
    let decoded = crate::encoding::base32::decode_bytes(&query.first_label[1..]).ok()?;
    if decoded.len() < 17 {
        return Some(ControlResponse {
            rr_type,
            payload: CONTROL_BADLEN.to_vec(),
        });
    }
    let userid = decoded[0];
    let Some(seed) = handshake.pending_login_challenges.get(&userid).copied() else {
        return Some(ControlResponse {
            rr_type,
            payload: b"BADIP".to_vec(),
        });
    };
    let expected_hash = login_hash(password, seed);
    if !constant_time_eq_16(&decoded[1..17], &expected_hash) {
        return Some(ControlResponse {
            rr_type,
            payload: crate::protocol::PACKET_PREFIX_LNAK.to_vec(),
        });
    }
    let mut supplied_hash = [0u8; 16];
    supplied_hash.copy_from_slice(&decoded[1..17]);
    let username = format!("user-{userid}");
    let created_id = state.add_user(username.clone(), supplied_hash);
    let client_ip = match state.create_session(&username, supplied_hash) {
        Ok((_, ip)) => ip,
        Err(err) => {
            warn!(
                error = %err,
                userid,
                "dropping packet: session allocation failed during login"
            );
            Ipv4Addr::new(10, 0, 0, 2)
        }
    };
    let _ = state.set_user_codec(created_id, Codec::Base32);
    handshake
        .session_id_by_handshake_user
        .insert(userid as u32, created_id);
    handshake.pending_login_challenges.remove(&userid);
    let payload = format!(
        "{}-{}-1500-{}",
        tun_ip,
        client_ip,
        ipv4_netmask_prefix(tun_netmask)
    )
    .into_bytes();
    Some(ControlResponse { rr_type, payload })
}

async fn handle_codec_packet(
    query: ControlQuery<'_>,
    state: &ServerState,
    handshake: &HandshakeState,
    rr_type: u16,
) -> Option<ControlResponse> {
    if query.first_label.len() < 3 {
        return Some(ControlResponse {
            rr_type,
            payload: CONTROL_BADLEN.to_vec(),
        });
    }
    let handshake_user = decode_base32_char(query.first_label[1]).unwrap_or(0) as u32;
    let session_id = session_id_for(handshake, handshake_user);
    let codec_id = decode_base32_char(query.first_label[2]).unwrap_or(0);
    let payload = match codec_id {
        5 => {
            let _ = state.set_user_codec(session_id, Codec::Base32);
            b"Base32".to_vec()
        }
        6 => {
            let _ = state.set_user_codec(session_id, Codec::Base64);
            let _ = state.set_use_tun_pi(session_id, true);
            b"Base64".to_vec()
        }
        26 => {
            let _ = state.set_user_codec(session_id, Codec::Base64u);
            let _ = state.set_use_tun_pi(session_id, true);
            b"Base64u".to_vec()
        }
        7 => {
            let _ = state.set_user_codec(session_id, Codec::Base128);
            let _ = state.set_use_tun_pi(session_id, true);
            b"Base128".to_vec()
        }
        _ => b"BADCODEC".to_vec(),
    };
    Some(ControlResponse { rr_type, payload })
}

fn decode_base32_char(ch: u8) -> Option<u8> {
    match ch.to_ascii_lowercase() {
        b'a'..=b'z' => Some(ch.to_ascii_lowercase() - b'a'),
        b'0'..=b'5' => Some(26 + (ch - b'0')),
        _ => None,
    }
}

fn control_rdata<'a>(rr_type: u16, payload: &'a [u8]) -> DnsRdata<'a> {
    if rr_type == DNS_TYPE_TXT {
        DnsRdata::Txt(payload)
    } else {
        DnsRdata::Null(payload)
    }
}

fn login_hash(password: &str, seed: u32) -> [u8; 16] {
    let mut temp = [0u8; 32];
    let pass_bytes = password.as_bytes();
    let copy_len = pass_bytes.len().min(32);
    temp[..copy_len].copy_from_slice(&pass_bytes[..copy_len]);
    for chunk in temp.chunks_exact_mut(4) {
        let n = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) ^ seed;
        chunk.copy_from_slice(&n.to_be_bytes());
    }
    crate::crypto::md5::compute_md5(&temp)
}

fn constant_time_eq_16(a: &[u8], b: &[u8; 16]) -> bool {
    if a.len() != 16 {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn ipv4_netmask_prefix(mask: Ipv4Addr) -> u8 {
    let octets = mask.octets();
    octets.iter().map(|b| b.count_ones() as u8).sum()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{hex_nibble, ipv4_netmask_prefix, login_hash, parse_upstream_query, UpstreamQuery};

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn login_hash_matches_upstream_vector() {
        let digest = login_hash("iodine is the shit", 15);
        assert_eq!(to_hex(&digest), "2a8a12b4e042eeabd019171e44a088cd");
    }

    #[test]
    fn ipv4_netmask_prefix_calculates_common_masks() {
        assert_eq!(ipv4_netmask_prefix(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(ipv4_netmask_prefix(Ipv4Addr::new(255, 255, 0, 0)), 16);
        assert_eq!(ipv4_netmask_prefix(Ipv4Addr::new(255, 255, 255, 252)), 30);
    }

    #[test]
    fn parse_upstream_data_query_uses_c_header_layout() {
        let data = b"1abczhello";
        let parsed = parse_upstream_query(data).expect("parsed");
        match parsed {
            UpstreamQuery::Data {
                user_id,
                up_seq,
                up_frag,
                down_seq,
                down_frag,
                last_frag,
                encoded_payload,
            } => {
                assert_eq!(user_id, 1);
                assert_eq!(up_seq, 0);
                assert_eq!(up_frag, 0);
                assert_eq!(down_seq, 1);
                assert_eq!(down_frag, 1);
                assert!(!last_frag);
                assert_eq!(encoded_payload, b"hello");
            }
            _ => panic!("expected data query"),
        }
    }

    #[test]
    fn hex_nibble_accepts_lower_upper_and_digits() {
        assert_eq!(hex_nibble(b'0'), Some(0));
        assert_eq!(hex_nibble(b'9'), Some(9));
        assert_eq!(hex_nibble(b'a'), Some(10));
        assert_eq!(hex_nibble(b'F'), Some(15));
        assert_eq!(hex_nibble(b'x'), None);
    }
}
