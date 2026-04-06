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
use std::collections::HashMap;
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
const PROTOCOL_VERSION: u32 = 0x0000_0502;
const DNS_FLAGS_RESPONSE_RA: u16 = 0x8000 | 0x0080;
const DNS_FLAGS_CLEAR_AA_MASK: u16 = !0x0200;
const CONTROL_BADLEN: &[u8] = b"BADLEN";
const DOWNCODECCHECK1: &[u8] = b"\x00\x00\x00\x00\xFF\xFF\xFF\xFF\x55\x55\x55\x55\xAA\xAA\xAA\xAA\
\x81\x63\xC8\xD2\xC7\x7C\xB2\x17\x5F\x4F\xCE\xC9\x49\x2D\x52\x21\
\x61\xA9\x71\x20\x25\xB3\x06\x73\xE6\xD8\x44\x30\x79\x50\x57\xBF";

const PACKET_TYPE_DATA: u8 = 0x20;
const PACKET_TYPE_LOGIN: u8 = 0x10;
const PACKET_TYPE_PING: u8 = 0x30;
const PACKET_TYPE_CODEC: u8 = 0x40;

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

    let mut udp_buf = [0u8; 2048];
    let mut tun_buf = [0u8; 2048];
    let mut handshake = HandshakeState::default();
    let udp_ctx = UdpContext {
        topdomain: topdomain.clone(),
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

    if !qname_matches_topdomain(question.qname_wire, &ctx.topdomain) {
        return Ok(());
    }

    let first_label = first_label_bytes(question.qname_wire).ok_or_else(|| {
        ServerError::InvalidPacket("dns question missing first label".to_string())
    })?;

    if let Some(control_response) = handle_control_request(
        ControlQuery {
            first_label,
            query_data_prefix: qname_data_prefix(question.qname_wire, &ctx.topdomain)
                .as_deref()
                .unwrap_or_default()
                .as_bytes(),
            request_qtype: question.qtype,
        },
        state,
        handshake,
        &ctx.password,
        ctx.tun_ip,
        ctx.tun_netmask,
    ) {
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

    let Some((packet_type, user_id, payload_bytes)) = parse_packet_type(first_label) else {
        send_probe_fallback_response(socket, peer, &header, question).await?;
        return Ok(());
    };

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
            send_rr_response(socket, peer, &header, question, DNS_TYPE_TXT, b"OK").await?;
        }
        PACKET_TYPE_LOGIN => {
            let decoded = crate::encoding::base32::decode_bytes(payload_bytes)
                .map_err(|e| ServerError::Encoding(format!("login decode failed: {e}")))?;
            if decoded.len() < 17 {
                send_rr_response(
                    socket,
                    peer,
                    &header,
                    question,
                    DNS_TYPE_TXT,
                    CONTROL_BADLEN,
                )
                .await?;
                return Ok(());
            }
            let handshake_userid = decoded[0];
            let Some(seed) = handshake
                .pending_login_challenges
                .get(&handshake_userid)
                .copied()
            else {
                send_rr_response(socket, peer, &header, question, DNS_TYPE_TXT, b"BADIP").await?;
                return Ok(());
            };
            let expected_hash = login_hash(&ctx.password, seed);
            if !constant_time_eq_16(&decoded[1..17], &expected_hash) {
                send_rr_response(socket, peer, &header, question, DNS_TYPE_TXT, b"LNAK").await?;
                return Ok(());
            }

            let mut supplied_hash = [0u8; 16];
            supplied_hash.copy_from_slice(&decoded[1..17]);
            let username = format!("user-{handshake_userid}");
            let user_id_created = state.add_user(username.clone(), supplied_hash);
            let (_, client_ip) = state
                .create_session(&username, supplied_hash)
                .map_err(|e| ServerError::InvalidPacket(format!("session create failed: {e}")))?;
            let _ = state.set_user_codec(user_id_created, Codec::Base32);
            handshake.pending_login_challenges.remove(&handshake_userid);

            let payload = format!(
                "{}-{}-1500-{}",
                ctx.tun_ip,
                client_ip,
                ipv4_netmask_prefix(ctx.tun_netmask)
            )
            .into_bytes();
            send_rr_response(
                socket,
                peer,
                &header,
                question,
                response_rr_type(question.qtype),
                &payload,
            )
            .await?;
        }
        PACKET_TYPE_PING => {
            let downstream = state.pop_downstream_packet(user_id).ok().flatten();
            send_data_response(socket, peer, &header, question, downstream).await?;
        }
        PACKET_TYPE_DATA => {
            let codec = state.user_codec_or_default(user_id, Codec::Base32);
            let decoded = crate::encoding::decode_upstream(codec, payload_bytes)
                .map_err(|e| ServerError::Encoding(e.to_string()))?;
            if decoded.len() < 2 {
                send_probe_fallback_response(socket, peer, &header, question).await?;
                return Ok(());
            }
            let ip_packet = &decoded[1..];
            tun.write_all(ip_packet)
                .await
                .map_err(|e| ServerError::Io(format!("tun write failed: {e}")))?;

            let downstream = state.pop_downstream_packet(user_id).ok().flatten();
            send_data_response(socket, peer, &header, question, downstream).await?;
        }
        _ => {
            send_probe_fallback_response(socket, peer, &header, question).await?;
        }
    }

    Ok(())
}

async fn handle_tun_packet(state: &ServerState, packet: &[u8]) -> Result<(), ServerError> {
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
    downstream: Option<Bytes>,
) -> Result<(), ServerError> {
    if let Some(downstream_packet) = downstream {
        let encoded = crate::encoding::base64::encode(&downstream_packet);
        let rr_type = if question.qtype == DNS_TYPE_TXT {
            DNS_TYPE_TXT
        } else {
            DNS_TYPE_NULL
        };
        send_rr_response(socket, peer, header, question, rr_type, encoded.as_bytes()).await
    } else {
        send_probe_fallback_response(socket, peer, header, question).await
    }
}

fn parse_packet_type(first_label: &[u8]) -> Option<(u8, u32, &[u8])> {
    let (&lead, payload) = first_label.split_first()?;
    let packet_type = lead & 0xF0;
    let user_id = (lead & 0x0F) as u32;
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

fn qname_data_prefix(qname_wire: &[u8], topdomain: &str) -> Option<String> {
    let qname = qname_to_string(qname_wire);
    if qname.is_empty() {
        return None;
    }
    let qname_lc = qname.to_ascii_lowercase();
    if qname_lc == topdomain {
        return Some(String::new());
    }
    let suffix = format!(".{topdomain}");
    if let Some(stripped) = qname_lc.strip_suffix(&suffix) {
        let orig_len = stripped.len();
        return Some(qname[..orig_len].to_string());
    }
    None
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
    topdomain: String,
    password: String,
    tun_ip: Ipv4Addr,
    tun_netmask: Ipv4Addr,
}

struct HandshakeState {
    next_handshake_userid: u8,
    login_challenge_seed: u32,
    pending_login_challenges: HashMap<u8, u32>,
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
        }
    }
}

fn handle_control_request(
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
        b'y' => {
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
        b'v' => {
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
                handshake.next_handshake_userid =
                    handshake.next_handshake_userid.wrapping_add(1).max(1);
                let seed = handshake.login_challenge_seed;
                handshake.login_challenge_seed =
                    handshake.login_challenge_seed.wrapping_add(0x1021);
                handshake.pending_login_challenges.insert(userid, seed);
                let mut out = Vec::with_capacity(9);
                out.extend_from_slice(b"VACK");
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
        b'l' => {
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
                    payload: b"LNAK".to_vec(),
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
        b'p' => Some(ControlResponse {
            rr_type,
            payload: vec![0, 0],
        }),
        b'i' => {
            let mut payload = Vec::with_capacity(5);
            payload.push(b'I');
            payload.extend_from_slice(&tun_ip.octets());
            Some(ControlResponse { rr_type, payload })
        }
        b'z' => Some(ControlResponse {
            rr_type,
            payload: query.query_data_prefix.to_vec(),
        }),
        b's' => {
            if query.first_label.len() < 3 {
                return Some(ControlResponse {
                    rr_type,
                    payload: CONTROL_BADLEN.to_vec(),
                });
            }
            let codec = decode_base32_char(query.first_label[2]).unwrap_or(0);
            let payload = match codec {
                5 => b"Base32".to_vec(),
                6 => b"Base64".to_vec(),
                26 => b"Base64u".to_vec(),
                7 => b"Base128".to_vec(),
                _ => b"BADCODEC".to_vec(),
            };
            Some(ControlResponse { rr_type, payload })
        }
        b'o' => {
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
        b'r' => {
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
        b'n' => {
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

    use super::{ipv4_netmask_prefix, login_hash, parse_packet_type};

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
    fn parse_packet_type_uses_high_nibble_command_mask() {
        let data = [0x43, 0x99, 0x88];
        let (ptype, uid, payload) = parse_packet_type(&data).expect("parsed");
        assert_eq!(ptype, 0x40);
        assert_eq!(uid, 0x03);
        assert_eq!(payload, &[0x99, 0x88]);
    }
}
