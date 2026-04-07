use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::Instant;

use bytes::Bytes;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use lru::LruCache;
use std::io::Write;

use crate::server::pool::IpPool;
use tracing::debug;

const MAX_DOWNSTREAM_QUEUE: usize = 128;
const DNS_CACHE_SIZE: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    Base32 = 0,
    Base64 = 1,
    Base64u = 2,
    Base128 = 3,
}

impl TryFrom<u8> for Codec {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Base32),
            1 => Ok(Self::Base64),
            2 => Ok(Self::Base64u),
            3 => Ok(Self::Base128),
            _ => Err(()),
        }
    }
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum ServerError {
    #[error("session not found")]
    SessionNotFound,
    #[error("authentication failed")]
    AuthFailed,
    #[error("no ip address available")]
    NoIpAvailable,
    #[error("invalid packet: {0}")]
    InvalidPacket(String),
    #[error("encoding error: {0}")]
    Encoding(String),
    #[error("io error: {0}")]
    Io(String),
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: u32,
    pub username: String,
    pub password_hash: [u8; 16],
}

#[derive(Debug, Clone)]
pub struct Session {
    pub user_id: u32,
    pub virtual_ip: Ipv4Addr,
    pub upstream_codec: Codec,
    pub downstream_queue: VecDeque<Bytes>,
    pub upstream_seq: u8,
    pub upstream_fragment: u8,
    pub upstream_reassembly: Vec<u8>,
    pub upstream_initialized: bool,
    pub downstream_seq: u8,
    pub downstream_fragment: u8,
    pub downstream_sentlen: usize,
    pub downstream_offset: usize,
    pub downstream_current: Vec<u8>,
    pub use_tun_pi: bool,
    pub last_active: Instant,
}

#[derive(Debug)]
pub struct ServerState {
    users: RwLock<HashMap<String, User>>,
    sessions_by_id: RwLock<HashMap<u32, Session>>,
    session_id_by_ip: RwLock<HashMap<Ipv4Addr, u32>>,
    ip_pool: Mutex<IpPool>,
    dns_cache: Mutex<LruCache<Vec<u8>, Bytes>>,
    next_user_id: AtomicU32,
}

impl ServerState {
    pub fn new(network: Ipv4Addr, netmask: Ipv4Addr) -> Self {
        Self {
            users: RwLock::new(HashMap::new()),
            sessions_by_id: RwLock::new(HashMap::new()),
            session_id_by_ip: RwLock::new(HashMap::new()),
            ip_pool: Mutex::new(IpPool::new(network, netmask)),
            dns_cache: Mutex::new(LruCache::new(NonZeroUsize::new(DNS_CACHE_SIZE).unwrap())),
            next_user_id: AtomicU32::new(1),
        }
    }

    pub fn add_user(&self, username: String, password_hash: [u8; 16]) -> u32 {
        let mut users = self
            .users
            .write()
            .expect("users lock poisoned during add_user");
        let id = self.next_user_id.fetch_add(1, Ordering::Relaxed);
        users.insert(
            username.clone(),
            User {
                id,
                username,
                password_hash,
            },
        );
        id
    }

    pub fn authenticate_user(&self, username: &str, password_hash: [u8; 16]) -> Option<u32> {
        let users = self
            .users
            .read()
            .expect("users lock poisoned during authenticate_user");
        users
            .get(username)
            .filter(|user| user.password_hash == password_hash)
            .map(|user| user.id)
    }

    pub fn create_session(
        &self,
        username: &str,
        password_hash: [u8; 16],
    ) -> Result<(u32, Ipv4Addr), ServerError> {
        let user_id = self
            .authenticate_user(username, password_hash)
            .ok_or(ServerError::AuthFailed)?;
        let virtual_ip = {
            let mut pool = self
                .ip_pool
                .lock()
                .expect("ip_pool lock poisoned during create_session");
            pool.acquire().ok_or(ServerError::NoIpAvailable)?
        };
        let session = Session {
            user_id,
            virtual_ip,
            upstream_codec: Codec::Base32,
            downstream_queue: VecDeque::new(),
            upstream_seq: 0,
            upstream_fragment: 0,
            upstream_reassembly: Vec::new(),
            upstream_initialized: false,
            downstream_seq: 0,
            downstream_fragment: 0,
            downstream_sentlen: 0,
            downstream_offset: 0,
            downstream_current: Vec::new(),
            use_tun_pi: false,
            last_active: Instant::now(),
        };
        let mut by_ip = self
            .session_id_by_ip
            .write()
            .expect("session_id_by_ip lock poisoned during create_session");
        by_ip.insert(session.virtual_ip, user_id);
        drop(by_ip);

        let mut sessions = self
            .sessions_by_id
            .write()
            .expect("sessions_by_id lock poisoned during create_session");
        sessions.insert(user_id, session);
        Ok((user_id, virtual_ip))
    }

    pub fn queue_downstream_packet(
        &self,
        session_id: u32,
        packet: Bytes,
    ) -> Result<(), ServerError> {
        let mut sessions = self
            .sessions_by_id
            .write()
            .expect("sessions_by_id lock poisoned during queue_downstream_packet");
        let session = sessions
            .get_mut(&session_id)
            .ok_or(ServerError::SessionNotFound)?;
        if session.downstream_queue.len() >= MAX_DOWNSTREAM_QUEUE {
            session.downstream_queue.pop_front();
            debug!(
                session_id,
                max_queue = MAX_DOWNSTREAM_QUEUE,
                "downstream queue full; dropped oldest packet"
            );
        }
        session.downstream_queue.push_back(packet);
        session.last_active = Instant::now();
        Ok(())
    }

    pub fn check_cache(&self, query: &[u8]) -> Option<Bytes> {
        let mut cache = self
            .dns_cache
            .lock()
            .expect("dns_cache lock poisoned during check_cache");
        cache.get(query).cloned()
    }

    pub fn put_cache(&self, query: Vec<u8>, response: Bytes) {
        let mut cache = self
            .dns_cache
            .lock()
            .expect("dns_cache lock poisoned during put_cache");
        cache.put(query, response);
    }

    pub fn find_session_id_by_virtual_ip(&self, virtual_ip: Ipv4Addr) -> Option<u32> {
        let by_ip = self
            .session_id_by_ip
            .read()
            .expect("session_id_by_ip lock poisoned during find_session_id_by_virtual_ip");
        by_ip.get(&virtual_ip).copied()
    }

    pub fn pop_downstream_packet(&self, session_id: u32) -> Result<Option<Bytes>, ServerError> {
        let mut sessions = self
            .sessions_by_id
            .write()
            .expect("sessions_by_id lock poisoned during pop_downstream_packet");
        let session = sessions
            .get_mut(&session_id)
            .ok_or(ServerError::SessionNotFound)?;
        let packet = session.downstream_queue.pop_front();
        if packet.is_some() {
            session.last_active = Instant::now();
        }
        Ok(packet)
    }

    pub fn set_user_codec(&self, user_id: u32, codec: Codec) -> Result<(), ServerError> {
        let mut sessions = self
            .sessions_by_id
            .write()
            .expect("sessions_by_id lock poisoned during set_user_codec");
        let session = sessions
            .get_mut(&user_id)
            .ok_or(ServerError::SessionNotFound)?;
        session.upstream_codec = codec;
        session.last_active = Instant::now();
        Ok(())
    }

    pub fn set_use_tun_pi(&self, user_id: u32, enabled: bool) -> Result<(), ServerError> {
        let mut sessions = self
            .sessions_by_id
            .write()
            .expect("sessions_by_id lock poisoned during set_use_tun_pi");
        let session = sessions
            .get_mut(&user_id)
            .ok_or(ServerError::SessionNotFound)?;
        session.use_tun_pi = enabled;
        session.last_active = Instant::now();
        Ok(())
    }

    pub fn use_tun_pi(&self, user_id: u32) -> Result<bool, ServerError> {
        let sessions = self
            .sessions_by_id
            .read()
            .expect("sessions_by_id lock poisoned during use_tun_pi");
        let session = sessions.get(&user_id).ok_or(ServerError::SessionNotFound)?;
        Ok(session.use_tun_pi)
    }

    pub fn process_downstream_ack(
        &self,
        user_id: u32,
        down_seq: u8,
        down_frag: u8,
    ) -> Result<(), ServerError> {
        let mut sessions = self
            .sessions_by_id
            .write()
            .expect("sessions_by_id lock poisoned during process_downstream_ack");
        let session = sessions
            .get_mut(&user_id)
            .ok_or(ServerError::SessionNotFound)?;
        if session.downstream_current.is_empty() {
            return Ok(());
        }
        if session.downstream_seq != down_seq || session.downstream_fragment != down_frag {
            return Ok(());
        }

        session.downstream_offset = session
            .downstream_offset
            .saturating_add(session.downstream_sentlen);
        session.downstream_sentlen = 0;
        session.downstream_fragment = session.downstream_fragment.wrapping_add(1) & 0x0f;

        if session.downstream_offset >= session.downstream_current.len() {
            session.downstream_current.clear();
            session.downstream_offset = 0;
        }
        session.last_active = Instant::now();
        Ok(())
    }

    pub fn push_upstream_fragment(
        &self,
        user_id: u32,
        up_seq: u8,
        up_frag: u8,
        fragment: &[u8],
        last_fragment: bool,
    ) -> Result<Option<Vec<u8>>, ServerError> {
        let mut sessions = self
            .sessions_by_id
            .write()
            .expect("sessions_by_id lock poisoned during push_upstream_fragment");
        let session = sessions
            .get_mut(&user_id)
            .ok_or(ServerError::SessionNotFound)?;

        if !session.upstream_initialized {
            session.upstream_seq = up_seq;
            session.upstream_fragment = up_frag;
            session.upstream_reassembly.clear();
            session.upstream_initialized = true;
        } else if up_seq != session.upstream_seq {
            if recent_seqno(session.upstream_seq, up_seq) {
                return Ok(None);
            }
            session.upstream_seq = up_seq;
            session.upstream_fragment = up_frag;
            session.upstream_reassembly.clear();
        } else if up_frag <= session.upstream_fragment
            && !(session.upstream_fragment == 0
                && up_frag == 0
                && session.upstream_reassembly.is_empty())
        {
            return Ok(None);
        } else {
            session.upstream_fragment = up_frag;
        }

        session.upstream_reassembly.extend_from_slice(fragment);
        session.last_active = Instant::now();

        if !last_fragment {
            return Ok(None);
        }

        let packet = std::mem::take(&mut session.upstream_reassembly);
        Ok(Some(packet))
    }

    pub fn upstream_ack(&self, user_id: u32) -> Result<(u8, u8), ServerError> {
        let sessions = self
            .sessions_by_id
            .read()
            .expect("sessions_by_id lock poisoned during upstream_ack");
        let session = sessions.get(&user_id).ok_or(ServerError::SessionNotFound)?;
        Ok((
            session.upstream_seq & 0x07,
            session.upstream_fragment & 0x0f,
        ))
    }

    pub fn build_downstream_packet(
        &self,
        user_id: u32,
        fragment_size: usize,
        up_ack_seq: u8,
        up_ack_frag: u8,
    ) -> Result<Vec<u8>, ServerError> {
        let mut sessions = self
            .sessions_by_id
            .write()
            .expect("sessions_by_id lock poisoned during build_downstream_packet");
        let session = sessions
            .get_mut(&user_id)
            .ok_or(ServerError::SessionNotFound)?;

        if session.downstream_current.is_empty() {
            if let Some(packet) = session.downstream_queue.pop_front() {
                session.downstream_seq = (session.downstream_seq + 1) & 0x07;
                session.downstream_fragment = 0;
                session.downstream_offset = 0;
                session.downstream_sentlen = 0;
                session.downstream_current = compress_packet(&packet);
            }
        }

        let mut out = Vec::new();
        let mut datalen = 0usize;
        let mut last = false;
        if !session.downstream_current.is_empty() {
            let available = session.downstream_current.len() - session.downstream_offset;
            datalen = fragment_size.min(available);
            last = session.downstream_offset + datalen >= session.downstream_current.len();
        }

        out.push(0x80 | ((up_ack_seq & 0x07) << 4) | (up_ack_frag & 0x0f));
        out.push(
            ((session.downstream_seq & 0x07) << 5)
                | ((session.downstream_fragment & 0x0f) << 1)
                | u8::from(last),
        );
        if datalen > 0 {
            let start = session.downstream_offset;
            out.extend_from_slice(&session.downstream_current[start..start + datalen]);
            session.downstream_sentlen = datalen;
        }

        session.last_active = Instant::now();
        Ok(out)
    }

    pub fn user_codec(&self, user_id: u32) -> Result<Codec, ServerError> {
        let sessions = self
            .sessions_by_id
            .read()
            .expect("sessions_by_id lock poisoned during user_codec");
        let session = sessions.get(&user_id).ok_or(ServerError::SessionNotFound)?;
        Ok(session.upstream_codec)
    }

    pub fn user_codec_or_default(&self, user_id: u32, default: Codec) -> Codec {
        self.user_codec(user_id).unwrap_or(default)
    }
}

fn compress_packet(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    if encoder.write_all(data).is_err() {
        return Vec::new();
    }
    encoder.finish().unwrap_or_default()
}

fn recent_seqno(current: u8, candidate: u8) -> bool {
    let candidate = (candidate & 0x07) as i8;
    let mut seq = current as i8;
    for _ in 0..4 {
        if candidate == seq {
            return true;
        }
        seq -= 1;
        if seq < 0 {
            seq = 7;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use bytes::Bytes;

    use super::{ServerError, ServerState};

    #[test]
    fn add_user_inserts_user_by_username() {
        let state = ServerState::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(255, 255, 255, 0));
        let username = "alice".to_string();
        let password_hash = [0xAB; 16];

        let id = state.add_user(username.clone(), password_hash);

        let users = state.users.read().expect("users lock should be readable");
        let user = users.get("alice").expect("user should be inserted");
        assert_eq!(user.id, id);
        assert_eq!(user.username, username);
        assert_eq!(user.password_hash, password_hash);
    }

    #[test]
    fn add_user_duplicate_username_overwrites_and_returns_new_id() {
        let state = ServerState::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(255, 255, 255, 0));
        let username = "alice".to_string();
        let old_hash = [0x11; 16];
        let new_hash = [0x22; 16];

        let first_id = state.add_user(username.clone(), old_hash);
        let second_id = state.add_user(username.clone(), new_hash);

        assert_ne!(first_id, second_id);
        let users = state.users.read().expect("users lock should be readable");
        let user = users
            .get(&username)
            .expect("username should still be present");
        assert_eq!(user.id, second_id);
        assert_eq!(user.password_hash, new_hash);
    }

    #[test]
    fn authenticate_user_fails_for_invalid_credentials_or_unknown_user() {
        let state = ServerState::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(255, 255, 255, 0));
        let username = "alice".to_string();
        let password_hash = [0xCD; 16];
        let wrong_hash = [0xEE; 16];
        let id = state.add_user(username.clone(), password_hash);

        assert_eq!(state.authenticate_user(&username, password_hash), Some(id));
        assert_eq!(state.authenticate_user(&username, wrong_hash), None);
        assert_eq!(state.authenticate_user("unknown", password_hash), None);
    }

    #[test]
    fn create_session_acquires_ip_from_pool() {
        let state = ServerState::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(255, 255, 255, 0));
        let username = "alice".to_string();
        let password_hash = [0xCD; 16];
        let id = state.add_user(username.clone(), password_hash);

        let (session_id, virtual_ip) = state
            .create_session(&username, password_hash)
            .expect("session should be created");

        assert_eq!(session_id, id);
        assert_eq!(virtual_ip, Ipv4Addr::new(10, 0, 0, 2));
    }

    #[test]
    fn create_session_returns_auth_failed_for_wrong_credentials() {
        let state = ServerState::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(255, 255, 255, 0));
        let username = "alice".to_string();
        let password_hash = [0x01; 16];
        state.add_user(username.clone(), password_hash);

        let result = state.create_session(&username, [0x02; 16]);
        assert_eq!(result, Err(ServerError::AuthFailed));
    }

    #[test]
    fn queue_downstream_packet_returns_not_found_when_missing_session() {
        let state = ServerState::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(255, 255, 255, 0));
        let result = state.queue_downstream_packet(99, Bytes::from_static(b"pkt"));
        assert_eq!(result, Err(ServerError::SessionNotFound));
    }

    #[test]
    fn dns_cache_round_trip() {
        let state = ServerState::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(255, 255, 255, 0));
        let query = vec![1, 2, 3, 4];
        let response = Bytes::from_static(b"response");
        assert_eq!(state.check_cache(&query), None);
        state.put_cache(query.clone(), response.clone());
        assert_eq!(state.check_cache(&query), Some(response));
    }

    #[test]
    fn queue_downstream_packet_drops_oldest_when_capacity_exceeded() {
        let state = ServerState::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(255, 255, 255, 0));
        let username = "alice".to_string();
        let password_hash = [0xEF; 16];
        let session_id = state.add_user(username.clone(), password_hash);
        let _ = state
            .create_session(&username, password_hash)
            .expect("session should be created");

        for i in 0..130 {
            let payload = Bytes::from(vec![i as u8]);
            state
                .queue_downstream_packet(session_id, payload)
                .expect("queue should succeed");
        }

        let sessions = state
            .sessions_by_id
            .read()
            .expect("sessions lock should be readable");
        let queued = &sessions
            .get(&session_id)
            .expect("session must exist")
            .downstream_queue;
        assert_eq!(queued.len(), 128);
        assert_eq!(queued.front(), Some(&Bytes::from_static(&[2])));
        assert_eq!(queued.back(), Some(&Bytes::from_static(&[129])));
    }
}
