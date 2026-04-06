use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::Instant;

use bytes::Bytes;
use lru::LruCache;

use crate::server::pool::IpPool;
use tracing::debug;

const MAX_DOWNSTREAM_QUEUE: usize = 128;
const DNS_CACHE_SIZE: usize = 1024;

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum ServerError {
    #[error("session not found")]
    SessionNotFound,
    #[error("authentication failed")]
    AuthFailed,
    #[error("no ip address available")]
    NoIpAvailable,
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
    pub downstream_queue: VecDeque<Bytes>,
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
            downstream_queue: VecDeque::new(),
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
        assert_eq!(virtual_ip, Ipv4Addr::new(10, 0, 0, 1));
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
