use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::{Mutex, RwLock};
use std::time::Instant;

use bytes::Bytes;

use crate::server::pool::IpPool;

const SESSION_NOT_FOUND: &str = "session not found";
const AUTH_FAILED: &str = "authentication failed";
const NO_IP_AVAILABLE: &str = "no ip address available";
const MAX_DOWNSTREAM_QUEUE: usize = 128;

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
    ip_pool: Mutex<IpPool>,
}

impl ServerState {
    pub fn new(network: Ipv4Addr, netmask: Ipv4Addr) -> Self {
        Self {
            users: RwLock::new(HashMap::new()),
            sessions_by_id: RwLock::new(HashMap::new()),
            ip_pool: Mutex::new(IpPool::new(network, netmask)),
        }
    }

    pub fn add_user(&self, username: String, password_hash: [u8; 16]) -> u32 {
        let mut users = self
            .users
            .write()
            .expect("users lock poisoned during add_user");
        let id = users
            .values()
            .map(|user| user.id)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
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
    ) -> Result<(u32, Ipv4Addr), &'static str> {
        let user_id = self
            .authenticate_user(username, password_hash)
            .ok_or(AUTH_FAILED)?;
        let virtual_ip = {
            let mut pool = self
                .ip_pool
                .lock()
                .expect("ip_pool lock poisoned during create_session");
            pool.acquire().ok_or(NO_IP_AVAILABLE)?
        };
        let session = Session {
            user_id,
            virtual_ip,
            downstream_queue: VecDeque::new(),
            last_active: Instant::now(),
        };
        let mut sessions = self
            .sessions_by_id
            .write()
            .expect("sessions_by_id lock poisoned during create_session");
        sessions.insert(user_id, session);
        Ok((user_id, virtual_ip))
    }

    pub fn queue_downstream_packet(&self, session_id: u32, packet: Bytes) -> Result<(), &'static str> {
        let mut sessions = self
            .sessions_by_id
            .write()
            .expect("sessions_by_id lock poisoned during queue_downstream_packet");
        let session = sessions.get_mut(&session_id).ok_or(SESSION_NOT_FOUND)?;
        if session.downstream_queue.len() >= MAX_DOWNSTREAM_QUEUE {
            session.downstream_queue.pop_front();
        }
        session.downstream_queue.push_back(packet);
        session.last_active = Instant::now();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use bytes::Bytes;

    use super::ServerState;

    #[test]
    fn add_user_inserts_user_by_username() {
        let state = ServerState::new(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 0),
        );
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
    fn create_session_acquires_ip_from_pool() {
        let state = ServerState::new(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 0),
        );
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
    fn queue_downstream_packet_drops_oldest_when_capacity_exceeded() {
        let state = ServerState::new(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 0),
        );
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
        let queued = sessions
            .get(&session_id)
            .expect("session must exist")
            .downstream_queue;
        assert_eq!(queued.len(), 128);
        assert_eq!(queued.front(), Some(&Bytes::from_static(&[2])));
        assert_eq!(queued.back(), Some(&Bytes::from_static(&[129])));
    }
}
