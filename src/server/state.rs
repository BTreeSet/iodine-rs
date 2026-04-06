use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::RwLock;
use std::time::Instant;

use bytes::Bytes;

const SESSION_NOT_FOUND: &str = "session not found for user id";

#[derive(Debug, Clone)]
pub struct User {
    pub id: u32,
    pub username: String,
    pub password_hash: [u8; 16],
    pub assigned_ip: Ipv4Addr,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub user_id: u32,
    pub downstream_queue: VecDeque<Bytes>,
    pub last_active: Instant,
}

#[derive(Debug, Default)]
pub struct ServerState {
    pub users: RwLock<HashMap<String, User>>,
    pub active_sessions: RwLock<HashMap<u32, Session>>,
}

impl ServerState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_user(&self, username: String, password_hash: [u8; 16], ip: Ipv4Addr) {
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
                assigned_ip: ip,
            },
        );
    }

    pub fn queue_downstream_packet(&self, user_id: u32, packet: Bytes) -> Result<(), &'static str> {
        let mut sessions = self
            .active_sessions
            .write()
            .expect("active_sessions lock poisoned during queue_downstream_packet");
        let session = sessions.get_mut(&user_id).ok_or(SESSION_NOT_FOUND)?;
        session.downstream_queue.push_back(packet);
        session.last_active = Instant::now();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;
    use std::time::Instant;

    use bytes::Bytes;

    use super::{ServerState, Session};

    #[test]
    fn add_user_inserts_user_by_username() {
        let state = ServerState::new();
        let username = "alice".to_string();
        let password_hash = [0xAB; 16];
        let ip = Ipv4Addr::new(10, 0, 0, 2);

        state.add_user(username.clone(), password_hash, ip);

        let users = state.users.read().expect("users lock should be readable");
        let user = users.get("alice").expect("user should be inserted");
        assert_eq!(user.username, username);
        assert_eq!(user.password_hash, password_hash);
        assert_eq!(user.assigned_ip, ip);
    }

    #[test]
    fn queue_downstream_packet_pushes_bytes() {
        let state = ServerState::new();
        let user_id = 7;
        let mut sessions = state
            .active_sessions
            .write()
            .expect("sessions lock should be writable");
        sessions.insert(
            user_id,
            Session {
                user_id,
                downstream_queue: VecDeque::new(),
                last_active: Instant::now(),
            },
        );
        drop(sessions);

        let payload = Bytes::from_static(b"packet");
        state
            .queue_downstream_packet(user_id, payload.clone())
            .expect("queue should succeed");

        let sessions = state
            .active_sessions
            .read()
            .expect("sessions lock should be readable");
        let queued = sessions
            .get(&user_id)
            .expect("session must exist")
            .downstream_queue
            .front()
            .expect("queued packet should exist");
        assert_eq!(queued, &payload);
    }
}
