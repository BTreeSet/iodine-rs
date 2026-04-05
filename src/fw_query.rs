use std::net::SocketAddr;

pub const FW_QUERY_CACHE_SIZE: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FwQuery {
    pub addr: SocketAddr,
    pub id: u16,
}

#[derive(Debug, Clone, Default)]
pub struct FwQueryCache {
    ring: Vec<FwQuery>,
    next: usize,
}

impl FwQueryCache {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            ring: Vec::with_capacity(capacity),
            next: 0,
        }
    }

    pub fn put(&mut self, query: FwQuery) {
        let cap = self.ring.capacity().max(FW_QUERY_CACHE_SIZE);
        if self.ring.len() < cap {
            self.ring.push(query);
            return;
        }

        self.ring[self.next] = query;
        self.next = (self.next + 1) % cap;
    }

    pub fn get(&self, id: u16) -> Option<&FwQuery> {
        self.ring.iter().find(|q| q.id == id)
    }
}
