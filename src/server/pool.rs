use std::collections::{HashSet, VecDeque};
use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct IpPool {
    pub network: Ipv4Addr,
    pub netmask: Ipv4Addr,
    available: VecDeque<Ipv4Addr>,
    available_set: HashSet<Ipv4Addr>,
}

impl IpPool {
    pub fn new(network: Ipv4Addr, netmask: Ipv4Addr) -> Self {
        let mut available = VecDeque::new();
        let network_u32 = u32::from(network);
        let mask_u32 = u32::from(netmask);
        let base = network_u32 & mask_u32;
        let broadcast = base | !mask_u32;

        let mut available_set = HashSet::new();
        // Ensure there is at least one assignable host address between
        // network and broadcast addresses.
        if broadcast >= base + 2 {
            for raw in (base + 1)..broadcast {
                let ip = Ipv4Addr::from(raw);
                available.push_back(ip);
                available_set.insert(ip);
            }
        }

        Self {
            network: Ipv4Addr::from(base),
            netmask,
            available,
            available_set,
        }
    }

    pub fn acquire(&mut self) -> Option<Ipv4Addr> {
        let ip = self.available.pop_front()?;
        self.available_set.remove(&ip);
        Some(ip)
    }

    pub fn release(&mut self, ip: Ipv4Addr) {
        let ip_raw = u32::from(ip);
        let base = u32::from(self.network) & u32::from(self.netmask);
        let broadcast = base | !u32::from(self.netmask);
        if ip_raw <= base || ip_raw >= broadcast {
            return;
        }
        if self.available_set.contains(&ip) {
            return;
        }
        self.available.push_back(ip);
        self.available_set.insert(ip);
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::IpPool;

    #[test]
    fn acquire_leases_unique_addresses() {
        let mut pool = IpPool::new(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 252),
        );
        let first = pool.acquire();
        let second = pool.acquire();
        let third = pool.acquire();

        assert_eq!(first, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(second, Some(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(third, None);
    }

    #[test]
    fn release_makes_address_available_again() {
        let mut pool = IpPool::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(255, 255, 255, 0));
        let leased = pool.acquire().expect("pool should have available address");
        pool.release(leased);
        let mut reacquired = None;
        while let Some(ip) = pool.acquire() {
            if ip == leased {
                reacquired = Some(ip);
                break;
            }
        }
        assert_eq!(reacquired, Some(leased));
    }
}
