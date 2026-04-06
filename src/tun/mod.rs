use std::net::Ipv4Addr;

const IPV4_MIN_MTU: i32 = 68;

fn invalid_mtu_error(mtu: i32) -> tun::Error {
    tun::Error::from(format!(
        "invalid mtu {mtu}; expected {}..={}",
        IPV4_MIN_MTU,
        u16::MAX
    ))
}

pub fn create_tun_device(
    name: &str,
    address: Ipv4Addr,
    netmask: Ipv4Addr,
    mtu: i32,
) -> Result<tun::AsyncDevice, tun::Error> {
    if mtu < IPV4_MIN_MTU {
        return Err(invalid_mtu_error(mtu));
    }
    let mtu = u16::try_from(mtu).map_err(|_| invalid_mtu_error(mtu))?;
    let mut config = tun::Configuration::default();
    config
        .tun_name(name)
        .address(address)
        .netmask(netmask)
        .mtu(mtu)
        .layer(tun::Layer::L3)
        .up();
    tun::create_as_async(&config)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::create_tun_device;

    #[test]
    fn create_tun_device_rejects_invalid_mtu_before_syscall() {
        let result = create_tun_device(
            "tun-test",
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            67,
        );
        assert!(result.is_err());
    }
}
