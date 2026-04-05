pub fn create_tun_device(name: &str, mtu: i32) -> Result<tun::AsyncDevice, tun::Error> {
    let mtu = u16::try_from(mtu).map_err(|_| tun::Error::InvalidConfig)?;
    let mut config = tun::Configuration::default();
    config.tun_name(name).mtu(mtu).layer(tun::Layer::L3);
    tun::create_as_async(&config)
}
