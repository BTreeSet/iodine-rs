pub fn create_tun_device(name: &str, mtu: i32) -> Result<tun::AsyncDevice, tun::Error> {
    let mut config = tun::Configuration::default();
    config.tun_name(name).mtu(mtu as u16).layer(tun::Layer::L3);
    tun::create_as_async(&config)
}
