use std::io;
use std::path::Path;

use nix::unistd::{chdir, chroot, setgid, setuid, User};

pub fn drop_privileges(username: &str, chroot_dir: Option<&Path>) -> Result<(), io::Error> {
    if let Some(dir) = chroot_dir {
        chroot(dir).map_err(io::Error::other)?;
        chdir("/").map_err(io::Error::other)?;
    }

    let user = User::from_name(username)
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "user not found"))?;

    setgid(user.gid).map_err(io::Error::other)?;
    setuid(user.uid).map_err(io::Error::other)?;
    Ok(())
}
