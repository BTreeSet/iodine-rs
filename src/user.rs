use std::io;
use std::path::Path;

use nix::errno::Errno;
use nix::unistd::{chdir, chroot, setgid, setuid, User};

fn errno_to_io(op: &str, err: Errno) -> io::Error {
    let io_err = io::Error::from_raw_os_error(err as i32);
    io::Error::new(io_err.kind(), format!("{op} failed: {err}"))
}

pub fn drop_privileges(username: &str, chroot_dir: Option<&Path>) -> Result<(), io::Error> {
    if let Some(dir) = chroot_dir {
        chroot(dir).map_err(|e| errno_to_io("chroot", e))?;
        chdir("/").map_err(|e| errno_to_io("chdir", e))?;
    }

    let user = User::from_name(username)
        .map_err(|e| errno_to_io("lookup user", e))?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("user '{username}' not found"),
            )
        })?;

    setgid(user.gid).map_err(|e| errno_to_io("setgid", e))?;
    setuid(user.uid).map_err(|e| errno_to_io("setuid", e))?;
    Ok(())
}
