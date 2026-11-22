//! Installed alongside the unmodified OpenShell supervisor. Docker exec owns
//! stdin/stdout; no listener, credentials, shell or agent-selected destination.
use std::{
    io::{self, Read, Write},
    net::Shutdown,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::UnixStream,
    },
    path::Path,
};

const SOCKET: &str = "/run/openshell/ssh.sock";
extern "C" {
    fn geteuid() -> u32;
}

fn run() -> io::Result<()> {
    if std::env::args_os().len() != 1 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let path = Path::new(SOCKET);
    let parent = std::fs::symlink_metadata(path.parent().unwrap())?;
    let socket = std::fs::symlink_metadata(path)?;
    let uid = unsafe { geteuid() };
    if !parent.is_dir()
        || parent.uid() != uid
        || parent.permissions().mode() & 0o077 != 0
        || !socket.file_type().is_socket()
        || socket.uid() != uid
        || socket.permissions().mode() & 0o077 != 0
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let mut output = UnixStream::connect(path)?;
    // Both directions belong to one SSH transport, not independent app streams.
    // Closing Docker stdin must terminate the helper even on an idle SSH peer.
    let mut input = output.try_clone()?;
    std::thread::spawn(move || {
        let _ = io::copy(&mut io::stdin().lock(), &mut input);
        let _ = input.shutdown(Shutdown::Both);
    });
    // Stdout is line-buffered by Rust even when Docker attaches a pipe. Flush
    // every binary chunk so an SSH packet without a newline cannot deadlock KEX.
    let result = (|| {
        let mut stdout = io::stdout().lock();
        let mut bytes = [0; 16384];
        loop {
            let count = output.read(&mut bytes)?;
            if count == 0 {
                return Ok(());
            }
            stdout.write_all(&bytes[..count])?;
            stdout.flush()?;
        }
    })();
    let _ = output.shutdown(Shutdown::Both);
    result
}

fn main() {
    if run().is_err() {
        eprintln!("private supervisor socket unavailable");
        std::process::exit(1);
    }
}
