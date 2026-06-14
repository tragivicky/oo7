use std::{collections::HashMap, os::unix::fs::PermissionsExt, path::PathBuf, sync::LazyLock};

use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixListener,
    time::Duration,
};

use crate::error::Error;

const CONTROL_TIMEOUT: Duration = Duration::from_secs(120);

const ENV_VARS: &[&str] = &[
    "DBUS_SESSION_BUS_ADDRESS",
    "XDG_RUNTIME_DIR",
    "XDG_DATA_HOME",
    "HOME",
    "LANG",
];

pub static CONTROL_SOCKET_PATH: LazyLock<PathBuf> = LazyLock::new(|| {
    let uid = rustix::process::getuid().as_raw();
    PathBuf::from(format!("/run/user/{uid}/oo7-control.sock"))
});

/// Pending control socket handshake. The response byte is deferred until the
/// caller has finished initialization (e.g. claimed the D-Bus name), so the
/// handoff process blocks until the login daemon is fully ready.
pub struct ControlHandshake {
    stream: tokio::net::UnixStream,
}

impl ControlHandshake {
    pub async fn complete(mut self) -> Result<(), Error> {
        self.stream.write_all(&[0]).await?;
        self.stream.flush().await?;
        let _ = tokio::fs::remove_file(&*CONTROL_SOCKET_PATH).await;
        tracing::info!("Control handshake completed");
        Ok(())
    }
}

/// Wait for a D-Bus-activated daemon to send us environment variables via the
/// control socket. Used by the `--login` daemon started by PAM before D-Bus is
/// ready. Returns the received environment variables and a handshake that must
/// be completed after initialization to unblock the handoff process.
pub async fn serve_control_socket() -> Result<(HashMap<String, String>, ControlHandshake), Error> {
    let path = &*CONTROL_SOCKET_PATH;

    if path.exists() {
        tokio::fs::remove_file(&path).await?;
    }

    let listener = UnixListener::bind(path)?;

    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)?;

    tracing::info!("Control socket listening on {}", path.display());

    let (mut stream, _addr) = match tokio::time::timeout(CONTROL_TIMEOUT, listener.accept()).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(e)) => {
            let _ = tokio::fs::remove_file(&path).await;
            return Err(Error::IO(e));
        }
        Err(_) => {
            let _ = tokio::fs::remove_file(&path).await;
            return Err(Error::IO(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "No initialization received within 120s, exiting",
            )));
        }
    };

    // Verify peer credentials
    let peer_cred = stream.peer_cred()?;
    let our_uid = rustix::process::getuid().as_raw();
    if peer_cred.uid() != our_uid {
        let _ = tokio::fs::remove_file(&path).await;
        return Err(Error::IO(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "Control socket: rejected UID {} (expected {})",
                peer_cred.uid(),
                our_uid
            ),
        )));
    }

    // Read env vars: KEY=VALUE\n lines, terminated by empty line
    let mut env_vars = HashMap::new();
    let mut reader = BufReader::new(&mut stream);
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim_end_matches('\n');
        if trimmed.is_empty() {
            break;
        }
        if let Some((key, value)) = trimmed.split_once('=') {
            env_vars.insert(key.to_owned(), value.to_owned());
        }
    }

    drop(reader);

    tracing::info!(
        "Received initialization with {} env var(s) via control socket",
        env_vars.len()
    );

    Ok((env_vars, ControlHandshake { stream }))
}

/// Connect to an existing `--login` daemon's control socket and send it our
/// environment variables so it can connect to D-Bus.
pub async fn handoff_to_login_daemon() -> Result<(), Error> {
    let path = &*CONTROL_SOCKET_PATH;

    let mut stream = match tokio::net::UnixStream::connect(&path).await {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            tracing::debug!("Stale control socket, removing");
            let _ = tokio::fs::remove_file(&path).await;
            return Err(Error::IO(e));
        }
        Err(e) => return Err(Error::IO(e)),
    };

    // Send env vars as KEY=VALUE\n lines, terminated by empty line
    for key in ENV_VARS {
        if let Ok(val) = std::env::var(key) {
            let line = format!("{key}={val}\n");
            stream.write_all(line.as_bytes()).await?;
        }
    }
    stream.write_all(b"\n").await?;
    stream.flush().await?;

    // Read response byte
    let mut response = [0u8; 1];
    match tokio::time::timeout(Duration::from_secs(30), stream.read_exact(&mut response)).await {
        Ok(Ok(_)) if response[0] == 0 => {
            tracing::info!("Handed off environment to login daemon");
            Ok(())
        }
        Ok(Ok(_)) => Err(Error::IO(std::io::Error::other(
            "Login daemon reported initialization failure",
        ))),
        Ok(Err(e)) => Err(Error::IO(e)),
        Err(_) => Err(Error::IO(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "Timed out waiting for login daemon response",
        ))),
    }
}
