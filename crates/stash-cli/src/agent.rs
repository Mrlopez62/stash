//! The session agent: a short-lived background process that keeps unlocked
//! vault keys in memory, so one Touch ID or password unlock covers the next
//! few commands. It works like `ssh-agent`.
//!
//! - It listens on a Unix socket (`~/.stash/agent.sock`, mode `0600`) and
//!   only answers processes running as the same user.
//! - **Sessions are scoped to the process that unlocked.** When `stash` hands
//!   over a key, the agent asks the kernel who connected and records that
//!   process's *parent*, usually your shell, as the session's owner. A later
//!   `GET` succeeds only if the requester's parent is that same process (pid
//!   and start time), so commands you type in that shell reuse the session.
//!   Anything else, like a command launched by `stash run`, a script, or an AI
//!   agent's shell, has a different parent and must unlock for itself, with a
//!   prompt saying who is asking. Callers can't claim an identity: it all
//!   comes from the kernel.
//! - Each key is forgotten after it has gone unused for its idle timeout.
//! - The agent exits as soon as it holds no keys, so nothing lingers.
//!
//! Protocol: one request line and one response line per connection.
//!
//! ```text
//! PING                        -> PONG
//! GET <vault>                 -> KEY <hex> | NONE
//! PUT <idle-secs> <hex> <vault> -> OK
//! LOCK                        -> OK
//! ```

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use stash_core::crypto::{self, SecretKey};
use zeroize::Zeroizing;

use crate::procinfo::{self, Identity};

/// How long a fresh agent waits for its first key before exiting.
const STARTUP_GRACE: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const IO_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_REQUEST_LEN: u64 = 8 * 1024;
/// `sun_path` is 104 bytes on macOS (108 on Linux), including the NUL.
const MAX_SOCKET_PATH_LEN: usize = 103;

pub fn default_socket() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("STASH_AGENT_SOCK") {
        return Ok(PathBuf::from(path));
    }
    let home = dirs::home_dir().context("could not find your home directory")?;
    Ok(home.join(".stash").join("agent.sock"))
}

struct Entry {
    key: SecretKey,
    idle_timeout: Duration,
    last_used: Instant,
}

impl Entry {
    fn expired(&self) -> bool {
        self.last_used.elapsed() >= self.idle_timeout
    }
}

/// Run the agent in the foreground until it holds no more keys.
pub fn serve(socket: &Path) -> Result<()> {
    if socket.exists() {
        if UnixStream::connect(socket).is_ok() {
            bail!("an agent is already running at {}", socket.display());
        }
        fs::remove_file(socket)?;
    }
    if let Some(dir) = socket.parent() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    let listener = UnixListener::bind(socket)?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;

    let started = Instant::now();
    let mut keys: Sessions = HashMap::new();
    let mut held_a_key = false;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                // A misbehaving client must not take the agent down.
                let _ = handle(stream, &mut keys);
                held_a_key |= !keys.is_empty();
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => std::thread::sleep(POLL_INTERVAL),
            Err(e) => return Err(e.into()),
        }
        keys.retain(|_, entry| !entry.expired());
        if keys.is_empty() && (held_a_key || started.elapsed() > STARTUP_GRACE) {
            break;
        }
    }
    let _ = fs::remove_file(socket);
    Ok(())
}

/// Keys by vault and by the process that owns the session.
type Sessions = HashMap<(PathBuf, Identity), Entry>;

/// The session owner a connection maps to: the connecting process's parent.
fn requester_scope(stream: &UnixStream) -> Option<Identity> {
    let peer = procinfo::info(procinfo::peer_pid(stream)?)?;
    Some(procinfo::info(peer.ppid)?.identity())
}

fn handle(stream: UnixStream, keys: &mut Sessions) -> Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    if !peer_is_same_user(&stream) {
        return Ok(());
    }
    let mut line = Zeroizing::new(String::new());
    BufReader::new(&stream)
        .take(MAX_REQUEST_LEN)
        .read_line(&mut line)?;
    let scope = requester_scope(&stream);
    let response = respond(line.trim_end_matches('\n'), scope, keys);
    (&stream).write_all(response.as_bytes())?;
    Ok(())
}

fn respond(request: &str, scope: Option<Identity>, keys: &mut Sessions) -> Zeroizing<String> {
    let reply = |s: &str| Zeroizing::new(format!("{s}\n"));
    let (command, rest) = request.split_once(' ').unwrap_or((request, ""));
    match command {
        "PING" => reply("PONG"),
        "GET" => match scope.and_then(|scope| keys.get_mut(&(PathBuf::from(rest), scope))) {
            Some(entry) if !entry.expired() => {
                entry.last_used = Instant::now();
                let hex = crypto::to_hex(entry.key.as_ref());
                reply(&format!("KEY {}", hex.as_str()))
            }
            _ => reply("NONE"),
        },
        "PUT" => {
            let mut parts = rest.splitn(3, ' ');
            let (Some(secs), Some(hex), Some(vault)) = (parts.next(), parts.next(), parts.next())
            else {
                return reply("ERR");
            };
            let (Ok(secs), Some(key), Some(scope)) =
                (secs.parse::<u64>(), crypto::key_from_hex(hex), scope)
            else {
                return reply("ERR");
            };
            keys.insert(
                (PathBuf::from(vault), scope),
                Entry {
                    key,
                    idle_timeout: Duration::from_secs(secs),
                    last_used: Instant::now(),
                },
            );
            reply("OK")
        }
        "LOCK" => {
            keys.clear();
            reply("OK")
        }
        _ => reply("ERR"),
    }
}

#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
fn peer_is_same_user(stream: &UnixStream) -> bool {
    let (mut uid, mut gid) = (0, 0);
    // SAFETY: the fd is a valid, open socket owned by `stream`.
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    rc == 0 && uid == unsafe { libc::geteuid() }
}

#[cfg(target_os = "linux")]
fn peer_is_same_user(stream: &UnixStream) -> bool {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` and `len` are valid for writes of the sizes given.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    rc == 0 && cred.uid == unsafe { libc::geteuid() }
}

// ---- client side ----

fn request(socket: &Path, line: &str) -> Option<Zeroizing<String>> {
    let mut stream = UnixStream::connect(socket).ok()?;
    stream.set_read_timeout(Some(IO_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(IO_TIMEOUT)).ok()?;
    stream.write_all(line.as_bytes()).ok()?;
    stream.write_all(b"\n").ok()?;
    let mut response = Zeroizing::new(String::new());
    BufReader::new(stream)
        .take(MAX_REQUEST_LEN)
        .read_line(&mut response)
        .ok()?;
    Some(Zeroizing::new(response.trim_end().to_owned()))
}

/// Paths are sent on one line, so a vault path containing a newline can't
/// use the agent.
fn usable(vault: &Path) -> Option<&str> {
    vault.to_str().filter(|p| !p.contains('\n'))
}

/// Ask a running agent for a vault's key.
pub fn get(socket: &Path, vault: &Path) -> Option<SecretKey> {
    let response = request(socket, &format!("GET {}", usable(vault)?))?;
    crypto::key_from_hex(response.strip_prefix("KEY ")?)
}

/// Hand a key to the agent, starting one if needed.
pub fn put(socket: &Path, vault: &Path, key: &[u8; 32], idle_timeout: Duration) -> Result<()> {
    let vault = usable(vault).context("vault path can't be used with the agent")?;
    let len = socket.as_os_str().len();
    if len > MAX_SOCKET_PATH_LEN {
        bail!(
            "the agent socket path is {len} bytes, over the {MAX_SOCKET_PATH_LEN}-byte limit \
             for Unix sockets ({}); set STASH_AGENT_SOCK to a shorter path",
            socket.display()
        );
    }
    ensure_running(socket)?;
    let hex = crypto::to_hex(key);
    let line = Zeroizing::new(format!(
        "PUT {} {} {vault}",
        idle_timeout.as_secs(),
        hex.as_str()
    ));
    match request(socket, &line) {
        Some(r) if r.as_str() == "OK" => Ok(()),
        _ => bail!("the agent did not accept the key"),
    }
}

/// Tell a running agent to forget every key. Returns whether one was running.
pub fn lock(socket: &Path) -> bool {
    request(socket, "LOCK").is_some_and(|r| r.as_str() == "OK")
}

fn is_running(socket: &Path) -> bool {
    request(socket, "PING").is_some_and(|r| r.as_str() == "PONG")
}

fn ensure_running(socket: &Path) -> Result<()> {
    if is_running(socket) {
        return Ok(());
    }
    Command::new(std::env::current_exe()?)
        .arg("agent")
        .arg("--socket")
        .arg(socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        // Own process group, so Ctrl-C in the terminal doesn't kill it.
        .process_group(0)
        .spawn()
        .context("could not start the stash agent")?;
    let deadline = Instant::now() + IO_TIMEOUT;
    while Instant::now() < deadline {
        if is_running(socket) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    bail!("the stash agent did not start")
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn start(dir: &TempDir) -> PathBuf {
        let socket = dir.path().join("agent.sock");
        let path = socket.clone();
        std::thread::spawn(move || serve(&path).unwrap());
        let deadline = Instant::now() + IO_TIMEOUT;
        while !is_running(&socket) {
            assert!(Instant::now() < deadline, "agent did not start");
            std::thread::sleep(Duration::from_millis(10));
        }
        socket
    }

    fn put_line(secs: u64, key: &[u8; 32], vault: &str) -> String {
        format!("PUT {secs} {} {vault}", crypto::to_hex(key).as_str())
    }

    #[test]
    fn stores_and_returns_keys_per_vault() {
        let dir = TempDir::new().unwrap();
        let socket = start(&dir);
        let key = [9u8; 32];
        assert_eq!(
            request(&socket, &put_line(60, &key, "/v/a b.db"))
                .unwrap()
                .as_str(),
            "OK"
        );
        assert_eq!(*get(&socket, Path::new("/v/a b.db")).unwrap(), key);
        assert!(get(&socket, Path::new("/v/other.db")).is_none());
        assert!(lock(&socket));
    }

    #[test]
    fn forgets_keys_after_idle_timeout_and_exits() {
        let dir = TempDir::new().unwrap();
        let socket = start(&dir);
        request(&socket, &put_line(1, &[1u8; 32], "/v.db")).unwrap();
        std::thread::sleep(Duration::from_millis(1200));
        assert!(get(&socket, Path::new("/v.db")).is_none());
        // With nothing left to hold, the agent shuts down and removes its socket.
        std::thread::sleep(Duration::from_millis(200));
        assert!(!is_running(&socket));
        assert!(!socket.exists());
    }

    #[test]
    fn lock_forgets_everything() {
        let dir = TempDir::new().unwrap();
        let socket = start(&dir);
        request(&socket, &put_line(60, &[1u8; 32], "/a.db")).unwrap();
        request(&socket, &put_line(60, &[2u8; 32], "/b.db")).unwrap();
        assert!(lock(&socket));
        assert!(get(&socket, Path::new("/a.db")).is_none());
    }

    const SCOPE: Identity = Identity { pid: 100, start: 1 };

    fn put_key(keys: &mut Sessions, scope: Option<Identity>, vault: &str) -> String {
        let line = put_line(60, &[3u8; 32], vault);
        respond(&line, scope, keys).as_str().to_owned()
    }

    #[test]
    fn sessions_only_serve_the_process_that_owns_them() {
        let mut keys = HashMap::new();
        assert_eq!(put_key(&mut keys, Some(SCOPE), "/v.db"), "OK\n");

        let get =
            |keys: &mut Sessions, scope| respond("GET /v.db", scope, keys).as_str().to_owned();
        assert!(get(&mut keys, Some(SCOPE)).starts_with("KEY "));
        // Another process, or the same pid reused by a newer process: refused.
        assert_eq!(
            get(&mut keys, Some(Identity { pid: 101, start: 1 })),
            "NONE\n"
        );
        assert_eq!(
            get(&mut keys, Some(Identity { pid: 100, start: 2 })),
            "NONE\n"
        );
        // Unknown requester (its info couldn't be read): refused.
        assert_eq!(get(&mut keys, None), "NONE\n");
    }

    #[test]
    fn put_without_a_known_requester_is_refused() {
        let mut keys = HashMap::new();
        assert_eq!(put_key(&mut keys, None, "/v.db"), "ERR\n");
        assert!(keys.is_empty());
    }

    #[test]
    fn too_long_socket_paths_get_a_clear_error() {
        let socket = PathBuf::from(format!("/tmp/{}/agent.sock", "x".repeat(120)));
        let err = put(
            &socket,
            Path::new("/v.db"),
            &[0u8; 32],
            Duration::from_secs(1),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("over the 103-byte limit"), "{err}");
    }

    #[test]
    fn rejects_malformed_requests() {
        let mut keys = HashMap::new();
        for bad in ["PUT", "PUT 60", "PUT x abc /v", "PUT 60 nothex /v", "NOPE"] {
            assert_eq!(
                respond(bad, Some(SCOPE), &mut keys).as_str(),
                "ERR\n",
                "{bad}"
            );
        }
        assert!(keys.is_empty());
    }

    #[test]
    fn socket_is_private() {
        let dir = TempDir::new().unwrap();
        let socket = start(&dir);
        let mode = fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        lock(&socket);
    }
}
