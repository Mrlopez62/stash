//! What the kernel says about a process: its parent, its start time, and its
//! name. The session agent uses this to decide who may reuse a session, and
//! unlock prompts use it to say who is asking.

use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcInfo {
    pub pid: i32,
    pub ppid: i32,
    /// Opaque start time. Together with the pid it identifies one specific
    /// process, so a recycled pid can't impersonate one that exited.
    pub start: u64,
    pub name: String,
}

/// A specific process, as recorded when a session is created.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Identity {
    pub pid: i32,
    pub start: u64,
}

impl ProcInfo {
    pub fn identity(&self) -> Identity {
        Identity {
            pid: self.pid,
            start: self.start,
        }
    }
}

#[cfg(target_os = "macos")]
pub fn info(pid: i32) -> Option<ProcInfo> {
    // SAFETY: `proc_bsdinfo` is plain data; proc_pidinfo fills at most `size` bytes.
    let mut bsd: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut bsd as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    if n != size {
        return None;
    }
    let name = c_chars_to_string(&bsd.pbi_name)
        .filter(|n| !n.is_empty())
        .or_else(|| c_chars_to_string(&bsd.pbi_comm))
        .unwrap_or_default();
    Some(ProcInfo {
        pid,
        ppid: bsd.pbi_ppid as i32,
        start: bsd.pbi_start_tvsec * 1_000_000 + bsd.pbi_start_tvusec,
        name,
    })
}

#[cfg(target_os = "macos")]
fn c_chars_to_string(chars: &[libc::c_char]) -> Option<String> {
    let bytes: Vec<u8> = chars
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8(bytes).ok()
}

#[cfg(target_os = "linux")]
pub fn info(pid: i32) -> Option<ProcInfo> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // `pid (comm) state ppid ...`; comm may contain spaces and parentheses,
    // so split on the last `)`.
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    let name = stat[open + 1..close].to_owned();
    let fields: Vec<&str> = stat[close + 1..].split_whitespace().collect();
    // After `)`: state(0) ppid(1) ... starttime is overall field 22 → index 19.
    Some(ProcInfo {
        pid,
        ppid: fields.get(1)?.parse().ok()?,
        start: fields.get(19)?.parse().ok()?,
        name,
    })
}

/// The pid of the process on the other end of a Unix socket, from the kernel.
#[cfg(target_os = "macos")]
pub fn peer_pid(stream: &UnixStream) -> Option<i32> {
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: `pid` and `len` are valid for writes of the sizes given.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut len,
        )
    };
    (rc == 0 && pid > 0).then_some(pid)
}

#[cfg(target_os = "linux")]
pub fn peer_pid(stream: &UnixStream) -> Option<i32> {
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
    (rc == 0 && cred.pid > 0).then_some(cred.pid)
}

/// The executable a process is running, with symlinks resolved.
#[cfg(target_os = "macos")]
pub fn exe_path(pid: i32) -> Option<std::path::PathBuf> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: proc_pidpath writes at most `buf.len()` bytes.
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    let path = std::path::PathBuf::from(String::from_utf8(buf).ok()?);
    path.canonicalize().ok().or(Some(path))
}

/// The executable a process is running, with symlinks resolved.
#[cfg(not(target_os = "macos"))]
pub fn exe_path(pid: i32) -> Option<std::path::PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

/// Whether the process on the other end of `stream` runs this same
/// executable. Used before trusting a socket with a key: any program can
/// listen on a path, but only stash runs the stash binary.
pub fn peer_is_this_program(stream: &UnixStream) -> bool {
    let Some(peer) = peer_pid(stream).and_then(exe_path) else {
        return false;
    };
    let Some(me) = std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
    else {
        return false;
    };
    peer == me
}

/// "sh ← stash ← zsh": who started this process, for unlock prompts.
pub fn requester_chain(depth: usize) -> String {
    let mut names = Vec::new();
    let mut pid = std::os::unix::process::parent_id() as i32;
    for _ in 0..depth {
        match info(pid) {
            Some(p) if p.pid > 1 => {
                names.push(crate::text::clean(&p.name, 32));
                pid = p.ppid;
            }
            _ => break,
        }
    }
    if names.is_empty() {
        "an unknown process".into()
    } else {
        names.join(" ← ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_this_process_and_its_parent() {
        let me = info(std::process::id() as i32).unwrap();
        assert_eq!(me.ppid, std::os::unix::process::parent_id() as i32);
        assert!(me.start > 0);
        assert!(!me.name.is_empty());
        let parent = info(me.ppid).unwrap();
        assert!(parent.start <= me.start || parent.pid == 1);
    }

    #[test]
    fn start_time_is_stable_for_a_process() {
        let pid = std::process::id() as i32;
        assert_eq!(info(pid).unwrap().start, info(pid).unwrap().start);
    }

    #[test]
    fn peer_pid_is_the_connecting_process() {
        let (a, b) = UnixStream::pair().unwrap();
        assert_eq!(peer_pid(&a), Some(std::process::id() as i32));
        drop(b);
    }
}
