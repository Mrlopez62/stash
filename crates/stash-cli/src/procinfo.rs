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

/// AI coding agents that run in a terminal. One of them that can script
/// your terminal (macOS Automation) can type commands into a shell that has
/// an unlocked session, so sessions pause while any of them runs.
const AI_AGENTS: &[&str] = &[
    "aider",
    "amp",
    "claude",
    "codex",
    "copilot",
    "crush",
    "cursor-agent",
    "droid",
    "gemini",
    "goose",
    "kiro-cli",
    "opencode",
    "qwen",
];

/// Agents installed as scripts (or shell wrappers) run under one of these;
/// the script's name is the first argument.
fn is_interpreter(name: &str) -> bool {
    matches!(
        name,
        "node" | "bun" | "deno" | "ruby" | "sh" | "bash" | "zsh" | "dash"
    ) || name.starts_with("python")
}

/// An AI agent found running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agent {
    /// The name it matched (see [`AI_AGENTS`]).
    pub name: String,
    pub pid: i32,
    /// What's actually running: the executable, or the script an
    /// interpreter runs. Some names are shared with unrelated tools (`goose`
    /// is also a database migration tool), so this tells them apart.
    pub path: std::path::PathBuf,
}

/// The agents' names, sorted and without repeats, for prompts.
pub fn agent_names(agents: &[Agent]) -> Vec<String> {
    let names: std::collections::BTreeSet<&str> = agents.iter().map(|a| a.name.as_str()).collect();
    names.into_iter().map(str::to_owned).collect()
}

/// The AI agents (see [`AI_AGENTS`]) running as this user right now.
pub fn running_ai_agents() -> Vec<Agent> {
    // Debug builds only, for tests: replace the list (comma-separated).
    let custom = cfg!(debug_assertions)
        .then(|| std::env::var("STASH_AI_AGENTS").ok())
        .flatten();
    let watched: Vec<&str> = match &custom {
        Some(list) => list
            .split(',')
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .collect(),
        None => AI_AGENTS.to_vec(),
    };
    let me = std::process::id() as i32;
    let mut found = Vec::new();
    for pid in own_pids() {
        if pid == me {
            continue;
        }
        let Some(mut path) = exe_path(pid) else {
            continue;
        };
        let Some(mut name) = file_name(&path) else {
            continue;
        };
        if is_interpreter(&name)
            && let Some(script) = argv1(pid)
            && let Some(script_name) = file_name(std::path::Path::new(&script))
        {
            name = script_name;
            path = script.into();
        }
        let name = name.trim_end_matches(".js").trim_end_matches(".py");
        if watched.contains(&name) {
            found.push(Agent {
                name: name.to_owned(),
                pid,
                path,
            });
        }
    }
    found.sort_by(|a, b| (&a.name, a.pid).cmp(&(&b.name, b.pid)));
    found
}

/// Processes running as this user whose environment holds exactly
/// `name=value`, with their start times (to signal only those exact
/// processes later). Every process a command starts inherits its
/// environment, even ones that left its process group (`setsid`, `nohup`,
/// double forks), unless they clear it. macOS hides the environment of its
/// own system programs (`/bin/sh`, `/bin/sleep`, ...), so those aren't
/// found there; everything else (node, python, your builds) is.
///
/// Only processes started at or after `since` (a [`ProcInfo::start`]) are
/// checked, which skips reading most environments.
pub fn with_env(name: &str, value: &str, since: u64) -> Vec<Identity> {
    let wanted = format!("{name}={value}").into_bytes();
    let me = std::process::id() as i32;
    own_pids()
        .into_iter()
        .filter(|&pid| pid != me)
        .filter_map(info)
        .filter(|p| p.start >= since)
        .filter(|p| environment(p.pid).is_some_and(|env| env.contains(&wanted)))
        .map(|p| p.identity())
        .collect()
}

/// Signal a process, only if it's still the one in `id`.
pub fn signal(id: Identity, signal: libc::c_int) -> bool {
    if info(id.pid).map(|p| p.start) != Some(id.start) {
        return false;
    }
    // SAFETY: signalling a process we just confirmed is the one we mean.
    unsafe { libc::kill(id.pid, signal) == 0 }
}

fn file_name(path: &std::path::Path) -> Option<String> {
    Some(path.file_name()?.to_str()?.to_owned())
}

/// Every process running as this user.
#[cfg(target_os = "macos")]
fn own_pids() -> Vec<i32> {
    // SAFETY: a null buffer asks for the count; then it's filled up to its size.
    let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if count <= 0 {
        return Vec::new();
    }
    let mut pids = vec![0i32; count as usize + 64];
    let size = (pids.len() * std::mem::size_of::<i32>()) as libc::c_int;
    let n = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), size) };
    pids.truncate(n.max(0) as usize);
    // SAFETY: getuid can't fail.
    let uid = unsafe { libc::getuid() };
    pids.retain(|&pid| pid > 0 && owner(pid) == Some(uid));
    pids
}

#[cfg(target_os = "macos")]
fn owner(pid: i32) -> Option<libc::uid_t> {
    // SAFETY: as in `info`.
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
    (n == size).then_some(bsd.pbi_uid)
}

/// A process's arguments and environment, from the kernel
/// (`KERN_PROCARGS2`: argc, the executable's path, padding, argv, then the
/// environment). Readable for processes running as this user.
/// A process's argv and environment strings.
#[cfg(target_os = "macos")]
type ProcArgs = (Vec<Vec<u8>>, Vec<Vec<u8>>);

#[cfg(target_os = "macos")]
fn procargs(pid: i32) -> Option<ProcArgs> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut size: libc::size_t = 0;
    // SAFETY: a null buffer asks for the size; then it's filled up to `size`.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || size < 4 {
        return None;
    }
    let mut buf = vec![0u8; size];
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    buf.truncate(size);
    let argc = usize::try_from(i32::from_ne_bytes(buf.get(..4)?.try_into().ok()?)).ok()?;
    let rest = &buf[4..];
    let exe_end = rest.iter().position(|&b| b == 0)?;
    let mut strings = rest[exe_end..]
        .split(|&b| b == 0)
        .skip_while(|a| a.is_empty());
    let argv: Vec<Vec<u8>> = strings.by_ref().take(argc).map(<[u8]>::to_vec).collect();
    let env = strings
        .take_while(|e| !e.is_empty())
        .map(<[u8]>::to_vec)
        .collect();
    Some((argv, env))
}

#[cfg(target_os = "macos")]
fn argv1(pid: i32) -> Option<String> {
    let (argv, _) = procargs(pid)?;
    String::from_utf8(argv.get(1)?.clone()).ok()
}

#[cfg(target_os = "macos")]
fn environment(pid: i32) -> Option<Vec<Vec<u8>>> {
    Some(procargs(pid)?.1)
}

#[cfg(target_os = "linux")]
fn own_pids() -> Vec<i32> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: getuid can't fail.
    let uid = unsafe { libc::getuid() };
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|e| e.metadata().is_ok_and(|m| m.uid() == uid))
        .filter_map(|e| e.file_name().to_str()?.parse().ok())
        .collect()
}

#[cfg(target_os = "linux")]
fn environment(pid: i32) -> Option<Vec<Vec<u8>>> {
    let environ = std::fs::read(format!("/proc/{pid}/environ")).ok()?;
    Some(
        environ
            .split(|&b| b == 0)
            .filter(|e| !e.is_empty())
            .map(<[u8]>::to_vec)
            .collect(),
    )
}

#[cfg(target_os = "linux")]
fn argv1(pid: i32) -> Option<String> {
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let arg = cmdline.split(|&b| b == 0).nth(1)?;
    String::from_utf8(arg.to_vec()).ok()
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

    /// A stand-in AI agent: a shell script with the watched name.
    fn fake_agent(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        // `read` waits on stdin without starting child processes (a loop
        // of `sleep` would fork copies of the shell, with the same name).
        std::fs::write(path, "#!/bin/sh\nread x\n").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn finds_agents_by_executable_name() {
        let dir = tempfile::TempDir::new().unwrap();
        let fake = dir.path().join("stash-unit-agent");
        fake_agent(&fake);
        let mut child = std::process::Command::new(&fake)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        // SAFETY (env): this test is the only one reading STASH_AI_AGENTS.
        unsafe { std::env::set_var("STASH_AI_AGENTS", "stash-unit-agent, other") };
        let mut found = Vec::new();
        for _ in 0..50 {
            found = agent_names(&running_ai_agents());
            if !found.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(found, vec!["stash-unit-agent"]);
        assert!(running_ai_agents().is_empty());
        unsafe { std::env::remove_var("STASH_AI_AGENTS") };
    }

    #[test]
    fn peer_pid_is_the_connecting_process() {
        let (a, b) = UnixStream::pair().unwrap();
        assert_eq!(peer_pid(&a), Some(std::process::id() as i32));
        drop(b);
    }
}
