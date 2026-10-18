//! Process hardening, applied at the start of every `stash` command.
//!
//! Several stash processes hold the vault key or secret values in memory
//! for a while (the session agent, `stash mcp`, the app server, the SSH
//! agent, the browser host, `stash run`). Another program running as you
//! shouldn't be able to read that memory, so:
//!
//! - **No core dumps**, which would write memory to disk.
//! - **No debugger attach** from other processes: `PT_DENY_ATTACH` on macOS,
//!   `PR_SET_DUMPABLE = 0` on Linux (which also blocks `/proc/<pid>/mem`).
//!
//! Root can still get around both; they stop same-user programs, which is
//! the threat here (an AI agent's shell, a malicious package script).

pub fn process() {
    // SAFETY: plain syscalls with constant arguments.
    unsafe {
        let none = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &none);
        #[cfg(target_os = "macos")]
        {
            // PT_DENY_ATTACH (31): later attach attempts fail.
            libc::ptrace(31, 0, std::ptr::null_mut(), 0);
        }
        #[cfg(target_os = "linux")]
        {
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
    }
}
