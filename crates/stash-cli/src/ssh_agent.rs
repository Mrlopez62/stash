//! The stash SSH agent: serves the vault's SSH keys to `ssh`, `git`, and
//! `ssh-keygen -Y sign` over the standard agent protocol
//! (draft-miller-ssh-agent), so private keys never sit in `~/.ssh`.
//!
//! - **Every signature needs Touch ID**, and the prompt names the key, what
//!   it's for (an SSH login as `git`, a git commit signature), and the
//!   process asking. A fingerprint that unlocks the vault also approves the
//!   signature it was unlocked for, so there's one prompt, not two.
//! - **It only answers processes running as the same user**, on a `0600`
//!   socket in a `0700` directory.
//! - **The vault locks itself** after `--lock-after` of no signing. Public
//!   keys stay listed while locked (they aren't secret), so `ssh` can pick
//!   a key without a prompt; signing unlocks again.
//! - **It can't be changed from outside**: requests to add, remove, or lock
//!   keys are refused, so a compromised process can't plant its own key.
//! - Each signature (and each refusal) goes to the audit log, by key name,
//!   never with any key material.

use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use stash_core::ssh::{self, Reader, SignPurpose};
use stash_core::{Kind, Vault};
use zeroize::Zeroizing;

use crate::{audit, procinfo, touchid};

const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const FAILURE: u8 = 5;
/// OpenSSH's own limit.
const MAX_MESSAGE: usize = 256 * 1024;

pub fn default_socket() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("STASH_SSH_AUTH_SOCK") {
        return Ok(PathBuf::from(path));
    }
    let home = dirs::home_dir().context("could not find your home directory")?;
    Ok(home.join(".stash").join("ssh-agent.sock"))
}

/// How the agent unlocks the vault and approves signatures. Touch ID in
/// real use; tests substitute their own.
pub trait Gate: Send {
    /// Unlock the vault, asking the user. Counts as approving `reason`.
    fn unlock(&mut self, vault: &Path, reason: &str) -> Result<Vault, String>;
    fn approve(&mut self, reason: &str) -> Result<(), String>;
}

pub struct TouchIdGate {
    /// Off only for headless use with STASH_PASSWORD (`--no-approval`).
    pub approve: bool,
}

impl Gate for TouchIdGate {
    fn unlock(&mut self, vault: &Path, reason: &str) -> Result<Vault, String> {
        if let Ok(password) = std::env::var(crate::PASSWORD_ENV) {
            // Headless use still needs a fingerprint per signature (below).
            let password = Zeroizing::new(password);
            return Vault::open(vault, password.as_bytes()).map_err(|e| e.to_string());
        }
        let helper = touchid::helper().ok_or("the stash-touchid helper was not found")?;
        if !touchid::is_enrolled(vault) {
            return Err("the SSH agent needs Touch ID; run `stash touchid enable`".into());
        }
        let key = touchid::unlock(&helper, vault, reason).map_err(describe)?;
        Vault::open_with_key(vault, &key).map_err(|e| e.to_string())
    }

    fn approve(&mut self, reason: &str) -> Result<(), String> {
        if !self.approve {
            return Ok(());
        }
        let helper = touchid::helper().ok_or("the stash-touchid helper was not found")?;
        touchid::confirm(&helper, reason).map_err(describe)
    }
}

fn describe(e: touchid::UnlockError) -> String {
    match e {
        touchid::UnlockError::Cancelled => "cancelled".into(),
        touchid::UnlockError::Unavailable(why) => format!("Touch ID unavailable: {why}"),
        touchid::UnlockError::Failed(why) => format!("Touch ID failed: {why}"),
    }
}

/// A key the agent offers: its vault name and public blob.
#[derive(Clone)]
struct Listed {
    name: String,
    blob: Vec<u8>,
}

pub struct Agent<G: Gate> {
    vault_path: PathBuf,
    audit_log: PathBuf,
    lock_after: Duration,
    gate: G,
    unlocked: Option<(Vault, Instant)>,
    /// Public keys from the last unlock, so listing never needs a prompt.
    listed: Option<Vec<Listed>>,
    /// Set when the user was just asked to unlock, which also approves the
    /// signature that needed it.
    fresh_unlock: bool,
}

impl<G: Gate> Agent<G> {
    pub fn new(vault_path: PathBuf, lock_after: Duration, gate: G) -> Self {
        Self {
            audit_log: audit::path_for(&vault_path),
            vault_path,
            lock_after,
            gate,
            unlocked: None,
            listed: None,
            fresh_unlock: false,
        }
    }

    /// The unlocked vault, unlocking (and so approving `reason`) if needed.
    fn vault(&mut self, reason: &str) -> Result<&Vault, String> {
        if self
            .unlocked
            .as_ref()
            .is_some_and(|(_, at)| at.elapsed() >= self.lock_after)
        {
            self.unlocked = None;
        }
        if self.unlocked.is_none() {
            let vault = self.gate.unlock(&self.vault_path, reason)?;
            self.listed = Some(list(&vault).map_err(|e| e.to_string())?);
            self.unlocked = Some((vault, Instant::now()));
            self.fresh_unlock = true;
        }
        let (vault, _) = self.unlocked.as_ref().expect("unlocked above");
        Ok(vault)
    }

    fn identities(&mut self, client: &str) -> Vec<Listed> {
        if self.listed.is_none() {
            let reason = format!("unlock stash to list SSH keys for {client}");
            if let Err(why) = self.vault(&reason) {
                eprintln!("stash ssh agent: not listing keys: {why}");
            }
        }
        self.listed.clone().unwrap_or_default()
    }

    fn sign(&mut self, blob: &[u8], data: &[u8], client: &str) -> Option<Vec<u8>> {
        self.fresh_unlock = false;
        let listed = self.identities(client);
        let name = listed.iter().find(|k| k.blob == blob)?.name.clone();
        let purpose = SignPurpose::of(data);
        let what = match &purpose {
            SignPurpose::Login { user } => format!("use SSH key “{name}” to log in as {user}"),
            SignPurpose::File { namespace } if namespace == "git" => {
                format!("sign a git commit or tag with SSH key “{name}”")
            }
            SignPurpose::File { namespace } => {
                format!("sign {namespace} data with SSH key “{name}”")
            }
            SignPurpose::Unknown => format!("sign with SSH key “{name}”"),
        };
        let reason = format!("{what}, for {client}");

        let mut event = audit::Event {
            time: audit::now_rfc3339(),
            client: client.to_owned(),
            tool: "ssh-sign".into(),
            secrets: vec![name.clone()],
            command: None,
            outcome: "approved".into(),
            exit_code: None,
            detail: Some(what),
        };
        let result = (|| {
            self.vault(&reason)?;
            if !std::mem::take(&mut self.fresh_unlock) {
                self.gate.approve(&reason)?;
            }
            // The vault that was just checked, even if the approval dialog
            // outlasted the idle timeout.
            let (vault, _) = self.unlocked.as_ref().ok_or("locked")?;
            let item = vault.item(&name).map_err(|e| e.to_string())?;
            let pair = item.ssh_key_pair().map_err(|e| e.to_string())?;
            if pair.public_blob() != blob {
                return Err("the key changed since it was listed".to_owned());
            }
            Ok(pair.sign(data))
        })();
        // Approval resets the idle clock.
        if let Some((_, at)) = self.unlocked.as_mut() {
            *at = Instant::now();
        }
        if let Err(why) = &result {
            event.outcome = if why == "cancelled" {
                "denied"
            } else {
                "error"
            }
            .into();
            event.detail = Some(format!(
                "{}: {why}",
                event.detail.take().unwrap_or_default()
            ));
        }
        if let Err(e) = audit::record(&self.audit_log, &event) {
            eprintln!("stash ssh agent: could not write the audit log: {e:#}");
        }
        result.ok()
    }

    /// Answer one agent message (its type byte and contents).
    pub fn respond(&mut self, message: &[u8], client: &str) -> Vec<u8> {
        let failure = vec![FAILURE];
        let Some((&kind, body)) = message.split_first() else {
            return failure;
        };
        match kind {
            REQUEST_IDENTITIES => {
                let keys = self.identities(client);
                let mut out = vec![IDENTITIES_ANSWER];
                out.extend_from_slice(&(keys.len() as u32).to_be_bytes());
                for k in keys {
                    ssh::put_string(&mut out, &k.blob);
                    ssh::put_string(&mut out, k.name.as_bytes());
                }
                out
            }
            SIGN_REQUEST => {
                let mut r = Reader::new(body);
                let (Ok(blob), Ok(data)) = (r.string(), r.string()) else {
                    return failure;
                };
                match self.sign(blob, data, client) {
                    Some(signature) => {
                        let mut out = vec![SIGN_RESPONSE];
                        ssh::put_string(&mut out, &signature);
                        out
                    }
                    None => failure,
                }
            }
            // Adding, removing, and locking keys, and extensions: refused.
            _ => failure,
        }
    }
}

/// Every SSH key item's name and public blob.
fn list(vault: &Vault) -> stash_core::Result<Vec<Listed>> {
    let mut keys = Vec::new();
    for summary in vault.summaries()? {
        if summary.kind != Kind::Ssh {
            continue;
        }
        let item = vault.item(&summary.name)?;
        if let Ok(pair) = item.ssh_key_pair() {
            keys.push(Listed {
                name: summary.name,
                blob: pair.public_blob(),
            });
        }
    }
    Ok(keys)
}

/// "ssh ← git ← zsh" for the process on the other end of the socket.
fn client_of(stream: &UnixStream) -> String {
    let mut names = Vec::new();
    let mut pid = procinfo::peer_pid(stream);
    while let Some(p) = pid.and_then(procinfo::info) {
        if p.pid <= 1 || names.len() == 3 {
            break;
        }
        names.push(p.name.clone());
        pid = Some(p.ppid);
    }
    if names.is_empty() {
        "an unknown process".into()
    } else {
        names.join(" ← ")
    }
}

/// Run the agent in the foreground.
pub fn serve<G: Gate + 'static>(socket: &Path, agent: Agent<G>) -> Result<()> {
    let listener = bind(socket)?;
    eprintln!("stash ssh agent listening on {}", socket.display());
    let agent = Arc::new(Mutex::new(agent));
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        if !crate::agent::peer_is_same_user(&stream) {
            continue;
        }
        let agent = Arc::clone(&agent);
        // `ssh` keeps its connection open for the whole session, so each
        // client gets a thread. Signing itself is one at a time.
        std::thread::spawn(move || {
            let _ = connection(stream, &agent);
        });
    }
    Ok(())
}

fn bind(socket: &Path) -> Result<UnixListener> {
    if socket.exists() {
        if UnixStream::connect(socket).is_ok() {
            bail!("an SSH agent is already running at {}", socket.display());
        }
        fs::remove_file(socket)?;
    }
    if let Some(dir) = socket.parent() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    let listener = UnixListener::bind(socket)
        .with_context(|| format!("could not listen on {}", socket.display()))?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

fn connection<G: Gate>(mut stream: UnixStream, agent: &Mutex<Agent<G>>) -> Result<()> {
    let client = client_of(&stream);
    loop {
        let mut len = [0u8; 4];
        match stream.read_exact(&mut len) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        }
        let len = u32::from_be_bytes(len) as usize;
        if len == 0 || len > MAX_MESSAGE {
            return Ok(());
        }
        let mut message = Zeroizing::new(vec![0u8; len]);
        stream.read_exact(&mut message)?;
        let reply = agent
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .respond(&message, &client);
        let mut framed = (reply.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(&reply);
        stream.write_all(&framed)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stash_core::ssh::KeyPair;
    use stash_core::{Item, KdfParams};
    use tempfile::TempDir;

    struct TestGate {
        unlocks: usize,
        approvals: usize,
        allow: bool,
    }

    impl Gate for &'static Mutex<TestGate> {
        fn unlock(&mut self, vault: &Path, _: &str) -> Result<Vault, String> {
            let mut g = self.lock().unwrap();
            g.unlocks += 1;
            if !g.allow {
                return Err("cancelled".into());
            }
            Vault::open(vault, b"pw").map_err(|e| e.to_string())
        }
        fn approve(&mut self, _: &str) -> Result<(), String> {
            let mut g = self.lock().unwrap();
            g.approvals += 1;
            if g.allow {
                Ok(())
            } else {
                Err("cancelled".into())
            }
        }
    }

    fn setup() -> (TempDir, PathBuf, KeyPair, &'static Mutex<TestGate>) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.db");
        let mut vault = Vault::create(
            &path,
            b"pw",
            KdfParams {
                m_cost_kib: 8,
                t_cost: 1,
                p_cost: 1,
            },
        )
        .unwrap();
        let pair = KeyPair::generate("laptop").unwrap();
        vault
            .put("ssh/github", &Item::ssh_key(&pair), false)
            .unwrap();
        vault.put("token", &Item::secret("x"), false).unwrap();
        let gate = Box::leak(Box::new(Mutex::new(TestGate {
            unlocks: 0,
            approvals: 0,
            allow: true,
        })));
        (dir, path, pair, gate)
    }

    fn counts(gate: &Mutex<TestGate>) -> (usize, usize) {
        let g = gate.lock().unwrap();
        (g.unlocks, g.approvals)
    }

    fn sign_request(blob: &[u8], data: &[u8]) -> Vec<u8> {
        let mut m = vec![SIGN_REQUEST];
        ssh::put_string(&mut m, blob);
        ssh::put_string(&mut m, data);
        m.extend_from_slice(&0u32.to_be_bytes());
        m
    }

    #[test]
    fn lists_only_ssh_keys() {
        let (_dir, path, pair, gate) = setup();
        let mut agent = Agent::new(path, Duration::from_secs(60), gate);
        let reply = agent.respond(&[REQUEST_IDENTITIES], "test");
        assert_eq!(reply[0], IDENTITIES_ANSWER);
        let mut r = Reader::new(&reply[1..]);
        assert_eq!(r.u32().unwrap(), 1);
        assert_eq!(r.string().unwrap(), pair.public_blob());
        assert_eq!(r.string().unwrap(), b"ssh/github");
        assert!(r.is_empty());
    }

    #[test]
    fn one_prompt_unlocks_and_signs_then_each_signature_asks() {
        let (_dir, path, pair, gate) = setup();
        let mut agent = Agent::new(path, Duration::from_secs(60), gate);
        let reply = agent.respond(&sign_request(&pair.public_blob(), b"data"), "test");
        assert_eq!(reply[0], SIGN_RESPONSE);
        assert_eq!(counts(gate), (1, 0));

        let reply = agent.respond(&sign_request(&pair.public_blob(), b"more"), "test");
        assert_eq!(reply[0], SIGN_RESPONSE);
        assert_eq!(counts(gate), (1, 1));

        // The signature verifies against the listed key.
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let mut r = Reader::new(&reply[1..]);
        let mut sig = Reader::new(r.string().unwrap());
        assert_eq!(sig.string().unwrap(), b"ssh-ed25519");
        let sig = Signature::from_slice(sig.string().unwrap()).unwrap();
        assert!(
            VerifyingKey::from_bytes(&pair.public())
                .unwrap()
                .verify(b"more", &sig)
                .is_ok()
        );
    }

    #[test]
    fn a_declined_prompt_signs_nothing_and_is_logged() {
        let (dir, path, pair, gate) = setup();
        let mut agent = Agent::new(path, Duration::from_secs(60), gate);
        agent.respond(&[REQUEST_IDENTITIES], "test");
        gate.lock().unwrap().allow = false;
        let reply = agent.respond(&sign_request(&pair.public_blob(), b"data"), "evil");
        assert_eq!(reply, vec![FAILURE]);
        let log = audit::recent(&dir.path().join("audit.log"), 10).unwrap();
        let last = log.last().unwrap();
        assert_eq!(
            (last.tool.as_str(), last.outcome.as_str()),
            ("ssh-sign", "denied")
        );
        assert_eq!(last.secrets, vec!["ssh/github".to_owned()]);
    }

    #[test]
    fn locks_after_idle_but_keeps_listing() {
        let (_dir, path, pair, gate) = setup();
        let mut agent = Agent::new(path, Duration::ZERO, gate);
        agent.respond(&[REQUEST_IDENTITIES], "test");
        assert_eq!(
            agent.respond(&[REQUEST_IDENTITIES], "test")[0],
            IDENTITIES_ANSWER
        );
        assert_eq!(counts(gate).0, 1, "listing again needs no prompt");
        agent.respond(&sign_request(&pair.public_blob(), b"x"), "test");
        assert_eq!(
            counts(gate).0,
            2,
            "signing after the idle lock unlocks again"
        );
    }

    #[test]
    fn refuses_unknown_keys_and_key_management() {
        let (_dir, path, _pair, gate) = setup();
        let mut agent = Agent::new(path, Duration::from_secs(60), gate);
        let stranger = KeyPair::generate("").unwrap();
        assert_eq!(
            agent.respond(&sign_request(&stranger.public_blob(), b"x"), "t"),
            vec![FAILURE]
        );
        for kind in [17u8, 18, 19, 22, 23, 27] {
            assert_eq!(agent.respond(&[kind, 0, 0, 0, 0], "t"), vec![FAILURE]);
        }
        assert_eq!(agent.respond(&[], "t"), vec![FAILURE]);
        assert_eq!(
            agent.respond(&[SIGN_REQUEST, 0, 0, 0, 9], "t"),
            vec![FAILURE]
        );
    }
}
