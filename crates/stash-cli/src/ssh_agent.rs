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

/// After a declined prompt, signing is refused for this long, so a process
/// can't keep asking until a prompt gets approved out of habit.
const DENIAL_COOLDOWN: Duration = Duration::from_secs(10);

pub struct Agent<G: Gate> {
    vault_path: PathBuf,
    audit_log: PathBuf,
    lock_after: Duration,
    gate: G,
    unlocked: Option<(Vault, Instant)>,
    /// Public keys, refreshed whenever the vault is unlocked and kept while
    /// it's locked, so listing never needs a prompt after the first time.
    listed: Option<Vec<Listed>>,
    last_denial: Option<Instant>,
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
            last_denial: None,
        }
    }

    /// Forget the vault key once it has gone unused for `lock_after`.
    fn expire(&mut self) {
        if self
            .unlocked
            .as_ref()
            .is_some_and(|(_, at)| at.elapsed() >= self.lock_after)
        {
            self.unlocked = None;
        }
    }

    /// Unlock with a prompt saying `reason`.
    fn unlock(&mut self, reason: &str) -> Result<(), String> {
        let vault = self.gate.unlock(&self.vault_path, reason)?;
        self.unlocked = Some((vault, Instant::now()));
        Ok(())
    }

    /// Re-read the key list from the unlocked vault, so keys added since
    /// the last unlock show up.
    fn refresh(&mut self) {
        if let Some((vault, _)) = &self.unlocked {
            match list(vault) {
                Ok(keys) => self.listed = Some(keys),
                Err(e) => eprintln!("stash ssh agent: could not list keys: {e}"),
            }
        }
    }

    fn identities(&mut self, client: &str) -> Vec<Listed> {
        self.expire();
        if self.unlocked.is_none() && self.listed.is_none() {
            let reason = format!("unlock stash to list SSH keys for {client}");
            if let Err(why) = self.unlock(&reason) {
                eprintln!("stash ssh agent: not listing keys: {why}");
            }
        }
        self.refresh();
        self.listed.clone().unwrap_or_default()
    }

    fn name_of(&self, blob: &[u8]) -> Option<String> {
        self.listed
            .as_ref()?
            .iter()
            .find(|k| k.blob == blob)
            .map(|k| k.name.clone())
    }

    fn sign(&mut self, blob: &[u8], data: &[u8], client: &str) -> Option<Vec<u8>> {
        self.expire();
        let purpose = SignPurpose::of(data);
        let mut event = audit::Event {
            time: audit::now_rfc3339(),
            client: client.to_owned(),
            tool: "ssh-sign".into(),
            secrets: Vec::new(),
            command: None,
            outcome: "approved".into(),
            exit_code: None,
            detail: None,
        };
        let result = self.approve_and_sign(blob, data, &purpose, client, &mut event);
        if let Err(why) = &result {
            event.outcome = match why {
                Refused::Denied => "denied",
                Refused::Cooldown | Refused::UnknownKey => "blocked",
                Refused::Failed(_) => "error",
            }
            .into();
            let why = match why {
                Refused::Denied => "declined".to_owned(),
                Refused::Cooldown => "refused for a few seconds after a declined prompt".to_owned(),
                Refused::UnknownKey => "not a stash key".to_owned(),
                Refused::Failed(why) => why.clone(),
            };
            event.detail = Some(format!(
                "{}: {why}",
                event.detail.take().unwrap_or_default()
            ));
        }
        // Signing (or trying to) resets the idle clock.
        if let Some((_, at)) = self.unlocked.as_mut() {
            *at = Instant::now();
        }
        // Unknown keys are routine (ssh tries keys from other agents too),
        // so only stash keys are logged.
        if !matches!(result, Err(Refused::UnknownKey))
            && let Err(e) = audit::record(&self.audit_log, &event)
        {
            eprintln!("stash ssh agent: could not write the audit log: {e:#}");
        }
        result.ok()
    }

    /// The approval rule: the prompt the user approves always names this
    /// signature. A locked vault is unlocked with that prompt (one prompt,
    /// not two); an unlocked one asks for a fingerprint. An unlock done
    /// earlier for any other reason, like listing keys, never counts.
    fn approve_and_sign(
        &mut self,
        blob: &[u8],
        data: &[u8],
        purpose: &SignPurpose,
        client: &str,
        event: &mut audit::Event,
    ) -> Result<Vec<u8>, Refused> {
        if self
            .last_denial
            .is_some_and(|at| at.elapsed() < DENIAL_COOLDOWN)
        {
            event.detail = Some(describe_purpose(purpose, self.name_of(blob).as_deref()));
            event.secrets = self.name_of(blob).into_iter().collect();
            return Err(Refused::Cooldown);
        }
        let mut approved = false;
        if self.unlocked.is_none() {
            // Only a key we've listed can be named; otherwise "an SSH key".
            if self.listed.is_some() && self.name_of(blob).is_none() {
                return Err(Refused::UnknownKey);
            }
            let reason = format!(
                "{}, for {client}",
                describe_purpose(purpose, self.name_of(blob).as_deref())
            );
            event.detail = Some(describe_purpose(purpose, self.name_of(blob).as_deref()));
            self.unlock(&reason).map_err(|why| self.refusal(why))?;
            approved = true;
        }
        self.refresh();
        let name = self.name_of(blob).ok_or(Refused::UnknownKey)?;
        let what = describe_purpose(purpose, Some(&name));
        event.secrets = vec![name.clone()];
        event.detail = Some(what.clone());
        if !approved {
            self.gate
                .approve(&format!("{what}, for {client}"))
                .map_err(|why| self.refusal(why))?;
        }
        let (vault, _) = self
            .unlocked
            .as_ref()
            .ok_or(Refused::Failed("locked".into()))?;
        let item = vault
            .item(&name)
            .map_err(|e| Refused::Failed(e.to_string()))?;
        let pair = item
            .ssh_key_pair()
            .map_err(|e| Refused::Failed(e.to_string()))?;
        if pair.public_blob() != blob {
            return Err(Refused::Failed(
                "the key changed since it was listed".into(),
            ));
        }
        Ok(pair.sign(data))
    }

    fn refusal(&mut self, why: String) -> Refused {
        if why == "cancelled" {
            self.last_denial = Some(Instant::now());
            Refused::Denied
        } else {
            Refused::Failed(why)
        }
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

enum Refused {
    Denied,
    Cooldown,
    UnknownKey,
    Failed(String),
}

/// What a signature is for, in the prompt's words. The user name and
/// namespace come from the requesting program, so only short, plain values
/// are shown; anything else could dress up the prompt.
fn describe_purpose(purpose: &SignPurpose, key: Option<&str>) -> String {
    let key = key.map_or_else(|| "an SSH key".to_owned(), |k| format!("SSH key “{k}”"));
    match purpose {
        SignPurpose::Login { user } => match plain(user) {
            Some(user) => format!("use {key} to log in as {user}"),
            None => format!("use {key} to log in"),
        },
        SignPurpose::File { namespace } if namespace == "git" => {
            format!("sign a git commit or tag with {key}")
        }
        SignPurpose::File { namespace } => match plain(namespace) {
            Some(ns) => format!("sign {ns} data with {key}"),
            None => format!("sign data with {key}"),
        },
        SignPurpose::Unknown => format!("sign with {key}"),
    }
}

/// `s` if it's short and made only of letters, digits, and `._@-`.
fn plain(s: &str) -> Option<&str> {
    let ok = !s.is_empty()
        && s.len() <= 32
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '@' | '-'));
    ok.then_some(s)
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
    if UnixStream::connect(socket).is_ok() {
        // Not an error: launchd, or a second shell, found one already
        // running. Exiting successfully keeps launchd from retrying.
        eprintln!("stash ssh agent is already running at {}", socket.display());
        return Ok(());
    }
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
        /// Every prompt's text, in order.
        reasons: Vec<String>,
    }

    impl Gate for &'static Mutex<TestGate> {
        fn unlock(&mut self, vault: &Path, reason: &str) -> Result<Vault, String> {
            let mut g = self.lock().unwrap();
            g.unlocks += 1;
            g.reasons.push(format!("unlock: {reason}"));
            if !g.allow {
                return Err("cancelled".into());
            }
            Vault::open(vault, b"pw").map_err(|e| e.to_string())
        }
        fn approve(&mut self, reason: &str) -> Result<(), String> {
            let mut g = self.lock().unwrap();
            g.approvals += 1;
            g.reasons.push(format!("approve: {reason}"));
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
            reasons: Vec::new(),
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

    fn reasons(gate: &Mutex<TestGate>) -> Vec<String> {
        gate.lock().unwrap().reasons.clone()
    }

    fn login(user: &[u8]) -> Vec<u8> {
        let mut d = Vec::new();
        ssh::put_string(&mut d, b"session");
        d.push(50);
        ssh::put_string(&mut d, user);
        ssh::put_string(&mut d, b"ssh-connection");
        ssh::put_string(&mut d, b"publickey");
        d
    }

    #[test]
    fn a_listing_unlock_never_approves_a_signature() {
        let (_dir, path, pair, gate) = setup();
        let mut agent = Agent::new(path, Duration::from_secs(60), gate);
        agent.respond(&[REQUEST_IDENTITIES], "ssh");
        let reply = agent.respond(&sign_request(&pair.public_blob(), &login(b"git")), "ssh");
        assert_eq!(reply[0], SIGN_RESPONSE);
        let r = reasons(gate);
        assert_eq!(r.len(), 2, "{r:?}");
        assert!(
            r[0].starts_with("unlock: unlock stash to list SSH keys"),
            "{r:?}"
        );
        assert_eq!(
            r[1],
            "approve: use SSH key “ssh/github” to log in as git, for ssh"
        );
    }

    #[test]
    fn a_locked_agent_unlocks_with_a_prompt_naming_the_signature() {
        let (_dir, path, pair, gate) = setup();
        let mut agent = Agent::new(path, Duration::from_secs(60), gate);
        let reply = agent.respond(&sign_request(&pair.public_blob(), &login(b"git")), "ssh");
        assert_eq!(reply[0], SIGN_RESPONSE);
        assert_eq!(
            reasons(gate),
            vec!["unlock: use an SSH key to log in as git, for ssh".to_owned()]
        );
    }

    #[test]
    fn requester_text_cant_dress_up_the_prompt() {
        let (_dir, path, pair, gate) = setup();
        let mut agent = Agent::new(path, Duration::from_secs(60), gate);
        agent.respond(&[REQUEST_IDENTITIES], "evil");
        let mut sshsig = b"SSHSIG".to_vec();
        ssh::put_string(
            &mut sshsig,
            "x with SSH key “ssh/github”, for git ← zsh\n\n\n".as_bytes(),
        );
        agent.respond(&sign_request(&pair.public_blob(), &sshsig), "evil");
        agent.respond(
            &sign_request(&pair.public_blob(), &login(b"root\nfor git")),
            "evil",
        );
        let r = reasons(gate);
        assert_eq!(
            r[1],
            "approve: sign data with SSH key “ssh/github”, for evil"
        );
        assert_eq!(
            r[2],
            "approve: use SSH key “ssh/github” to log in, for evil"
        );
    }

    #[test]
    fn new_keys_are_offered_without_restarting() {
        let (_dir, path, _pair, gate) = setup();
        let mut agent = Agent::new(path.clone(), Duration::from_secs(60), gate);
        agent.respond(&[REQUEST_IDENTITIES], "ssh");
        let mut vault = Vault::open(&path, b"pw").unwrap();
        let fresh = KeyPair::generate("new").unwrap();
        vault.put("ssh/new", &Item::ssh_key(&fresh), false).unwrap();
        let reply = agent.respond(&[REQUEST_IDENTITIES], "ssh");
        assert_eq!(Reader::new(&reply[1..]).u32().unwrap(), 2);
        assert_eq!(counts(gate).0, 1, "no new prompt");
    }

    #[test]
    fn a_declined_prompt_pauses_signing() {
        let (_dir, path, pair, gate) = setup();
        let mut agent = Agent::new(path, Duration::from_secs(60), gate);
        agent.respond(&[REQUEST_IDENTITIES], "ssh");
        gate.lock().unwrap().allow = false;
        agent.respond(&sign_request(&pair.public_blob(), b"x"), "evil");
        gate.lock().unwrap().allow = true;
        let reply = agent.respond(&sign_request(&pair.public_blob(), b"x"), "evil");
        assert_eq!(reply, vec![FAILURE], "refused during the cooldown");
        assert_eq!(counts(gate).1, 1, "without another prompt");
        agent.last_denial = Some(Instant::now() - DENIAL_COOLDOWN);
        assert_eq!(
            agent.respond(&sign_request(&pair.public_blob(), b"x"), "me")[0],
            SIGN_RESPONSE
        );
    }
}
