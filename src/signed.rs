//! The signed member list. The admin's desktop signs who is in the mesh
//! with the admin's own SSH key (an older swarm: secrets/signing_ed25519);
//! the coordinator only stores and hands out the result, and cannot change
//! it, because it has no private key.
//!
//! Only each member's identity is signed (host number, name, WireGuard key,
//! SSH host key). Addresses and "last seen" change every minute and stay
//! unsigned: a coordinator lying about them can break connections, but
//! WireGuard still checks the keys.
//!
//! Signing and checking use OpenSSH (`ssh-keygen -Y sign` / `-Y verify`),
//! which every server has.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};

use crate::ctx::Ctx;
use crate::err::{Error, Result};
use crate::registry::{self, Member};
use crate::runner::{Cmd, Runner};
use crate::{bail, errf, fsx};

/// SSH signature namespaces: a signature made for one use never passes
/// for another.
pub const NS_MEMBERS: &str = "dryserver-members";
pub const NS_ADMIN: &str = "dryserver-admin";
/// A change of the key the swarm trusts, signed by the key it replaces.
pub const NS_KEY: &str = "dryserver-key";
/// An image the admin built, for the servers (images.rs).
pub const NS_IMAGE: &str = "dryserver-image";
/// More key changes than this in one list are not a swarm's.
pub const MAX_KEY_CHANGES: usize = 64;
/// The signer name in the allowed-signers file.
const SIGNER: &str = "dryserver";
/// How far the admin's clock and the coordinator's may differ.
pub const ADMIN_WINDOW_SECS: i64 = 15 * 60;

/// A member's signed identity.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Entry {
    pub host: u32,
    pub name: String,
    pub wg_key: String,
    /// "type base64", without a comment.
    pub ssh_host_key: String,
}

impl Entry {
    pub fn of(m: &Member) -> Entry {
        Entry { host: m.host, name: m.name.clone(), wg_key: m.wg_key.clone(), ssh_host_key: key_body(&m.ssh_host_key) }
    }

    /// Same host number, name and keys. Key comments do not count.
    pub fn matches(&self, m: &Member) -> bool {
        self.host == m.host && self.name == m.name && self.wg_key == m.wg_key && key_body(&self.ssh_host_key) == key_body(&m.ssh_host_key)
    }

    fn member(&self) -> Member {
        Member {
            host: self.host,
            name: self.name.clone(),
            wg_key: self.wg_key.clone(),
            ssh_host_key: self.ssh_host_key.clone(),
            ..Member::default()
        }
    }
}

/// "type base64" of an SSH public key line.
pub fn key_body(k: &str) -> String {
    k.split_whitespace().take(2).collect::<Vec<_>>().join(" ")
}

/// What the admin signs.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct List {
    /// Grows with every signature. Servers refuse a lower one than they
    /// have seen, so an old list cannot bring a removed machine back.
    pub version: u64,
    pub members: Vec<Entry>,
    /// WireGuard keys of waiting requests the admin turned down.
    pub rejected: Vec<String>,
    /// Every change of the key the swarm trusts, oldest first, each signed
    /// by the key it replaced (KeyChange). A machine follows them from the
    /// key it trusts to the one that signed this list; every list after a
    /// change carries them, so a machine that was off catches up.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<Envelope>,
    /// Other people who may log in to the machines: an account of their
    /// own, a shell, no sudo, no forwarding (people.rs).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub people: Vec<Person>,
}

/// More people than this in one list are not a home swarm's.
pub const MAX_PEOPLE: usize = 32;
/// Keys one person may log in with.
pub const MAX_PERSON_KEYS: usize = 8;

/// Someone the admin lets log in.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Person {
    /// The account's name on the machines.
    pub name: String,
    /// "type base64", without comments.
    pub keys: Vec<String>,
    /// The machines (by name) the person may log in to; none: every
    /// server, not the coordinator.
    pub on: Vec<String>,
}

impl Person {
    /// Whether the person may log in to the machine called name.
    pub fn may_log_in(&self, name: &str, coordinator: bool) -> bool {
        if self.on.is_empty() { !coordinator } else { self.on.iter().any(|n| n == name) }
    }
}

/// A name an account of a person can have: like a Linux user's, lowercase,
/// and none of the machines' own accounts.
pub fn valid_person_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
        && !RESERVED.contains(&s)
}

/// Accounts a machine has or may have that are never a person's.
const RESERVED: [&str; 24] = [
    "root",
    "bin",
    "daemon",
    "mail",
    "ftp",
    "http",
    "nobody",
    "dbus",
    "systemd-journal-remote",
    "systemd-network",
    "systemd-oom",
    "systemd-resolve",
    "systemd-timesync",
    "systemd-coredump",
    "uuidd",
    "polkitd",
    "git",
    "docker",
    "admin",
    "dryreg",
    "wheel",
    "sshd",
    "k3s",
    "users",
];

/// The swarm trusts another key from now on: to, in place of from. Signed
/// (NS_KEY) by from, so only the holder of the key trusted now can hand
/// the trust on.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct KeyChange {
    /// When it was made (seconds since 1970); grows along the chain.
    pub serial: u64,
    /// "ssh-ed25519 base64".
    pub from: String,
    pub to: String,
    /// The key also logs in as the admin: the machines put to in place of
    /// from in the admin's authorized_keys and config.
    pub login: bool,
}

/// Signs a key change with the key it replaces.
pub fn seal_key_change(s: &dyn Signer, c: &KeyChange) -> Result<Envelope> {
    let doc = serde_json::to_string(c)?;
    let sig = s.sign(NS_KEY, &doc)?;
    Ok(Envelope { doc, sig })
}

/// Follows chain from the key trusted now, start: each change whose from
/// is the key trusted at that point is checked with that key (check:
/// key, namespace, doc, sig) and hands the trust to its to. Changes of
/// other keys (ones already followed, or of a fork nobody trusted) are
/// passed over. Returns the key trusted at the end and the changes taken.
/// A change of the key trusted that does not check out is an error: the
/// list that carries it is refused as a whole.
pub fn follow(start: &str, chain: &[Envelope], check: &dyn Fn(&str, &str, &str, &str) -> Result<()>) -> Result<(String, Vec<KeyChange>)> {
    if chain.len() > MAX_KEY_CHANGES {
        bail!("the list carries {} key changes, more than {MAX_KEY_CHANGES}", chain.len());
    }
    let mut cur = key_body(start);
    let mut taken = Vec::new();
    let mut last = 0u64;
    for env in chain {
        let c: KeyChange = serde_json::from_str(&env.doc).map_err(|_| errf!("a key change in the list is damaged"))?;
        if key_body(&c.from) != cur {
            continue;
        }
        check(&cur, NS_KEY, &env.doc, &env.sig).map_err(|e| e.wrap("a key change not signed by the key it replaces"))?;
        let to = key_body(&c.to);
        if !to.starts_with("ssh-ed25519 ") || to.split_whitespace().count() != 2 || to == cur {
            bail!("a key change hands the trust to something that is not a new ed25519 key");
        }
        if c.serial <= last {
            bail!("the key changes in the list are out of order");
        }
        last = c.serial;
        cur = to;
        taken.push(c);
    }
    Ok((cur, taken))
}

impl List {
    pub fn has(&self, m: &Member) -> bool {
        self.members.iter().any(|e| e.matches(m))
    }

    /// Checks the content: a usable coordinator entry, and every entry
    /// well-formed and unique. fits says whether a host number is inside
    /// the mesh.
    pub fn check(&self, fits: impl Fn(u32) -> bool) -> Result<()> {
        if self.version == 0 {
            bail!("the signed list has no version");
        }
        let members: Vec<Member> = self.members.iter().map(Entry::member).collect();
        let (ok, problems) = registry::check_members(members, fits);
        if let Some(p) = problems.first() {
            bail!("the signed list has a bad entry: {p}");
        }
        if !ok.iter().any(|m| m.host == 1) {
            bail!("the signed list has no coordinator");
        }
        if self.people.len() > MAX_PEOPLE {
            bail!("the signed list has {} people, more than {MAX_PEOPLE}", self.people.len());
        }
        let mut names = std::collections::BTreeSet::new();
        for p in &self.people {
            if !valid_person_name(&p.name) || !names.insert(p.name.as_str()) {
                bail!("the signed list has a person with a bad or repeated name: {:?}", p.name);
            }
            if p.keys.is_empty() || p.keys.len() > MAX_PERSON_KEYS {
                bail!("{} has {} keys (1 to {MAX_PERSON_KEYS})", p.name, p.keys.len());
            }
            if let Some(k) = p.keys.iter().find(|k| key_body(k) != **k || !registry::valid_ssh_key(k)) {
                bail!("{} has a bad SSH key: {k:?}", p.name);
            }
            if let Some(n) = p.on.iter().find(|n| !registry::valid_name(n)) {
                bail!("{} is let in on a bad machine name: {n:?}", p.name);
            }
        }
        Ok(())
    }
}

/// A document and its signature. doc is the exact text that was signed.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Envelope {
    pub doc: String,
    pub sig: String,
}

impl Envelope {
    pub fn is_empty(&self) -> bool {
        self.doc.is_empty() && self.sig.is_empty()
    }

    /// The member list inside, after its signature and content are checked.
    pub fn list(&self, v: &dyn Verifier, fits: impl Fn(u32) -> bool) -> Result<List> {
        self.list_signed_by(v, fits).map(|(l, _)| l)
    }

    /// The member list and the key that signed it: the one v trusts, or
    /// the one the list's key changes hand the trust to from there.
    pub fn list_signed_by(&self, v: &dyn Verifier, fits: impl Fn(u32) -> bool) -> Result<(List, Option<String>)> {
        // Read before it is checked only to find the key changes, which
        // prove themselves one by one from the key v trusts.
        let list: List = serde_json::from_str(&self.doc).map_err(|e| Error::from(e).wrap("signed list"))?;
        let signer = match v.key() {
            Some(start) => {
                let (cur, _) = follow(&start, &list.keys, &|k, ns, d, s| v.verify_with(k, ns, d, s))?;
                if cur == key_body(&start) {
                    v.verify(NS_MEMBERS, &self.doc, &self.sig)?;
                } else {
                    v.verify_with(&cur, NS_MEMBERS, &self.doc, &self.sig)?;
                }
                Some(cur)
            }
            None => {
                v.verify(NS_MEMBERS, &self.doc, &self.sig)?;
                None
            }
        };
        list.check(fits)?;
        Ok((list, signer))
    }
}

/// Signs a member list.
pub fn seal(s: &dyn Signer, list: &List) -> Result<Envelope> {
    let doc = serde_json::to_string(list)?;
    let sig = s.sign(NS_MEMBERS, &doc)?;
    Ok(Envelope { doc, sig })
}

/// An admin's request to the coordinator, signed so that only the holder
/// of the signing key can read the registry from outside.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AdminRequest {
    pub op: String,
    /// Unix seconds; the coordinator accepts ADMIN_WINDOW_SECS either way.
    pub time: i64,
    /// A resume or a skip: the release whose rollout stopped, and the host
    /// it stopped at (0: the coordinator's own update), as the admin saw
    /// them. Root on the coordinator carries out only an ask for the stop
    /// it is at, once.
    #[serde(skip_serializing_if = "is_zero64")]
    pub serial: u64,
    #[serde(skip_serializing_if = "is_zero32")]
    pub host: u32,
}

fn is_zero64(n: &u64) -> bool {
    *n == 0
}

fn is_zero32(n: &u32) -> bool {
    *n == 0
}

pub fn seal_admin(s: &dyn Signer, op: &str, now_unix: i64) -> Result<Envelope> {
    seal_request(s, &AdminRequest { op: op.into(), time: now_unix, ..AdminRequest::default() })
}

/// A resume or a skip (op) for the rollout of release serial, stopped at
/// host.
pub fn seal_ask(s: &dyn Signer, op: &str, now_unix: i64, serial: u64, host: u32) -> Result<Envelope> {
    seal_request(s, &AdminRequest { op: op.into(), time: now_unix, serial, host })
}

fn seal_request(s: &dyn Signer, r: &AdminRequest) -> Result<Envelope> {
    let doc = serde_json::to_string(r)?;
    let sig = s.sign(NS_ADMIN, &doc)?;
    Ok(Envelope { doc, sig })
}

/// Checks an admin request: signature, operation and freshness.
pub fn open_admin(v: &dyn Verifier, e: &Envelope, op: &str, now_unix: i64) -> Result<()> {
    open_request(v, e, op, now_unix).map(drop)
}

/// open_admin, and what the request says.
pub fn open_request(v: &dyn Verifier, e: &Envelope, op: &str, now_unix: i64) -> Result<AdminRequest> {
    v.verify(NS_ADMIN, &e.doc, &e.sig)?;
    let r: AdminRequest = serde_json::from_str(&e.doc).map_err(|e| Error::from(e).wrap("admin request"))?;
    if r.op != op {
        bail!("admin request is for {:?}, not {op:?}", r.op);
    }
    let off = now_unix.saturating_sub(r.time);
    if off.saturating_abs() > ADMIN_WINDOW_SECS {
        bail!(
            "admin request is {} seconds {}: check the clock on your computer and on the coordinator",
            off.saturating_abs(),
            if off > 0 { "old" } else { "in the future" }
        );
    }
    Ok(r)
}

// ---- a machine's own SSH host key ----

/// What root on the coordinator signs a server's turn as, with the
/// coordinator's SSH host key (rollout::Grant).
pub const NS_TURN: &str = "dryserver-rollout-turn";
/// What a server signs its report as, with its own SSH host key
/// (report::Report::sign): the registry account relays it.
pub const NS_REPORT: &str = "dryserver-report";
/// What root on the coordinator signs its receipt for the list it applied
/// as (registry::Receipt).
pub const NS_RECEIPT: &str = "dryserver-receipt";
/// The signer name in the allowed-signers file of a host key check.
const HOST_SIGNER: &str = "dryserver-host";

/// Signs text with the SSH private key at key (a machine's host key,
/// readable by root only), through run: `ssh-keygen -Y sign`.
pub fn host_sign(ctx: &Ctx, run: &dyn Runner, key: &Path, namespace: &str, text: &str) -> Result<String> {
    let k = key.display().to_string();
    let sig = run
        .output(ctx, &Cmd::new("ssh-keygen", &["-Y", "sign", "-f", &k, "-n", namespace]).stdin(text).quiet().stdout_only())
        .map_err(|e| e.wrap("sign with the host key"))?;
    if !sig.contains("BEGIN SSH SIGNATURE") {
        bail!("ssh-keygen made no signature with {k}");
    }
    Ok(sig)
}

/// Checks sig over text by the public key "ssh-ed25519 BASE64" (another
/// machine's host key, from the list the admin signed), through run.
/// tmp_dir takes the two small files ssh-keygen needs, removed after it.
pub fn host_verify(ctx: &Ctx, run: &dyn Runner, tmp_dir: &Path, key: &str, namespace: &str, text: &str, sig: &str) -> Result<()> {
    let key = key_body(key);
    if !key.starts_with("ssh-ed25519 ") || key.split_whitespace().count() != 2 {
        bail!("no ssh-ed25519 key to check the signature with");
    }
    if !sig.contains("BEGIN SSH SIGNATURE") || sig.len() > 4096 {
        bail!("not signed");
    }
    let id = fsx::hex(&fsx::random_bytes(8));
    let allowed = tmp_dir.join(format!("dryserver-host-signers-{id}"));
    let sig_file = tmp_dir.join(format!("dryserver-host-sig-{id}"));
    struct Remove<'a>(&'a Path, &'a Path);
    impl Drop for Remove<'_> {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(self.0);
            let _ = std::fs::remove_file(self.1);
        }
    }
    let _rm = Remove(&allowed, &sig_file);
    fsx::create_file(&allowed, format!("{HOST_SIGNER} namespaces=\"{namespace}\" {key}\n"), 0o600)?;
    fsx::create_file(&sig_file, sig, 0o600)?;
    let (a, s) = (allowed.display().to_string(), sig_file.display().to_string());
    run.ok(ctx, &Cmd::new("ssh-keygen", &["-Y", "verify", "-f", &a, "-I", HOST_SIGNER, "-n", namespace, "-s", &s]).stdin(text).quiet())
        .map_err(|e| e.wrap("bad signature"))
}

pub trait Signer: Send {
    fn sign(&self, namespace: &str, doc: &str) -> Result<String>;
}

pub trait Verifier: Send + Sync {
    /// Checks a signature of the key trusted now.
    fn verify(&self, namespace: &str, doc: &str, sig: &str) -> Result<()>;
    /// The key trusted now ("ssh-ed25519 base64"), for following the key
    /// changes in a member list; None: this one follows none.
    fn key(&self) -> Option<String> {
        None
    }
    /// Checks a signature of key: one a key change hands the trust to.
    fn verify_with(&self, _key: &str, _namespace: &str, _doc: &str, _sig: &str) -> Result<()> {
        Err("this check follows no key change".into())
    }
}

fn ssh_keygen(args: &[&str], stdin: &str) -> Result<std::process::Output> {
    let mut c = Command::new("ssh-keygen");
    c.args(args);
    run_with_input(c, stdin)
}

/// Runs ssh-keygen with stdin as its input and returns what it said.
/// Its terminal stays its own: a passphrase is asked on /dev/tty.
fn run_with_input(mut c: Command, stdin: &str) -> Result<std::process::Output> {
    use std::io::Write;
    let mut child = c
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::from(e).wrap("ssh-keygen (is OpenSSH installed?)"))?;
    // Written from a thread: a large document must not deadlock against
    // ssh-keygen's own output.
    let mut pipe = child.stdin.take().ok_or_else(|| Error::new("ssh-keygen: no stdin"))?;
    let text = stdin.to_string();
    let writer = std::thread::spawn(move || {
        let _ = pipe.write_all(text.as_bytes());
    });
    let out = child.wait_with_output().map_err(|e| Error::from(e).wrap("ssh-keygen"))?;
    let _ = writer.join();
    Ok(out)
}

/// Signs with a private key file (an older swarm's secrets/signing_ed25519).
pub struct SshSigner {
    pub key: PathBuf,
}

impl Signer for SshSigner {
    fn sign(&self, namespace: &str, doc: &str) -> Result<String> {
        let key = self.key.display().to_string();
        let out = ssh_keygen(&["-Y", "sign", "-f", &key, "-n", namespace], doc)?;
        let sig = String::from_utf8_lossy(&out.stdout).into_owned();
        if !out.status.success() || !sig.contains("BEGIN SSH SIGNATURE") {
            return Err(errf!("cannot sign with {key}: {}", String::from_utf8_lossy(&out.stderr).trim()));
        }
        Ok(sig)
    }
}

/// Where the private half of the admin's own key is.
#[derive(Debug, Clone, PartialEq)]
pub enum KeyAt {
    /// Loaded in ssh-agent: signing needs nothing more.
    Agent,
    /// A file in ~/.ssh; with a passphrase ssh-keygen asks for it on the
    /// terminal at each signature.
    File { path: PathBuf, passphrase: bool },
}

/// Signs with the admin's own SSH key, the one that also logs in to the
/// machines: the private half from ssh-agent, or from the file in ~/.ssh
/// whose public half matches. The swarm trusts the public half in pubkey
/// (secrets/signing_ed25519.pub, put there by the first build).
///
/// One key for both is safe: an SSH login signs data of its own form, and
/// every signature here is made for one namespace (dryserver-members,
/// dryserver-release...), so none passes for a login or for another use.
pub struct OwnKeySigner {
    pub pubkey: PathBuf,
    /// ~/.ssh, where a key file is looked for.
    pub ssh_dir: Option<PathBuf>,
    /// The agent's socket (SSH_AUTH_SOCK); None: no agent.
    pub agent: Option<PathBuf>,
}

impl OwnKeySigner {
    /// For this user: ~/.ssh and the agent in SSH_AUTH_SOCK.
    pub fn for_user(pubkey: PathBuf) -> OwnKeySigner {
        let home = std::env::var_os("HOME").filter(|h| !h.is_empty()).map(PathBuf::from);
        let agent = std::env::var_os("SSH_AUTH_SOCK").filter(|s| !s.is_empty()).map(PathBuf::from);
        OwnKeySigner { pubkey, ssh_dir: home.map(|h| h.join(".ssh")), agent }
    }

    fn trusted(&self) -> Result<String> {
        let line = fsx::read_string(&self.pubkey).map_err(|e| e.wrap("the public half of your signing key"))?;
        let k = key_body(&line);
        if !k.starts_with("ssh-ed25519 ") {
            bail!("{} is not an ed25519 public key", self.pubkey.display());
        }
        Ok(k)
    }

    /// Whether the agent holds the key: `ssh-add -L` lists it.
    fn in_agent(&self, key: &str) -> bool {
        let Some(sock) = &self.agent else { return false };
        let out = Command::new("ssh-add").arg("-L").env("SSH_AUTH_SOCK", sock).stdin(Stdio::null()).stderr(Stdio::null()).output();
        out.is_ok_and(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).lines().any(|l| key_body(l) == key))
    }

    /// The private key file in ~/.ssh whose public half the swarm trusts,
    /// also when the agent has it.
    pub fn trusted_file(&self) -> Option<PathBuf> {
        self.key_file(&self.trusted().ok()?)
    }

    /// The private key file in ~/.ssh whose .pub holds key.
    fn key_file(&self, key: &str) -> Option<PathBuf> {
        let dir = self.ssh_dir.as_ref()?;
        let mut pubs: Vec<PathBuf> =
            std::fs::read_dir(dir).ok()?.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "pub")).collect();
        pubs.sort();
        pubs.into_iter().filter(|p| key_body(&fsx::read_or_empty(p)) == key).map(|p| p.with_extension("")).find(|k| k.is_file())
    }

    /// Where the private half is: the agent first, then ~/.ssh.
    pub fn locate(&self) -> Result<KeyAt> {
        let key = self.trusted()?;
        if self.in_agent(&key) {
            return Ok(KeyAt::Agent);
        }
        if let Some(path) = self.key_file(&key) {
            let passphrase = crate::publish::has_passphrase(&path);
            return Ok(KeyAt::File { path, passphrase });
        }
        Err(errf!(
            "the private half of your signing key ({}) is neither in ssh-agent nor in ~/.ssh. It is your SSH key, \
             the one in {}: add it with ssh-add, or put it back at ~/.ssh/id_ed25519",
            short_key(&key),
            self.pubkey.display()
        ))
    }

    /// Signing works without a terminal to ask a passphrase on (the
    /// screens), or why not and what to do.
    pub fn ready_without_terminal(&self) -> Result<()> {
        match self.locate()? {
            KeyAt::File { path, passphrase: true } => Err(errf!(
                "your SSH key {p} has a passphrase and is not in ssh-agent, and this screen cannot ask for it. Add it \
                 once (it asks for the passphrase there): ssh-add {p}",
                p = path.display()
            )),
            _ => Ok(()),
        }
    }
}

/// "ssh-ed25519 …last8": enough to tell keys apart in a message.
pub fn short_key(k: &str) -> String {
    let b = k.split_whitespace().nth(1).unwrap_or("");
    let tail = &b[b.len().saturating_sub(8)..];
    format!("ssh-ed25519 …{tail}")
}

impl Signer for OwnKeySigner {
    fn sign(&self, namespace: &str, doc: &str) -> Result<String> {
        let what = match self.locate()? {
            // The public half names the key; ssh-keygen asks the agent.
            KeyAt::Agent => self.pubkey.clone(),
            KeyAt::File { path, .. } => path,
        };
        let f = what.display().to_string();
        let mut child = Command::new("ssh-keygen");
        child.args(["-Y", "sign", "-f", &f, "-n", namespace]);
        match &self.agent {
            Some(sock) => child.env("SSH_AUTH_SOCK", sock),
            None => child.env_remove("SSH_AUTH_SOCK"),
        };
        let out = run_with_input(child, doc)?;
        let sig = String::from_utf8_lossy(&out.stdout).into_owned();
        if !out.status.success() || !sig.contains("BEGIN SSH SIGNATURE") {
            return Err(errf!("cannot sign with your SSH key ({f}): {}", String::from_utf8_lossy(&out.stderr).trim()));
        }
        Ok(sig)
    }
}

/// Checks signatures against a public key file.
pub struct SshVerifier {
    pub pubkey: PathBuf,
    /// For the two small files ssh-keygen needs; removed after each check.
    pub tmp_dir: PathBuf,
}

/// The key in a public key file, when it is an ed25519 one.
fn key_in(path: &Path) -> Result<String> {
    let line = fsx::read_string(path).map_err(|e| e.wrap("no signing key on this machine"))?;
    let key = key_body(&line);
    if !key.starts_with("ssh-ed25519 ") {
        bail!("{} is not an ed25519 public key", path.display());
    }
    Ok(key)
}

/// Checks sig of key with ssh-keygen, through two small files in tmp_dir.
fn verify_key(tmp_dir: &Path, key: &str, namespace: &str, doc: &str, sig: &str) -> Result<()> {
    if !key.starts_with("ssh-ed25519 ") {
        bail!("not an ed25519 key");
    }
    if !sig.contains("BEGIN SSH SIGNATURE") {
        bail!("not signed");
    }
    let id = fsx::hex(&fsx::random_bytes(8));
    let allowed = tmp_dir.join(format!("dryserver-signers-{id}"));
    let sig_file = tmp_dir.join(format!("dryserver-sig-{id}"));
    struct Remove<'a>(&'a Path, &'a Path);
    impl Drop for Remove<'_> {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(self.0);
            let _ = std::fs::remove_file(self.1);
        }
    }
    let _rm = Remove(&allowed, &sig_file);
    // New files under names of their own: in a shared temporary
    // directory a name taken already is someone else's, never ours to
    // write through.
    fsx::create_file(&allowed, format!("{SIGNER} namespaces=\"{namespace}\" {key}\n"), 0o600)?;
    fsx::create_file(&sig_file, sig, 0o600)?;
    let (a, s) = (allowed.display().to_string(), sig_file.display().to_string());
    let out = ssh_keygen(&["-Y", "verify", "-f", &a, "-I", SIGNER, "-n", namespace, "-s", &s], doc)?;
    if !out.status.success() {
        return Err(errf!("bad signature ({})", String::from_utf8_lossy(&out.stderr).lines().next().unwrap_or("").trim()));
    }
    Ok(())
}

impl Verifier for SshVerifier {
    fn verify(&self, namespace: &str, doc: &str, sig: &str) -> Result<()> {
        verify_key(&self.tmp_dir, &key_in(&self.pubkey)?, namespace, doc, sig)
    }

    fn key(&self) -> Option<String> {
        key_in(&self.pubkey).ok()
    }

    fn verify_with(&self, key: &str, namespace: &str, doc: &str, sig: &str) -> Result<()> {
        verify_key(&self.tmp_dir, &key_body(key), namespace, doc, sig)
    }
}

/// The key changes of the list in path: an Envelope, or a registry state
/// with it under "signed". None when it cannot be read.
pub fn chain_in(path: &Path) -> Vec<Envelope> {
    let Ok(b) = std::fs::read(path) else { return Vec::new() };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&b) else { return Vec::new() };
    let env = v.get("signed").cloned().unwrap_or(v);
    let Ok(env) = serde_json::from_value::<Envelope>(env) else { return Vec::new() };
    serde_json::from_str::<List>(&env.doc).map(|l| l.keys).unwrap_or_default()
}

/// What a machine trusts: the key the installer put there, followed
/// through the key changes of the newest member list it took. That list
/// only ever grows in version and was checked when it was taken, so a
/// key once handed on is never trusted again, here or after a reboot.
pub struct Trust {
    /// The installer's key (node::SIGNING_PUB).
    pub base: PathBuf,
    /// The newest list taken: an Envelope (node::SIGNED_FILE), or the
    /// registry's state with it under "signed". Missing or unreadable:
    /// the base key alone.
    pub newest: PathBuf,
    pub tmp_dir: PathBuf,
}

impl Trust {
    /// For a server (root): its installer's key and its newest list.
    pub fn installed(root: &Path, tmp_dir: PathBuf) -> Trust {
        Trust { base: fsx::under(root, crate::node::SIGNING_PUB), newest: fsx::under(root, crate::node::SIGNED_FILE), tmp_dir }
    }

    /// For the registry account on the coordinator, which cannot read
    /// root's list: the list in the registry's own state.
    pub fn for_registry(root: &Path, store: &Path, tmp_dir: PathBuf) -> Trust {
        Trust { base: fsx::under(root, crate::node::SIGNING_PUB), newest: store.to_path_buf(), tmp_dir }
    }

    fn chain(&self) -> Vec<Envelope> {
        chain_in(&self.newest)
    }

    /// The key trusted now, and every change that led there from the
    /// installer's key.
    pub fn followed(&self) -> Result<(String, Vec<KeyChange>)> {
        let base = key_in(&self.base)?;
        follow(&base, &self.chain(), &|k, ns, d, s| verify_key(&self.tmp_dir, k, ns, d, s))
    }
}

impl Verifier for Trust {
    fn verify(&self, namespace: &str, doc: &str, sig: &str) -> Result<()> {
        verify_key(&self.tmp_dir, &self.followed()?.0, namespace, doc, sig)
    }

    fn key(&self) -> Option<String> {
        self.followed().ok().map(|(k, _)| k)
    }

    fn verify_with(&self, key: &str, namespace: &str, doc: &str, sig: &str) -> Result<()> {
        verify_key(&self.tmp_dir, &key_body(key), namespace, doc, sig)
    }
}

/// Test doubles that sign by hashing with a secret word.
#[cfg(test)]
pub mod fake {
    use super::*;
    use sha2::{Digest, Sha256};

    pub struct Key(pub &'static str);

    fn mac(secret: &str, namespace: &str, doc: &str) -> String {
        format!("BEGIN SSH SIGNATURE {}", fsx::hex(&Sha256::digest(format!("{secret}\n{namespace}\n{doc}").as_bytes())))
    }

    impl Signer for Key {
        fn sign(&self, namespace: &str, doc: &str) -> Result<String> {
            Ok(mac(self.0, namespace, doc))
        }
    }

    impl Key {
        /// Its "public key", for key changes.
        pub fn public(&self) -> String {
            format!("ssh-ed25519 FAKE{}", self.0)
        }
    }

    impl Verifier for Key {
        fn verify(&self, namespace: &str, doc: &str, sig: &str) -> Result<()> {
            if sig == mac(self.0, namespace, doc) { Ok(()) } else { Err("bad signature".into()) }
        }

        fn key(&self) -> Option<String> {
            Some(self.public())
        }

        fn verify_with(&self, key: &str, namespace: &str, doc: &str, sig: &str) -> Result<()> {
            let name = key_body(key).strip_prefix("ssh-ed25519 FAKE").map(str::to_string).unwrap_or_default();
            if !name.is_empty() && sig == mac(&name, namespace, doc) { Ok(()) } else { Err("bad signature".into()) }
        }
    }

    /// Trusts what Trust would with fake keys: base, followed through the
    /// key changes of the list in newest.
    pub struct Chained {
        pub base: &'static str,
        pub newest: PathBuf,
    }

    impl Verifier for Chained {
        fn verify(&self, namespace: &str, doc: &str, sig: &str) -> Result<()> {
            let k = self.key().ok_or_else(|| Error::new("no key"))?;
            self.verify_with(&k, namespace, doc, sig)
        }

        fn key(&self) -> Option<String> {
            follow(&Key(self.base).public(), &chain_in(&self.newest), &|k, ns, d, s| Key("any").verify_with(k, ns, d, s)).ok().map(|f| f.0)
        }

        fn verify_with(&self, key: &str, namespace: &str, doc: &str, sig: &str) -> Result<()> {
            Key("any").verify_with(key, namespace, doc, sig)
        }
    }

    /// Trusts the fake key named in a file ("ssh-ed25519 FAKEname"), like
    /// SshVerifier trusts the key in its file: what a desktop holds.
    pub struct FileKey(pub PathBuf);

    impl Verifier for FileKey {
        fn verify(&self, namespace: &str, doc: &str, sig: &str) -> Result<()> {
            let k = self.key().ok_or_else(|| Error::new("no key"))?;
            self.verify_with(&k, namespace, doc, sig)
        }

        fn key(&self) -> Option<String> {
            std::fs::read_to_string(&self.0).ok().map(|t| key_body(&t))
        }

        fn verify_with(&self, key: &str, namespace: &str, doc: &str, sig: &str) -> Result<()> {
            Key("any").verify_with(key, namespace, doc, sig)
        }
    }

    /// What `ssh-keygen -Y sign` makes with the host key whose public half
    /// is key, in namespace, of text.
    pub fn host_sig(key: &str, namespace: &str, text: &str) -> String {
        format!("-----BEGIN SSH SIGNATURE-----\n{}\n-----END SSH SIGNATURE-----\n", mac(&key_body(key), namespace, text))
    }

    fn arg<'a>(c: &'a Cmd, flag: &str) -> Option<&'a str> {
        c.args.iter().position(|a| a == flag).and_then(|i| c.args.get(i + 1)).map(String::as_str)
    }

    /// Answers c if it is `ssh-keygen -Y sign` or `-Y verify` as host_sign
    /// and host_verify use it: only the holder of the private key file
    /// (its .pub beside it says whose) makes a signature, in any namespace.
    pub fn host_run(c: &Cmd) -> Option<(String, Result<()>)> {
        if c.name != "ssh-keygen" {
            return None;
        }
        let has = |a: &str| c.args.iter().any(|x| x == a);
        let fail = || (String::new(), Err(Error::new("ssh-keygen failed: exit status 255")));
        let ns = arg(c, "-n").unwrap_or_default();
        Some(if has("sign") {
            match arg(c, "-f").filter(|p| std::fs::metadata(p).is_ok()).and_then(|p| std::fs::read_to_string(format!("{p}.pub")).ok()) {
                Some(public) => (host_sig(&public, ns, &c.stdin), Ok(())),
                None => fail(),
            }
        } else if has("verify") {
            let allowed = arg(c, "-f").and_then(|p| std::fs::read_to_string(p).ok()).unwrap_or_default();
            let sig = arg(c, "-s").and_then(|p| std::fs::read_to_string(p).ok()).unwrap_or_default();
            let key = allowed.split_whitespace().skip(2).collect::<Vec<_>>().join(" ");
            let ns_ok = allowed.contains(&format!("namespaces=\"{ns}\""));
            if ns_ok && !key.is_empty() && sig == host_sig(&key, ns, &c.stdin) { (String::new(), Ok(())) } else { fail() }
        } else {
            return None;
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use base64::Engine;

    pub fn entry(host: u32, name: &str) -> Entry {
        Entry {
            host,
            name: name.into(),
            wg_key: base64::engine::general_purpose::STANDARD.encode([host as u8; 32]),
            ssh_host_key: format!("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{name}"),
        }
    }

    fn fits(h: u32) -> bool {
        (1..=254).contains(&h)
    }

    fn list() -> List {
        List { version: 3, members: vec![entry(1, "coord"), entry(2, "nodeb")], rejected: vec![], keys: vec![], people: vec![] }
    }

    #[test]
    fn seal_and_open() {
        let key = fake::Key("admin");
        let env = seal(&key, &list()).unwrap();
        assert_eq!(env.list(&key, fits).unwrap(), list());
        // Any change to the text, another key, or another namespace fails.
        let mut changed = env.clone();
        changed.doc = changed.doc.replace("nodeb", "nodex");
        assert!(changed.list(&key, fits).is_err());
        assert!(env.list(&fake::Key("other"), fits).is_err());
        let as_admin = Envelope { doc: env.doc.clone(), sig: key.sign(NS_ADMIN, &env.doc).unwrap() };
        assert!(as_admin.list(&key, fits).is_err(), "an admin-request signature must not pass as a member list");
        assert!(Envelope::default().list(&key, fits).is_err());
    }

    #[test]
    fn list_content_is_checked() {
        let key = fake::Key("admin");
        let bad = [
            (List { version: 0, ..list() }, "no version"),
            (List { members: vec![entry(2, "nodeb")], ..list() }, "no coordinator"),
            (List { members: vec![entry(1, "coord"), entry(1, "twice")], ..list() }, "used twice"),
            (List { members: vec![entry(1, "coord"), Entry { name: "a b".into(), ..entry(2, "x") }], ..list() }, "bad name"),
            (List { members: vec![entry(1, "coord"), entry(900, "far")], ..list() }, "outside the mesh"),
        ];
        for (l, want) in bad {
            // Correctly signed, still refused: the signature is not enough.
            let e = seal(&key, &l).unwrap().list(&key, fits).unwrap_err().to_string();
            assert!(e.contains(want), "{want}: {e}");
        }
    }

    #[test]
    fn entries_ignore_comments_and_addresses() {
        let m = Member {
            host: 2,
            name: "nodeb".into(),
            wg_key: entry(2, "nodeb").wg_key,
            ssh_host_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAInodeb root@nodeb".into(),
            lan_ip: "192.168.1.20".into(),
            switch: true,
            ..Member::default()
        };
        assert!(list().has(&m), "the key comment and the LAN address are not part of the identity");
        assert!(!list().has(&Member { wg_key: entry(9, "x").wg_key, ..m.clone() }));
        assert!(!list().has(&Member { host: 3, ..m.clone() }));
        assert!(!list().has(&Member { name: "other".into(), ..m }));
    }

    #[test]
    fn admin_requests() {
        let key = fake::Key("admin");
        let e = seal_admin(&key, "state", 1000).unwrap();
        open_admin(&key, &e, "state", 1000 + ADMIN_WINDOW_SECS).unwrap();
        open_admin(&key, &e, "state", 1000 - ADMIN_WINDOW_SECS).unwrap();
        for (op, now, want) in
            [("state", 1000 + ADMIN_WINDOW_SECS + 1, "old"), ("state", 1000 - ADMIN_WINDOW_SECS - 1, "future"), ("publish", 1000, "is for")]
        {
            let err = open_admin(&key, &e, op, now).unwrap_err().to_string();
            assert!(err.contains(want), "{op} {now}: {err}");
        }
        assert!(open_admin(&fake::Key("other"), &e, "state", 1000).is_err());
        // A plain request reads as before; an ask names its stop, and an
        // older coordinator, which knows only op and time, still reads it.
        assert_eq!(e.doc, r#"{"op":"state","time":1000}"#);
        let ask = seal_ask(&key, "release-skip", 1000, 9, 2).unwrap();
        let r = open_request(&key, &ask, "release-skip", 1000).unwrap();
        assert_eq!((r.serial, r.host, r.time), (9, 2, 1000));
        #[derive(Deserialize)]
        struct Older {
            op: String,
            time: i64,
        }
        let old: Older = serde_json::from_str(&ask.doc).unwrap();
        assert_eq!((old.op.as_str(), old.time), ("release-skip", 1000));
        let far = seal_admin(&key, "state", i64::MIN).unwrap();
        assert!(open_admin(&key, &far, "state", i64::MAX).is_err(), "no overflow");
        // A member-list signature is not an admin request.
        let as_list = Envelope { doc: e.doc.clone(), sig: key.sign(NS_MEMBERS, &e.doc).unwrap() };
        assert!(open_admin(&key, &as_list, "state", 1000).is_err());
    }

    /// A machine's host key signs, another machine checks against its
    /// public half: with real OpenSSH, and the fakes the tests use agree.
    #[test]
    fn host_key_signatures() {
        let dir = TempDir::new();
        let run = crate::runner::ExecRunner::silent();
        let ctx = Ctx::new();
        let text = r#"{"host":2,"serial":9}"#;
        if crate::iso::in_path("ssh-keygen") {
            let make = |name: &str| {
                let key = dir.join(name);
                let st = Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-f"]).arg(&key).status().unwrap();
                assert!(st.success());
                (key.clone(), key_body(&std::fs::read_to_string(dir.join(format!("{name}.pub"))).unwrap()))
            };
            let ((coord, coord_pub), (_, other_pub)) = (make("coord"), make("other"));
            let sig = host_sign(&ctx, &run, &coord, NS_TURN, text).unwrap();
            host_verify(&ctx, &run, dir.path(), &coord_pub, NS_TURN, text, &sig).unwrap();
            assert!(host_verify(&ctx, &run, dir.path(), &other_pub, NS_TURN, text, &sig).is_err(), "another key");
            assert!(host_verify(&ctx, &run, dir.path(), &coord_pub, NS_ADMIN, text, &sig).is_err(), "another namespace");
            assert!(host_verify(&ctx, &run, dir.path(), &coord_pub, NS_TURN, "{}", &sig).is_err(), "another text");
            assert!(host_sign(&ctx, &run, &dir.join("missing"), NS_TURN, text).is_err());
        }
        assert!(host_verify(&ctx, &run, dir.path(), "ssh-rsa AAAA", NS_TURN, text, "x").unwrap_err().to_string().contains("ssh-ed25519"));
        assert!(
            host_verify(&ctx, &run, dir.path(), "ssh-ed25519 AAAA", NS_TURN, text, "x").unwrap_err().to_string().contains("not signed")
        );
        let left: Vec<_> =
            std::fs::read_dir(dir.path()).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().contains("host-")).collect();
        assert!(left.is_empty(), "{left:?}");
    }

    /// The same with real OpenSSH keys.
    #[test]
    fn real_openssh() {
        if !crate::iso::in_path("ssh-keygen") {
            return;
        }
        let dir = TempDir::new();
        let make = |name: &str| {
            let key = dir.join(name);
            let st = Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-f"]).arg(&key).status().unwrap();
            assert!(st.success());
            key
        };
        let (key, other) = (make("signing"), make("other"));
        let signer = SshSigner { key: key.clone() };
        let v = SshVerifier { pubkey: dir.join("signing.pub"), tmp_dir: dir.path().to_path_buf() };

        // A full-size list: 254 members.
        let big = List {
            version: 7,
            members: (1..=254).map(|h| entry(h, &format!("node{h}"))).collect(),
            rejected: vec![],
            keys: vec![],
            people: vec![],
        };
        let env = seal(&signer, &big).unwrap();
        assert_eq!(env.list(&v, fits).unwrap(), big);

        let mut changed = env.clone();
        changed.doc = changed.doc.replace("node200", "node2oo");
        assert!(changed.list(&v, fits).unwrap_err().to_string().contains("bad signature"));
        let forged = seal(&SshSigner { key: other }, &big).unwrap();
        assert!(forged.list(&v, fits).is_err(), "a list signed with another key passed");
        let wrong_ns = Envelope { doc: env.doc.clone(), sig: signer.sign(NS_ADMIN, &env.doc).unwrap() };
        assert!(wrong_ns.list(&v, fits).is_err());
        assert!(Envelope { doc: env.doc.clone(), sig: "garbage".into() }.list(&v, fits).unwrap_err().to_string().contains("not signed"));

        // No key on the machine, or a file that is not a key.
        let none = SshVerifier { pubkey: dir.join("missing.pub"), tmp_dir: dir.path().to_path_buf() };
        assert!(env.list(&none, fits).unwrap_err().to_string().contains("no signing key"));
        std::fs::write(dir.join("junk.pub"), "hello\n").unwrap();
        let junk = SshVerifier { pubkey: dir.join("junk.pub"), tmp_dir: dir.path().to_path_buf() };
        assert!(env.list(&junk, fits).is_err());

        // Nothing is left behind in the temporary directory.
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("dryserver-"))
            .collect();
        assert!(left.is_empty(), "{left:?}");

        // A signing key that cannot be read gives a clear error.
        let e = SshSigner { key: dir.join("nokey") }.sign(NS_MEMBERS, "x").unwrap_err().to_string();
        assert!(e.contains("cannot sign"), "{e}");
    }

    fn change(signer: &fake::Key, from: &fake::Key, to: &fake::Key, serial: u64, login: bool) -> Envelope {
        seal_key_change(signer, &KeyChange { serial, from: from.public(), to: to.public(), login }).unwrap()
    }

    #[test]
    fn key_changes_hand_the_trust_on_one_by_one() {
        use fake::Key;
        let (k1, k2, k3, thief) = (Key("k1"), Key("k2"), Key("k3"), Key("thief"));
        let check = |k: &str, ns: &str, d: &str, s: &str| k1.verify_with(k, ns, d, s);
        let c12 = change(&k1, &k1, &k2, 10, true);
        let c23 = change(&k2, &k2, &k3, 20, true);
        // From k1 through both; from k2 only the second; from k3 none.
        let (cur, taken) = follow(&k1.public(), &[c12.clone(), c23.clone()], &check).unwrap();
        assert_eq!((cur, taken.len()), (k3.public(), 2));
        assert_eq!(follow(&k2.public(), &[c12.clone(), c23.clone()], &check).unwrap().0, k3.public());
        assert_eq!(follow(&k3.public(), &[c12.clone(), c23.clone()], &check).unwrap(), (k3.public(), vec![]));
        // A change of the trusted key signed by another key: refused.
        let forged = change(&thief, &k1, &thief, 10, true);
        let e = follow(&k1.public(), &[forged], &check).unwrap_err().to_string();
        assert!(e.contains("not signed by the key it replaces"), "{e}");
        // A fork of a key not trusted (any more) is passed over.
        let fork = change(&k1, &k1, &thief, 15, true);
        assert_eq!(follow(&k2.public(), &[c12.clone(), fork.clone(), c23.clone()], &check).unwrap().0, k3.public());
        // Order: a change older than the one before it is refused.
        let back = change(&k2, &k2, &k3, 5, true);
        assert!(follow(&k1.public(), &[c12.clone(), back], &check).unwrap_err().to_string().contains("out of order"));
        // Only to a new ed25519 key.
        for bad in ["ssh-rsa AAAA", "", "ssh-ed25519", "ssh-ed25519 FAKEk1"] {
            let c = seal_key_change(&k1, &KeyChange { serial: 1, from: k1.public(), to: bad.into(), login: false }).unwrap();
            assert!(follow(&k1.public(), &[c], &check).is_err(), "{bad:?}");
        }
        // Damaged, or too many.
        assert!(follow(&k1.public(), &[Envelope { doc: "{".into(), sig: "x".into() }], &check).is_err());
        assert!(follow(&k1.public(), &vec![c12.clone(); MAX_KEY_CHANGES + 1], &check).unwrap_err().to_string().contains("more than"));
    }

    #[test]
    fn a_list_after_a_key_change_proves_its_signer() {
        use fake::Key;
        let (k1, k2) = (Key("k1"), Key("k2"));
        let base = List { version: 5, members: vec![entry(1, "coord")], rejected: vec![], keys: vec![], people: vec![] };
        let old = seal(&k1, &base).unwrap();
        let with = List { version: 6, keys: vec![change(&k1, &k1, &k2, 10, true)], ..base.clone() };
        let new = seal(&k2, &with).unwrap();
        // A machine that trusts k1 follows the change to k2 and takes it.
        assert_eq!(new.list_signed_by(&k1, fits).unwrap(), (with.clone(), Some(k2.public())));
        // One that trusts k2 already takes it as it is.
        assert_eq!(new.list_signed_by(&k2, fits).unwrap().0, with);
        // Once on k2, a list of the old key is refused, change or not.
        assert!(old.list(&k2, fits).is_err());
        let old_with = seal(&k1, &with).unwrap();
        assert!(old_with.list(&k1, fits).is_err(), "signed by k1, but its own change says k2 signs");
        assert!(old_with.list(&k2, fits).is_err());
        // A list signed by k2 without the change is no list for k1.
        assert!(seal(&k2, &base).unwrap().list(&k1, fits).is_err());
        // Old lists without key changes read as before.
        let doc: serde_json::Value = serde_json::from_str(&old.doc).unwrap();
        assert!(doc.get("keys").is_none(), "no field when there is no change");
    }

    #[test]
    fn a_machine_trusts_the_newest_key_of_the_list_it_took() {
        if !crate::iso::in_path("ssh-keygen") {
            return;
        }
        let dir = TempDir::new();
        let make = |name: &str| {
            let key = dir.join(name);
            assert!(Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-f"]).arg(&key).status().unwrap().success());
            (SshSigner { key: key.clone() }, key_body(&std::fs::read_to_string(format!("{}.pub", key.display())).unwrap()))
        };
        let ((s1, p1), (s2, p2)) = (make("k1"), make("k2"));
        let root = dir.join("root");
        crate::testutil::put(&root, crate::node::SIGNING_PUB, format!("{p1} dryserver-signing\n"));
        let t = Trust::installed(&root, dir.path().to_path_buf());
        // Fresh: the installer's key.
        assert_eq!(t.key(), Some(p1.clone()));
        let doc = "hello";
        let by1 = s1.sign(NS_ADMIN, doc).unwrap();
        let by2 = s2.sign(NS_ADMIN, doc).unwrap();
        t.verify(NS_ADMIN, doc, &by1).unwrap();
        assert!(t.verify(NS_ADMIN, doc, &by2).is_err());
        // A list with the change, signed by k2, proves itself from k1...
        let c = seal_key_change(&s1, &KeyChange { serial: 7, from: p1.clone(), to: p2.clone(), login: true }).unwrap();
        let list = List { version: 2, members: vec![entry(1, "coord")], rejected: vec![], keys: vec![c], people: vec![] };
        let env = seal(&s2, &list).unwrap();
        assert_eq!(env.list_signed_by(&t, fits).unwrap(), (list.clone(), Some(p2.clone())));
        // ...and once it is the list taken, k2 is trusted and k1 no more.
        crate::testutil::put(&root, crate::node::SIGNED_FILE, serde_json::to_string(&env).unwrap());
        assert_eq!(t.key(), Some(p2.clone()));
        t.verify(NS_ADMIN, doc, &by2).unwrap();
        assert!(t.verify(NS_ADMIN, doc, &by1).is_err());
        let (_, taken) = t.followed().unwrap();
        assert_eq!(taken.len(), 1);
        // The registry reads the same from its own state.
        let state = serde_json::json!({ "members": [], "signed": env });
        crate::testutil::put(&root, "/var/lib/dryreg/registry.json", state.to_string());
        let r = Trust::for_registry(&root, &fsx::under(&root, "/var/lib/dryreg/registry.json"), dir.path().to_path_buf());
        assert_eq!(r.key(), Some(p2));
    }

    /// An ssh-agent of a test's own, stopped when dropped.
    struct Agent {
        sock: PathBuf,
        pid: u32,
    }

    impl Agent {
        fn start(dir: &Path) -> Option<Agent> {
            let sock = dir.join("agent.sock");
            let out = Command::new("ssh-agent").arg("-a").arg(&sock).arg("-s").output().ok()?;
            let text = String::from_utf8_lossy(&out.stdout).into_owned();
            let pid = text.split("SSH_AGENT_PID=").nth(1)?.split(';').next()?.trim().parse().ok()?;
            Some(Agent { sock, pid })
        }

        fn add(&self, key: &Path) {
            let st = Command::new("ssh-add").arg("-q").arg(key).env("SSH_AUTH_SOCK", &self.sock).stdin(Stdio::null()).status().unwrap();
            assert!(st.success(), "ssh-add {}", key.display());
        }
    }

    impl Drop for Agent {
        fn drop(&mut self) {
            let _ = Command::new("kill").arg(self.pid.to_string()).status();
        }
    }

    #[test]
    fn the_admins_own_key_signs_from_the_agent_or_from_ssh() {
        if !crate::iso::in_path("ssh-keygen") || !crate::iso::in_path("ssh-agent") || !crate::iso::in_path("ssh-add") {
            return;
        }
        let dir = TempDir::new();
        let ssh = dir.join("ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        let keygen = |path: &Path, pass: &str| {
            let st = Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", pass, "-f"]).arg(path).status().unwrap();
            assert!(st.success());
        };
        keygen(&ssh.join("id_ed25519"), "");
        keygen(&dir.join("other"), "");
        // The swarm trusts the admin's key: a copy of its public half.
        let trusted = dir.join("signing_ed25519.pub");
        std::fs::copy(ssh.join("id_ed25519.pub"), &trusted).unwrap();
        let v = SshVerifier { pubkey: trusted.clone(), tmp_dir: dir.path().to_path_buf() };
        let list = List { version: 3, members: vec![entry(1, "coord")], rejected: vec![], keys: vec![], people: vec![] };

        // No agent: the file in ~/.ssh signs.
        let file = OwnKeySigner { pubkey: trusted.clone(), ssh_dir: Some(ssh.clone()), agent: None };
        assert_eq!(file.locate().unwrap(), KeyAt::File { path: ssh.join("id_ed25519"), passphrase: false });
        file.ready_without_terminal().unwrap();
        let env = seal(&file, &list).unwrap();
        assert_eq!(env.list(&v, fits).unwrap(), list);
        // A signature for one use never passes for another.
        let other_ns = Envelope { doc: env.doc.clone(), sig: file.sign(NS_ADMIN, &env.doc).unwrap() };
        assert!(other_ns.list(&v, fits).is_err());

        // A key file with another name is found by its public half.
        std::fs::rename(ssh.join("id_ed25519"), ssh.join("laptop")).unwrap();
        std::fs::rename(ssh.join("id_ed25519.pub"), ssh.join("laptop.pub")).unwrap();
        assert_eq!(file.locate().unwrap(), KeyAt::File { path: ssh.join("laptop"), passphrase: false });

        // In the agent: the agent signs, also with no file left in ~/.ssh.
        let Some(agent) = Agent::start(dir.path()) else { return };
        agent.add(&dir.join("other"));
        let with_agent = OwnKeySigner { pubkey: trusted.clone(), ssh_dir: Some(ssh.clone()), agent: Some(agent.sock.clone()) };
        // Another key in the agent is not used.
        assert!(matches!(with_agent.locate().unwrap(), KeyAt::File { .. }));
        agent.add(&ssh.join("laptop"));
        std::fs::remove_file(ssh.join("laptop")).unwrap();
        assert_eq!(with_agent.locate().unwrap(), KeyAt::Agent);
        with_agent.ready_without_terminal().unwrap();
        let env = seal(&with_agent, &list).unwrap();
        assert_eq!(env.list(&v, fits).unwrap(), list);

        // Nowhere: the error says where it looked and what to do.
        let none = OwnKeySigner { pubkey: trusted.clone(), ssh_dir: Some(ssh.clone()), agent: None };
        let e = none.locate().unwrap_err().to_string();
        assert!(e.contains("neither in ssh-agent nor in ~/.ssh") && e.contains("ssh-add"), "{e}");
        assert!(none.sign(NS_MEMBERS, "x").is_err());

        // A passphrase and no agent: the screens cannot sign, and say how.
        let ssh2 = dir.join("ssh2");
        std::fs::create_dir_all(&ssh2).unwrap();
        keygen(&ssh2.join("id_ed25519"), "secret passphrase");
        let trusted2 = dir.join("trusted2.pub");
        std::fs::copy(ssh2.join("id_ed25519.pub"), &trusted2).unwrap();
        let locked = OwnKeySigner { pubkey: trusted2, ssh_dir: Some(ssh2.clone()), agent: Some(agent.sock.clone()) };
        assert_eq!(locked.locate().unwrap(), KeyAt::File { path: ssh2.join("id_ed25519"), passphrase: true });
        let e = locked.ready_without_terminal().unwrap_err().to_string();
        assert!(e.contains("has a passphrase") && e.contains(&format!("ssh-add {}", ssh2.join("id_ed25519").display())), "{e}");

        // A trusted file that is not an ed25519 key is refused.
        std::fs::write(&trusted, "ssh-rsa AAAAB3Nza x\n").unwrap();
        assert!(with_agent.locate().unwrap_err().to_string().contains("not an ed25519"));
    }
}
