//! The signed member list. The admin's desktop signs who is in the mesh
//! with secrets/signing_ed25519; the coordinator only stores and hands out
//! the result, and cannot change it, because it has no private key.
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
        v.verify(NS_MEMBERS, &self.doc, &self.sig)?;
        let list: List = serde_json::from_str(&self.doc).map_err(|e| Error::from(e).wrap("signed list"))?;
        list.check(fits)?;
        Ok(list)
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
    fn verify(&self, namespace: &str, doc: &str, sig: &str) -> Result<()>;
}

fn ssh_keygen(args: &[&str], stdin: &str) -> Result<std::process::Output> {
    use std::io::Write;
    let mut child = Command::new("ssh-keygen")
        .args(args)
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

/// Signs with a private key file (the desktop's secrets/signing_ed25519).
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

/// Checks signatures against a public key file.
pub struct SshVerifier {
    pub pubkey: PathBuf,
    /// For the two small files ssh-keygen needs; removed after each check.
    pub tmp_dir: PathBuf,
}

impl SshVerifier {
    /// For a server: the key the installer put there.
    pub fn installed(root: &Path, tmp_dir: PathBuf) -> SshVerifier {
        SshVerifier { pubkey: fsx::under(root, crate::node::SIGNING_PUB), tmp_dir }
    }
}

impl Verifier for SshVerifier {
    fn verify(&self, namespace: &str, doc: &str, sig: &str) -> Result<()> {
        let line = fsx::read_string(&self.pubkey).map_err(|e| e.wrap("no signing key on this machine"))?;
        let key = key_body(&line);
        if !key.starts_with("ssh-ed25519 ") {
            bail!("{} is not an ed25519 public key", self.pubkey.display());
        }
        if !sig.contains("BEGIN SSH SIGNATURE") {
            bail!("not signed");
        }
        let id = fsx::hex(&fsx::random_bytes(8));
        let allowed = self.tmp_dir.join(format!("dryserver-signers-{id}"));
        let sig_file = self.tmp_dir.join(format!("dryserver-sig-{id}"));
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

    impl Verifier for Key {
        fn verify(&self, namespace: &str, doc: &str, sig: &str) -> Result<()> {
            if sig == mac(self.0, namespace, doc) { Ok(()) } else { Err("bad signature".into()) }
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
        List { version: 3, members: vec![entry(1, "coord"), entry(2, "nodeb")], rejected: vec![] }
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
        let big = List { version: 7, members: (1..=254).map(|h| entry(h, &format!("node{h}"))).collect(), rejected: vec![] };
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
}
