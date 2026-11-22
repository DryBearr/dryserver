//! The cluster's join token on its way from the coordinator to the
//! servers.
//!
//! k3s agents join the cluster with one token. On the coordinator it is in
//! a file only root reads; the way to the servers is the registry
//! (registry.rs), whose account every server reaches over SSH. Whatever
//! that account can read is as good as known: a bug in its forced command
//! is enough. With the token it could join a machine of its own to the
//! cluster through the coordinator's own k3s, and pods with their secrets
//! would go there.
//!
//! So the registry account never holds the token itself. Root's sync on
//! the coordinator seals it for each member the admin signed:
//!
//! - encrypted with `age` to the member's SSH host key (ssh-ed25519, from
//!   the signed list): only root on that member can read it;
//! - signed with the coordinator's SSH host key (namespace NAMESPACE),
//!   together with the member's host number and key. Anyone can encrypt to
//!   a public key: a token of the registry account's choosing, with the
//!   hash of a certificate authority of its own, would have a server trust
//!   whatever answers on the coordinator's k3s port (the registry account
//!   could listen there while k3s restarts). The server checks the
//!   signature against the coordinator's key in the list the admin signed.
//!
//! The token goes to `age` on stdin, never on a command line, and the
//! commands that see it log nothing.
//!
//! Limit: the registry account can send a server a token the coordinator
//! sealed for it before. Until the token is changed it is the same one;
//! after a change it is the old one, which no longer works there.

use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ctx::Ctx;
use crate::err::Result;
use crate::runner::{Cmd, Runner};
use crate::{bail, fsx};

/// What the coordinator's host key signs sealed tokens as.
pub const NAMESPACE: &str = "dryserver-k3s-token";
/// The signer name in the allowed-signers file.
const SIGNER: &str = "dryserver";
/// The most an `age` text or a signature may hold. One token for one
/// recipient is about 600 bytes armored, a signature about 300.
pub const MAX_PART: usize = 4096;
/// The longest token taken.
pub const MAX_TOKEN: usize = 512;
/// The longest "ssh-ed25519 BASE64" taken (an ed25519 key is 80 bytes).
const MAX_KEY: usize = 128;
const AGE_BEGIN: &str = "-----BEGIN AGE ENCRYPTED FILE-----";
const SIG_BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";

/// The token for one member, as root on the coordinator made it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Sealed {
    /// The member's mesh host number.
    pub host: u32,
    /// The member's SSH host key it is encrypted to: "ssh-ed25519 BASE64".
    pub key: String,
    /// `age --armor` output; `age -d -i /etc/ssh/ssh_host_ed25519_key` on
    /// that member gives the token.
    pub age: String,
    /// The coordinator host key's SSH signature over signed_text().
    pub sig: String,
}

impl Sealed {
    /// What is wrong with its form, if anything.
    pub fn problem(&self) -> Option<&'static str> {
        if self.host < 2 {
            return Some("made for no server");
        }
        if !is_ed25519(&self.key) {
            return Some("made for a key that is not one ssh-ed25519 key");
        }
        if self.age.len() > MAX_PART || self.sig.len() > MAX_PART {
            return Some("larger than a token ever is");
        }
        if !self.age.starts_with(AGE_BEGIN) {
            return Some("not encrypted with age");
        }
        if !self.sig.starts_with(SIG_BEGIN) {
            return Some("not signed");
        }
        None
    }
}

/// "ssh-ed25519 BASE64" without a comment.
pub fn is_ed25519(key: &str) -> bool {
    let Some(body) = key.strip_prefix("ssh-ed25519 ") else {
        return false;
    };
    key.len() <= MAX_KEY && !body.is_empty() && body.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
}

/// What is wrong with a token for agents, if anything. Its form is
/// "K10" + the SHA-256 (hex) of the cluster's certificate authority +
/// "::node:" + the secret. Without the hash a k3s agent trusts whichever
/// certificate authority the server it reaches shows; the control plane's
/// own token ("::server:") opens more than an agent needs.
pub fn problem(token: &str) -> Option<&'static str> {
    if token.is_empty() || token.len() > MAX_TOKEN || !token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b':') {
        return Some("not a k3s token");
    }
    let Some((hash, cred)) = token.strip_prefix("K10").and_then(|t| t.split_once("::")) else {
        return Some("not a k3s token");
    };
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Some("without the hash of the cluster's certificate authority");
    }
    match cred.strip_prefix("node:") {
        Some(secret) if !secret.is_empty() && !secret.contains(':') => None,
        Some(_) => Some("not a k3s token"),
        None => Some("not for agents"),
    }
}

/// What the coordinator signs: the member it is for and the encrypted
/// token, so it cannot pass for another member's.
pub fn signed_text(host: u32, key: &str, age: &str) -> String {
    format!("dryserver-k3s-token-v1\nhost {host}\nkey {key}\n{age}")
}

/// What root on the coordinator remembers of a sealed token it made, in a
/// file of its own: it makes the token again only when the token, the
/// coordinator's key or the member's key changed, or the registry holds
/// something else. age output is new every time; made every minute, it
/// would change the registry every minute. It covers the token, so it
/// stays root's: in the registry it would be a check for guesses.
pub fn digest(token: &str, coord_key: &str, s: &Sealed) -> String {
    let text = ["dryserver-k3s-sealed-v1", token, coord_key, &s.host.to_string(), &s.key, &s.age, &s.sig].join("\n");
    fsx::hex(&Sha256::digest(text.as_bytes()))
}

/// Seals token for the member host with SSH host key key, signed with
/// the coordinator's private host key at host_key.
pub fn seal(ctx: &Ctx, run: &dyn Runner, token: &str, host: u32, key: &str, host_key: &Path) -> Result<Sealed> {
    if let Some(p) = problem(token) {
        bail!("the cluster token is {p}");
    }
    if !is_ed25519(key) {
        bail!("{key:?} is not one ssh-ed25519 key");
    }
    let age = run
        .output(ctx, &Cmd::new("age", &["--encrypt", "--armor", "--recipient", key]).stdin(token).quiet().stdout_only())
        .map_err(|e| e.wrap("encrypt the cluster token (is age installed?)"))?;
    let k = host_key.display().to_string();
    let sig = run
        .output(
            ctx,
            &Cmd::new("ssh-keygen", &["-Y", "sign", "-f", &k, "-n", NAMESPACE]).stdin(signed_text(host, key, &age)).quiet().stdout_only(),
        )
        .map_err(|e| e.wrap("sign the cluster token with the host key"))?;
    let s = Sealed { host, key: key.into(), age, sig };
    if let Some(p) = s.problem() {
        bail!("the sealed cluster token came out {p}");
    }
    Ok(s)
}

/// The token in s, for the member me whose SSH host key is my_key and
/// whose private host key is at identity. coord_key is the coordinator's
/// host key as the admin signed it. tmp_dir takes the two small files
/// ssh-keygen needs for the check, removed after it.
#[allow(clippy::too_many_arguments)]
pub fn open(
    ctx: &Ctx,
    run: &dyn Runner,
    s: &Sealed,
    me: u32,
    my_key: &str,
    coord_key: &str,
    identity: &Path,
    tmp_dir: &Path,
) -> Result<String> {
    if let Some(p) = s.problem() {
        bail!("the coordinator sent a cluster token that is {p}");
    }
    if s.host != me {
        bail!("the coordinator sent the cluster token made for another machine (host {}), not for this one (host {me})", s.host);
    }
    if s.key != my_key {
        bail!("the coordinator sent a cluster token made for another SSH host key than this machine's");
    }
    if !is_ed25519(coord_key) {
        bail!("the signed list holds no ssh-ed25519 key for the coordinator");
    }
    verify(ctx, run, tmp_dir, coord_key, &signed_text(s.host, &s.key, &s.age), &s.sig)
        .map_err(|e| e.wrap("the cluster token is not signed by the coordinator the admin signed"))?;
    let id = identity.display().to_string();
    let out = run
        .output(ctx, &Cmd::new("age", &["--decrypt", "--identity", &id]).stdin(s.age.clone()).quiet().stdout_only())
        .map_err(|e| e.wrap("cannot decrypt the cluster token with this machine's host key"))?;
    let token = out.trim();
    if let Some(p) = problem(token) {
        bail!("the coordinator sent a cluster token that is {p}");
    }
    Ok(token.to_string())
}

/// Checks an SSH signature by key over text, through ssh-keygen.
fn verify(ctx: &Ctx, run: &dyn Runner, tmp_dir: &Path, key: &str, text: &str, sig: &str) -> Result<()> {
    let id = fsx::hex(&fsx::random_bytes(8));
    let allowed = tmp_dir.join(format!("dryserver-k3s-signers-{id}"));
    let sig_file = tmp_dir.join(format!("dryserver-k3s-sig-{id}"));
    struct Remove<'a>(&'a Path, &'a Path);
    impl Drop for Remove<'_> {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(self.0);
            let _ = std::fs::remove_file(self.1);
        }
    }
    let _rm = Remove(&allowed, &sig_file);
    // New files under names of their own, never through a link.
    fsx::create_file(&allowed, format!("{SIGNER} namespaces=\"{NAMESPACE}\" {key}\n"), 0o600)?;
    fsx::create_file(&sig_file, sig, 0o600)?;
    let (a, f) = (allowed.display().to_string(), sig_file.display().to_string());
    run.ok(ctx, &Cmd::new("ssh-keygen", &["-Y", "verify", "-f", &a, "-I", SIGNER, "-n", NAMESPACE, "-s", &f]).stdin(text).quiet())
}

/// Stand-ins for age and ssh-keygen in tests. They keep the parts that
/// matter: only the holder of the private half opens a token or makes a
/// signature, and the plain token is not in what they write.
#[cfg(test)]
pub mod fake {
    use super::*;
    use base64::Engine;

    /// A token for agents as k3s writes it.
    pub const TOKEN: &str = "K10f3a1c0d9e8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1::node:0123456789abcdef0123456789abcdef";

    /// The public key next to a private key file, as the real tools find
    /// it in the key file itself.
    fn public(path: &str) -> Option<String> {
        std::fs::metadata(path).ok()?;
        let line = std::fs::read_to_string(format!("{path}.pub")).ok()?;
        Some(crate::signed::key_body(&line))
    }

    fn arg<'a>(c: &'a Cmd, flag: &str) -> Option<&'a str> {
        c.args.iter().position(|a| a == flag).and_then(|i| c.args.get(i + 1)).map(String::as_str)
    }

    /// What `age --encrypt --armor --recipient key` makes of token.
    pub fn encrypt(key: &str, token: &str) -> String {
        let body = base64::engine::general_purpose::STANDARD.encode(format!("{key}\n{token}"));
        format!("{AGE_BEGIN}\n{body}\n-----END AGE ENCRYPTED FILE-----\n")
    }

    /// An SSH signature by key over text.
    pub fn sign(key: &str, text: &str) -> String {
        let mac = fsx::hex(&Sha256::digest(format!("{key}\n{NAMESPACE}\n{text}").as_bytes()));
        format!("{SIG_BEGIN}\n{mac}\n-----END SSH SIGNATURE-----\n")
    }

    /// A sealed token as the coordinator with host key coord would make it.
    pub fn sealed(coord: &str, host: u32, key: &str, token: &str) -> Sealed {
        let age = encrypt(key, token);
        let sig = sign(coord, &signed_text(host, key, &age));
        Sealed { host, key: key.into(), age, sig }
    }

    fn fail(msg: &str) -> (String, Result<()>) {
        (String::new(), Err(crate::err::Error::new(msg)))
    }

    /// Answers c if it is age or ssh-keygen as used here.
    pub fn run(c: &Cmd) -> Option<(String, Result<()>)> {
        let has = |a: &str| c.args.iter().any(|x| x == a);
        Some(match c.name.as_str() {
            "age" if has("--encrypt") => match arg(c, "--recipient") {
                Some(key) => (encrypt(key, &c.stdin), Ok(())),
                None => fail("age failed: exit status 1"),
            },
            "age" if has("--decrypt") => {
                let Some(mine) = arg(c, "--identity").and_then(public) else {
                    return Some(fail("age failed: exit status 1"));
                };
                let body: String = c.stdin.lines().filter(|l| !l.starts_with("-----")).collect();
                let plain = base64::engine::general_purpose::STANDARD.decode(body).ok().and_then(|b| String::from_utf8(b).ok());
                match plain.as_deref().and_then(|p| p.split_once('\n')) {
                    Some((to, token)) if to == mine => (token.to_string(), Ok(())),
                    _ => fail("age failed: exit status 1"),
                }
            }
            "ssh-keygen" if has("sign") => match arg(c, "-f").and_then(public) {
                Some(key) if arg(c, "-n") == Some(NAMESPACE) => (sign(&key, &c.stdin), Ok(())),
                _ => fail("ssh-keygen failed: exit status 255"),
            },
            "ssh-keygen" if has("verify") => {
                let allowed = arg(c, "-f").and_then(|p| std::fs::read_to_string(p).ok()).unwrap_or_default();
                let sig = arg(c, "-s").and_then(|p| std::fs::read_to_string(p).ok()).unwrap_or_default();
                let key = allowed.split_whitespace().skip(2).collect::<Vec<_>>().join(" ");
                let ns_ok = arg(c, "-n") == Some(NAMESPACE) && allowed.contains(&format!("namespaces=\"{NAMESPACE}\""));
                if ns_ok && !key.is_empty() && sig == sign(&key, &c.stdin) {
                    (format!("Good \"{NAMESPACE}\" signature for {SIGNER}\n"), Ok(()))
                } else {
                    fail("ssh-keygen failed: exit status 255")
                }
            }
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::err::Error;
    use crate::runner::ExecRunner;
    use crate::testutil::{TempDir, put};
    use fake::TOKEN;
    use std::sync::Mutex;
    const COORD: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIcoord";
    const NODE: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAInode";

    /// The fake tools, with every command recorded.
    struct Tools(Mutex<Vec<Cmd>>);

    impl Runner for Tools {
        fn run(&self, _ctx: &Ctx, c: &Cmd) -> (String, Result<()>) {
            self.0.lock().unwrap().push(c.clone());
            fake::run(c).unwrap_or_else(|| (String::new(), Err(Error::new("unknown"))))
        }
    }

    /// A machine's host key files under dir: the private one and the .pub
    /// the fakes read.
    fn host_key(dir: &TempDir, name: &str, key: &str) -> std::path::PathBuf {
        put(dir.path(), &format!("/{name}"), "private\n");
        put(dir.path(), &format!("/{name}.pub"), format!("{key} root@{name}\n"));
        dir.join(name)
    }

    #[test]
    fn the_form_of_a_token_for_agents() {
        assert_eq!(problem(TOKEN), None);
        let hash = &TOKEN[3..67];
        for (bad, want) in [
            ("", "not a k3s token"),
            ("not a token", "not a k3s token"),
            ("K10abc\nserver: https://evil", "not a k3s token"),
            ("K10;rm -rf", "not a k3s token"),
            (&"K10".repeat(400), "not a k3s token"),
            (&format!("K10{hash}"), "not a k3s token"),
            // The short form: an agent would trust any certificate authority.
            ("K10::node:secret", "without the hash"),
            ("K10abc::node:secret", "without the hash"),
            (&format!("K10{hash}x::node:secret"), "without the hash"),
            (&format!("K10{}::node:secret", "g".repeat(64)), "without the hash"),
            (&format!("K10{hash}::server:secret"), "not for agents"),
            (&format!("K10{hash}::node:"), "not a k3s token"),
            (&format!("K10{hash}::node:a:b"), "not a k3s token"),
            (&format!("K10{hash}::node:{}", "a".repeat(MAX_TOKEN)), "not a k3s token"),
        ] {
            assert!(problem(bad).is_some_and(|p| p.contains(want)), "{bad:?}: {:?}", problem(bad));
        }
    }

    #[test]
    fn seal_and_open() {
        let dir = TempDir::new();
        let (coord_key, node_key) = (host_key(&dir, "coord", COORD), host_key(&dir, "node", NODE));
        let tools = Tools(Mutex::new(Vec::new()));
        let ctx = Ctx::new();
        let s = seal(&ctx, &tools, TOKEN, 2, NODE, &coord_key).unwrap();
        assert_eq!(s.problem(), None);
        assert!(!format!("{s:?}").contains("0123456789abcdef"), "the token itself is in the sealed one: {s:?}");
        // On stdin only, and nothing logged of what carries it.
        for c in tools.0.lock().unwrap().iter() {
            assert!(!c.args.join(" ").contains("0123456789abcdef"), "the token on a command line: {c}");
            assert!(c.quiet, "{c} logs its output");
        }
        let open = |s: &Sealed, me: u32, my: &str, coord: &str| open(&ctx, &tools, s, me, my, coord, &node_key, dir.path());
        assert_eq!(open(&s, 2, NODE, COORD).unwrap(), TOKEN);
        let left: Vec<_> =
            std::fs::read_dir(dir.path()).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().contains("k3s")).collect();
        assert!(left.is_empty(), "the check left files behind: {left:?}");

        // Made for someone else, or changed on the way.
        let other = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIother";
        let forged = fake::sealed("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIevil", 2, NODE, TOKEN);
        let cases: Vec<(Sealed, &str)> = vec![
            (Sealed { host: 3, ..s.clone() }, "made for another machine"),
            (Sealed { key: other.into(), ..s.clone() }, "another SSH host key"),
            // Its host number changed to this machine's: the signature says no.
            (Sealed { host: 2, ..seal(&ctx, &tools, TOKEN, 3, NODE, &coord_key).unwrap() }, "not signed by the coordinator"),
            (forged, "not signed by the coordinator"),
            (Sealed { sig: s.sig.replacen(SIG_BEGIN, &format!("{SIG_BEGIN}\n00"), 1), ..s.clone() }, "not signed by the coordinator"),
            // Signed by the coordinator, encrypted to another key.
            (
                Sealed {
                    age: fake::encrypt(other, TOKEN),
                    sig: fake::sign(COORD, &signed_text(2, NODE, &fake::encrypt(other, TOKEN))),
                    ..s.clone()
                },
                "cannot decrypt",
            ),
            (Sealed { age: "x".repeat(MAX_PART + 1), ..s.clone() }, "larger than"),
            (Sealed { sig: "x".repeat(MAX_PART + 1), ..s.clone() }, "larger than"),
            (Sealed { age: "hello".into(), ..s.clone() }, "not encrypted"),
            (Sealed { sig: String::new(), ..s.clone() }, "not signed"),
            (Sealed { key: format!("{NODE} root@node"), ..s.clone() }, "not one ssh-ed25519 key"),
            (Sealed { host: 1, ..s.clone() }, "made for no server"),
            (Sealed::default(), "made for no server"),
        ];
        for (bad, want) in cases {
            let e = open(&bad, 2, NODE, COORD).unwrap_err().to_string();
            assert!(e.contains(want), "{want}: {e}");
        }
        // Signed by the coordinator, but junk inside: never a token.
        let junk = seal_any(&tools, &ctx, "K10abc::node:x", &coord_key);
        assert!(open(&junk, 2, NODE, COORD).unwrap_err().to_string().contains("without the hash"));
        // The coordinator's key from the signed list is not an ed25519 key.
        assert!(open(&s, 2, NODE, "").unwrap_err().to_string().contains("no ssh-ed25519 key"));
        assert!(open(&s, 2, NODE, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIother").unwrap_err().to_string().contains("not signed"));
        // Nothing is sealed from a token that is not one, or for a key
        // that is not one.
        assert!(seal(&ctx, &tools, "K10abc::server:x", 2, NODE, &coord_key).is_err());
        assert!(seal(&ctx, &tools, TOKEN, 2, "ssh-rsa AAAAB3NzaC1yc2E", &coord_key).is_err());
        assert!(seal(&ctx, &tools, TOKEN, 2, NODE, &dir.join("missing")).unwrap_err().to_string().contains("sign the cluster token"));
    }

    /// Seals whatever text, as a coordinator gone wrong would.
    fn seal_any(tools: &Tools, ctx: &Ctx, text: &str, coord_key: &Path) -> Sealed {
        let age = tools.output(ctx, &Cmd::new("age", &["--encrypt", "--armor", "--recipient", NODE]).stdin(text)).unwrap();
        let k = coord_key.display().to_string();
        let sig = tools
            .output(ctx, &Cmd::new("ssh-keygen", &["-Y", "sign", "-f", &k, "-n", NAMESPACE]).stdin(signed_text(2, NODE, &age)))
            .unwrap();
        Sealed { host: 2, key: NODE.into(), age, sig }
    }

    #[test]
    fn the_digest_follows_what_it_was_made_from() {
        let s = fake::sealed(COORD, 2, NODE, TOKEN);
        let d = digest(TOKEN, COORD, &s);
        assert_eq!(d, digest(TOKEN, COORD, &s.clone()));
        assert!(!d.contains("0123456789abcdef"));
        for (token, coord, other) in [
            (&format!("{}0", &TOKEN[..TOKEN.len() - 1]) as &str, COORD, s.clone()),
            (TOKEN, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIcoord2", s.clone()),
            (TOKEN, COORD, Sealed { host: 3, ..s.clone() }),
            (TOKEN, COORD, Sealed { age: fake::encrypt(NODE, TOKEN).replace('A', "B"), ..s.clone() }),
            (TOKEN, COORD, Sealed { sig: fake::sign(COORD, "x"), ..s.clone() }),
        ] {
            assert_ne!(digest(token, coord, &other), d);
        }
    }

    /// The real OpenSSH signs and checks, with age faked: runs wherever
    /// ssh-keygen is, also without age.
    #[test]
    fn real_openssh_with_a_fake_age() {
        if !crate::iso::in_path("ssh-keygen") {
            return;
        }
        struct Half(ExecRunner);
        impl Runner for Half {
            fn run(&self, ctx: &Ctx, c: &Cmd) -> (String, Result<()>) {
                if c.name == "age" { fake::run(c).unwrap() } else { self.0.run(ctx, c) }
            }
        }
        let dir = TempDir::new();
        let make = |name: &str| {
            let key = dir.join(name);
            let st = std::process::Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-f"]).arg(&key).status().unwrap();
            assert!(st.success());
            (key.clone(), crate::signed::key_body(&std::fs::read_to_string(dir.join(format!("{name}.pub"))).unwrap()))
        };
        let ((coord, coord_pub), (node, node_pub), (other, _)) = (make("coord"), make("node"), make("other"));
        let (run, ctx) = (Half(ExecRunner::silent()), Ctx::new());
        let s = seal(&ctx, &run, TOKEN, 2, &node_pub, &coord).unwrap();
        assert!(s.sig.starts_with(SIG_BEGIN) && s.sig.len() < 1000, "{}", s.sig);
        assert_eq!(open(&ctx, &run, &s, 2, &node_pub, &coord_pub, &node, dir.path()).unwrap(), TOKEN);
        for (bad, why) in [
            (seal(&ctx, &run, TOKEN, 2, &node_pub, &other).unwrap(), "signed by another key"),
            (Sealed { host: 2, ..seal(&ctx, &run, TOKEN, 3, &node_pub, &coord).unwrap() }, "made for host 3"),
            (Sealed { age: fake::encrypt(&node_pub, TOKEN2), ..s.clone() }, "another token under its signature"),
        ] {
            let e = open(&ctx, &run, &bad, 2, &node_pub, &coord_pub, &node, dir.path()).unwrap_err().to_string();
            assert!(e.contains("not signed by the coordinator"), "{why}: {e}");
        }
        // A signature for something else (a backup's receipt) is not one
        // for a token.
        let k = coord.display().to_string();
        let text = signed_text(2, &node_pub, &s.age);
        let backup = run.0.output(&ctx, &Cmd::new("ssh-keygen", &["-Y", "sign", "-f", &k, "-n", "dryserver-backup"]).stdin(text)).unwrap();
        assert!(open(&ctx, &run, &Sealed { sig: backup, ..s.clone() }, 2, &node_pub, &coord_pub, &node, dir.path()).is_err());
        let left: Vec<_> =
            std::fs::read_dir(dir.path()).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().contains("k3s")).collect();
        assert!(left.is_empty(), "{left:?}");
    }

    const TOKEN2: &str = "K10f3a1c0d9e8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1::node:fedcba9876543210";

    /// The same with the real age and OpenSSH, where they are installed.
    #[test]
    fn real_age_and_openssh() {
        if !crate::iso::in_path("age") || !crate::iso::in_path("ssh-keygen") {
            eprintln!("real_age_and_openssh: age or ssh-keygen missing, skipped");
            return;
        }
        let dir = TempDir::new();
        let make = |name: &str| {
            let key = dir.join(name);
            let st = std::process::Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-f"]).arg(&key).status().unwrap();
            assert!(st.success());
            let public = crate::signed::key_body(&std::fs::read_to_string(dir.join(format!("{name}.pub"))).unwrap());
            (key, public)
        };
        let ((coord, coord_pub), (node, node_pub), (other, other_pub)) = (make("coord"), make("node"), make("other"));
        let (run, ctx) = (ExecRunner::silent(), Ctx::new());
        let s = seal(&ctx, &run, TOKEN, 2, &node_pub, &coord).unwrap();
        assert!(!s.age.contains("0123456789abcdef") && s.age.len() < 1500 && s.sig.len() < 1000, "{s:?}");
        assert_eq!(open(&ctx, &run, &s, 2, &node_pub, &coord_pub, &node, dir.path()).unwrap(), TOKEN);
        // Signed by the coordinator for another machine, but encrypted to
        // this one: that machine's key opens nothing.
        let k = coord.display().to_string();
        let text = signed_text(2, &other_pub, &s.age);
        let sig = run.output(&ctx, &Cmd::new("ssh-keygen", &["-Y", "sign", "-f", &k, "-n", NAMESPACE]).stdin(text).stdout_only()).unwrap();
        let moved = Sealed { key: other_pub.clone(), sig, ..s.clone() };
        let e = open(&ctx, &run, &moved, 2, &other_pub, &coord_pub, &other, dir.path()).unwrap_err().to_string();
        assert!(e.contains("cannot decrypt"), "{e}");
        // Another key signs nothing that passes.
        let forged = seal(&ctx, &run, TOKEN, 2, &node_pub, &other).unwrap();
        assert!(open(&ctx, &run, &forged, 2, &node_pub, &coord_pub, &node, dir.path()).unwrap_err().to_string().contains("not signed"));
        let s3 = seal(&ctx, &run, TOKEN, 3, &node_pub, &coord).unwrap();
        assert!(open(&ctx, &run, &Sealed { host: 2, ..s3 }, 2, &node_pub, &coord_pub, &node, dir.path()).is_err());
        let left: Vec<_> =
            std::fs::read_dir(dir.path()).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().contains("k3s")).collect();
        assert!(left.is_empty(), "{left:?}");
    }
}
