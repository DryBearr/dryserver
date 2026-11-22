//! A server's token for joining the cluster, on its way from the
//! coordinator to that server.
//!
//! Each server joins with a token of its own: a k3s bootstrap token that
//! root on the coordinator makes for it (`k3s token create`) and deletes
//! once the server is in the cluster, from then on the server proves
//! itself with its kubelet certificate. One token shared by all servers
//! would let any of them, hacked, register a k3s node under the name of a
//! server the admin just approved before that server does: k3s then turns
//! the real one away, and that server's pods and their secrets go to the
//! hacked one. A server that has joined holds no token that registers
//! any other name (node.rs, k3s_share).
//!
//! The way to the servers is the registry (registry.rs), whose account
//! every server reaches over SSH. Whatever that account can read is as good
//! as known: a bug in its forced command is enough. With a token it could
//! join a machine of its own to the cluster through the coordinator's own
//! k3s, and pods with their secrets would go there.
//!
//! So the registry account never holds a token itself. Root's sync on the
//! coordinator seals each one for the member it is for:
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
//! sealed for it before: an older one, which no longer works there.
//!
//! A bootstrap token itself registers any node name. What ties a name to
//! one server is its node password: k3s keeps a hash of it per name in the
//! cluster (the secret `<name>.node-password.k3s`, see password_hash) and
//! gives a kubelet certificate for that name only to an agent that shows
//! it (`/etc/rancher/node/password` on the agent). Root makes a password
//! for each server, puts its hash in the cluster before it hands out the
//! server's token, and seals the password together with the token: a
//! server holding a token, even before it joined, cannot take another
//! server's name, as it does not know that server's password.

use std::path::Path;

use serde::{Deserialize, Serialize};

use base64::Engine;

use crate::ctx::Ctx;
use crate::err::Result;
use crate::runner::{Cmd, Runner};
use crate::{bail, fsx, registry};

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
/// The line after the token that carries the node password.
const PASSWORD_LINE: &str = "node-password ";
/// The suffix of the secret in which k3s keeps a node name's password
/// hash (namespace kube-system).
pub const PASSWORD_SECRET: &str = ".node-password.k3s";
/// The secret type k3s gives those secrets.
pub const PASSWORD_TYPE: &str = "k3s.cattle.io/node-password";
/// k3s's scrypt parameters (pkg/authenticator/hash): N = 2^15, r 8, p 1,
/// 64 bytes, 8 bytes of salt. Lower in tests, which hash a lot.
#[cfg(not(test))]
const HASH_LOG_N: u32 = 15;
#[cfg(test)]
const HASH_LOG_N: u32 = 4;
const HASH_R: usize = 8;
const HASH_P: usize = 1;
const HASH_LEN: usize = 64;

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
/// "::" + the credentials: a bootstrap token "<id>.<secret>" (6 and 16
/// characters a-z, 0-9) as `k3s token create` makes one, or "node:" + the
/// secret, the one token for every agent older versions handed out.
/// Without the hash a k3s agent trusts whichever certificate authority the
/// server it reaches shows; the control plane's own token ("::server:")
/// opens more than an agent needs.
pub fn problem(token: &str) -> Option<&'static str> {
    if token.is_empty() || token.len() > MAX_TOKEN || !token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b':' || b == b'.') {
        return Some("not a k3s token");
    }
    let Some((hash, cred)) = token.strip_prefix("K10").and_then(|t| t.split_once("::")) else {
        return Some("not a k3s token");
    };
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Some("without the hash of the cluster's certificate authority");
    }
    if bootstrap_id(token).is_some() {
        return None;
    }
    match cred.strip_prefix("node:") {
        Some(secret) if !secret.is_empty() && !secret.contains([':', '.']) => None,
        Some(_) => Some("not a k3s token"),
        None if cred.contains(':') => Some("not for agents"),
        None => Some("not a k3s token"),
    }
}

/// The id of a bootstrap token ("K10<hash>::<id>.<secret>"), which `k3s
/// token delete` takes; none for any other form.
pub fn bootstrap_id(token: &str) -> Option<&str> {
    let (_, cred) = token.split_once("::")?;
    let (id, secret) = cred.split_once('.')?;
    let plain = |s: &str, len: usize| s.len() == len && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    (plain(id, 6) && plain(secret, 16)).then_some(id)
}

/// What the coordinator signs: the member it is for and the encrypted
/// token, so it cannot pass for another member's.
pub fn signed_text(host: u32, key: &str, age: &str) -> String {
    format!("dryserver-k3s-token-v1\nhost {host}\nkey {key}\n{age}")
}

/// What a sealed token holds, opened.
#[derive(Debug, Clone, PartialEq)]
pub struct Opened {
    pub token: String,
    /// The node password for the agent; none from a coordinator of an
    /// older version, which bound no name (the agent makes its own then).
    pub password: Option<String>,
}

/// What is wrong with a node password, if anything: k3s makes 32 hex
/// characters, and so does new_password.
pub fn password_problem(p: &str) -> Option<&'static str> {
    if !(16..=64).contains(&p.len()) || !p.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Some("not a node password");
    }
    None
}

/// A new node password, as k3s makes one: 16 random bytes in hex.
pub fn new_password() -> String {
    fsx::hex(&fsx::random_bytes(16))
}

/// The name of the secret in kube-system that holds the password hash of
/// node name (k3s's nodepassword.getSecretName).
pub fn password_secret(name: &str) -> String {
    format!("{name}{PASSWORD_SECRET}").to_lowercase()
}

/// The hash k3s keeps of a node password and checks an agent's against:
/// "$1:<salt hex>:<log2 N>:<r>:<p>:<key, base64 without padding>", scrypt
/// with a new salt (k3s's hash.SCrypt, CreateHash).
pub fn password_hash(password: &str) -> String {
    hash_with(password, &fsx::random_bytes(8), HASH_LOG_N, HASH_R, HASH_P)
}

fn hash_with(password: &str, salt: &[u8], log_n: u32, r: usize, p: usize) -> String {
    let key = scrypt(password.as_bytes(), salt, log_n, r, p, HASH_LEN);
    let enc = base64::engine::general_purpose::STANDARD_NO_PAD.encode(key);
    format!("$1:{}:{log_n}:{r}:{p}:{enc}", fsx::hex(salt))
}

/// Whether hash (password_hash's form) is of password, as k3s checks it.
#[cfg(test)]
pub fn hash_matches(hash: &str, password: &str) -> bool {
    let f: Vec<&str> = hash.split(':').collect();
    let [v, salt, n, r, p, enc] = f.as_slice() else { return false };
    let salt: Option<Vec<u8>> =
        (0..salt.len() / 2).map(|i| salt.get(2 * i..2 * i + 2).and_then(|b| u8::from_str_radix(b, 16).ok())).collect();
    let (Some(salt), Ok(n), Ok(r), Ok(p)) = (salt, n.parse::<u32>(), r.parse::<usize>(), p.parse::<usize>()) else {
        return false;
    };
    let Ok(want) = base64::engine::general_purpose::STANDARD_NO_PAD.decode(enc) else { return false };
    *v == "$1" && n < 20 && scrypt(password.as_bytes(), &salt, n, r, p, want.len()) == want
}

/// scrypt (RFC 7914) with HMAC-SHA256.
fn scrypt(password: &[u8], salt: &[u8], log_n: u32, r: usize, p: usize, len: usize) -> Vec<u8> {
    let block = 128 * r;
    let words = block / 4;
    let n = 1usize << log_n;
    let mut b = pbkdf2_sha256(password, salt, p * block);
    let mut v = vec![0u32; n * words];
    let (mut x, mut y) = (vec![0u32; words], vec![0u32; words]);
    for chunk in b.chunks_mut(block) {
        for (w, c) in x.iter_mut().zip(chunk.as_chunks::<4>().0) {
            *w = u32::from_le_bytes(*c);
        }
        for i in 0..n {
            v[i * words..(i + 1) * words].copy_from_slice(&x);
            block_mix(&x, &mut y, r);
            std::mem::swap(&mut x, &mut y);
        }
        for _ in 0..n {
            let j = (x[words - 16] as usize) & (n - 1);
            for (a, b) in x.iter_mut().zip(&v[j * words..(j + 1) * words]) {
                *a ^= b;
            }
            block_mix(&x, &mut y, r);
            std::mem::swap(&mut x, &mut y);
        }
        for (c, w) in chunk.as_chunks_mut::<4>().0.iter_mut().zip(&x) {
            c.copy_from_slice(&w.to_le_bytes());
        }
    }
    pbkdf2_sha256(password, &b, len)
}

/// PBKDF2-HMAC-SHA256 with one iteration, as scrypt uses it.
fn pbkdf2_sha256(password: &[u8], salt: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 32);
    let mut i = 1u32;
    while out.len() < len {
        let mut msg = salt.to_vec();
        msg.extend_from_slice(&i.to_be_bytes());
        out.extend_from_slice(&registry::hmac_sha256(password, &msg));
        i += 1;
    }
    out.truncate(len);
    out
}

/// scrypt's BlockMix with Salsa20/8 over 2r blocks of 16 words.
fn block_mix(input: &[u32], out: &mut [u32], r: usize) {
    let mut t = [0u32; 16];
    t.copy_from_slice(&input[(2 * r - 1) * 16..2 * r * 16]);
    for i in 0..2 * r {
        for (a, b) in t.iter_mut().zip(&input[i * 16..(i + 1) * 16]) {
            *a ^= b;
        }
        salsa20_8(&mut t);
        let at = if i % 2 == 0 { i / 2 } else { r + i / 2 } * 16;
        out[at..at + 16].copy_from_slice(&t);
    }
}

fn salsa20_8(b: &mut [u32; 16]) {
    let mut x = *b;
    let qr = |x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize| {
        x[b] ^= x[a].wrapping_add(x[d]).rotate_left(7);
        x[c] ^= x[b].wrapping_add(x[a]).rotate_left(9);
        x[d] ^= x[c].wrapping_add(x[b]).rotate_left(13);
        x[a] ^= x[d].wrapping_add(x[c]).rotate_left(18);
    };
    for _ in 0..4 {
        qr(&mut x, 0, 4, 8, 12);
        qr(&mut x, 5, 9, 13, 1);
        qr(&mut x, 10, 14, 2, 6);
        qr(&mut x, 15, 3, 7, 11);
        qr(&mut x, 0, 1, 2, 3);
        qr(&mut x, 5, 6, 7, 4);
        qr(&mut x, 10, 11, 8, 9);
        qr(&mut x, 15, 12, 13, 14);
    }
    for (a, b) in b.iter_mut().zip(x) {
        *a = a.wrapping_add(b);
    }
}

/// Seals token and the agent's node password for the member host with
/// SSH host key key, signed with the coordinator's private host key at
/// host_key.
pub fn seal(ctx: &Ctx, run: &dyn Runner, token: &str, password: &str, host: u32, key: &str, host_key: &Path) -> Result<Sealed> {
    if let Some(p) = problem(token) {
        bail!("the cluster token is {p}");
    }
    if let Some(p) = password_problem(password) {
        bail!("the node password is {p}");
    }
    if !is_ed25519(key) {
        bail!("{key:?} is not one ssh-ed25519 key");
    }
    let plain = format!("{token}\n{PASSWORD_LINE}{password}\n");
    let age = run
        .output(ctx, &Cmd::new("age", &["--encrypt", "--armor", "--recipient", key]).stdin(plain).quiet().stdout_only())
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

/// The token in s, and the node password with it, for the member me
/// whose SSH host key is my_key and whose private host key is at
/// identity. coord_key is the coordinator's host key as the admin signed
/// it. tmp_dir takes the two small files ssh-keygen needs for the check,
/// removed after it.
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
) -> Result<Opened> {
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
    // The token alone (a coordinator of an older version), or with the
    // node password on the next line.
    let (token, password) = match out.trim().split_once('\n') {
        None => (out.trim(), None),
        Some((token, rest)) => match rest.strip_prefix(PASSWORD_LINE) {
            Some(p) if password_problem(p).is_none() => (token, Some(p.to_string())),
            _ => bail!("the coordinator sent a cluster token that is not a k3s token"),
        },
    };
    if let Some(p) = problem(token) {
        bail!("the coordinator sent a cluster token that is {p}");
    }
    Ok(Opened { token: token.to_string(), password })
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
    use sha2::{Digest, Sha256};

    /// A bootstrap token as `k3s token create` prints it.
    pub const BOOTSTRAP: &str = "K10f3a1c0d9e8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1::tok001.0123456789abcdef";

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

    /// A node password as new_password makes one.
    const PW: &str = "00112233445566778899aabbccddeeff";

    fn opened() -> Opened {
        Opened { token: TOKEN.into(), password: Some(PW.into()) }
    }

    /// scrypt against RFC 7914 and Python's hashlib.scrypt, and the hash
    /// in the form k3s reads (pkg/authenticator/hash, VerifyHash).
    #[test]
    fn the_node_password_hash_is_the_one_k3s_checks() {
        let hex = |b: &[u8]| fsx::hex(b);
        assert_eq!(
            hex(&pbkdf2_sha256(b"passwd", b"salt", 64)),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
        );
        assert_eq!(
            hex(&scrypt(b"", b"", 4, 1, 1, 64)),
            "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"
        );
        assert_eq!(
            hex(&scrypt(b"password", b"NaCl", 10, 8, 16, 64)),
            "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"
        );
        let salt = [1u8, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(
            hex(&scrypt(b"0123456789abcdef0123456789abcdef", &salt, 10, 8, 1, 64)),
            "291e12ade72f35114dc29b530fe3d933a26d19fe28155a963e4e490023e5b514e8b14dadf74c9f94aa1f20f717cee9fd46d16e16e7d26ccfb042f1feb32caf8d"
        );
        assert_eq!(
            hash_with("0123456789abcdef0123456789abcdef", &salt, 4, 8, 1),
            "$1:0102030405060708:4:8:1:pGr++1yswNxP08QKoNdGOoQl9n1Yw1CunqkLx3ZhzCpNZbUD4OILJxfY6XM9spDDfRbKRNqbREEGOTK/TVlStw"
        );
        // A new salt every time, and only the password matches.
        let (a, b) = (password_hash(PW), password_hash(PW));
        assert_ne!(a, b);
        assert!(a.starts_with("$1:") && a.contains(&format!(":{HASH_LOG_N}:8:1:")), "{a}");
        assert!(hash_matches(&a, PW) && hash_matches(&b, PW) && !hash_matches(&a, &PW.replace('0', "1")));
        // The form k3s makes.
        let pw = new_password();
        assert_eq!((pw.len(), password_problem(&pw)), (32, None));
        assert_ne!(pw, new_password());
        for bad in ["", "short", &"a".repeat(65), "0123456789ABCDEF0123", "0123456789abcdef\n0123", "0123456789abcdef 0123"] {
            assert!(password_problem(bad).is_some(), "{bad:?}");
        }
        assert_eq!(password_secret("node-c"), "node-c.node-password.k3s");
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
        let s = seal(&ctx, &tools, TOKEN, PW, 2, NODE, &coord_key).unwrap();
        assert_eq!(s.problem(), None);
        assert!(!format!("{s:?}").contains("0123456789abcdef"), "the token itself is in the sealed one: {s:?}");
        // On stdin only, and nothing logged of what carries it.
        for c in tools.0.lock().unwrap().iter() {
            assert!(!c.args.join(" ").contains("0123456789abcdef"), "the token on a command line: {c}");
            assert!(c.quiet, "{c} logs its output");
        }
        let open = |s: &Sealed, me: u32, my: &str, coord: &str| open(&ctx, &tools, s, me, my, coord, &node_key, dir.path());
        assert_eq!(open(&s, 2, NODE, COORD).unwrap(), opened());
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
            (Sealed { host: 2, ..seal(&ctx, &tools, TOKEN, PW, 3, NODE, &coord_key).unwrap() }, "not signed by the coordinator"),
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
        for junk in [
            format!("{TOKEN}\nnode-password short\n"),
            format!("{TOKEN}\nserver: https://evil\n"),
            format!("{TOKEN}\nnode-password {PW}\nmore\n"),
            format!("node-password {PW}\n{TOKEN}\n"),
        ] {
            let s = seal_any(&tools, &ctx, &junk, &coord_key);
            assert!(open(&s, 2, NODE, COORD).unwrap_err().to_string().contains("not a k3s token"), "{junk:?}");
        }
        // A coordinator of an older version sealed the token alone: the
        // agent makes its own password then.
        let old = seal_any(&tools, &ctx, &format!("{TOKEN}\n"), &coord_key);
        assert_eq!(open(&old, 2, NODE, COORD).unwrap(), Opened { token: TOKEN.into(), password: None });
        assert!(seal(&ctx, &tools, TOKEN, "not hex", 2, NODE, &coord_key).unwrap_err().to_string().contains("node password"));
        assert!(!format!("{s:?}").contains(PW) && !tools.0.lock().unwrap().iter().any(|c| c.args.join(" ").contains(PW)));
        // The coordinator's key from the signed list is not an ed25519 key.
        assert!(open(&s, 2, NODE, "").unwrap_err().to_string().contains("no ssh-ed25519 key"));
        assert!(open(&s, 2, NODE, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIother").unwrap_err().to_string().contains("not signed"));
        // Nothing is sealed from a token that is not one, or for a key
        // that is not one.
        assert!(seal(&ctx, &tools, "K10abc::server:x", PW, 2, NODE, &coord_key).is_err());
        assert!(seal(&ctx, &tools, TOKEN, PW, 2, "ssh-rsa AAAAB3NzaC1yc2E", &coord_key).is_err());
        assert!(seal(&ctx, &tools, TOKEN, PW, 2, NODE, &dir.join("missing")).unwrap_err().to_string().contains("sign the cluster token"));
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

    /// What `k3s token create` prints, and nothing near it.
    #[test]
    fn a_bootstrap_token() {
        let hash = &TOKEN[3..67];
        let good = format!("K10{hash}::abc123.0123456789abcdef");
        assert_eq!((problem(&good), bootstrap_id(&good)), (None, Some("abc123")));
        assert_eq!(problem(fake::BOOTSTRAP), None);
        assert_eq!(bootstrap_id(TOKEN), None, "the token shared by all agents has no id");
        for bad in [
            "K10::abc123.0123456789abcdef".to_string(),
            format!("K10{hash}::ABC123.0123456789abcdef"),
            format!("K10{hash}::abc12.0123456789abcdef"),
            format!("K10{hash}::abc123.0123456789abcde"),
            format!("K10{hash}::abc123.0123456789abcdef0"),
            format!("K10{hash}::abc123.01234567.9abcdef"),
            format!("K10{hash}::abc123:0123456789abcdef"),
            format!("K10{hash}::node:abc123.0123456789abcdef"),
            format!("K10{hash}::abc123.0123456789abcdef\n"),
        ] {
            assert!(problem(&bad).is_some(), "{bad:?}");
            assert!(bootstrap_id(&bad).is_none() || problem(&bad).is_some(), "{bad:?}");
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
        let s = seal(&ctx, &run, TOKEN, PW, 2, &node_pub, &coord).unwrap();
        assert!(s.sig.starts_with(SIG_BEGIN) && s.sig.len() < 1000, "{}", s.sig);
        assert_eq!(open(&ctx, &run, &s, 2, &node_pub, &coord_pub, &node, dir.path()).unwrap(), opened());
        for (bad, why) in [
            (seal(&ctx, &run, TOKEN, PW, 2, &node_pub, &other).unwrap(), "signed by another key"),
            (Sealed { host: 2, ..seal(&ctx, &run, TOKEN, PW, 3, &node_pub, &coord).unwrap() }, "made for host 3"),
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
        let s = seal(&ctx, &run, TOKEN, PW, 2, &node_pub, &coord).unwrap();
        assert!(!s.age.contains("0123456789abcdef") && s.age.len() < 1500 && s.sig.len() < 1000, "{s:?}");
        assert_eq!(open(&ctx, &run, &s, 2, &node_pub, &coord_pub, &node, dir.path()).unwrap(), opened());
        // Signed by the coordinator for another machine, but encrypted to
        // this one: that machine's key opens nothing.
        let k = coord.display().to_string();
        let text = signed_text(2, &other_pub, &s.age);
        let sig = run.output(&ctx, &Cmd::new("ssh-keygen", &["-Y", "sign", "-f", &k, "-n", NAMESPACE]).stdin(text).stdout_only()).unwrap();
        let moved = Sealed { key: other_pub.clone(), sig, ..s.clone() };
        let e = open(&ctx, &run, &moved, 2, &other_pub, &coord_pub, &other, dir.path()).unwrap_err().to_string();
        assert!(e.contains("cannot decrypt"), "{e}");
        // Another key signs nothing that passes.
        let forged = seal(&ctx, &run, TOKEN, PW, 2, &node_pub, &other).unwrap();
        assert!(open(&ctx, &run, &forged, 2, &node_pub, &coord_pub, &node, dir.path()).unwrap_err().to_string().contains("not signed"));
        let s3 = seal(&ctx, &run, TOKEN, PW, 3, &node_pub, &coord).unwrap();
        assert!(open(&ctx, &run, &Sealed { host: 2, ..s3 }, 2, &node_pub, &coord_pub, &node, dir.path()).is_err());
        let left: Vec<_> =
            std::fs::read_dir(dir.path()).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().contains("k3s")).collect();
        assert!(left.is_empty(), "{left:?}");
    }
}
