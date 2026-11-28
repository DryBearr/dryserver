//! Apps that GitHub builds on every push to a branch, and that the
//! coordinator puts on the servers by itself.
//!
//! - GitHub Actions builds the app (its own Dockerfile, or Railpack when
//!   it has none) on GitHub's machines and pushes the image to GitHub's
//!   registry (ghcr.io). The workflow is written by `dryserver app github
//!   init`.
//! - In a second job, which runs none of the app's code, GitHub signs a
//!   statement for the image (an OIDC token): this repository, this
//!   branch, this workflow file, this commit, on a GitHub-hosted machine,
//!   about exactly this image. The job puts it on the registry under the
//!   tag dryserver-BRANCH.
//! - The coordinator asks the registry for that tag every minute (it
//!   dials out: no open port, no webhook), checks GitHub's signature and
//!   every claim, and only then points the app at the image. A newer
//!   proof replaces an older one, never the other way round.
//!
//! So only a push to the branch deploys. A pull request, another branch,
//! another repository, another workflow file, a self-hosted runner, or
//! anyone who can only write to the registry cannot. Whoever can push to
//! the branch can deploy: that is what "push to deploy" means, and why
//! the branch should be protected on GitHub.
//!
//! Nothing here holds a secret of the admin's but one GitHub token that
//! can only read packages, kept in the cluster for the servers to pull
//! the images with.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine;
use serde::Deserialize;

use crate::apps::Cluster;
use crate::ctx::Ctx;
use crate::err::Result;
use crate::runner::{Cmd, Runner};
use crate::{bail, errf, fsx};

pub const ISSUER: &str = "https://token.actions.githubusercontent.com";
const JWKS_URL: &str = "https://token.actions.githubusercontent.com/.well-known/jwks";
pub const REGISTRY: &str = "ghcr.io";
/// The workflow file in the app's repository. The proof names it: a
/// build by any other workflow does not count.
pub const WORKFLOW: &str = ".github/workflows/dryserver.yml";
/// The annotation of the proof on the registry's index.
pub const PROOF: &str = "dev.dryserver.proof";
pub const AUDIENCE: &str = "dryserver:";

// Annotations on an app's Deployment.
pub const A_REPO: &str = "dryserver/repo";
pub const A_BRANCH: &str = "dryserver/branch";
/// GitHub's number for the repository, taken from the first build: a
/// repository of the same name made later (after a rename or a delete)
/// is another one.
pub const A_REPO_ID: &str = "dryserver/repo-id";
/// The workflow run number of the running build: builds are ordered by
/// it (a re-run keeps its number, so it never counts as newer).
pub const A_RUN: &str = "dryserver/run";
pub const A_COMMIT: &str = "dryserver/commit";
/// No build of this run number or older is deployed (after a rollback,
/// or a build whose copies never started).
pub const A_HOLD: &str = "dryserver/hold";
/// The builds before, newest first: "run@digest@commit,...".
pub const A_HISTORY: &str = "dryserver/history";
/// The image the coordinator is rolling out now.
pub const A_ROLLING: &str = "dryserver/rolling";
/// What the coordinator last said about the app: "UNIX text".
pub const A_WATCH: &str = "dryserver/watch";
/// The cluster's copy of the token, for the servers to pull with.
pub const PULL_SECRET: &str = "dryserver-ghcr";
/// The coordinator's sign of life: a ConfigMap it writes when it looked.
pub const HEARTBEAT: &str = "dryserver-github";
/// Builds kept to go back to.
pub const HISTORY: usize = 5;

/// What builds an app: a repository and the branch whose pushes deploy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub owner: String,
    pub repo: String,
    pub branch: String,
}

/// A GitHub account or organization name.
pub fn valid_owner(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 39
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !s.starts_with('-')
        && !s.ends_with('-')
        && !s.contains("--")
}

pub fn valid_repo(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && s != "."
        && s != ".."
        && !s.to_ascii_lowercase().ends_with(".git")
}

/// A branch name as git takes it, kept to plain characters.
pub fn valid_branch(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 200
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
        && !s.starts_with(['-', '.', '/'])
        && !s.ends_with(['/', '.'])
        && !s.contains("..")
        && !s.contains("//")
        && !s.ends_with(".lock")
        && s != "HEAD"
}

impl Source {
    /// From what people write: github.com/OWNER/REPO, OWNER/REPO, the
    /// https or git@ address, with or without .git.
    pub fn parse(repo: &str, branch: &str) -> Result<Source> {
        let t = repo.trim();
        let t = t.strip_prefix("https://").or_else(|| t.strip_prefix("http://")).unwrap_or(t);
        let t = t.strip_prefix("git@github.com:").unwrap_or(t);
        let t = t.strip_prefix("github.com/").or_else(|| t.strip_prefix("www.github.com/")).unwrap_or(t);
        let t = t.trim_end_matches('/');
        let t = t.strip_suffix(".git").unwrap_or(t);
        let Some((owner, name)) = t.split_once('/') else {
            bail!("{repo}: a GitHub repository, like github.com/you/shop");
        };
        if t.contains("://") || !valid_owner(owner) || !valid_repo(name) {
            bail!("{repo}: a GitHub repository, like github.com/you/shop (only github.com)");
        }
        if !valid_branch(branch) {
            bail!("{branch}: a branch name, like main");
        }
        Ok(Source { owner: owner.into(), repo: name.into(), branch: branch.into() })
    }

    /// OWNER/REPO.
    pub fn full(&self) -> String {
        format!("{}/{}", self.owner, self.repo)
    }

    /// How the app file writes it.
    pub fn text(&self) -> String {
        format!("github.com/{}", self.full())
    }

    /// The image's name on the registry (lowercase, as ghcr.io has it).
    pub fn image(&self) -> String {
        format!("{REGISTRY}/{}", self.path())
    }

    fn path(&self) -> String {
        self.full().to_ascii_lowercase()
    }

    /// The registry tag of the branch's newest proof.
    pub fn tag(&self) -> String {
        tag_for(&self.branch)
    }
}

/// dryserver-BRANCH. A branch a tag cannot carry as it is (a / in it,
/// or too long) gets the start of its sha256 too, so two branches never
/// share a tag (feature/a and feature-a).
pub fn tag_for(branch: &str) -> String {
    let b: String = branch.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-') { c } else { '-' }).collect();
    if b == branch && b.len() <= 100 {
        return format!("dryserver-{b}");
    }
    use sha2::Digest;
    let h = fsx::hex(&sha2::Sha256::digest(branch.as_bytes()));
    format!("dryserver-{}-{}", &b[..b.len().min(80)], &h[..12])
}

/// A build GitHub proved.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Build {
    /// The image's digest, sha256:...
    pub digest: String,
    pub commit: String,
    /// The workflow run's number in the repository: one more for every
    /// run, the same for a re-run. Builds are ordered by it, so re-running
    /// an old run never brings its old version back.
    pub run: i64,
    /// When GitHub signed the proof (Unix seconds).
    pub iat: i64,
    pub repo_id: String,
    pub run_id: String,
    pub actor: String,
}

impl Build {
    pub fn short(&self) -> String {
        self.commit.chars().take(7).collect()
    }
}

pub fn valid_digest(s: &str) -> bool {
    s.strip_prefix("sha256:").is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

// ---- GitHub's proof ----

/// GitHub's signing keys (its JWKS), as JSON text. fresh: not from a
/// cache (a key the cache does not know yet).
pub trait Keys: Send + Sync {
    fn get(&self, ctx: &Ctx, fresh: bool) -> Result<String>;
}

/// Checks an RS256 signature: key (modulus, exponent), what was signed.
pub trait Rsa: Send + Sync {
    fn verify(&self, ctx: &Ctx, n: &[u8], e: &[u8], data: &[u8], sig: &[u8]) -> Result<()>;
}

fn b64u(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).map_err(|_| errf!("not base64url"))
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    kid: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Claims {
    iss: String,
    aud: serde_json::Value,
    repository: String,
    repository_id: String,
    #[serde(rename = "ref")]
    git_ref: String,
    ref_type: String,
    sha: String,
    workflow_ref: String,
    event_name: String,
    runner_environment: String,
    iat: i64,
    run_id: String,
    run_number: String,
    actor: String,
}

#[derive(Deserialize)]
struct Jwk {
    #[serde(default)]
    kid: String,
    #[serde(default)]
    kty: String,
    #[serde(default)]
    n: String,
    #[serde(default)]
    e: String,
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

/// The largest proof taken: GitHub's are about 1.5 KiB.
const MAX_PROOF: usize = 16 << 10;

/// Checks a proof for the image digest of src: GitHub's signature, then
/// every claim. pin: the repository's number from an earlier build.
pub fn check_proof(ctx: &Ctx, jwt: &str, keys: &dyn Keys, rsa: &dyn Rsa, src: &Source, digest: &str, pin: Option<&str>) -> Result<Build> {
    if jwt.len() > MAX_PROOF {
        bail!("the proof is larger than any GitHub signs");
    }
    if !valid_digest(digest) {
        bail!("the registry named no image digest");
    }
    let parts: Vec<&str> = jwt.trim().split('.').collect();
    let [h, p, s] = parts.as_slice() else { bail!("the proof is not a signed token") };
    let header: Header = serde_json::from_slice(&b64u(h)?).map_err(|_| errf!("the proof's header is not one"))?;
    let shown = |s: &str| s.chars().filter(|c| c.is_ascii_graphic()).take(40).collect::<String>();
    if header.alg != "RS256" {
        bail!("the proof is signed with {}, not RS256 as GitHub signs", shown(&header.alg));
    }
    if header.kid.is_empty() || header.kid.len() > 128 {
        bail!("the proof names no key");
    }
    let find = |text: &str| -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        let set: Jwks = serde_json::from_str(text).map_err(|_| errf!("GitHub's key list is not one"))?;
        Ok(match set.keys.iter().find(|k| k.kid == header.kid && k.kty == "RSA") {
            Some(k) => Some((b64u(&k.n)?, b64u(&k.e)?)),
            None => None,
        })
    };
    let key = match find(&keys.get(ctx, false)?)? {
        Some(k) => k,
        None => {
            find(&keys.get(ctx, true)?)?.ok_or_else(|| errf!("GitHub's key {} is not (any more) in its key list", shown(&header.kid)))?
        }
    };
    let n = key.0.iter().skip_while(|b| **b == 0).count();
    if !(256..=512).contains(&n) || key.1.is_empty() || key.1.len() > 8 {
        bail!("GitHub's key is not one dryserver takes");
    }
    let sig = b64u(s)?;
    let signed = format!("{h}.{p}");
    rsa.verify(ctx, &key.0, &key.1, signed.as_bytes(), &sig).map_err(|e| e.wrap("the proof is not signed by GitHub"))?;
    let c: Claims = serde_json::from_slice(&b64u(p)?).map_err(|_| errf!("the proof's claims are not readable"))?;
    let say = |what: &str, got: &str| {
        errf!("the proof is for {what} {}, not this app's", got.chars().filter(|c| !c.is_control()).take(120).collect::<String>())
    };
    if c.iss != ISSUER {
        return Err(say("the issuer", &c.iss));
    }
    let want_aud = format!("{AUDIENCE}{digest}");
    let aud_ok = match &c.aud {
        serde_json::Value::String(a) => *a == want_aud,
        serde_json::Value::Array(l) => l.iter().any(|a| a.as_str() == Some(&want_aud)),
        _ => false,
    };
    if !aud_ok {
        bail!("the proof is about another image than the one the registry names");
    }
    if !c.repository.eq_ignore_ascii_case(&src.full()) {
        return Err(say("the repository", &c.repository));
    }
    let branch_ref = format!("refs/heads/{}", src.branch);
    if c.git_ref != branch_ref || (!c.ref_type.is_empty() && c.ref_type != "branch") {
        return Err(say("the branch", &c.git_ref));
    }
    // OWNER/REPO/.github/workflows/dryserver.yml@refs/heads/BRANCH: the
    // repository in any case (GitHub's names are), the file exactly.
    let (wf_path, wf_ref) = c.workflow_ref.split_once('@').unwrap_or((&c.workflow_ref, ""));
    let prefix = format!("{}/", src.full());
    let ok_path = wf_path.len() > prefix.len()
        && wf_path.is_char_boundary(prefix.len())
        && wf_path[..prefix.len()].eq_ignore_ascii_case(&prefix)
        && &wf_path[prefix.len()..] == WORKFLOW;
    if !ok_path || wf_ref != branch_ref {
        return Err(say("the workflow", &c.workflow_ref));
    }
    // Only a push: a run started by hand, a re-run of an old one, or any
    // other event does not deploy.
    if c.event_name != "push" {
        return Err(say("an event", &c.event_name));
    }
    if c.runner_environment != "github-hosted" {
        return Err(say("a machine that is", &format!("{} (not GitHub's own)", c.runner_environment)));
    }
    if c.sha.len() != 40 || !c.sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("the proof names no commit");
    }
    if c.repository_id.is_empty() || c.repository_id.len() > 20 || !c.repository_id.bytes().all(|b| b.is_ascii_digit()) {
        bail!("the proof names no repository number");
    }
    if let Some(pin) = pin.filter(|p| !p.is_empty())
        && c.repository_id != pin
    {
        bail!(
            "the proof is from repository number {}, but this app's builds came from number {pin}: a repository of the same name made \
             anew is another one. If that is right, remove the app and deploy it again",
            c.repository_id
        );
    }
    if c.iat <= 0 {
        bail!("the proof has no time");
    }
    let run = c
        .run_number
        .parse::<i64>()
        .ok()
        .filter(|n| *n > 0 && c.run_number.len() <= 18)
        .ok_or_else(|| errf!("the proof names no run number"))?;
    let clean = |s: &str| s.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')).take(64).collect::<String>();
    Ok(Build {
        digest: digest.into(),
        commit: c.sha.to_ascii_lowercase(),
        run,
        iat: c.iat,
        repo_id: c.repository_id,
        run_id: clean(&c.run_id),
        actor: clean(&c.actor),
    })
}

/// GitHub's keys, fetched with curl and kept for a few hours in cache.
pub struct CurlKeys {
    pub run: Arc<dyn Runner>,
    pub cache: PathBuf,
}

/// How long a cached key list is used without asking GitHub.
const KEYS_FOR: std::time::Duration = std::time::Duration::from_secs(6 * 3600);

impl Keys for CurlKeys {
    fn get(&self, ctx: &Ctx, fresh: bool) -> Result<String> {
        let cached = std::fs::read_to_string(&self.cache).ok();
        let young =
            std::fs::metadata(&self.cache).and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).is_some_and(|a| a < KEYS_FOR);
        if !fresh
            && young
            && let Some(c) = &cached
        {
            return Ok(c.clone());
        }
        let got = curl(ctx, self.run.as_ref(), JWKS_URL, &[], None, 256 << 10).and_then(|(status, body)| {
            if status != 200 {
                bail!("GitHub's key list answered HTTP {status}");
            }
            serde_json::from_str::<Jwks>(&body).map_err(|_| errf!("GitHub's key list is not one"))?;
            Ok(body)
        });
        match got {
            Ok(body) => {
                if let Some(dir) = self.cache.parent() {
                    let _ = fsx::mkdir_all(dir, 0o700);
                }
                let tmp = self.cache.with_extension("tmp");
                let _ = std::fs::remove_file(&tmp);
                if fsx::write_new(&tmp, &body, 0o600).is_ok() {
                    let _ = fsx::rename(&tmp, &self.cache);
                }
                Ok(body)
            }
            // Offline: an older list still checks proofs made with its keys.
            Err(e) => cached.ok_or(e),
        }
    }
}

/// RS256 with the openssl program: the key as a PEM file, in a directory
/// of this process alone, gone afterwards.
pub struct Openssl {
    pub run: Arc<dyn Runner>,
    pub tmp: PathBuf,
}

fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let bytes: Vec<u8> = n.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
    let mut v = vec![0x80 | bytes.len() as u8];
    v.extend(bytes);
    v
}

fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    v.extend(der_len(body.len()));
    v.extend_from_slice(body);
    v
}

fn der_uint(b: &[u8]) -> Vec<u8> {
    let mut b: Vec<u8> = b.iter().copied().skip_while(|x| *x == 0).collect();
    if b.is_empty() || b[0] & 0x80 != 0 {
        b.insert(0, 0);
    }
    der(0x02, &b)
}

/// The PEM of an RSA public key (SubjectPublicKeyInfo).
pub fn rsa_pem(n: &[u8], e: &[u8]) -> String {
    let rsa = der(0x30, &[der_uint(n), der_uint(e)].concat());
    // rsaEncryption, NULL
    let alg = der(0x30, &[der(0x06, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]), vec![0x05, 0x00]].concat());
    let spki = der(0x30, &[alg, der(0x03, &[vec![0], rsa].concat())].concat());
    let b64 = base64::engine::general_purpose::STANDARD.encode(spki);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem + "-----END PUBLIC KEY-----\n"
}

impl Rsa for Openssl {
    fn verify(&self, ctx: &Ctx, n: &[u8], e: &[u8], data: &[u8], sig: &[u8]) -> Result<()> {
        fsx::mkdir_all(&self.tmp, 0o700)?;
        let dir = self.tmp.join(format!("proof-{}", fsx::hex(&fsx::random_bytes(8))));
        fsx::mkdir_all(&dir, 0o700)?;
        let res = (|| {
            fsx::write_new(dir.join("key.pem"), rsa_pem(n, e), 0o600)?;
            fsx::write_new(dir.join("data"), data, 0o600)?;
            fsx::write_new(dir.join("sig"), sig, 0o600)?;
            let p = |f: &str| dir.join(f).display().to_string();
            let out = self
                .run
                .output(
                    ctx,
                    &Cmd::new("openssl", &["dgst", "-sha256", "-verify", &p("key.pem"), "-signature", &p("sig"), &p("data")]).quiet(),
                )
                .map_err(|e| if e.to_string().contains("not found") { errf!("openssl is not installed here") } else { e })?;
            if out.trim() == "Verified OK" { Ok(()) } else { Err(errf!("the signature does not check out")) }
        })();
        let _ = std::fs::remove_dir_all(&dir);
        res.map_err(|_| errf!("the signature does not check out"))
    }
}

// ---- the registry ----

/// What the registry holds for a branch: the image and its proof.
#[derive(Debug, Clone, PartialEq)]
pub struct Found {
    pub digest: String,
    pub proof: String,
}

pub trait Registry: Send + Sync {
    /// The newest build of src's branch: None when there is none yet.
    fn proof(&self, ctx: &Ctx, src: &Source) -> Result<Option<Found>>;
}

/// A value for curl's config, quoted. Nothing with a line break or any
/// other control character in it: one would start another option (an
/// output file, say), and curl runs as root on the coordinator.
fn curl_quoted(s: &str) -> Result<String> {
    if s.chars().any(|c| c.is_control()) {
        bail!("a value for curl with a control character in it; not sent");
    }
    Ok(format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")))
}

/// A bearer token as a registry gives it: base64 and dots. Anything else
/// (a line break that would start another curl option) is not taken.
fn valid_bearer(t: &str) -> bool {
    !t.is_empty() && t.len() <= 8192 && t.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~+/=".contains(&b))
}

/// One HTTPS request with curl, everything (the token too) on its stdin:
/// nothing secret in a command line other users of the machine can read.
fn curl(ctx: &Ctx, run: &dyn Runner, url: &str, headers: &[String], user: Option<&str>, max: usize) -> Result<(u16, String)> {
    let q = curl_quoted;
    let mut c = format!("url = {}\n", q(url)?);
    for h in headers {
        c += &format!("header = {}\n", q(h)?);
    }
    if let Some(u) = user {
        c += &format!("user = {}\n", q(u)?);
    }
    c += &format!(
        "proto = \"=https\"\nproto-redir = \"=https\"\nmax-time = \"20\"\nconnect-timeout = \"10\"\nmax-filesize = \"{max}\"\nwrite-out = \"\\n%{{http_code}}\"\nlocation\ntlsv1.2\nsilent\nshow-error\n"
    );
    let (out, res) = run.run(ctx, &Cmd::new("curl", &["-q", "--config", "-"]).stdin(c).quiet().stdout_only());
    if let Err(e) = res {
        if let Some(why) = ctx.err() {
            return Err(why);
        }
        let host = url.split('/').nth(2).unwrap_or("GitHub");
        let msg = e.to_string();
        bail!("no answer from {host}{}", if msg.contains("exit status 28") { " in time" } else { "" });
    }
    if out.len() > max + 16 {
        bail!("the answer is larger than any expected");
    }
    let (body, code) = out.rsplit_once('\n').unwrap_or(("", out.as_str()));
    let status: u16 = code.trim().parse().map_err(|_| errf!("no HTTP status"))?;
    Ok((status, body.to_string()))
}

/// GitHub's registry, read with a token that can read packages.
pub struct Ghcr {
    pub token: String,
    pub run: Arc<dyn Runner>,
}

impl Registry for Ghcr {
    fn proof(&self, ctx: &Ctx, src: &Source) -> Result<Option<Found>> {
        let path = src.path();
        let (status, body) = curl(
            ctx,
            self.run.as_ref(),
            &format!("https://{REGISTRY}/token?service={REGISTRY}&scope=repository:{path}:pull"),
            &[],
            Some(&format!("dryserver:{}", self.token)),
            64 << 10,
        )?;
        match status {
            200 => {}
            401 | 403 => bail!("the GitHub token cannot read {} (it needs read:packages, and access to that package)", src.image()),
            429 => bail!("GitHub asks to slow down; it is asked again in a few minutes"),
            s => bail!("GitHub's registry answered HTTP {s}"),
        }
        #[derive(Deserialize)]
        struct Tok {
            token: String,
        }
        let t: Tok = serde_json::from_str(&body).map_err(|_| errf!("GitHub's registry gave no token"))?;
        if !valid_bearer(&t.token) {
            bail!("GitHub's registry gave a token that is not one");
        }
        let (status, body) = curl(
            ctx,
            self.run.as_ref(),
            &format!("https://{REGISTRY}/v2/{path}/manifests/{}", src.tag()),
            &[
                format!("Authorization: Bearer {}", t.token),
                "Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json".into(),
            ],
            None,
            1 << 20,
        )?;
        match status {
            200 => {}
            404 => return Ok(None),
            401 | 403 => bail!("the GitHub token cannot read {} (it needs read:packages, and access to that package)", src.image()),
            s => bail!("GitHub's registry answered HTTP {s}"),
        }
        let v: serde_json::Value =
            serde_json::from_str(&body).map_err(|_| errf!("the registry's answer about {} is not one", src.tag()))?;
        found(&v)
    }
}

/// The image and the proof in a registry index.
pub fn found(v: &serde_json::Value) -> Result<Option<Found>> {
    let proof = v["annotations"][PROOF]
        .as_str()
        .ok_or_else(|| errf!("the newest build carries no proof (was it made by dryserver's workflow?)"))?;
    let list = v["manifests"].as_array().cloned().unwrap_or_default();
    // The image for these machines: linux/amd64, or the only one.
    let pick = list
        .iter()
        .find(|m| m["platform"]["os"] == "linux" && m["platform"]["architecture"] == "amd64")
        .or_else(|| if list.len() == 1 { list.first() } else { None })
        .ok_or_else(|| errf!("the newest build has no image for these machines (linux/amd64)"))?;
    let digest = pick["digest"].as_str().filter(|d| valid_digest(d)).ok_or_else(|| errf!("the newest build names no image digest"))?;
    Ok(Some(Found { digest: digest.into(), proof: proof.into() }))
}

/// The newest proved build of src, if any.
pub fn newest(ctx: &Ctx, reg: &dyn Registry, keys: &dyn Keys, rsa: &dyn Rsa, src: &Source, pin: Option<&str>) -> Result<Option<Build>> {
    let Some(f) = reg.proof(ctx, src)? else { return Ok(None) };
    check_proof(ctx, &f.proof, keys, rsa, src, &f.digest, pin).map(Some)
}

// ---- the token in the cluster ----

/// How the pull secret is applied: on the cluster's side, so kubectl
/// keeps no copy of it (with the token) in an annotation.
pub const PULL_APPLY: [&str; 6] = ["apply", "--server-side", "--force-conflicts", "--field-manager=dryserver", "-f", "-"];

/// The Secret the servers pull the images with: a docker config for
/// ghcr.io. The token is in it, so it goes to kubectl on stdin only.
pub fn pull_secret(token: &str) -> String {
    let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
    let auth = b64(&format!("dryserver:{token}"));
    let config = serde_json::json!({"auths": {REGISTRY: {"username": "dryserver", "password": token, "auth": auth}}}).to_string();
    format!(
        "{}---\napiVersion: v1\nkind: Secret\nmetadata:\n  name: {PULL_SECRET}\n  namespace: {}\ntype: kubernetes.io/dockerconfigjson\ndata:\n  .dockerconfigjson: {}\n",
        crate::apps::namespace_yaml(),
        crate::apps::NAMESPACE,
        b64(&config)
    )
}

/// The token in the cluster's Secret (kubectl's JSON of it).
pub fn token_in(secret_json: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(secret_json).ok()?;
    let raw = base64::engine::general_purpose::STANDARD.decode(v["data"][".dockerconfigjson"].as_str()?).ok()?;
    let c: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    let t = c["auths"][REGISTRY]["password"].as_str()?;
    valid_token(t).is_ok().then(|| t.to_string())
}

/// A GitHub token as it is written: plain characters, no spaces.
pub fn valid_token(t: &str) -> Result<()> {
    if t.starts_with("github_pat_") {
        bail!(
            "that is a fine-grained token, and GitHub's registry takes only classic tokens: make a classic token (Settings, Developer \
             settings, Personal access tokens, Tokens (classic)) with only read:packages"
        );
    }
    if t.len() < 20 || t.len() > 255 || !t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        bail!("that does not look like a GitHub token (ghp_...)");
    }
    Ok(())
}

// ---- the workflow ----

/// Railpack, which builds an app without a Dockerfile: one release, its
/// file's sha256 (as GitHub publishes it) and its BuildKit frontend by
/// digest. A newer one comes with a newer dryserver.
pub const RAILPACK: &str = "0.43.0";
pub const RAILPACK_SHA256: &str = "248a8f60f36854aabed6124113631078a802de3461660855fc4de9c26065c1fb";
pub const RAILPACK_FRONTEND: &str =
    "ghcr.io/railwayapp/railpack-frontend:v0.43.0@sha256:355ef61fae6f2551103cd8b10c710cb07167dd353d561f15c69b8d7ac1c676cc";
/// BuildKit for the build job's builder, by digest.
pub const BUILDKIT: &str = "moby/buildkit:v0.35.0@sha256:aa632b921ef07411d2cb77292cd34213d4f7b384001d6fceef1e1f25bf9752bb";
/// Actions, by commit (a tag can be moved).
const CHECKOUT: &str = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"; // v7.0.1
const BUILDX: &str = "docker/setup-buildx-action@f87e5991a6d7451dcb8d9637bfbc97413f497069"; // v4.4.1

/// The workflow: builds on every push to branch.
pub fn workflow(branch: &str) -> String {
    let tag = tag_for(branch);
    format!(
        r#"# dryserver: builds this app on every push to {branch} and proves to your
# coordinator that the image came from here. Written by
# `dryserver app github init`; dryserver checks its name and the branch
# in GitHub's proof, so keep the file where it is.
name: dryserver
# Only a push builds a version that deploys: to build again, push (an
# empty commit is fine: git commit --allow-empty -m rebuild).
on:
  push:
    branches: ["{branch}"]
permissions: {{}}
# One run at a time per branch; a push to another branch waits for none.
concurrency:
  group: dryserver-${{{{ github.ref }}}}
  cancel-in-progress: false
jobs:
  build:
    # Runs the app's own build (its packages' scripts too). It cannot ask
    # GitHub for a proof; it hands the next job one image digest, which is
    # proved as it is. (What runs here decides what the image is anyway.)
    if: github.ref == 'refs/heads/{branch}'
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    permissions:
      contents: read
      packages: write
    outputs:
      digest: ${{{{ steps.build.outputs.digest }}}}
    steps:
      - uses: {CHECKOUT}
        with:
          persist-credentials: false
      - uses: {BUILDX}
        with:
          driver-opts: image={BUILDKIT}
      - name: Log in to GitHub's registry
        run: echo "$TOKEN" | docker login {REGISTRY} -u "$GITHUB_ACTOR" --password-stdin
        env:
          TOKEN: ${{{{ secrets.GITHUB_TOKEN }}}}
      - name: Build and push (its Dockerfile, or Railpack without one)
        id: build
        run: |
          set -euo pipefail
          image="{REGISTRY}/${{GITHUB_REPOSITORY,,}}"
          if [ -f Dockerfile ]; then
            docker buildx build --platform linux/amd64 --provenance=false --push \
              --tag "$image:sha-$GITHUB_SHA" --metadata-file meta.json .
          else
            curl -fsSL -o railpack.tgz \
              "https://github.com/railwayapp/railpack/releases/download/v{RAILPACK}/railpack-v{RAILPACK}-x86_64-unknown-linux-musl.tar.gz"
            echo "{RAILPACK_SHA256}  railpack.tgz" | sha256sum -c -
            tar -xzf railpack.tgz railpack
            ./railpack prepare . --plan-out "$RUNNER_TEMP/railpack-plan.json"
            docker buildx build --platform linux/amd64 --provenance=false --push \
              --build-arg BUILDKIT_SYNTAX="{RAILPACK_FRONTEND}" \
              -f "$RUNNER_TEMP/railpack-plan.json" \
              --tag "$image:sha-$GITHUB_SHA" --metadata-file meta.json .
          fi
          digest="$(jq -r '."containerimage.digest"' meta.json)"
          [[ "$digest" =~ ^sha256:[0-9a-f]{{64}}$ ]] || {{ echo "no image digest" >&2; exit 1; }}
          echo "digest=$digest" >> "$GITHUB_OUTPUT"
  prove:
    # Runs none of the app's code: asks GitHub to sign that this image was
    # built here, and puts the proof next to it.
    needs: build
    if: github.ref == 'refs/heads/{branch}'
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    permissions:
      packages: write
      id-token: write
    steps:
      # No builder here: the runner's own docker writes the index.
      - name: Prove and publish
        env:
          DIGEST: ${{{{ needs.build.outputs.digest }}}}
          TOKEN: ${{{{ secrets.GITHUB_TOKEN }}}}
        run: |
          set -euo pipefail
          # Exactly one image digest, or nothing is proved.
          [[ "$DIGEST" =~ ^sha256:[0-9a-f]{{64}}$ ]] || {{ echo "no image digest" >&2; exit 1; }}
          echo "$TOKEN" | docker login {REGISTRY} -u "$GITHUB_ACTOR" --password-stdin
          image="{REGISTRY}/${{GITHUB_REPOSITORY,,}}"
          proof="$(curl -fsS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=dryserver%3A${{DIGEST/:/%3A}}" | jq -r .value)"
          docker buildx imagetools create \
            --annotation "index:{PROOF}=$proof" \
            --tag "$image:{tag}" "$image@$DIGEST"
"#
    )
}

// ---- the coordinator's watch ----

/// kubectl on the coordinator itself, as root.
pub struct LocalKubectl {
    pub run: Arc<dyn Runner>,
}

impl Cluster for LocalKubectl {
    fn kubectl(&self, ctx: &Ctx, args: &[&str], stdin: &str) -> Result<String> {
        let mut a = vec!["kubectl", "--request-timeout=30s"];
        a.extend_from_slice(args);
        self.run.output(ctx, &Cmd::new("/usr/local/bin/k3s", &a).stdin(stdin).quiet().stdout_only())
    }
}

/// What a Deployment of an app built by GitHub says about its builds.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct State {
    pub source: Option<Source>,
    pub repo_id: String,
    pub run: i64,
    pub commit: String,
    pub hold: i64,
    /// (run, digest, commit), newest first.
    pub history: Vec<(i64, String, String)>,
    pub rolling: String,
    /// When the coordinator last said something, and what.
    pub watch: Option<(i64, String)>,
}

/// The state from a Deployment's annotations; only what checks out.
pub fn state_of(annotations: &serde_json::Value) -> State {
    let a = |k: &str| annotations[k].as_str().unwrap_or("").to_string();
    let num = |k: &str| a(k).parse::<i64>().ok().filter(|n| *n >= 0).unwrap_or(0);
    let source = Source::parse(&a(A_REPO), &a(A_BRANCH)).ok().filter(|_| !a(A_REPO).is_empty());
    let hex = |s: &str| s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit());
    let history = a(A_HISTORY)
        .split(',')
        .filter_map(|e| {
            let mut p = e.split('@');
            let (t, d, c) = (p.next()?.parse().ok()?, p.next()?, p.next()?);
            (valid_digest(&format!("sha256:{d}")) && hex(c)).then(|| (t, format!("sha256:{d}"), c.to_string()))
        })
        .take(HISTORY)
        .collect();
    let watch =
        a(A_WATCH).split_once(' ').and_then(|(t, s)| Some((t.parse().ok()?, s.chars().filter(|c| !c.is_control()).take(300).collect())));
    State {
        source,
        repo_id: Some(a(A_REPO_ID)).filter(|r| !r.is_empty() && r.len() <= 20 && r.bytes().all(|b| b.is_ascii_digit())).unwrap_or_default(),
        run: num(A_RUN),
        commit: Some(a(A_COMMIT)).filter(|c| hex(c)).unwrap_or_default(),
        hold: num(A_HOLD),
        history,
        rolling: Some(a(A_ROLLING)).filter(|d| valid_digest(d)).unwrap_or_default(),
        watch,
    }
}

/// The history once another build replaces the running one: the running
/// one first, at most HISTORY.
pub fn history_after(st: &State, running_digest: &str) -> Vec<(i64, String, String)> {
    let mut h: Vec<(i64, String, String)> = Vec::new();
    // Only a build that ran: not one still starting (never seen to run),
    // not one held back (it did not start). A rollback goes to one that
    // ran.
    let ran = st.rolling.is_empty() && st.run > st.hold;
    if ran && st.run > 0 && valid_digest(running_digest) && !st.commit.is_empty() {
        h.push((st.run, running_digest.to_string(), st.commit.clone()));
    }
    for e in &st.history {
        if h.len() < HISTORY && !h.iter().any(|x| x.1 == e.1) {
            h.push(e.clone());
        }
    }
    h
}

/// The history as its annotation has it.
pub fn history_text(st: &State, running_digest: &str) -> String {
    history_after(st, running_digest)
        .iter()
        .map(|(t, d, c)| format!("{t}@{}@{c}", d.trim_start_matches("sha256:")))
        .collect::<Vec<_>>()
        .join(",")
}

/// Who a token is and what it may do: GitHub's answer about it.
pub fn token_info(ctx: &Ctx, run: &dyn Runner, token: &str) -> Result<(String, Vec<String>)> {
    let q = |s: &str| curl_quoted(s).unwrap_or_default();
    let c = format!(
        "url = \"https://api.github.com/user\"\nheader = {}\nheader = \"Accept: application/vnd.github+json\"\nheader = \"User-Agent: dryserver\"\nproto = \"=https\"\nmax-time = \"20\"\ninclude\nwrite-out = \"\\n%{{http_code}}\"\ntlsv1.2\nsilent\nshow-error\n",
        q(&format!("Authorization: Bearer {token}"))
    );
    let (out, res) = run.run(ctx, &Cmd::new("curl", &["-q", "--config", "-"]).stdin(c).quiet().stdout_only());
    res.map_err(|_| errf!("no answer from api.github.com (is this computer online?)"))?;
    let (rest, code) = out.rsplit_once('\n').unwrap_or(("", &out));
    match code.trim() {
        "200" => {}
        "401" => bail!("GitHub does not know that token (a typo, or it expired or was revoked)"),
        s => bail!("GitHub answered HTTP {s} about the token"),
    }
    let (head, body) = rest.split_once("\r\n\r\n").or_else(|| rest.split_once("\n\n")).unwrap_or((rest, ""));
    let scopes: Vec<String> = head
        .lines()
        .find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("x-oauth-scopes")).map(|(_, v)| v.to_string()))
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let login =
        serde_json::from_str::<serde_json::Value>(body.trim()).ok().and_then(|v| v["login"].as_str().map(String::from)).unwrap_or_default();
    Ok((login.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').take(39).collect(), scopes))
}

/// How long one app's look at GitHub may take, and all of the watch in
/// one minute's sync.
const PER_APP: std::time::Duration = std::time::Duration::from_secs(8);
pub const BUDGET: std::time::Duration = std::time::Duration::from_secs(20);

/// One app the watch looks at.
struct Watched {
    name: String,
    st: State,
    src: Source,
    /// The digest its copies run now ("" when not one of GitHub's).
    running: String,
    d: serde_json::Value,
}

/// Notes on an app what the coordinator found, when it is news.
fn say(ctx: &Ctx, c: &dyn Cluster, a: &Watched, now: i64, text: &str, log: &mut Vec<String>) {
    if a.st.watch.as_ref().is_some_and(|(_, w)| w == text) {
        return;
    }
    let patch = serde_json::json!({"metadata": {"annotations": {A_WATCH: format!("{now} {text}")}}}).to_string();
    if let Err(e) = c.kubectl(
        ctx,
        &["-n", crate::apps::NAMESPACE, "patch", "deployment", &a.name, "--type", "merge", "--patch-file", "/dev/stdin"],
        &patch,
    ) {
        log.push(format!("github: {}: the note was not written: {e}", a.name));
    }
    log.push(format!("github: {}: {text}", a.name));
}

/// A rollout the coordinator follows: true when something was changed now
/// (taken back, or done), so the app is left alone for the rest of this
/// minute and the next one starts from what the cluster says then.
fn follow_rollout(ctx: &Ctx, c: &dyn Cluster, a: &Watched, now: i64, log: &mut Vec<String>) -> bool {
    let ns = crate::apps::NAMESPACE;
    let d = &a.d;
    let s = &d["status"];
    // Only what the cluster says about this very version counts.
    let current = matches!((s["observedGeneration"].as_i64(), d["metadata"]["generation"].as_i64()), (Some(o), Some(g)) if o >= g);
    let want = d["spec"]["replicas"].as_i64().unwrap_or(1);
    let failed = current
        && s["conditions"]
            .as_array()
            .is_some_and(|cs| cs.iter().any(|c| c["type"] == "Progressing" && c["reason"] == "ProgressDeadlineExceeded"));
    let done = current
        && s["updatedReplicas"].as_i64().unwrap_or(0) >= want
        && s["availableReplicas"].as_i64().unwrap_or(0) >= want
        && s["replicas"].as_i64().unwrap_or(0) <= want;
    let commit = a.st.commit.get(..7).unwrap_or("?").to_string();
    if failed {
        // Back to the build before, by its image: the settings stay as
        // they are now. This build and every older one are not tried again.
        let hold = a.st.hold.max(a.st.run).to_string();
        let res = match a.st.history.first() {
            Some((run, digest, prev)) => {
                let rest: Vec<String> =
                    a.st.history.iter().skip(1).map(|(t, d, c)| format!("{t}@{}@{c}", d.trim_start_matches("sha256:"))).collect();
                // Only onto the Deployment as listed: changed since (a
                // deploy from the desktop), the cluster refuses, and the
                // next minute looks again.
                let patch = serde_json::json!({
                    "metadata": {"resourceVersion": d["metadata"]["resourceVersion"], "annotations": {
                        A_RUN: run.to_string(), A_COMMIT: prev, A_HISTORY: rest.join(","), A_HOLD: hold, A_ROLLING: null,
                    }},
                    "spec": {"template": {"spec": {"containers": [{"name": a.name, "image": format!("{}@{digest}", a.src.image())}]}}}
                })
                .to_string();
                c.kubectl(ctx, &["-n", ns, "patch", "deployment", &a.name, "--type", "strategic", "--patch-file", "/dev/stdin"], &patch)
                    .map(|_| format!("back on {}", &prev[..7]))
            }
            // Its first build: nothing of GitHub's to go back to. The old
            // copies (if any) keep running; it is held back.
            None => {
                let patch = serde_json::json!({"metadata": {"annotations": {A_HOLD: hold, A_ROLLING: null}}}).to_string();
                c.kubectl(ctx, &["-n", ns, "patch", "deployment", &a.name, "--type", "merge", "--patch-file", "/dev/stdin"], &patch)
                    .map(|_| "no build before it to go back to".to_string())
            }
        };
        match res {
            Ok(back) => {
                say(ctx, c, a, now, &format!("build {commit} did not start (its copies never answered within 10 minutes); {back}"), log)
            }
            Err(e) => log.push(format!("github: {}: build {commit} did not start, and was not taken back yet: {e}", a.name)),
        }
        return true;
    }
    if done {
        let patch = serde_json::json!({"metadata": {"annotations": {A_ROLLING: null}}}).to_string();
        match c.kubectl(ctx, &["-n", ns, "patch", "deployment", &a.name, "--type", "merge", "--patch-file", "/dev/stdin"], &patch) {
            Ok(_) => say(ctx, c, a, now, &format!("running build {commit}"), log),
            Err(e) => log.push(format!("github: {}: {e}", a.name)),
        }
        return true;
    }
    false
}

/// One look at every app built by GitHub: follows rollouts (and takes
/// back a build whose copies never started), then deploys newer proved
/// builds, each app within PER_APP, starting each minute at another app
/// so a slow GitHub never leaves the same ones out. Notes on each app
/// what it found. make: a registry for a token.
pub fn watch(
    ctx: &Ctx,
    c: &dyn Cluster,
    make: &dyn Fn(String) -> Box<dyn Registry>,
    keys: &dyn Keys,
    rsa: &dyn Rsa,
    now: i64,
    turn: u64,
) -> Result<Vec<String>> {
    let ns = crate::apps::NAMESPACE;
    let mut log = Vec::new();
    let out = c.kubectl(ctx, &["-n", ns, "get", "deployments", "-o", "json"], "")?;
    // A sign of life for the desktop: this coordinator follows GitHub
    // (before any app is, so the first deploy knows; the namespace too).
    let beat = format!(
        "{}---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {HEARTBEAT}\n  namespace: {ns}\ndata:\n  last: \"{now}\"\n",
        crate::apps::namespace_yaml()
    );
    if let Err(e) = c.kubectl(ctx, &["apply", "-f", "-"], &beat) {
        log.push(format!("github: the sign of life was not written: {e}"));
    }
    let list: serde_json::Value = serde_json::from_str(&out).map_err(|_| errf!("the cluster's list of apps is not one"))?;
    let mut apps = Vec::new();
    for d in list["items"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|d| d["metadata"]["annotations"][A_REPO].is_string())
        .take(200)
    {
        let name = d["metadata"]["name"].as_str().unwrap_or("").to_string();
        if crate::apps::valid_app_name(&name).is_err() {
            continue;
        }
        // Set up by a newer dryserver: this one would read it wrong.
        let format = d["metadata"]["annotations"][crate::apps::FORMAT_ANNOTATION].as_str().unwrap_or("");
        if format.parse::<u32>().map_or(!format.is_empty(), |f| f > crate::apps::FORMAT) {
            log.push(format!("github: {name}: set up by a newer dryserver; left alone"));
            continue;
        }
        let st = state_of(&d["metadata"]["annotations"]);
        let Some(src) = st.source.clone() else { continue };
        let image = d["spec"]["template"]["spec"]["containers"][0]["image"].as_str().unwrap_or("");
        let running = image.strip_prefix(&format!("{}@", src.image())).filter(|dg| valid_digest(dg)).map(String::from).unwrap_or_default();
        apps.push(Watched { name, st, src, running, d });
    }
    if apps.is_empty() {
        return Ok(log);
    }
    // First, without the network: the rollouts under way.
    let mut left_alone = std::collections::BTreeSet::new();
    for a in apps.iter().filter(|a| !a.st.rolling.is_empty()) {
        if follow_rollout(ctx, c, a, now, &mut log) {
            left_alone.insert(a.name.clone());
        }
    }
    let token = match c.kubectl(ctx, &["-n", ns, "get", "secret", PULL_SECRET, "-o", "json", "--ignore-not-found"], "") {
        Ok(j) if j.trim().is_empty() => Err("no GitHub token in the cluster: dryserver app github token".to_string()),
        Ok(j) => token_in(&j).ok_or_else(|| "the GitHub token in the cluster is not one: dryserver app github token".to_string()),
        Err(e) => Err(format!("the GitHub token in the cluster could not be read ({e})")),
    };
    let n = apps.len();
    let start = usize::try_from(turn % n as u64).unwrap_or(0);
    for i in 0..n {
        let a = &apps[(start + i) % n];
        if left_alone.contains(&a.name) {
            continue;
        }
        if ctx.done() {
            log.push(format!("github: no time left this minute for {} more app(s); next minute starts with them", n - i));
            break;
        }
        let token = match &token {
            Ok(t) => t.clone(),
            Err(why) => {
                say(ctx, c, a, now, why, &mut log);
                continue;
            }
        };
        let reg = make(token);
        let pin = Some(a.st.repo_id.as_str()).filter(|p| !p.is_empty());
        let b = match newest(&ctx.with_timeout(PER_APP), reg.as_ref(), keys, rsa, &a.src, pin) {
            Ok(Some(b)) => b,
            Ok(None) if a.st.run > 0 => {
                say(
                    ctx,
                    c,
                    a,
                    now,
                    &format!("the registry has no build of {} (deleted?); the running build stays", a.src.branch),
                    &mut log,
                );
                continue;
            }
            Ok(None) => {
                say(ctx, c, a, now, &format!("no build of {} yet", a.src.branch), &mut log);
                continue;
            }
            Err(e) => {
                say(ctx, c, a, now, &format!("newest build not taken: {e}"), &mut log);
                continue;
            }
        };
        if b.run <= a.st.run || b.run <= a.st.hold || b.digest == a.running {
            // Nothing newer. What it said about a build that did not start
            // stays until another build comes.
            let failed_note = a.st.watch.as_ref().is_some_and(|(_, w)| w.contains("did not start"));
            if a.st.rolling.is_empty() && !failed_note {
                say(ctx, c, a, now, &format!("running build {}", a.st.commit.get(..7).unwrap_or(&b.short())), &mut log);
            }
            continue;
        }
        // Only onto the Deployment as listed (see follow_rollout).
        let patch = serde_json::json!({
            "metadata": {"resourceVersion": a.d["metadata"]["resourceVersion"], "annotations": {
                A_RUN: b.run.to_string(),
                A_COMMIT: b.commit,
                A_REPO_ID: b.repo_id,
                A_HISTORY: history_text(&a.st, &a.running),
                A_ROLLING: b.digest,
            }},
            "spec": {"template": {"spec": {"containers": [{"name": a.name, "image": format!("{}@{}", a.src.image(), b.digest)}]}}}
        })
        .to_string();
        match c.kubectl(ctx, &["-n", ns, "patch", "deployment", &a.name, "--type", "strategic", "--patch-file", "/dev/stdin"], &patch) {
            Ok(_) => say(ctx, c, a, now, &format!("deploying build {} of {}", b.short(), a.src.branch), &mut log),
            Err(e) => say(ctx, c, a, now, &format!("build {} not deployed: {e}", b.short()), &mut log),
        }
    }
    Ok(log)
}

/// On the coordinator, from its sync: the watch with curl and openssl.
/// A run that fails is said in the sync's log; the apps keep running.
pub fn run_on_coordinator(ctx: &Ctx, run: Arc<dyn Runner>, state_dir: &Path, tmp: &Path) {
    let c = LocalKubectl { run: run.clone() };
    let keys = CurlKeys { run: run.clone(), cache: state_dir.join("github-keys.json") };
    let rsa = Openssl { run: run.clone(), tmp: tmp.to_path_buf() };
    let make = |token: String| -> Box<dyn Registry> { Box::new(Ghcr { token, run: run.clone() }) };
    // Which app goes first: one on each time (the timer's minutes are
    // not exact, so not from the clock).
    let turn_file = state_dir.join("github-turn");
    let turn = std::fs::read_to_string(&turn_file).ok().and_then(|t| t.trim().parse::<u64>().ok()).unwrap_or(0);
    if crate::fsx::mkdir_all(state_dir, 0o700).is_ok() {
        let tmp = turn_file.with_extension("tmp");
        let _ = std::fs::remove_file(&tmp);
        if crate::fsx::write_new(&tmp, format!("{}\n", turn.wrapping_add(1)), 0o600).is_ok() {
            let _ = crate::fsx::rename(&tmp, &turn_file);
        }
    }
    match watch(ctx, &c, &make, &keys, &rsa, chrono::Utc::now().timestamp(), turn) {
        Ok(lines) => {
            for l in lines {
                eprintln!("dryserver: {l}");
            }
        }
        Err(e) => eprintln!("dryserver: github: {e}"),
    }
}

#[cfg(test)]
pub mod tests;
