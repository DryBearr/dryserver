use std::process::Command;
use std::sync::Mutex;

use super::*;
use crate::apps::tests::Fake;
use crate::runner::ExecRunner;
use crate::testutil::TempDir;

pub const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub const DIGEST2: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
pub const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

fn src() -> Source {
    Source::parse("github.com/You/Shop", "main").unwrap()
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// The claims GitHub puts in a proof of src's build of DIGEST.
pub fn claims() -> serde_json::Value {
    serde_json::json!({
        "iss": ISSUER,
        "aud": format!("{AUDIENCE}{DIGEST}"),
        "repository": "You/Shop",
        "repository_id": "123456",
        "ref": "refs/heads/main",
        "ref_type": "branch",
        "sha": SHA,
        "workflow_ref": "You/Shop/.github/workflows/dryserver.yml@refs/heads/main",
        "event_name": "push",
        "runner_environment": "github-hosted",
        "iat": 1000,
        "run_id": "777",
        "run_number": "10",
        "actor": "you"
    })
}

/// A real RSA key, made by openssl, and GitHub's key list with it.
struct Signer {
    dir: TempDir,
}

impl Signer {
    fn new() -> Signer {
        let dir = TempDir::new();
        let ok = Command::new("openssl")
            .args(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out"])
            .arg(dir.join("key.pem"))
            .output()
            .unwrap();
        assert!(ok.status.success(), "openssl genpkey: {}", String::from_utf8_lossy(&ok.stderr));
        Signer { dir }
    }

    fn jwks(&self, kid: &str) -> String {
        let out = Command::new("openssl").args(["rsa", "-noout", "-modulus", "-in"]).arg(self.dir.join("key.pem")).output().unwrap();
        let hex = String::from_utf8_lossy(&out.stdout).trim().trim_start_matches("Modulus=").to_string();
        let n: Vec<u8> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
        serde_json::json!({"keys": [{"kid": kid, "kty": "RSA", "alg": "RS256", "use": "sig", "n": b64(&n), "e": "AQAB"}]}).to_string()
    }

    fn sign(&self, header: &serde_json::Value, claims: &serde_json::Value) -> String {
        let signed = format!("{}.{}", b64(header.to_string().as_bytes()), b64(claims.to_string().as_bytes()));
        std::fs::write(self.dir.join("data"), &signed).unwrap();
        let out = Command::new("openssl")
            .args(["dgst", "-sha256", "-sign"])
            .arg(self.dir.join("key.pem"))
            .arg("-out")
            .arg(self.dir.join("sig"))
            .arg(self.dir.join("data"))
            .output()
            .unwrap();
        assert!(out.status.success());
        format!("{signed}.{}", b64(&std::fs::read(self.dir.join("sig")).unwrap()))
    }

    fn proof(&self, claims: &serde_json::Value) -> String {
        self.sign(&serde_json::json!({"alg": "RS256", "kid": "k1", "typ": "JWT"}), claims)
    }
}

/// GitHub's key list as given, counting fresh fetches.
pub struct FixedKeys {
    cached: String,
    fresh: String,
    fetched: Mutex<u32>,
}

impl Keys for FixedKeys {
    fn get(&self, _: &Ctx, fresh: bool) -> Result<String> {
        if fresh {
            *self.fetched.lock().unwrap() += 1;
            return Ok(self.fresh.clone());
        }
        Ok(self.cached.clone())
    }
}

fn keys(jwks: &str) -> FixedKeys {
    FixedKeys { cached: jwks.into(), fresh: jwks.into(), fetched: Mutex::new(0) }
}

fn openssl() -> (Openssl, TempDir) {
    let t = TempDir::new();
    (Openssl { run: Arc::new(ExecRunner::silent()), tmp: t.join("tmp") }, t)
}

#[test]
fn sources_as_people_write_them() {
    for written in [
        "github.com/You/Shop",
        "You/Shop",
        "https://github.com/You/Shop.git",
        "git@github.com:You/Shop.git",
        "https://github.com/You/Shop/",
    ] {
        let s = Source::parse(written, "main").unwrap();
        assert_eq!((s.owner.as_str(), s.repo.as_str()), ("You", "Shop"), "{written}");
    }
    let s = src();
    assert_eq!(
        (s.full(), s.image(), s.text(), s.tag()),
        ("You/Shop".into(), "ghcr.io/you/shop".into(), "github.com/You/Shop".into(), "dryserver-main".into())
    );
    // Branches a tag cannot carry as they are get a sha256 of their own:
    // feature/a and feature-a never share a tag.
    let slash = Source::parse("you/shop", "feature/a").unwrap().tag();
    let dash = Source::parse("you/shop", "feature-a").unwrap().tag();
    assert!(slash.starts_with("dryserver-feature-a-") && slash.len() == "dryserver-feature-a-".len() + 12, "{slash}");
    assert_eq!(dash, "dryserver-feature-a");
    let long = |c: char| tag_for(&format!("{}{c}", "x".repeat(120)));
    assert!(long('1') != long('2') && long('1').len() <= 128, "{}", long('1'));
    for bad in [
        "gitlab.com/you/shop",
        "https://evil.example/you/shop",
        "you",
        "you/shop/extra",
        "-you/shop",
        "you/..",
        "you/sh op",
        "you--x/shop",
        "",
    ] {
        assert!(Source::parse(bad, "main").is_err(), "{bad}");
    }
    for bad in ["", "-x", "a..b", "a//b", "/a", "a/", "x.lock", "HEAD", "a b", "a~1", "a^", "a:b", ".hidden"] {
        assert!(Source::parse("you/shop", bad).is_err(), "{bad:?}");
    }
}

#[test]
fn a_real_proof_checks_out() {
    let s = Signer::new();
    let (rsa, _t) = openssl();
    let k = keys(&s.jwks("k1"));
    let b = check_proof(&Ctx::new(), &s.proof(&claims()), &k, &rsa, &src(), DIGEST, None).unwrap();
    assert_eq!(
        b,
        Build {
            digest: DIGEST.into(),
            commit: SHA.into(),
            run: 10,
            iat: 1000,
            repo_id: "123456".into(),
            run_id: "777".into(),
            actor: "you".into()
        }
    );
    assert_eq!(b.short(), "0123456");
    // The same repository number again: fine; another: refused.
    check_proof(&Ctx::new(), &s.proof(&claims()), &k, &rsa, &src(), DIGEST, Some("123456")).unwrap();
    let e = check_proof(&Ctx::new(), &s.proof(&claims()), &k, &rsa, &src(), DIGEST, Some("999")).unwrap_err().to_string();
    assert!(e.contains("made anew is another one"), "{e}");
    // GitHub's key list did not have the key yet: asked again, once.
    let stale = FixedKeys { cached: r#"{"keys":[]}"#.into(), fresh: s.jwks("k1"), fetched: Mutex::new(0) };
    check_proof(&Ctx::new(), &s.proof(&claims()), &stale, &rsa, &src(), DIGEST, None).unwrap();
    assert_eq!(*stale.fetched.lock().unwrap(), 1);
}

#[test]
fn every_claim_must_be_this_apps() {
    let s = Signer::new();
    let (rsa, _t) = openssl();
    let k = keys(&s.jwks("k1"));
    let refused = |c: serde_json::Value, why: &str| {
        let e = check_proof(&Ctx::new(), &s.proof(&c), &k, &rsa, &src(), DIGEST, None).unwrap_err().to_string();
        assert!(e.contains(why), "{why}: {e}");
    };
    let with = |k: &str, v: serde_json::Value| {
        let mut c = claims();
        c[k] = v;
        c
    };
    refused(with("iss", "https://evil.example".into()), "the issuer");
    refused(with("aud", format!("{AUDIENCE}{DIGEST2}").into()), "another image");
    refused(with("aud", "sts.amazonaws.com".into()), "another image");
    refused(with("repository", "someone/Shop".into()), "the repository someone/Shop");
    refused(with("ref", "refs/heads/feature".into()), "the branch refs/heads/feature");
    refused(with("ref", "refs/pull/12/merge".into()), "the branch");
    refused(with("ref_type", "tag".into()), "the branch");
    refused(with("workflow_ref", "You/Shop/.github/workflows/other.yml@refs/heads/main".into()), "the workflow");
    refused(with("workflow_ref", "You/Shop/.github/workflows/dryserver.yml@refs/heads/feature".into()), "the workflow");
    refused(with("workflow_ref", "Evil/Shop/.github/workflows/dryserver.yml@refs/heads/main".into()), "the workflow");
    refused(with("event_name", "pull_request_target".into()), "an event pull_request_target");
    // Started by hand: not a push, so it does not deploy.
    refused(with("event_name", "workflow_dispatch".into()), "an event workflow_dispatch");
    // The workflow file exactly as dryserver writes it.
    refused(with("workflow_ref", "You/Shop/.github/workflows/DryServer.yml@refs/heads/main".into()), "the workflow");
    refused(with("workflow_ref", "You/Shop/.github/workflows/dryserver.yml".into()), "the workflow");
    refused(with("run_number", "".into()), "no run number");
    refused(with("run_number", "0".into()), "no run number");
    refused(with("run_number", "-3".into()), "no run number");
    refused(with("run_number", "1e3".into()), "no run number");
    refused(with("runner_environment", "self-hosted".into()), "not GitHub's own");
    refused(with("sha", "abc".into()), "no commit");
    refused(with("repository_id", "".into()), "no repository number");
    refused(with("iat", 0.into()), "no time");
    // The audience may be a list; case of the repository does not matter.
    let mut c = with("aud", serde_json::json!(["other", format!("{AUDIENCE}{DIGEST}")]));
    c["repository"] = "you/shop".into();
    c["workflow_ref"] = "you/shop/.github/workflows/dryserver.yml@refs/heads/main".into();
    check_proof(&Ctx::new(), &s.proof(&c), &k, &rsa, &src(), DIGEST, None).unwrap();
    // A changed claim breaks GitHub's signature.
    let good = s.proof(&claims());
    let parts: Vec<&str> = good.split('.').collect();
    let forged = format!("{}.{}.{}", parts[0], b64(with("repository", "Evil/Shop".into()).to_string().as_bytes()), parts[2]);
    let e = check_proof(&Ctx::new(), &forged, &k, &rsa, &src(), DIGEST, None).unwrap_err().to_string();
    assert!(e.contains("not signed by GitHub"), "{e}");
    // Another key, an unsigned token, another algorithm, nonsense.
    let other = Signer::new();
    let e = check_proof(&Ctx::new(), &other.proof(&claims()), &k, &rsa, &src(), DIGEST, None).unwrap_err().to_string();
    assert!(e.contains("not signed by GitHub"), "{e}");
    let none = format!("{}.{}.", b64(br#"{"alg":"none","kid":"k1"}"#), b64(claims().to_string().as_bytes()));
    assert!(check_proof(&Ctx::new(), &none, &k, &rsa, &src(), DIGEST, None).unwrap_err().to_string().contains("not RS256"));
    let hs = s.sign(&serde_json::json!({"alg": "HS256", "kid": "k1"}), &claims());
    assert!(check_proof(&Ctx::new(), &hs, &k, &rsa, &src(), DIGEST, None).unwrap_err().to_string().contains("not RS256"));
    // Whoever writes to the registry chooses the header: nothing of it
    // reaches a terminal unfiltered.
    let esc = s.sign(&serde_json::json!({"alg": "\u{1b}[2JRS", "kid": "k1"}), &claims());
    let e = check_proof(&Ctx::new(), &esc, &k, &rsa, &src(), DIGEST, None).unwrap_err().to_string();
    assert!(!e.contains('\u{1b}') && e.contains("[2JRS"), "{e}");
    let esc = s.sign(&serde_json::json!({"alg": "RS256", "kid": "k9\u{1b}]0;x\u{7}"}), &claims());
    let e = check_proof(&Ctx::new(), &esc, &k, &rsa, &src(), DIGEST, None).unwrap_err().to_string();
    assert!(!e.chars().any(|c| c.is_control()), "{e:?}");
    let nokid = s.sign(&serde_json::json!({"alg": "RS256"}), &claims());
    assert!(check_proof(&Ctx::new(), &nokid, &k, &rsa, &src(), DIGEST, None).unwrap_err().to_string().contains("names no key"));
    let unknown = s.sign(&serde_json::json!({"alg": "RS256", "kid": "k9"}), &claims());
    assert!(check_proof(&Ctx::new(), &unknown, &k, &rsa, &src(), DIGEST, None).unwrap_err().to_string().contains("not (any more)"));
    for junk in ["", "a.b", "a.b.c.d", &"x".repeat(MAX_PROOF + 1)] {
        assert!(check_proof(&Ctx::new(), junk, &k, &rsa, &src(), DIGEST, None).is_err(), "{}", junk.len());
    }
    assert!(check_proof(&Ctx::new(), &good, &k, &rsa, &src(), "sha256:short", None).unwrap_err().to_string().contains("no image digest"));
}

#[test]
fn what_the_registry_holds() {
    let idx = |annotations: serde_json::Value, manifests: serde_json::Value| serde_json::json!({"annotations": annotations, "manifests": manifests});
    let one = serde_json::json!([{"digest": DIGEST}]);
    let f = found(&idx(serde_json::json!({PROOF: "jwt"}), one.clone())).unwrap().unwrap();
    assert_eq!(f, Found { digest: DIGEST.into(), proof: "jwt".into() });
    let many = serde_json::json!([
        {"digest": DIGEST2, "platform": {"os": "linux", "architecture": "arm64"}},
        {"digest": DIGEST, "platform": {"os": "linux", "architecture": "amd64"}}
    ]);
    assert_eq!(found(&idx(serde_json::json!({PROOF: "jwt"}), many)).unwrap().unwrap().digest, DIGEST);
    assert!(found(&idx(serde_json::json!({}), one.clone())).unwrap_err().to_string().contains("carries no proof"));
    let arm = serde_json::json!([{"digest": DIGEST2, "platform": {"os": "linux", "architecture": "arm64"}}, {"digest": DIGEST, "platform": {"os": "linux", "architecture": "s390x"}}]);
    assert!(found(&idx(serde_json::json!({PROOF: "jwt"}), arm)).unwrap_err().to_string().contains("linux/amd64"));
    assert!(found(&idx(serde_json::json!({PROOF: "jwt"}), serde_json::json!([{"digest": "sha256:x"}]))).is_err());
}

#[test]
fn the_token_in_the_cluster() {
    let t = "ghp_0123456789abcdefghijABCDEFGHIJ012345";
    let y = pull_secret(t);
    assert!(
        y.contains("type: kubernetes.io/dockerconfigjson") && y.contains("name: dryserver-ghcr") && !y.contains(t),
        "the token is only base64 in it"
    );
    // As kubectl gives it back.
    let data = y.lines().find_map(|l| l.trim().strip_prefix(".dockerconfigjson: ")).unwrap();
    let back = serde_json::json!({"data": {".dockerconfigjson": data}}).to_string();
    assert_eq!(token_in(&back).as_deref(), Some(t));
    assert_eq!(token_in("{}"), None);
    valid_token(t).unwrap();
    assert!(valid_token("github_pat_11AAAA").unwrap_err().to_string().contains("classic tokens"));
    assert!(valid_token("ghp_x y").is_err() && valid_token("short").is_err());
    // The key as openssl reads it.
    let pem = rsa_pem(&[0xc0; 256], &[1, 0, 1]);
    assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n") && pem.ends_with("-----END PUBLIC KEY-----\n"));
}

#[test]
fn the_workflow_builds_only_the_branch_and_proves_apart() {
    let w = workflow("main");
    for want in [
        "branches: [\"main\"]",
        "permissions: {}\n",
        "if: github.ref == 'refs/heads/main'",
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "persist-credentials: false",
        &format!("echo \"{RAILPACK_SHA256}  railpack.tgz\" | sha256sum -c -"),
        RAILPACK_FRONTEND,
        "--platform linux/amd64 --provenance=false --push",
        "audience=dryserver%3A${DIGEST/:/%3A}",
        "[[ \"$DIGEST\" =~ ^sha256:[0-9a-f]{64}$ ]]",
        "[[ \"$digest\" =~ ^sha256:[0-9a-f]{64}$ ]]",
        &format!("driver-opts: image={BUILDKIT}"),
        "--annotation \"index:dev.dryserver.proof=$proof\"",
        "--tag \"$image:dryserver-main\"",
    ] {
        assert!(w.contains(want), "missing {want:?}:\n{w}");
    }
    // Only the job that runs none of the app's code may get a proof.
    let build = &w[w.find("  build:").unwrap()..w.find("  prove:").unwrap()];
    let prove = &w[w.find("  prove:").unwrap()..];
    assert!(!build.contains("id-token") && build.contains("packages: write") && build.contains("actions/checkout"), "{build}");
    assert!(prove.contains("id-token: write") && !prove.contains("actions/checkout"), "{prove}");
    // Nothing but the runner's own tools where the proof is made.
    assert!(!prove.contains("uses:"), "{prove}");
    // Only a push builds: no run by hand, no other event.
    assert!(!w.contains("workflow_dispatch") && !w.contains("pull_request"), "{w}");
    // Tokens never in a command line: from the environment.
    assert!(!w.contains("${{ secrets.GITHUB_TOKEN }}\" |") && w.matches("--password-stdin").count() == 2);
    let other = workflow("release/v2");
    assert!(
        other.contains("branches: [\"release/v2\"]") && other.contains("refs/heads/release/v2") && other.contains(&tag_for("release/v2"))
    );
}

/// A registry that holds one proof, or none.
pub struct OneProof(pub Mutex<Option<Result<Option<Found>>>>);

impl Registry for OneProof {
    fn proof(&self, _: &Ctx, _: &Source) -> Result<Option<Found>> {
        match &*self.0.lock().unwrap() {
            Some(Ok(f)) => Ok(f.clone()),
            Some(Err(e)) => Err(errf!("{e}")),
            None => Ok(None),
        }
    }
}

/// Signatures "good" are good.
pub struct SaysGood;

impl Rsa for SaysGood {
    fn verify(&self, _: &Ctx, _: &[u8], _: &[u8], _: &[u8], sig: &[u8]) -> Result<()> {
        if sig == b"good" { Ok(()) } else { Err(errf!("bad")) }
    }
}

pub fn fake_proof(c: &serde_json::Value) -> String {
    format!("{}.{}.{}", b64(br#"{"alg":"RS256","kid":"k1"}"#), b64(c.to_string().as_bytes()), b64(b"good"))
}

pub fn fake_keys() -> FixedKeys {
    let k = serde_json::json!({"keys": [{"kid": "k1", "kty": "RSA", "n": b64(&[0xc0; 256]), "e": "AQAB"}]}).to_string();
    keys(&k)
}

/// A cluster with the app shop, built from You/Shop's main, running
/// image digest with these annotations, and the token in it.
fn cluster(digest: &str, annotations: serde_json::Value, status: serde_json::Value) -> Fake {
    let mut ann = serde_json::json!({A_REPO: "You/Shop", A_BRANCH: "main"});
    for (k, v) in annotations.as_object().unwrap() {
        ann[k] = v.clone();
    }
    let dep = serde_json::json!({"items": [{
        "metadata": {"name": "shop", "generation": 2, "resourceVersion": "41", "annotations": ann},
        "spec": {"replicas": 1, "template": {"spec": {"containers": [{"name": "shop", "image": format!("ghcr.io/you/shop@{digest}")}]}}},
        "status": status
    }]});
    let c = Fake::default();
    c.answers.lock().unwrap().push(("-n apps get deployments".into(), dep.to_string()));
    let token = pull_secret("ghp_0123456789abcdefghijABCDEFGHIJ012345");
    let data = token.lines().find_map(|l| l.trim().strip_prefix(".dockerconfigjson: ")).unwrap().to_string();
    c.answers
        .lock()
        .unwrap()
        .push(("get secret dryserver-ghcr".into(), serde_json::json!({"data": {".dockerconfigjson": data}}).to_string()));
    c
}

fn watch_with(c: &Fake, reg: Option<Result<Option<Found>>>) -> Vec<String> {
    let reg = Arc::new(OneProof(Mutex::new(reg)));
    let make = |_: String| -> Box<dyn Registry> {
        Box::new(OneProof(Mutex::new(reg.0.lock().unwrap().as_ref().map(|r| match r {
            Ok(f) => Ok(f.clone()),
            Err(e) => Err(errf!("{e}")),
        }))))
    };
    watch(&Ctx::new(), c, &make, &fake_keys(), &SaysGood, 5000, 0).unwrap()
}

fn patches(c: &Fake) -> Vec<(String, String)> {
    c.calls.lock().unwrap().iter().filter(|(a, _)| a.contains("patch deployment shop")).cloned().collect()
}

#[test]
fn the_coordinator_deploys_newer_builds_only() {
    let newer = Some(Ok(Some(Found {
        digest: DIGEST2.into(),
        proof: fake_proof(&{
            let mut c = claims();
            c["aud"] = format!("{AUDIENCE}{DIGEST2}").into();
            c["run_number"] = "2000".into();
            c
        }),
    })));
    // Running an older build: the newer one goes out, the old one into the
    // history, and the rollout is watched.
    let c = cluster(DIGEST, serde_json::json!({A_RUN: "1000", A_COMMIT: SHA, A_REPO_ID: "123456"}), serde_json::json!({}));
    let log = watch_with(&c, newer.clone());
    let p = patches(&c);
    let deploy = p.iter().find(|(a, _)| a.contains("--type strategic")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&deploy.1).unwrap();
    assert_eq!(v["spec"]["template"]["spec"]["containers"][0]["image"], format!("ghcr.io/you/shop@{DIGEST2}"));
    assert_eq!(v["metadata"]["resourceVersion"], "41", "only onto the Deployment as it was listed");
    let ann = &v["metadata"]["annotations"];
    assert_eq!((ann[A_RUN].as_str(), ann[A_ROLLING].as_str()), (Some("2000"), Some(DIGEST2)));
    assert_eq!(ann[A_HISTORY], format!("1000@{}@{SHA}", DIGEST.trim_start_matches("sha256:")));
    assert!(log.iter().any(|l| l.contains("deploying build 0123456 of main")), "{log:?}");
    assert!(
        c.calls
            .lock()
            .unwrap()
            .iter()
            .any(|(a, m)| a == "apply -f -" && m.contains("name: dryserver-github") && m.contains("last: \"5000\""))
    );
    // The same build, an older one, one held back: nothing is changed.
    for (ann, why) in [
        (serde_json::json!({A_RUN: "2000", A_COMMIT: SHA}), "running it"),
        (serde_json::json!({A_RUN: "3000", A_COMMIT: SHA}), "running a newer one"),
        (serde_json::json!({A_RUN: "500", A_HOLD: "2000", A_COMMIT: SHA}), "held"),
    ] {
        let c = cluster(DIGEST, ann, serde_json::json!({}));
        watch_with(&c, newer.clone());
        assert!(!patches(&c).iter().any(|(a, _)| a.contains("strategic")), "{why}");
    }
    // A repository made anew under the same name: not taken.
    let c = cluster(DIGEST, serde_json::json!({A_RUN: "1000", A_REPO_ID: "999"}), serde_json::json!({}));
    let log = watch_with(&c, newer.clone());
    assert!(log.iter().any(|l| l.contains("made anew")) && !patches(&c).iter().any(|(a, _)| a.contains("strategic")), "{log:?}");
    // A proof that does not check out, no build yet, the registry down.
    let mut bad = claims();
    bad["ref"] = "refs/heads/feature".into();
    for (reg, why) in [
        (Some(Ok(Some(Found { digest: DIGEST.into(), proof: fake_proof(&bad) }))), "not taken: the proof is for the branch"),
        (None, "the registry has no build of main (deleted?); the running build stays"),
        (Some(Err(errf!("no answer from ghcr.io"))), "not taken: no answer from ghcr.io"),
    ] {
        let c = cluster(DIGEST, serde_json::json!({A_RUN: "1000"}), serde_json::json!({}));
        let log = watch_with(&c, reg);
        assert!(log.iter().any(|l| l.contains(why)), "{why}: {log:?}");
        assert!(!patches(&c).iter().any(|(a, _)| a.contains("strategic")));
    }
    // What it said is not said again.
    let c = cluster(DIGEST, serde_json::json!({A_WATCH: "4000 no build of main yet"}), serde_json::json!({}));
    assert!(watch_with(&c, None).is_empty());
    // No token in the cluster: said, nothing asked.
    let c = cluster(DIGEST, serde_json::json!({A_RUN: "1000"}), serde_json::json!({}));
    c.answers.lock().unwrap().retain(|(k, _)| !k.contains("secret"));
    // kubectl --ignore-not-found says nothing.
    c.answers.lock().unwrap().push(("get secret dryserver-ghcr".into(), String::new()));
    let log = watch_with(&c, newer);
    assert!(log.iter().any(|l| l.contains("no GitHub token in the cluster")), "{log:?}");
}

#[test]
fn a_build_whose_copies_never_start_is_taken_back() {
    let history = format!("10@{}@{}", DIGEST.trim_start_matches("sha256:"), "f".repeat(40));
    let ann = serde_json::json!({A_RUN: "20", A_COMMIT: SHA, A_ROLLING: DIGEST2, A_HISTORY: history});
    // The cluster gave up on this very version.
    let failed = serde_json::json!({"observedGeneration": 2, "conditions": [{"type": "Progressing", "status": "False", "reason": "ProgressDeadlineExceeded"}]});
    let c = cluster(DIGEST2, ann.clone(), failed.clone());
    let log = watch_with(&c, None);
    let calls = c.calls.lock().unwrap().clone();
    // Back by its image, not by the cluster's revisions (a secret or a
    // setting changed since would be one of them).
    assert!(!calls.iter().any(|(a, _)| a.contains("rollout undo")), "{calls:?}");
    let back = patches(&c).into_iter().find(|(a, _)| a.contains("--type strategic")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&back.1).unwrap();
    assert_eq!(v["spec"]["template"]["spec"]["containers"][0]["image"], format!("ghcr.io/you/shop@{DIGEST}"));
    // Only onto the Deployment as it was listed.
    assert_eq!(v["metadata"]["resourceVersion"], "41");
    let a = &v["metadata"]["annotations"];
    assert_eq!((a[A_HOLD].as_str(), a[A_RUN].as_str(), a[A_COMMIT].as_str()), (Some("20"), Some("10"), Some("f".repeat(40).as_str())));
    assert!(a[A_ROLLING].is_null() && a[A_HISTORY] == "");
    assert!(log.iter().any(|l| l.contains("build 0123456 did not start") && l.contains("back on fffffff")), "{log:?}");
    // A hold already higher (a rollback before) stays as high.
    let mut held = ann.clone();
    held[A_HOLD] = "50".into();
    let c = cluster(DIGEST2, held, failed.clone());
    watch_with(&c, None);
    let back = patches(&c).into_iter().find(|(a, _)| a.contains("--type strategic")).unwrap();
    assert!(back.1.contains(&format!("\"{A_HOLD}\":\"50\"")), "{back:?}");
    // Its first build: nothing to go back to; held, and said so.
    let first = serde_json::json!({A_RUN: "20", A_COMMIT: SHA, A_ROLLING: DIGEST2});
    let c = cluster(DIGEST2, first, failed.clone());
    let log = watch_with(&c, None);
    assert!(!patches(&c).iter().any(|(a, _)| a.contains("strategic")));
    assert!(patches(&c).iter().any(|(_, m)| m.contains(&format!("\"{A_HOLD}\":\"20\""))), "{:?}", patches(&c));
    assert!(log.iter().any(|l| l.contains("no build before it")), "{log:?}");
    // A condition about an older version of the Deployment: not this one's.
    let stale = serde_json::json!({"observedGeneration": 1, "conditions": failed["conditions"].clone()});
    let c = cluster(DIGEST2, ann.clone(), stale);
    watch_with(&c, None);
    assert!(!patches(&c).iter().any(|(_, m)| m.contains(A_HOLD)), "{:?}", patches(&c));
    // Done: the mark goes, and it says what runs; nothing else this
    // minute (the Deployment just changed).
    let done = serde_json::json!({"observedGeneration": 2, "replicas": 1, "updatedReplicas": 1, "availableReplicas": 1});
    let c = cluster(DIGEST2, ann.clone(), done.clone());
    let mut c9 = claims();
    c9["aud"] = format!("{AUDIENCE}{DIGEST}").into();
    c9["run_number"] = "99".into();
    let log = watch_with(&c, Some(Ok(Some(Found { digest: DIGEST.into(), proof: fake_proof(&c9) }))));
    assert!(!patches(&c).iter().any(|(a, _)| a.contains("strategic")), "{:?}", patches(&c));
    assert!(patches(&c).iter().any(|(_, m)| m.contains(&format!("\"{A_ROLLING}\":null"))), "{:?}", patches(&c));
    assert!(log.iter().any(|l| l.contains("running build 0123456")), "{log:?}");
    // Still going: left alone.
    let going = serde_json::json!({"observedGeneration": 2, "replicas": 2, "updatedReplicas": 1, "availableReplicas": 1});
    let c = cluster(DIGEST2, ann, going);
    watch_with(&c, None);
    assert!(!patches(&c).iter().any(|(_, m)| m.contains(A_ROLLING) || m.contains(A_HOLD)));
}

#[test]
fn a_run_of_before_run_again_never_deploys() {
    // Run 5 re-run today: GitHub signs it now, with its old number.
    let mut c5 = claims();
    c5["aud"] = format!("{AUDIENCE}{DIGEST2}").into();
    c5["run_number"] = "5".into();
    c5["iat"] = 999_999.into();
    let rerun = Some(Ok(Some(Found { digest: DIGEST2.into(), proof: fake_proof(&c5) })));
    let c = cluster(DIGEST, serde_json::json!({A_RUN: "10", A_COMMIT: SHA}), serde_json::json!({}));
    watch_with(&c, rerun.clone());
    assert!(!patches(&c).iter().any(|(a, _)| a.contains("strategic")), "an old version is not brought back");
    // Nor past a rollback's hold.
    let c = cluster(DIGEST, serde_json::json!({A_RUN: "3", A_HOLD: "8", A_COMMIT: SHA}), serde_json::json!({}));
    watch_with(&c, rerun);
    assert!(!patches(&c).iter().any(|(a, _)| a.contains("strategic")));
}

/// A cluster with apps a, b, c, ... built by GitHub.
fn many(n: usize) -> Fake {
    let items: Vec<serde_json::Value> = (0..n)
        .map(|i| {
            let name = format!("app{i}");
            serde_json::json!({
                "metadata": {"name": name, "generation": 1, "annotations": {A_REPO: "You/Shop", A_BRANCH: "main", A_RUN: "10", A_COMMIT: SHA}},
                "spec": {"replicas": 1, "template": {"spec": {"containers": [{"name": name, "image": format!("ghcr.io/you/shop@{DIGEST}")}]}}},
                "status": {}
            })
        })
        .collect();
    let c = cluster(DIGEST, serde_json::json!({}), serde_json::json!({}));
    c.answers.lock().unwrap()[0].1 = serde_json::json!({"items": items}).to_string();
    c
}

/// A registry that takes its time, and has nothing.
struct Slow(std::time::Duration);

impl Registry for Slow {
    fn proof(&self, _: &Ctx, _: &Source) -> Result<Option<Found>> {
        std::thread::sleep(self.0);
        Ok(None)
    }
}

#[test]
fn a_slow_github_never_leaves_the_same_apps_out() {
    // The minute's time is gone after the first app: said, and the
    // others are not asked.
    let c = many(3);
    let asked = std::sync::atomic::AtomicUsize::new(0);
    let slow = |_: String| -> Box<dyn Registry> {
        asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::new(Slow(std::time::Duration::from_millis(300)))
    };
    let ctx = Ctx::new().with_timeout(std::time::Duration::from_millis(150));
    let log = watch(&ctx, &c, &slow, &fake_keys(), &SaysGood, 5000, 0).unwrap();
    assert!(log.iter().any(|l| l.contains("no time left this minute for 2 more app(s)")), "{log:?}");
    assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 1);
    let reg = |_: String| -> Box<dyn Registry> { Box::new(OneProof(Mutex::new(None))) };
    // Each minute starts at another app.
    let first = |turn: u64| {
        let c = many(3);
        let log = watch(&Ctx::new(), &c, &reg, &fake_keys(), &SaysGood, 5000, turn).unwrap();
        log.iter().find(|l| l.contains("has no build of main")).cloned().unwrap()
    };
    assert!(first(0).starts_with("github: app0:") && first(1).starts_with("github: app1:") && first(5).starts_with("github: app2:"));
}

#[test]
fn the_sign_of_life_comes_before_any_app() {
    // No app built by GitHub yet: the desktop still learns that this
    // coordinator follows GitHub, before the first deploy.
    let c = Fake::default();
    let make = |_: String| -> Box<dyn Registry> { Box::new(OneProof(Mutex::new(None))) };
    assert!(watch(&Ctx::new(), &c, &make, &fake_keys(), &SaysGood, 5000, 0).unwrap().is_empty());
    assert!(c.calls.lock().unwrap().iter().any(|(a, m)| a == "apply -f -" && m.contains("name: dryserver-github")));
}

#[test]
fn nothing_from_the_network_becomes_a_curl_option() {
    // A line break in a value would start another option (output = ...).
    assert!(curl_quoted("Bearer abc\noutput = /etc/x").is_err());
    assert!(curl_quoted("a\rb").is_err() && curl_quoted("a\0b").is_err());
    assert_eq!(curl_quoted(r#"Authorization: Bearer a"b\c"#).unwrap(), r#""Authorization: Bearer a\"b\\c""#);
    assert!(valid_bearer("djE6eW91L3Nob3A6MTc=.x-y_z~+/"));
    for bad in ["", "abc\noutput = /tmp/x", "a b", "a\"b", &"x".repeat(8193)] {
        assert!(!valid_bearer(bad), "{bad:?}");
    }
}

#[test]
fn only_builds_that_ran_are_gone_back_to() {
    let st = |ann: serde_json::Value| {
        let mut a = serde_json::json!({A_REPO: "You/Shop", A_BRANCH: "main", A_COMMIT: SHA});
        for (k, v) in ann.as_object().unwrap() {
            a[k] = v.clone();
        }
        state_of(&a)
    };
    let before = format!("5@{}@{}", DIGEST2.trim_start_matches("sha256:"), "f".repeat(40));
    // It ran: it goes in front.
    let h = history_after(&st(serde_json::json!({A_RUN: "10", A_HISTORY: before})), DIGEST);
    assert_eq!(h.iter().map(|e| e.0).collect::<Vec<_>>(), vec![10, 5]);
    // Still starting (never seen to run), or held (it did not start): not.
    let h = history_after(&st(serde_json::json!({A_RUN: "10", A_ROLLING: DIGEST, A_HISTORY: before})), DIGEST);
    assert_eq!(h.iter().map(|e| e.0).collect::<Vec<_>>(), vec![5]);
    let h = history_after(&st(serde_json::json!({A_RUN: "10", A_HOLD: "10", A_HISTORY: before})), DIGEST);
    assert_eq!(h.iter().map(|e| e.0).collect::<Vec<_>>(), vec![5]);
}

#[test]
fn the_namespace_comes_along() {
    // On a new cluster the apps' namespace is not there before the first
    // app: what goes into it brings it.
    let y = pull_secret("ghp_0123456789abcdefghijABCDEFGHIJ012345");
    assert!(y.starts_with(&crate::apps::namespace_yaml()) && y.find("kind: Namespace") < y.find("kind: Secret"), "{y}");
    let c = Fake::default();
    let make = |_: String| -> Box<dyn Registry> { Box::new(OneProof(Mutex::new(None))) };
    watch(&Ctx::new(), &c, &make, &fake_keys(), &SaysGood, 5000, 0).unwrap();
    assert!(
        c.calls.lock().unwrap().iter().any(|(a, m)| a == "apply -f -" && m.contains("kind: Namespace") && m.contains("kind: ConfigMap"))
    );
}

#[test]
fn state_from_annotations() {
    let st = state_of(&serde_json::json!({
        A_REPO: "You/Shop", A_BRANCH: "main", A_REPO_ID: "123", A_RUN: "2000", A_COMMIT: SHA, A_HOLD: "nonsense",
        A_HISTORY: format!("1000@{}@{SHA},bad,5@zz@{SHA}", DIGEST.trim_start_matches("sha256:")),
        A_ROLLING: DIGEST2, A_WATCH: "4000 running build 0123456"
    }));
    assert_eq!(st.source, Some(src()));
    assert_eq!((st.repo_id.as_str(), st.run, st.hold, st.history.len(), st.rolling.as_str()), ("123", 2000, 0, 1, DIGEST2));
    assert_eq!(st.watch, Some((4000, "running build 0123456".into())));
    assert_eq!(state_of(&serde_json::json!({})), State::default());
    assert_eq!(state_of(&serde_json::json!({A_REPO: "evil.example/x/y"})).source, None);
}
