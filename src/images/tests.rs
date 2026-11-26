use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use super::*;
use crate::config::Config;
use crate::runner::Runner;
use crate::signed::Signer;
use crate::signed::fake::Key;
use crate::testutil::TempDir;

const ADMIN: Key = Key("admin");
pub const ID: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
pub const ID2: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

/// A tar file of these members, as podman and docker write them.
pub fn tar(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, data) in files {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..107].copy_from_slice(b"0000644");
        h[124..135].copy_from_slice(format!("{:011o}", data.len()).as_bytes());
        h[136..147].copy_from_slice(b"00000000000");
        h[156] = b'0';
        h[257..263].copy_from_slice(b"ustar\0");
        h[148..156].copy_from_slice(b"        ");
        let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
        h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
        out.extend_from_slice(&h);
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(512) * 512, 0);
    }
    out.resize(out.len() + 1024, 0);
    out
}

/// An image archive that loads as names, of the build id.
pub fn image(names: &[&str], id: &str, layer: &str) -> Vec<u8> {
    let hex = id.trim_start_matches("sha256:");
    let manifest = serde_json::json!([{"Config": format!("{hex}.json"), "RepoTags": names, "Layers": ["layer.tar"]}]).to_string();
    tar(&[("manifest.json", manifest.as_bytes()), (&format!("{hex}.json"), b"{}"), ("layer.tar", layer.as_bytes())])
}

/// containerd and crictl on a fake server: an import loads what the
/// archive's manifest names, as the archive's build.
#[derive(Default)]
struct Ctr {
    ran: Mutex<Vec<String>>,
    loaded: Mutex<BTreeMap<String, String>>,
    /// Image ids containers here run.
    running: Mutex<Vec<String>>,
    broken: Mutex<bool>,
    /// crictl ps fails.
    blind: Mutex<bool>,
}

impl Runner for Ctr {
    fn run(&self, _: &Ctx, c: &Cmd) -> (String, Result<()>) {
        let line = format!("{} {}", c.name, c.args.join(" "));
        self.ran.lock().unwrap().push(line);
        match c.args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
            ["ctr", "-n", "k8s.io", "images", "import", file] => {
                if *self.broken.lock().unwrap() {
                    return (String::new(), Err("ctr: unexpected EOF".into()));
                }
                let a = archive(Path::new(file)).unwrap();
                for n in a.names {
                    self.loaded.lock().unwrap().insert(n, format!("sha256:{}", a.config));
                }
                (String::new(), Ok(()))
            }
            ["ctr", "-n", "k8s.io", "images", "ls", "-q"] => {
                (self.loaded.lock().unwrap().keys().map(|n| format!("{n}\n")).collect(), Ok(()))
            }
            ["ctr", "-n", "k8s.io", "images", "label", ..] => (String::new(), Ok(())),
            ["crictl", "inspecti", "-o", "json", name] => match self.loaded.lock().unwrap().get(*name) {
                Some(id) => (serde_json::json!({"status": {"id": id}}).to_string(), Ok(())),
                None => (String::new(), Err("no such image".into())),
            },
            ["crictl", "ps", "-a", "-o", "json"] if *self.blind.lock().unwrap() => {
                (String::new(), Err("crictl: connection refused".into()))
            }
            ["crictl", "ps", "-a", "-o", "json"] => {
                let cs: Vec<_> =
                    self.running.lock().unwrap().iter().map(|id| serde_json::json!({"imageRef": id, "image": {"image": id}})).collect();
                (serde_json::json!({"containers": cs}).to_string(), Ok(()))
            }
            _ => (String::new(), Ok(())),
        }
    }
}

struct Server {
    _dir: TempDir,
    n: Node,
    ctr: Arc<Ctr>,
}

impl Server {
    fn new() -> Server {
        let dir = TempDir::new();
        let ctr = Arc::new(Ctr::default());
        let n = Node {
            cfg: Config { username: "admin".into(), ..Config::default() },
            hostname: "node-a".into(),
            root: dir.path().to_path_buf(),
            run: ctr.clone(),
            tmp_dir: None,
            verifier: Arc::new(ADMIN),
        };
        Server { _dir: dir, n, ctr }
    }

    fn inbox(&self) -> PathBuf {
        let d = self.n.path(&format!("/home/admin/{INBOX}"));
        std::fs::create_dir_all(&d).unwrap();
        for p in [self.n.path("/home/admin"), self.n.path("/home/admin/.dryserver"), d.clone()] {
            fsx::chmod(&p, 0o700).unwrap();
        }
        d
    }

    /// The desktop's upload of a file, and its document signed with key.
    fn put(&self, key: &Key, name: &str, id: &str, made: i64, body: &[u8]) -> String {
        let sha = fsx::hex(&Sha256::digest(body));
        let doc = Doc { name: name.into(), id: id.into(), sha256: sha.clone(), size: body.len() as u64, made };
        let text = serde_json::to_string(&doc).unwrap();
        let env = Envelope { sig: key.sign(NS, &text).unwrap(), doc: text };
        let d = self.inbox();
        std::fs::write(d.join(format!("{sha}.tar")), body).unwrap();
        std::fs::write(d.join(format!("{sha}.json")), serde_json::to_string(&env).unwrap()).unwrap();
        sha
    }

    /// The image name, of build id, as the desktop sends it.
    fn send(&self, name: &str, id: &str, made: i64) -> String {
        self.put(&ADMIN, name, id, made, &image(&[name], id, &format!("{name} {made}")))
    }

    fn take(&self, now: i64) -> Done {
        take(&Ctx::new(), &self.n, now).unwrap()
    }

    fn inbox_files(&self) -> Vec<String> {
        let mut v: Vec<String> =
            std::fs::read_dir(self.inbox()).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        v.sort();
        v
    }

    fn imports(&self) -> usize {
        self.ctr.ran.lock().unwrap().iter().filter(|l| l.contains("images import")).count()
    }
}

#[test]
fn a_signed_image_is_taken_loaded_and_pinned() {
    let s = Server::new();
    assert!(!waiting(&s.n), "no inbox yet: nothing to take");
    let sha = s.send("localhost/shop:v1", ID, 100);
    assert!(waiting(&s.n));
    let d = s.take(1000);
    assert_eq!(d.taken, vec!["localhost/shop:v1"]);
    let st = load(&s.n);
    assert!(st.has("localhost/shop:v1", ID) && !st.has("localhost/shop:v1", ID2));
    assert_eq!((st.images[0].at, st.marks["localhost/shop:v1"], st.checked), (1000, 100, 1000));
    // Kept for root alone; the state readable by the admin's login.
    use std::os::unix::fs::PermissionsExt;
    let mode = |p: &str| std::fs::metadata(s.n.path(p)).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&format!("{STORE}/{sha}.tar")), 0o600);
    assert_eq!((mode(STATE), mode(STORE)), (0o644, 0o711));
    assert!(s.inbox_files().is_empty(), "the inbox is emptied");
    let ran = s.ctr.ran.lock().unwrap().clone();
    assert!(ran.iter().any(|l| l.contains("images import") && l.contains(&sha)));
    assert!(ran.iter().any(|l| l.ends_with("images label localhost/shop:v1 io.cri-containerd.pinned=pinned")), "{ran:?}");
    // Nothing to do: nothing changes.
    assert_eq!(s.take(1001), Done::default());
    // The very same file sent again: nothing loaded again.
    s.send("localhost/shop:v1", ID, 100);
    assert_eq!(s.take(1002).taken, vec!["localhost/shop:v1"]);
    assert_eq!(s.imports(), 1);
}

#[test]
fn what_is_refused_is_never_loaded() {
    let s = Server::new();
    let refused = |s: &Server, now: i64, why: &str| {
        let d = s.take(now);
        assert!(d.taken.is_empty() && d.refused.len() == 1 && d.refused[0].contains(why), "{why}: {d:?}");
        assert!(s.inbox_files().is_empty(), "a refused file is not tried again: {:?}", s.inbox_files());
    };
    // Another key signed it.
    let sha = s.put(&Key("someone"), "localhost/shop:v1", ID, 100, &image(&["localhost/shop:v1"], ID, "x"));
    refused(&s, 10, "not signed by the admin");
    assert!(load(&s.n).refusal(&sha).is_some_and(|r| r.name == "localhost/shop:v1" && r.why.contains("not signed")));
    // Changed after it was signed.
    let sha = s.send("localhost/shop:v1", ID, 100);
    let tar_path = s.inbox().join(format!("{sha}.tar"));
    let len = fsx::read(&tar_path).unwrap().len();
    std::fs::write(&tar_path, vec![b'x'; len]).unwrap();
    refused(&s, 11, "not the one signed");
    // Cut off on the way, or missing.
    let sha = s.send("localhost/shop:v1", ID, 100);
    std::fs::write(s.inbox().join(format!("{sha}.tar")), "short").unwrap();
    refused(&s, 12, "not sent whole");
    let sha = s.send("localhost/shop:v1", ID, 100);
    std::fs::remove_file(s.inbox().join(format!("{sha}.tar"))).unwrap();
    refused(&s, 13, "the image file");
    // A link instead of a file: never followed.
    let sha = s.send("localhost/shop:v1", ID, 100);
    let tar_path = s.inbox().join(format!("{sha}.tar"));
    std::fs::rename(&tar_path, s.n.path("/elsewhere.tar")).unwrap();
    std::os::unix::fs::symlink(s.n.path("/elsewhere.tar"), &tar_path).unwrap();
    refused(&s, 14, "the image file");
    assert!(s.n.path("/elsewhere.tar").exists(), "and what it pointed at is left alone");
    // Names that are not the admin's own images.
    for (name, why) in [
        ("docker.io/library/nginx:1", "localhost/NAME:TAG"),
        ("localhost/shop", "with a tag"),
        ("localhost/:v1", "with a tag"),
        ("localhost/a:v1:v2", "with a tag"),
    ] {
        s.put(&ADMIN, name, ID, 100, &image(&[name], ID, "x"));
        refused(&s, 15, why);
    }
    // The archive loads as more, or as another name, or as another build:
    // refused before anything is loaded, so nothing is overwritten.
    s.put(&ADMIN, "localhost/shop:v1", ID, 100, &image(&["localhost/shop:v1", "docker.io/library/nginx:1.27"], ID, "x"));
    refused(&s, 16, "not as localhost/shop:v1 alone");
    s.put(&ADMIN, "localhost/shop:v1", ID, 100, &image(&["localhost/other:v1"], ID, "x"));
    refused(&s, 17, "loads as localhost/other:v1");
    s.put(&ADMIN, "localhost/shop:v1", ID, 100, &image(&["localhost/shop:v1"], ID2, "x"));
    refused(&s, 18, "another build than the one signed");
    s.put(&ADMIN, "localhost/shop:v1", ID, 100, b"not an archive at all, just bytes");
    refused(&s, 19, "archive");
    let hex = ID.trim_start_matches("sha256:");
    let one = format!(r#"[{{"Config":"{hex}.json","RepoTags":["localhost/shop:v1"]}}]"#);
    s.put(&ADMIN, "localhost/shop:v1", ID, 100, &tar(&[("manifest.json", one.as_bytes()), ("manifest.json", one.as_bytes())]));
    refused(&s, 20, "manifest.json twice");
    let index = r#"{"manifests":[{"annotations":{"io.containerd.image.name":"docker.io/library/nginx:1.27"}}]}"#;
    s.put(&ADMIN, "localhost/shop:v1", ID, 100, &tar(&[("manifest.json", one.as_bytes()), ("index.json", index.as_bytes())]));
    refused(&s, 21, "index.json names docker.io/library/nginx:1.27");
    assert_eq!(s.imports(), 0, "nothing was loaded");
    // containerd refuses it.
    *s.ctr.broken.lock().unwrap() = true;
    s.send("localhost/shop:v2", ID, 100);
    refused(&s, 22, "loading it into the cluster");
    *s.ctr.broken.lock().unwrap() = false;
    // A document too large, whatever it says.
    std::fs::write(s.inbox().join(format!("{}.json", "c".repeat(64))), vec![b' '; 70 << 10]).unwrap();
    refused(&s, 23, "larger than any is");
    // Signed ahead of the server's clock.
    s.send("localhost/shop:v1", ID, 10_000);
    refused(&s, 24, "ahead of this server's clock");
    assert!(load(&s.n).images.is_empty() && load(&s.n).refused.len() <= 20);
}

#[test]
fn nothing_older_is_taken_again() {
    let s = Server::new();
    s.send("localhost/shop:v1", ID2, 500);
    assert_eq!(s.take(1000).taken, vec!["localhost/shop:v1"]);
    // An older signed document of the name: a replay.
    s.send("localhost/shop:v1", ID, 400);
    assert!(s.take(1001).refused[0].contains("older than a version this server took"));
    assert!(load(&s.n).has("localhost/shop:v1", ID2));
    // A newer build under the same name replaces it, and the cluster's
    // name leads to it.
    s.send("localhost/shop:v1", ID, 600);
    assert_eq!(s.take(1002).taken, vec!["localhost/shop:v1"]);
    assert!(load(&s.n).has("localhost/shop:v1", ID) && load(&s.n).images.len() == 1);
    assert_eq!(s.ctr.loaded.lock().unwrap()["localhost/shop:v1"], ID);
    // Also once its version was dropped: the mark stays.
    for (i, tag) in ["v2", "v3", "v4"].iter().enumerate() {
        s.send(&format!("localhost/shop:{tag}"), ID2, 700 + i as i64);
        s.take(1003 + i as i64);
    }
    assert!(!load(&s.n).images.iter().any(|h| h.name == "localhost/shop:v1"), "v1 rotated out");
    s.send("localhost/shop:v1", ID2, 550);
    assert!(s.take(1010).refused[0].contains("older than a version"));
}

#[test]
fn the_inbox_is_the_admins_and_stays_the_one_opened() {
    let s = Server::new();
    s.send("localhost/shop:v1", ID, 100);
    // Open to others: someone else could have put files in it.
    fsx::chmod(s.inbox(), 0o777).unwrap();
    assert!(!waiting(&s.n) && s.take(1).taken.is_empty());
    fsx::chmod(s.inbox(), 0o700).unwrap();
    // A link on the way.
    let real = s.n.path("/home/admin/.dryserver");
    std::fs::rename(&real, s.n.path("/home/admin/real")).unwrap();
    std::os::unix::fs::symlink(s.n.path("/home/admin/real"), &real).unwrap();
    assert!(!waiting(&s.n) && s.take(2).taken.is_empty());
    std::fs::remove_file(&real).unwrap();
    std::fs::rename(s.n.path("/home/admin/real"), &real).unwrap();
    // Opened, then its path swapped for a link to the store: what is
    // deleted is still in the inbox opened, never in the store.
    let i = Inbox::open(&s.n).unwrap();
    let inbox = s.n.path(&format!("/home/admin/{INBOX}"));
    std::fs::rename(&inbox, s.n.path("/home/admin/moved")).unwrap();
    fsx::mkdir_all(s.n.path(STORE), 0o711).unwrap();
    std::fs::write(s.n.path(&format!("{STORE}/victim.tar")), "kept").unwrap();
    std::os::unix::fs::symlink(s.n.path(STORE), &inbox).unwrap();
    i.unlink("victim.tar");
    assert!(s.n.path(&format!("{STORE}/victim.tar")).exists(), "the store is untouched");
    assert_eq!(i.docs().len(), 1, "the inbox opened still has its document");
    assert!(i.file("victim.tar").is_err());
}

#[test]
fn leftovers_go_after_a_day() {
    let s = Server::new();
    let d = s.inbox();
    let (a, b, c) = ("a".repeat(64), "b".repeat(64), "c".repeat(64));
    for f in [format!("{a}.tar"), format!("{b}.tar.part"), format!("{c}.json.part"), "notes.txt".into()] {
        std::fs::write(d.join(&f), "x").unwrap();
    }
    s.take(chrono::Utc::now().timestamp());
    assert_eq!(s.inbox_files().len(), 4, "young: maybe still on its way");
    s.take(chrono::Utc::now().timestamp() + 2 * 24 * 3600);
    assert_eq!(s.inbox_files(), vec!["notes.txt"], "only dryserver's own leftovers go");
}

#[test]
fn dropped_images_come_back_and_old_ones_go_unless_they_run() {
    let s = Server::new();
    for (i, tag) in ["v1", "v2", "v3", "v4"].iter().enumerate() {
        let id = format!("sha256:{}", format!("{i}").repeat(64));
        if *tag == "v1" {
            // v1 runs in a pod here: it stays.
            s.ctr.running.lock().unwrap().push(id.clone());
        }
        s.send(&format!("localhost/shop:{tag}"), &id, 100 + i as i64);
        s.take(1000 + i as i64);
    }
    let names = |s: &Server| load(&s.n).images.iter().map(|h| h.name.clone()).collect::<Vec<_>>();
    assert_eq!(names(&s), vec!["localhost/shop:v1", "localhost/shop:v2", "localhost/shop:v3", "localhost/shop:v4"]);
    // It stops running: the oldest that does not run goes, unpinned.
    s.ctr.running.lock().unwrap().clear();
    let d = s.take(2000);
    assert_eq!(d.dropped, vec!["localhost/shop:v1"]);
    assert!(s.ctr.ran.lock().unwrap().iter().any(|l| l.ends_with("images label localhost/shop:v1 io.cri-containerd.pinned=")));
    let kept =
        std::fs::read_dir(s.n.path(STORE)).unwrap().filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().ends_with(".tar")).count();
    assert_eq!(kept, 3, "its file is gone");
    // Not knowing what runs, nothing is dropped.
    *s.ctr.blind.lock().unwrap() = true;
    s.send("localhost/shop:v5", ID, 200);
    assert!(s.take(2001).dropped.is_empty());
    *s.ctr.blind.lock().unwrap() = false;
    // The cluster dropped one: loaded again, from the kept file.
    s.ctr.loaded.lock().unwrap().remove("localhost/shop:v4");
    let d = s.take(2002);
    assert_eq!(d.reloaded, vec!["localhost/shop:v4"]);
    assert!(s.ctr.loaded.lock().unwrap().contains_key("localhost/shop:v4"));
}

#[test]
fn the_sync_starts_it_only_when_there_is_something_to_do() {
    let s = Server::new();
    let runs = |s: &Server| s.ctr.ran.lock().unwrap().iter().filter(|l| l.starts_with("systemd-run")).count();
    kick(&Ctx::new(), &s.n, 5000);
    assert_eq!(runs(&s), 0, "nothing held, nothing waiting");
    s.send("localhost/shop:v1", ID, 100);
    kick(&Ctx::new(), &s.n, 5000);
    assert_eq!(runs(&s), 1);
    assert!(
        s.ctr
            .ran
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.contains("--unit=dryserver-images") && l.contains("RuntimeMaxSec") && l.ends_with("dryserver images"))
    );
    s.take(5000);
    kick(&Ctx::new(), &s.n, 5300);
    assert_eq!(runs(&s), 1, "held, looked at five minutes ago");
    kick(&Ctx::new(), &s.n, 5600);
    assert_eq!(runs(&s), 2, "ten minutes on: is everything still loaded?");
}

#[test]
fn archives_as_the_tools_write_them() {
    let t = TempDir::new();
    let f = t.join("a.tar");
    // podman's docker archive.
    std::fs::write(&f, image(&["localhost/shop:v1"], ID, "layers")).unwrap();
    let a = archive(&f).unwrap();
    assert_eq!(a, Archive { names: vec!["localhost/shop:v1".into()], config: ID.trim_start_matches("sha256:").into() });
    archive_is(&a, "localhost/shop:v1", ID).unwrap();
    assert!(archive_is(&a, "localhost/shop:v2", ID).is_err() && archive_is(&a, "localhost/shop:v1", ID2).is_err());
    // docker 25's OCI layout: its config under blobs/, its name in the
    // index too, and "./" in front of every member.
    let hex = ID.trim_start_matches("sha256:");
    let manifest = format!(r#"[{{"Config":"blobs/sha256/{hex}","RepoTags":["localhost/shop:v1"],"Layers":[]}}]"#);
    let index =
        r#"{"manifests":[{"annotations":{"io.containerd.image.name":"localhost/shop:v1","org.opencontainers.image.ref.name":"v1"}}]}"#;
    std::fs::write(&f, tar(&[("./oci-layout", b"{}"), ("./index.json", index.as_bytes()), ("./manifest.json", manifest.as_bytes())]))
        .unwrap();
    archive_is(&archive(&f).unwrap(), "localhost/shop:v1", ID).unwrap();
    // Two images in one: not one.
    let two =
        format!(r#"[{{"Config":"{hex}.json","RepoTags":["localhost/a:v1"]}},{{"Config":"{hex}.json","RepoTags":["localhost/b:v1"]}}]"#);
    std::fs::write(&f, tar(&[("manifest.json", two.as_bytes())])).unwrap();
    assert!(archive(&f).unwrap_err().to_string().contains("holds 2 images"));
}

#[test]
fn names_and_states() {
    for ok in ["localhost/shop:v1", "localhost/a/b:2026-11-26", "localhost/x:1.2.3", "localhost/shop:latest"] {
        local_name(ok).unwrap();
    }
    for bad in [
        "shop:v1",
        "localhost/shop",
        "localhost/shop@sha256:abc",
        "localhost/Shop:v1",
        "localhost/a b:v1",
        "localhost/:v1",
        "localhost/a:v1:v2",
    ] {
        assert!(local_name(bad).is_err(), "{bad}");
    }
    assert!(is_local("localhost/shop:v1") && !is_local("ghcr.io/x/shop:v1"));
    assert_eq!(repo("localhost/shop:v1"), "localhost/shop");
    // What a server says is taken only where it makes sense.
    let s = State::parse(&format!(
        r#"{{"images":[{{"name":"localhost/shop:v1","id":"{ID}","sha256":"{}"}},{{"name":"nginx","id":"{ID}","sha256":"{}"}},{{"name":"localhost/x:v1","id":"bad","sha256":"{}"}}],"refused":[{{"sha256":"zz"}}],"marks":{{"localhost/shop:v1":5,"bad name":6}}}}"#,
        "a".repeat(64),
        "a".repeat(64),
        "a".repeat(64)
    ));
    assert_eq!((s.images.len(), s.refused.len(), s.marks.len()), (1, 0, 1));
    assert_eq!(State::parse("not json"), State::default());
}

// ---- the desktop ----

/// podman on a fake desktop: one image, saved as a small file.
pub struct FakeDesk {
    have: Option<Local>,
    dir: TempDir,
    saved: Mutex<usize>,
    pub saves_as: Mutex<Option<String>>,
}

impl FakeDesk {
    pub fn with(id: &str, arch: &str) -> FakeDesk {
        FakeDesk {
            have: Some(Local { name: "localhost/shop:v1".into(), id: id.into(), arch: arch.into(), size: 30 << 20 }),
            dir: TempDir::new(),
            saved: Mutex::new(0),
            saves_as: Mutex::new(None),
        }
    }
}

impl Desk for FakeDesk {
    fn inspect(&self, _: &Ctx, name: &str) -> Result<Option<Local>> {
        Ok(self.have.clone().filter(|l| l.name == name))
    }
    fn save(&self, _: &Ctx, name: &str, to: &Path) -> Result<()> {
        *self.saved.lock().unwrap() += 1;
        // Built again between the look and the save, when told so.
        let id = self.saves_as.lock().unwrap().clone().unwrap_or_else(|| self.have.as_ref().unwrap().id.clone());
        std::fs::write(to, image(&[name], &id, "layers")).map_err(Error::from)
    }
    fn sign(&self, doc: &str) -> Result<String> {
        ADMIN.sign(NS, doc)
    }
    fn scratch(&self) -> PathBuf {
        self.dir.join("scratch")
    }
}

/// Servers that take what they are sent, unless told otherwise.
#[derive(Default)]
pub struct FakeServers {
    pub states: Mutex<BTreeMap<String, State>>,
    pub sent: Mutex<Vec<(String, String)>>,
    /// Servers that cannot be reached.
    pub down: Mutex<Vec<String>>,
    /// Servers that refuse with this reason.
    pub refuse: Mutex<Option<String>>,
    /// Servers that never take it.
    pub slow: Mutex<bool>,
}

impl FakeServers {
    pub fn with(names: &[&str]) -> FakeServers {
        let f = FakeServers::default();
        for n in names {
            f.states.lock().unwrap().insert(n.to_string(), State::default());
        }
        f
    }
}

impl Servers for FakeServers {
    fn names(&self) -> Vec<String> {
        self.states.lock().unwrap().keys().cloned().collect()
    }
    fn state(&self, _: &Ctx, s: &str) -> Result<State> {
        if self.down.lock().unwrap().iter().any(|d| d == s) {
            bail!("cannot log in over ssh: no route to host");
        }
        Ok(self.states.lock().unwrap().get(s).cloned().unwrap_or_default())
    }
    fn send(&self, _: &Ctx, s: &str, file: &Path, sha: &str, env: &str) -> Result<()> {
        assert!(file.exists());
        let e: Envelope = serde_json::from_str(env).unwrap();
        verify(&ADMIN, &e).unwrap();
        let doc: Doc = serde_json::from_str(&e.doc).unwrap();
        assert_eq!(doc.sha256, sha);
        self.sent.lock().unwrap().push((s.to_string(), e.doc));
        Ok(())
    }
    fn wait(&self, _: &Ctx, s: &str, sha: &str, _: std::time::Duration) -> Result<Option<State>> {
        if *self.slow.lock().unwrap() {
            return Ok(None);
        }
        let (_, doc) = self.sent.lock().unwrap().iter().rev().find(|(x, _)| x == s).cloned().unwrap();
        let doc: Doc = serde_json::from_str(&doc).unwrap();
        let mut states = self.states.lock().unwrap();
        let st = states.entry(s.to_string()).or_default();
        if let Some(why) = self.refuse.lock().unwrap().clone() {
            st.refused.push(Refused { sha256: sha.into(), name: doc.name, why, at: 1 });
        } else {
            st.images.retain(|h| h.name != doc.name);
            st.images.push(Held { name: doc.name, id: doc.id, sha256: doc.sha256, size: doc.size, made: doc.made, at: 1 });
        }
        Ok(Some(st.clone()))
    }
}

#[test]
fn a_push_goes_where_the_image_is_missing() {
    let desk = FakeDesk::with(ID, "amd64");
    let servers = FakeServers::with(&["node-a", "node-b"]);
    servers.states.lock().unwrap().get_mut("node-b").unwrap().images.push(Held {
        name: "localhost/shop:v1".into(),
        id: ID.into(),
        sha256: "a".repeat(64),
        ..Held::default()
    });
    let p = plan(&Ctx::new(), &desk, &servers, "localhost/shop:v1").unwrap();
    assert_eq!((p.todo.clone(), p.have.clone()), (vec!["node-a".to_string()], vec!["node-b".to_string()]));
    assert_eq!(p.line(), "localhost/shop:v1 (30 MB): copy it to node-a");
    let mut said = Vec::new();
    send(&Ctx::new(), &desk, &servers, &p, 1234, &mut |l| said.push(l)).unwrap();
    assert!(said.iter().any(|l| l == "node-a: has localhost/shop:v1."), "{said:?}");
    let sent = servers.sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 1, "only where it was missing");
    let doc: Doc = serde_json::from_str(&sent[0].1).unwrap();
    assert_eq!((doc.name.as_str(), doc.id.as_str(), doc.made), ("localhost/shop:v1", ID, 1234));
    assert!(!desk.scratch().join(format!("{}.tar", ID.trim_start_matches("sha256:"))).exists(), "the file on the way is gone");
    // Everywhere now: nothing to do.
    let p = plan(&Ctx::new(), &desk, &servers, "localhost/shop:v1").unwrap();
    assert!(p.todo.is_empty() && p.line().contains("on every server already"));
    send(&Ctx::new(), &desk, &servers, &p, 1235, &mut |_| {}).unwrap();
    assert_eq!(*desk.saved.lock().unwrap(), 1);
}

#[test]
fn a_push_says_what_stops_it() {
    let servers = FakeServers::with(&["node-a"]);
    // Built again between the look and the save: not sent under the old id.
    let desk = FakeDesk::with(ID, "amd64");
    let p = plan(&Ctx::new(), &desk, &servers, "localhost/shop:v1").unwrap();
    *desk.saves_as.lock().unwrap() = Some(ID2.into());
    let e = send(&Ctx::new(), &desk, &servers, &p, 1, &mut |_| {}).unwrap_err().to_string();
    assert!(e.contains("changed while it was saved"), "{e}");
    assert!(servers.sent.lock().unwrap().is_empty());
    let e = plan(&Ctx::new(), &FakeDesk::with(ID, "amd64"), &servers, "localhost/blog:v1").unwrap_err().to_string();
    assert!(e.contains("no image localhost/blog:v1 on this computer; build it first: podman build -t blog:v1 ."), "{e}");
    let e = plan(&Ctx::new(), &FakeDesk::with(ID, "arm64"), &servers, "localhost/shop:v1").unwrap_err().to_string();
    assert!(e.contains("built for arm64") && e.contains("--platform linux/amd64"), "{e}");
    let e = plan(&Ctx::new(), &FakeDesk::with("1234", "amd64"), &servers, "localhost/shop:v1").unwrap_err().to_string();
    assert!(e.contains("an image id that is not one"), "{e}");
    assert!(plan(&Ctx::new(), &FakeDesk::with(ID, "amd64"), &servers, "shop:v1").is_err());
    let e = plan(&Ctx::new(), &FakeDesk::with(ID, "amd64"), &FakeServers::default(), "localhost/shop:v1").unwrap_err().to_string();
    assert!(e.contains("no server in your server list"), "{e}");
    servers.down.lock().unwrap().push("node-a".into());
    let e = plan(&Ctx::new(), &FakeDesk::with(ID, "amd64"), &servers, "localhost/shop:v1").unwrap_err().to_string();
    assert!(e.contains("cannot go to every server") && e.contains("node-a: cannot log in"), "{e}");
    servers.down.lock().unwrap().clear();
    // Refused there, or not taken in time: said.
    let desk = FakeDesk::with(ID, "amd64");
    let p = plan(&Ctx::new(), &desk, &servers, "localhost/shop:v1").unwrap();
    *servers.refuse.lock().unwrap() = Some("not enough room on this server's disk".into());
    let e = send(&Ctx::new(), &desk, &servers, &p, 1, &mut |_| {}).unwrap_err().to_string();
    assert!(e.contains("node-a refused it: not enough room"), "{e}");
    *servers.refuse.lock().unwrap() = None;
    *servers.slow.lock().unwrap() = true;
    let e = send(&Ctx::new(), &desk, &servers, &p, 1, &mut |_| {}).unwrap_err().to_string();
    assert!(e.contains("did not load it within 8 minutes"), "{e}");
    // The same file again, taken this time: the old refusal of it is not
    // read as this try's.
    *servers.slow.lock().unwrap() = false;
    send(&Ctx::new(), &desk, &servers, &p, 2, &mut |_| {}).unwrap();
}
