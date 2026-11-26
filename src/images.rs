//! Container images the admin built on the desktop, on every server, with
//! no registry in between.
//!
//! On the desktop (`dryserver app push IMAGE`, and `app deploy` for an
//! IMAGE=localhost/...): the image is saved to one file (podman or docker
//! save), its sha256 taken, and a small document about it (its name, its
//! image id, the file's sha256 and size, when) signed with the admin's
//! key, like every other order to the swarm. File and document go over
//! the admin's own SSH login on the home network into ~/.dryserver/images
//! on each server.
//!
//! On a server (`dryserver images`, started by the minute's sync when
//! there is something to take): root checks the signature with the key
//! the server trusts, the file's size and sha256, and that the disk has
//! room, keeps the file in /var/lib/dryserver-images and loads it into the
//! cluster's containerd. What each server holds is in
//! /var/lib/dryserver-images/state.json, readable by the admin's login: the
//! desktop reads it to see what is there.
//!
//! - Only names under localhost/ are taken: they can never be pulled from
//!   anywhere, so an app that names one runs only what was signed here
//!   (imagePullPolicy Never), and one that names another image is never
//!   given a local copy in its place.
//! - Nothing unsigned, too large, half sent or older than what a server
//!   holds for the name is loaded. A refused file is deleted and the
//!   reason kept in the state.
//! - What the cluster loads is checked first: the file loads as exactly
//!   the one name signed, as the build signed, so it never overwrites
//!   another image. Loaded images are pinned against the cluster's own
//!   cleanup; one dropped all the same is loaded again from the kept file.
//! - Per repository the newest KEEP names are kept, and every one a pod
//!   on the server runs. A new build under the same name replaces the
//!   name's file: going back is going to another name (tag).

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ctx::Ctx;
use crate::err::{Error, Result};
use crate::node::Node;
use crate::runner::Cmd;
use crate::signed::{Envelope, Verifier};
use crate::{apps, bail, errf, fsx};

/// The signature namespace of an image document.
pub const NS: &str = crate::signed::NS_IMAGE;
/// Under the admin's home on a server: where the desktop puts images.
pub const INBOX: &str = ".dryserver/images";
/// Where a server keeps the images it took (root only), and what it holds
/// (state.json, readable by all: no secret in it).
pub const STORE: &str = "/var/lib/dryserver-images";
pub const STATE: &str = "/var/lib/dryserver-images/state.json";
/// The largest image file a server takes.
pub const MAX_SIZE: u64 = 16 << 30;
/// Versions of one name a server keeps.
pub const KEEP: usize = 3;
/// Room left on the disk after an image is in, besides twice its size
/// (the file and what containerd unpacks).
const MARGIN: u64 = 1 << 30;
/// Documents taken per run, at most.
const PER_RUN: usize = 8;
const K3S: &str = "/usr/local/bin/k3s";

/// What the admin signed about one image file.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Doc {
    /// localhost/NAME:TAG
    pub name: String,
    /// The image's id: sha256:<64 hex>.
    pub id: String,
    /// The file's sha256, 64 hex.
    pub sha256: String,
    pub size: u64,
    /// When it was signed (unix seconds): a server takes nothing older
    /// than what it holds for the name.
    pub made: i64,
}

/// An image a server holds.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Held {
    pub name: String,
    pub id: String,
    pub sha256: String,
    pub size: u64,
    pub made: i64,
    /// When it was taken (unix seconds).
    pub at: i64,
}

/// A file a server refused, and why.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Refused {
    pub sha256: String,
    pub name: String,
    pub why: String,
    pub at: i64,
}

/// What a server holds.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    pub images: Vec<Held>,
    /// The latest refusals, newest last.
    pub refused: Vec<Refused>,
    /// For each name ever taken: the newest document's time. Nothing
    /// older is taken for it again, also once its version was dropped.
    pub marks: std::collections::BTreeMap<String, i64>,
    /// When the server last looked whether the cluster still has every
    /// image (unix seconds).
    pub checked: i64,
}

impl State {
    /// Whether the server holds this image under this name.
    pub fn has(&self, name: &str, id: &str) -> bool {
        self.images.iter().any(|h| h.name == name && h.id == id)
    }

    /// Why the server refused the file with this sha256, if it did.
    pub fn refusal(&self, sha256: &str) -> Option<&Refused> {
        self.refused.iter().rev().find(|r| r.sha256 == sha256)
    }

    /// What a server says about itself: only well-formed entries count.
    pub fn parse(text: &str) -> State {
        let mut s: State = serde_json::from_str(text).unwrap_or_default();
        s.images.retain(|h| local_name(&h.name).is_ok() && valid_id(&h.id) && valid_sha(&h.sha256));
        s.refused.retain(|r| valid_sha(&r.sha256));
        s.marks.retain(|name, _| local_name(name).is_ok());
        s
    }
}

/// An image name that only exists where dryserver put it.
pub fn is_local(name: &str) -> bool {
    name.starts_with("localhost/")
}

/// localhost/NAME:TAG.
pub fn local_name(name: &str) -> Result<()> {
    apps::valid_image(name)?;
    let Some(rest) = name.strip_prefix("localhost/") else { bail!("{name}: an image of your own is named localhost/NAME:TAG") };
    let (repo, tag) = rest.rsplit_once(':').unwrap_or((rest, ""));
    if rest.contains('@') || tag.is_empty() || tag.contains('/') || repo.is_empty() || repo.contains(':') || repo.ends_with('/') {
        bail!("{name}: name it with a tag, like localhost/{}:v1", rest.split([':', '@']).next().unwrap_or(rest));
    }
    Ok(())
}

pub fn valid_id(id: &str) -> bool {
    id.strip_prefix("sha256:").is_some_and(valid_sha)
}

pub fn valid_sha(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Doc {
    pub fn check(&self) -> Result<()> {
        local_name(&self.name)?;
        if !valid_id(&self.id) || !valid_sha(&self.sha256) {
            bail!("the document's id or sha256 is not one");
        }
        if self.size == 0 || self.size > MAX_SIZE {
            bail!("{}: {} bytes; an image file is at most {} GiB", self.name, self.size, MAX_SIZE >> 30);
        }
        Ok(())
    }
}

/// The repository of a name: localhost/shop of localhost/shop:v1.
fn repo(name: &str) -> &str {
    name.rsplit_once(':').map_or(name, |(r, _)| r)
}

// ---- image archives ----

/// What an image archive (a docker archive, or the OCI layout docker 25
/// saves) says it holds: the names it loads as and the id of its build.
#[derive(Debug, Clone, PartialEq)]
pub struct Archive {
    pub names: Vec<String>,
    /// The build's id, 64 hex.
    pub config: String,
}

/// The members of a tar file named in want (top level, "./" or not),
/// each at most 1 MiB. A member listed twice is an error: what the
/// cluster's loader would read is not known then.
fn tar_members(path: &Path, want: &[&str]) -> Result<std::collections::BTreeMap<String, Vec<u8>>> {
    use std::io::{Seek, SeekFrom};
    let mut f = std::fs::File::open(path).map_err(|e| Error::from(e).wrap(path.display()))?;
    let mut out = std::collections::BTreeMap::new();
    let mut next_name: Option<String> = None;
    let octal = |b: &[u8]| -> Result<u64> {
        if b.first().is_some_and(|c| c & 0x80 != 0) {
            // base-256, for members over 8 GiB
            let mut n: u64 = 0;
            for (i, c) in b.iter().enumerate() {
                n = n.checked_mul(256).ok_or_else(|| errf!("a tar size too large"))? + u64::from(if i == 0 { c & 0x7f } else { *c });
            }
            return Ok(n);
        }
        let t: String = b.iter().take_while(|c| **c != 0).map(|c| *c as char).collect();
        let t = t.trim();
        if t.is_empty() { Ok(0) } else { u64::from_str_radix(t, 8).map_err(|_| errf!("not a tar file")) }
    };
    let mut header = [0u8; 512];
    loop {
        if f.read(&mut header[..1])? == 0 {
            break;
        }
        f.read_exact(&mut header[1..]).map_err(|_| errf!("a tar file cut off"))?;
        if header.iter().all(|b| *b == 0) {
            break;
        }
        let cstr = |b: &[u8]| String::from_utf8_lossy(&b[..b.iter().position(|c| *c == 0).unwrap_or(b.len())]).into_owned();
        let size = octal(&header[124..136])?;
        let kind = header[156];
        let mut name = cstr(&header[0..100]);
        if &header[257..262] == b"ustar" {
            let prefix = cstr(&header[345..500]);
            if !prefix.is_empty() {
                name = format!("{prefix}/{name}");
            }
        }
        let padded = size.div_ceil(512) * 512;
        let read_data = |f: &mut std::fs::File, limit: u64| -> Result<Vec<u8>> {
            if size > limit {
                bail!("a tar member larger than expected");
            }
            let mut d = vec![0u8; size as usize];
            f.read_exact(&mut d).map_err(|_| errf!("a tar file cut off"))?;
            f.seek(SeekFrom::Current((padded - size) as i64))?;
            Ok(d)
        };
        match kind {
            // A long name (GNU) or extended header (pax) for the next member.
            b'L' => {
                let d = read_data(&mut f, 1 << 16)?;
                next_name = Some(cstr(&d));
                continue;
            }
            b'x' => {
                let d = read_data(&mut f, 1 << 20)?;
                for rec in String::from_utf8_lossy(&d).lines() {
                    if let Some((_, kv)) = rec.split_once(' ')
                        && let Some(p) = kv.strip_prefix("path=")
                    {
                        next_name = Some(p.to_string());
                    }
                }
                continue;
            }
            _ => {}
        }
        if let Some(n) = next_name.take() {
            name = n;
        }
        let clean = name.trim_start_matches("./").to_string();
        if (kind == b'0' || kind == 0) && want.contains(&clean.as_str()) {
            if out.contains_key(&clean) {
                bail!("the archive holds {clean} twice");
            }
            let d = read_data(&mut f, 1 << 20)?;
            out.insert(clean, d);
        } else {
            f.seek(SeekFrom::Current(padded as i64))?;
        }
    }
    Ok(out)
}

/// What the archive at path loads as: its manifest.json, and its
/// index.json when it has one (an OCI layout), must agree on one image.
pub fn archive(path: &Path) -> Result<Archive> {
    #[derive(Deserialize)]
    struct Entry {
        #[serde(rename = "Config")]
        config: String,
        #[serde(rename = "RepoTags", default)]
        repo_tags: Option<Vec<String>>,
    }
    let m = tar_members(path, &["manifest.json", "index.json"]).map_err(|e| e.wrap("not an image archive"))?;
    let manifest = m.get("manifest.json").ok_or_else(|| errf!("not an image archive (it has no manifest.json)"))?;
    let entries: Vec<Entry> = serde_json::from_slice(manifest).map_err(|_| errf!("the archive's manifest.json is not one"))?;
    let [e] = entries.as_slice() else { bail!("the archive holds {} images; one is wanted", entries.len()) };
    let names = e.repo_tags.clone().unwrap_or_default();
    let hex = e.config.trim_end_matches(".json").rsplit('/').next().unwrap_or("").to_string();
    if !valid_sha(&hex) {
        bail!("the archive's manifest.json names no build");
    }
    // An OCI layout names images in its index, for loaders that read it.
    if let Some(index) = m.get("index.json") {
        let v: serde_json::Value = serde_json::from_slice(index).map_err(|_| errf!("the archive's index.json is not one"))?;
        let list = v["manifests"].as_array().cloned().unwrap_or_default();
        if list.len() != 1 {
            bail!("the archive's index.json lists {} images; one is wanted", list.len());
        }
        let a = &list[0]["annotations"];
        if let Some(n) = a["io.containerd.image.name"].as_str()
            && !names.iter().any(|x| x == n)
        {
            bail!("the archive's index.json names {n}, its manifest.json {}", names.join(", "));
        }
        if let Some(r) = a["org.opencontainers.image.ref.name"].as_str()
            && !names.iter().any(|x| x == r || x.rsplit_once(':').is_some_and(|(_, t)| t == r))
        {
            bail!("the archive's index.json names {r}, its manifest.json {}", names.join(", "));
        }
    }
    Ok(Archive { names, config: hex })
}

/// Whether the archive is exactly this image: its one name, its build.
pub fn archive_is(a: &Archive, name: &str, id: &str) -> Result<()> {
    if a.names != [name.to_string()] {
        bail!("the file loads as {}, not as {name} alone", if a.names.is_empty() { "no name".to_string() } else { a.names.join(", ") });
    }
    if format!("sha256:{}", a.config) != id {
        bail!("the file holds another build than the one signed");
    }
    Ok(())
}

// ---- on a server ----

/// The admin's inbox, open: every look and change in it goes through this
/// directory itself, never through its path again, so a link put in its
/// place later leads nowhere.
struct Inbox {
    fd: std::os::fd::OwnedFd,
    uid: u32,
}

fn open_dir(at: Option<&std::os::fd::OwnedFd>, path: &Path) -> Option<(std::os::fd::OwnedFd, libc::stat)> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: c is a valid C string; the fd returned is owned below.
    let fd = unsafe {
        match at {
            Some(d) => libc::openat(d.as_raw_fd(), c.as_ptr(), flags),
            None => libc::open(c.as_ptr(), flags),
        }
    };
    if fd < 0 {
        return None;
    }
    // SAFETY: fd is a new descriptor this function owns.
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    // SAFETY: st is a plain struct fstat fills in.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return None;
    }
    Some((fd, st))
}

impl Inbox {
    /// The admin's inbox, if it is a plain directory of the admin's all
    /// the way (root reads and deletes in it).
    fn open(n: &Node) -> Option<Inbox> {
        let home = n.path(&format!("/home/{}", n.cfg.username));
        let (mut fd, hst) = open_dir(None, &home)?;
        for part in INBOX.split('/') {
            let (next, st) = open_dir(Some(&fd), Path::new(part))?;
            if st.st_uid != hst.st_uid || st.st_mode & 0o022 != 0 {
                return None;
            }
            fd = next;
        }
        Some(Inbox { fd, uid: hst.st_uid })
    }

    fn names(&self) -> Vec<String> {
        use std::os::fd::AsRawFd;
        // The directory this descriptor holds, whatever its path is now.
        std::fs::read_dir(format!("/proc/self/fd/{}", self.fd.as_raw_fd()))
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| !n.contains('/'))
            .collect()
    }

    /// The documents waiting: <sha256>.json.
    fn docs(&self) -> Vec<String> {
        let mut d: Vec<String> =
            self.names().iter().filter_map(|n| n.strip_suffix(".json")).filter(|s| valid_sha(s)).map(String::from).collect();
        d.sort();
        d
    }

    /// Opens a plain file of the admin's in it, never through a link.
    fn file(&self, name: &str) -> Result<(std::fs::File, u64)> {
        use std::os::fd::{AsRawFd, FromRawFd};
        let c = std::ffi::CString::new(name).map_err(|_| errf!("not a file name"))?;
        // SAFETY: a valid C string relative to a directory fd we hold.
        let fd = unsafe {
            libc::openat(self.fd.as_raw_fd(), c.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        };
        if fd < 0 {
            return Err(Error::from(std::io::Error::last_os_error()).wrap(name));
        }
        // SAFETY: fd is a new descriptor owned by the File.
        let f = unsafe { std::fs::File::from_raw_fd(fd) };
        use std::os::unix::fs::MetadataExt;
        let m = f.metadata()?;
        if !m.is_file() || m.uid() != self.uid {
            bail!("{name}: not a plain file of the admin's");
        }
        Ok((f, m.len()))
    }

    fn unlink(&self, name: &str) {
        use std::os::fd::AsRawFd;
        if let Ok(c) = std::ffi::CString::new(name) {
            // SAFETY: a valid C string relative to a directory fd we hold.
            unsafe { libc::unlinkat(self.fd.as_raw_fd(), c.as_ptr(), 0) };
        }
    }

    /// How old a file in it is (seconds), never through a link.
    fn age(&self, name: &str, now: i64) -> Option<i64> {
        use std::os::fd::AsRawFd;
        let c = std::ffi::CString::new(name).ok()?;
        // SAFETY: st is a plain struct fstatat fills in.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatat(self.fd.as_raw_fd(), c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
            return None;
        }
        Some(now - st.st_mtime)
    }

    /// Files left by a send that stopped half way (a file without its
    /// document, a part): gone after a day.
    fn sweep(&self, now: i64) {
        let names = self.names();
        for n in &names {
            let sha = n.strip_suffix(".tar.part").or_else(|| n.strip_suffix(".json.part")).or_else(|| n.strip_suffix(".tar"));
            let Some(sha) = sha.filter(|s| valid_sha(s)) else { continue };
            if n.ends_with(".tar") && names.contains(&format!("{sha}.json")) {
                continue;
            }
            if self.age(n, now).is_some_and(|a| a > 24 * 3600) {
                self.unlink(n);
            }
        }
    }

    /// Reads a document, at most 64 KiB whatever the file does meanwhile.
    fn read_doc(&self, sha: &str) -> Result<Envelope> {
        let (f, _) = self.file(&format!("{sha}.json"))?;
        let mut text = String::new();
        f.take((64 << 10) + 1).read_to_string(&mut text).map_err(|_| errf!("the document is not text"))?;
        if text.len() > 64 << 10 {
            bail!("the document is larger than any is");
        }
        serde_json::from_str(&text).map_err(|_| errf!("not a signed document"))
    }
}

/// Whether the inbox has a document waiting: cheap, for the sync to ask
/// every minute.
pub fn waiting(n: &Node) -> bool {
    Inbox::open(n).is_some_and(|i| !i.docs().is_empty())
}

/// How often a server looks whether the cluster still has every image.
const CHECK_EVERY: i64 = 10 * 60;

/// Started by the sync when there is something to do: a document in the
/// inbox, or every ten minutes a look whether the cluster still has every
/// image. Runs apart from the sync (its own unit), since loading a large
/// image takes longer than a sync may. now: unix seconds.
pub fn kick(ctx: &Ctx, n: &Node, now: i64) {
    let st = load(n);
    let due = !st.images.is_empty() && now - st.checked >= CHECK_EVERY;
    if !due && !waiting(n) {
        return;
    }
    // One at a time: a second start while one runs fails, which is fine.
    let _ = n.run.ok(
        ctx,
        &Cmd::new(
            "systemd-run",
            &["--unit=dryserver-images", "--collect", "--no-block", "--property=RuntimeMaxSec=30min", "/usr/local/bin/dryserver", "images"],
        )
        .quiet(),
    );
}

/// What this server holds.
pub fn load(n: &Node) -> State {
    State::parse(&fsx::read_or_empty(n.path(STATE)))
}

fn save(n: &Node, s: &State) -> Result<()> {
    let path = n.path(STATE);
    fsx::mkdir_all(n.path(STORE), 0o711)?;
    fsx::chmod(n.path(STORE), 0o711)?;
    let tmp = path.with_extension("json.tmp");
    let _ = std::fs::remove_file(&tmp);
    fsx::write_new(&tmp, serde_json::to_string_pretty(s)? + "\n", 0o644)?;
    fsx::rename(&tmp, &path)
}

/// What one run did, for its log.
#[derive(Debug, Default, PartialEq)]
pub struct Done {
    pub taken: Vec<String>,
    pub refused: Vec<String>,
    pub reloaded: Vec<String>,
    pub dropped: Vec<String>,
}

/// What became of one document.
enum Took {
    Loaded(Doc),
    /// This very file is held and loaded already (sent again).
    Held(Doc),
}

/// Room an image needs on the disk: its kept file, containerd's copy and
/// what containerd unpacks, plus what keeps the cluster from cleaning up
/// on its own (it starts at 85% full) or moving pods off (85%).
fn room(n: &Node, size: u64) -> Result<()> {
    let (total, free) = fsx::space(n.path("/var/lib"))?;
    let need = size.saturating_mul(3).saturating_add(MARGIN.max(total / 5));
    if free < need {
        bail!("not enough room on this server's disk: {} MiB free, {} MiB needed", free >> 20, need >> 20);
    }
    Ok(())
}

/// Takes what waits in the inbox, loads again what the cluster dropped,
/// and keeps the newest KEEP versions of each repository that no pod
/// here runs. now: unix seconds.
pub fn take(ctx: &Ctx, n: &Node, now: i64) -> Result<Done> {
    fsx::mkdir_all(n.path(STORE), 0o711)?;
    let _lock = fsx::lock(n.path(&format!("{STORE}/.lock")))?;
    let mut st = load(n);
    let mut done = Done::default();
    if let Some(i) = Inbox::open(n) {
        i.sweep(now);
        for sha in i.docs().into_iter().take(PER_RUN) {
            ctx.check()?;
            match take_one(ctx, n, &i, &sha, &st, now) {
                Ok(Took::Loaded(doc)) | Ok(Took::Held(doc)) => {
                    st.images.retain(|h| h.name != doc.name);
                    let mark = st.marks.entry(doc.name.clone()).or_insert(doc.made);
                    *mark = (*mark).max(doc.made);
                    done.taken.push(doc.name.clone());
                    st.images.push(Held { name: doc.name, id: doc.id, sha256: doc.sha256, size: doc.size, made: doc.made, at: now });
                }
                Err(e) => {
                    let name = i
                        .read_doc(&sha)
                        .ok()
                        .and_then(|env| serde_json::from_str::<Doc>(&env.doc).ok())
                        .map(|d| d.name)
                        .unwrap_or_default();
                    let why = e.to_string();
                    done.refused.push(format!("{sha}: {why}"));
                    st.refused.push(Refused { sha256: sha.clone(), name, why, at: now });
                    let keep = st.refused.len().saturating_sub(20);
                    st.refused.drain(..keep);
                }
            }
            // What became of it is saved first; only then is it taken out
            // of the inbox (the desktop waits for that), taken or refused:
            // a refused file is not tried again and again.
            save(n, &st)?;
            i.unlink(&format!("{sha}.json"));
            i.unlink(&format!("{sha}.tar"));
        }
    }
    // The cluster's own garbage collection may have dropped an image (it
    // keeps pinned ones, but the pin may be missing): back from the kept
    // file.
    if !st.images.is_empty() {
        let have = cluster_images(ctx, n)?;
        for h in &st.images {
            if have.contains(&h.name) {
                continue;
            }
            let file = n.path(&format!("{STORE}/{}.tar", h.sha256));
            match room(n, h.size).and_then(|_| load_into_cluster(ctx, n, &file, &h.name, &h.id)) {
                Ok(()) => done.reloaded.push(h.name.clone()),
                Err(e) => done.refused.push(format!("{}: could not be loaded again: {e}", h.name)),
            }
        }
        st.checked = now;
        save(n, &st)?;
    }
    // Per repository the newest KEEP names are kept, and every one a pod
    // here runs. Without knowing what runs, nothing is dropped.
    if let Ok(running) = in_use(ctx, n) {
        let mut by_repo: std::collections::BTreeMap<&str, Vec<&Held>> = std::collections::BTreeMap::new();
        for h in &st.images {
            by_repo.entry(repo(&h.name)).or_default().push(h);
        }
        let mut drop: BTreeSet<String> = BTreeSet::new();
        for list in by_repo.values_mut() {
            list.sort_by_key(|h| std::cmp::Reverse(h.made));
            for h in list.iter().skip(KEEP) {
                if !running.contains(&h.id) && !running.contains(&h.name) {
                    drop.insert(h.name.clone());
                }
            }
        }
        if !drop.is_empty() {
            for name in &drop {
                // No longer kept by dryserver: the cluster may clean it up.
                let _ = n.run.ok(ctx, &Cmd::new(K3S, &["ctr", "-n", "k8s.io", "images", "label", name, &format!("{PIN}=")]).quiet());
            }
            st.images.retain(|h| !drop.contains(&h.name));
            done.dropped.extend(drop);
            save(n, &st)?;
        }
    }
    let keep: BTreeSet<String> = st.images.iter().map(|h| format!("{}.tar", h.sha256)).collect();
    for e in std::fs::read_dir(n.path(STORE)).into_iter().flatten().flatten() {
        let f = e.file_name().to_string_lossy().into_owned();
        if f.ends_with(".tar") && !keep.contains(&f) || f.ends_with(".tar.tmp") {
            let _ = std::fs::remove_file(e.path());
        }
    }
    Ok(done)
}

/// One document and its file: checked, kept, loaded.
fn take_one(ctx: &Ctx, n: &Node, i: &Inbox, sha: &str, st: &State, now: i64) -> Result<Took> {
    let env = i.read_doc(sha)?;
    verify(n.verifier.as_ref(), &env)?;
    let doc: Doc = serde_json::from_str(&env.doc).map_err(|_| errf!("the signed document is not about an image"))?;
    doc.check()?;
    if doc.sha256 != sha {
        bail!("the document is about another file");
    }
    if doc.made > now + crate::signed::ADMIN_WINDOW_SECS {
        bail!(
            "{}: signed {} minutes ahead of this server's clock; set the desktop's clock right and send it again",
            doc.name,
            (doc.made - now) / 60
        );
    }
    if let Some(mark) = st.marks.get(&doc.name)
        && doc.made < *mark
    {
        bail!("{}: older than a version this server took (signed {} s before it)", doc.name, mark - doc.made);
    }
    // This very file again (a send that was repeated): nothing to do.
    if st.images.iter().any(|h| h.name == doc.name && h.sha256 == doc.sha256 && h.id == doc.id)
        && cluster_images(ctx, n)?.contains(&doc.name)
    {
        return Ok(Took::Held(doc));
    }
    let (mut src, size) = i.file(&format!("{sha}.tar")).map_err(|e| e.wrap("the image file"))?;
    if size != doc.size {
        bail!("the image file has {size} bytes, the document says {}: it was not sent whole", doc.size);
    }
    room(n, size)?;
    // Copied while its sha256 is taken: what is loaded is what was hashed.
    let kept = n.path(&format!("{STORE}/{sha}.tar"));
    let tmp = kept.with_extension("tar.tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut out = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)
    }
    .map_err(|e| Error::from(e).wrap(tmp.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut copied = 0u64;
    let res = (|| {
        loop {
            ctx.check()?;
            let k = src.read(&mut buf)?;
            if k == 0 {
                break;
            }
            copied += k as u64;
            if copied > size {
                bail!("the image file grew while it was read");
            }
            h.update(&buf[..k]);
            out.write_all(&buf[..k])?;
        }
        out.sync_all()?;
        if fsx::hex(&h.finalize()) != doc.sha256 || copied != size {
            bail!("the image file is not the one signed (its sha256 differs)");
        }
        // What the cluster's loader will read: exactly this one name, this
        // build. Nothing else is overwritten, nothing is named otherwise.
        archive_is(&archive(&tmp)?, &doc.name, &doc.id)
    })();
    if let Err(e) = res {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    fsx::rename(&tmp, &kept)?;
    load_into_cluster(ctx, n, &kept, &doc.name, &doc.id)?;
    Ok(Took::Loaded(doc))
}

/// Checks the admin's signature on an image document.
pub fn verify(v: &dyn Verifier, env: &Envelope) -> Result<()> {
    v.verify(NS, &env.doc, &env.sig).map_err(|e| e.wrap("not signed by the admin"))
}

/// containerd keeps images with this label from the cluster's cleanup.
const PIN: &str = "io.cri-containerd.pinned";

/// Loads a kept file into the cluster, pins it, and checks the name now
/// leads to that build.
fn load_into_cluster(ctx: &Ctx, n: &Node, file: &Path, name: &str, id: &str) -> Result<()> {
    let f = file.display().to_string();
    n.run
        .ok(ctx, &Cmd::new(K3S, &["ctr", "-n", "k8s.io", "images", "import", &f]).quiet())
        .map_err(|e| e.wrap("loading it into the cluster"))?;
    if let Err(e) = n.run.ok(ctx, &Cmd::new(K3S, &["ctr", "-n", "k8s.io", "images", "label", name, &format!("{PIN}=pinned")]).quiet()) {
        eprintln!("dryserver: {name} is loaded but not pinned (the cluster may clean it up; it is loaded again then): {e}");
    }
    let out = n.run.output(ctx, &Cmd::new(K3S, &["crictl", "inspecti", "-o", "json", name]).quiet().stdout_only())?;
    let v: serde_json::Value = serde_json::from_str(&out).map_err(|_| errf!("the cluster said nothing readable about {name}"))?;
    if v["status"]["id"].as_str() != Some(id) {
        bail!("after loading, the cluster's {name} is not this build");
    }
    Ok(())
}

/// The image names the cluster's containerd has on this server.
fn cluster_images(ctx: &Ctx, n: &Node) -> Result<BTreeSet<String>> {
    let out = n.run.output(ctx, &Cmd::new(K3S, &["ctr", "-n", "k8s.io", "images", "ls", "-q"]).quiet().stdout_only())?;
    Ok(out.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect())
}

/// The images (ids and names) the containers on this server run.
fn in_use(ctx: &Ctx, n: &Node) -> Result<BTreeSet<String>> {
    let out = n.run.output(ctx, &Cmd::new(K3S, &["crictl", "ps", "-a", "-o", "json"]).quiet().stdout_only())?;
    let v: serde_json::Value = serde_json::from_str(&out).map_err(|_| errf!("the cluster's list of containers is not one"))?;
    let mut s = BTreeSet::new();
    for c in v["containers"].as_array().cloned().unwrap_or_default() {
        for k in [&c["imageRef"], &c["image"]["image"]] {
            if let Some(x) = k.as_str() {
                s.insert(x.to_string());
            }
        }
    }
    Ok(s)
}

#[cfg(test)]
pub mod tests;

// ---- on the desktop ----

/// An image on this desktop.
#[derive(Debug, Clone, PartialEq)]
pub struct Local {
    pub name: String,
    pub id: String,
    pub arch: String,
    pub size: u64,
}

/// What the desktop does with its images.
pub trait Desk {
    /// The image of that name in podman (or docker), if there is one.
    fn inspect(&self, ctx: &Ctx, name: &str) -> Result<Option<Local>>;
    /// Saves it to one file.
    fn save(&self, ctx: &Ctx, name: &str, to: &Path) -> Result<()>;
    /// Signs a document with the admin's key (NS).
    fn sign(&self, doc: &str) -> Result<String>;
    /// Where the file is made, on the way to the servers.
    fn scratch(&self) -> PathBuf;
}

/// The servers, over the admin's own login on the home network.
pub trait Servers {
    /// Every server apps run on, by name.
    fn names(&self) -> Vec<String>;
    fn state(&self, ctx: &Ctx, server: &str) -> Result<State>;
    /// Puts the file and its signed document in the server's inbox.
    fn send(&self, ctx: &Ctx, server: &str, file: &Path, sha256: &str, envelope: &str) -> Result<()>;
    /// What the server holds once it took or refused the file (its
    /// document is gone from the inbox); None when it did neither within
    /// max. A refusal from an earlier try of the same file is never taken
    /// for this one's.
    fn wait(&self, ctx: &Ctx, server: &str, sha256: &str, max: std::time::Duration) -> Result<Option<State>>;
}

/// What a push would do.
#[derive(Debug, Clone, PartialEq)]
pub struct Push {
    pub local: Local,
    /// Servers that hold this image already.
    pub have: Vec<String>,
    /// Servers it goes to.
    pub todo: Vec<String>,
}

impl Push {
    /// One line for a preview.
    pub fn line(&self) -> String {
        let mb = (self.local.size >> 20).max(1);
        if self.todo.is_empty() {
            format!("{} ({mb} MB) is on every server already", self.local.name)
        } else {
            format!("{} ({mb} MB): copy it to {}", self.local.name, self.todo.join(", "))
        }
    }
}

/// How long a server may take to load an image it was sent: its sync
/// looks every minute, and a large image takes a while.
pub const WAIT: std::time::Duration = std::time::Duration::from_secs(8 * 60);

/// Which servers need the image of that name, as this desktop has it now.
/// A server that cannot be asked is an error: an app that may land there
/// would not start.
pub fn plan(ctx: &Ctx, desk: &dyn Desk, servers: &dyn Servers, name: &str) -> Result<Push> {
    local_name(name)?;
    let local = desk.inspect(ctx, name)?.ok_or_else(|| {
        let short = name.strip_prefix("localhost/").unwrap_or(name);
        errf!("there is no image {name} on this computer; build it first: podman build -t {short} . (or docker build -t {name} .)")
    })?;
    if !valid_id(&local.id) {
        bail!("{name}: podman or docker gave an image id that is not one ({})", local.id);
    }
    if local.arch != "amd64" {
        bail!("{name} is built for {}; the servers are amd64 (x86-64): build it with --platform linux/amd64", local.arch);
    }
    if local.size > MAX_SIZE {
        bail!("{name} is {} GiB; a server takes at most {} GiB", local.size >> 30, MAX_SIZE >> 30);
    }
    let names = servers.names();
    if names.is_empty() {
        bail!("no server in your server list: approve a server, then run dryserver ssh-config");
    }
    let (mut have, mut todo, mut down) = (Vec::new(), Vec::new(), Vec::new());
    for s in names {
        match servers.state(ctx, &s) {
            Ok(st) if st.has(name, &local.id) => have.push(s),
            Ok(_) => todo.push(s),
            Err(e) => down.push(format!("{s}: {e}")),
        }
    }
    if !down.is_empty() {
        bail!("{name} cannot go to every server, so an app could not start on some: {}", down.join("; "));
    }
    Ok(Push { local, have, todo })
}

/// Copies the image to the servers of p.todo and waits until each loaded
/// it. say: one line of progress. now: unix seconds, for the document.
pub fn send(ctx: &Ctx, desk: &dyn Desk, servers: &dyn Servers, p: &Push, now: i64, say: &mut dyn FnMut(String)) -> Result<()> {
    if p.todo.is_empty() {
        return Ok(());
    }
    let dir = desk.scratch();
    fsx::mkdir_all(&dir, 0o700)?;
    let file = dir.join(format!("{}.tar", p.local.id.trim_start_matches("sha256:")));
    let _ = std::fs::remove_file(&file);
    say(format!("Saving {} to one file...", p.local.name));
    let res = (|| {
        desk.save(ctx, &p.local.name, &file)?;
        // The build looked at is the one in the file: one built again
        // between the look and the save is not sent under the old id.
        archive_is(&archive(&file)?, &p.local.name, &p.local.id)
            .map_err(|e| e.wrap(format!("{} changed while it was saved (built again?); run it again", p.local.name)))?;
        let (sha256, size) = hash_file(ctx, &file)?;
        let doc = Doc { name: p.local.name.clone(), id: p.local.id.clone(), sha256: sha256.clone(), size, made: now };
        doc.check()?;
        let text = serde_json::to_string(&doc)?;
        let env = serde_json::to_string(&Envelope { sig: desk.sign(&text)?, doc: text })?;
        for s in &p.todo {
            say(format!("Copying it to {s} ({} MB)...", (size >> 20).max(1)));
            servers.send(ctx, s, &file, &sha256, &env).map_err(|e| e.wrap(s))?;
        }
        let mut failed = Vec::new();
        for s in &p.todo {
            say(format!("Waiting for {s} to load it (it looks every minute)..."));
            match servers.wait(ctx, s, &sha256, WAIT) {
                Ok(Some(st)) if st.has(&doc.name, &doc.id) => say(format!("{s}: has {}.", doc.name)),
                Ok(Some(st)) => match st.refusal(&sha256) {
                    Some(r) => failed.push(format!("{s} refused it: {}", r.why)),
                    None => failed.push(format!("{s} took the file but does not hold {} (sudo dryserver images there says why)", doc.name)),
                },
                Ok(None) => failed.push(format!(
                    "{s} did not load it within {} minutes (is it on, and does it run this dryserver? sudo dryserver images there says why)",
                    WAIT.as_secs() / 60
                )),
                Err(e) => failed.push(format!("{s}: {e}")),
            }
        }
        if !failed.is_empty() {
            bail!("{} is not on every server: {}", doc.name, failed.join("; "));
        }
        Ok(())
    })();
    let _ = std::fs::remove_file(&file);
    res
}

fn hash_file(ctx: &Ctx, path: &Path) -> Result<(String, u64)> {
    let mut f = std::fs::File::open(path).map_err(|e| Error::from(e).wrap(path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut n = 0u64;
    loop {
        ctx.check()?;
        let k = f.read(&mut buf)?;
        if k == 0 {
            break;
        }
        n += k as u64;
        h.update(&buf[..k]);
    }
    Ok((fsx::hex(&h.finalize()), n))
}

/// podman, or docker when podman does not have the image.
pub struct Tools {
    pub signer: Box<dyn crate::signed::Signer>,
    pub scratch: PathBuf,
}

/// The id of an image in a tool, if the tool has it.
fn id_in(tool: &str, name: &str) -> Option<String> {
    let out = std::process::Command::new(tool)
        .args(["image", "inspect", "--format", "{{.Id}}", name])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && !id.is_empty()).then(|| if id.starts_with("sha256:") { id } else { format!("sha256:{id}") })
}

/// The tool that has the image of that name. docker names an image built
/// as shop:v1 just that: it is tagged localhost/shop:v1 again each time,
/// so a new build under that tag is the one sent. When podman and docker
/// both have the name as different builds, nobody can tell which is
/// meant: that is an error.
fn find(ctx: &Ctx, name: &str) -> Result<Option<&'static str>> {
    ctx.check()?;
    let short = name.strip_prefix("localhost/").unwrap_or(name);
    if let Some(built) = id_in("docker", short)
        && id_in("docker", name).as_deref() != Some(built.as_str())
    {
        let ok = std::process::Command::new("docker").args(["tag", short, name]).status().is_ok_and(|s| s.success());
        if !ok {
            bail!("docker tag {short} {name} did not work");
        }
    }
    match (id_in("podman", name), id_in("docker", name)) {
        (Some(p), Some(d)) if p != d => bail!(
            "podman and docker both have {name}, as different builds; remove the one you do not use (podman rmi {name}, or docker rmi {name})"
        ),
        (Some(_), _) => Ok(Some("podman")),
        (None, Some(_)) => Ok(Some("docker")),
        (None, None) => Ok(None),
    }
}

impl Desk for Tools {
    fn inspect(&self, ctx: &Ctx, name: &str) -> Result<Option<Local>> {
        let Some(tool) = find(ctx, name)? else { return Ok(None) };
        let n = name.to_string();
        let out = std::process::Command::new(tool)
            .args(["image", "inspect", "--format", "{{.Id}}|{{.Architecture}}|{{.Size}}", &n])
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| Error::from(e).wrap(tool))?;
        if !out.status.success() {
            bail!("{tool} image inspect {n}: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let mut f = text.splitn(3, '|');
        let (id, arch, size) = (f.next().unwrap_or(""), f.next().unwrap_or(""), f.next().unwrap_or(""));
        let id = if id.starts_with("sha256:") { id.to_string() } else { format!("sha256:{id}") };
        Ok(Some(Local { name: name.into(), id, arch: arch.into(), size: size.parse().unwrap_or(0) }))
    }

    fn save(&self, ctx: &Ctx, name: &str, to: &Path) -> Result<()> {
        let Some(tool) = find(ctx, name)? else { bail!("{name} is gone from this computer") };
        let n = name.to_string();
        let to_s = to.display().to_string();
        // A docker archive: it carries the name (localhost/...), which
        // the cluster's containerd keeps.
        let mut args = vec!["save", "-o", &to_s];
        if tool == "podman" {
            args.extend(["--format", "docker-archive"]);
        }
        args.push(&n);
        let out = std::process::Command::new(tool)
            .args(&args)
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| Error::from(e).wrap(tool))?;
        if !out.status.success() {
            bail!("{tool} save {n}: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(())
    }

    fn sign(&self, doc: &str) -> Result<String> {
        self.signer.sign(NS, doc)
    }

    fn scratch(&self) -> PathBuf {
        self.scratch.clone()
    }
}

/// The servers of the desktop's server list (~/.ssh/config.d/dryserver,
/// written by dryserver ssh-config), reached on the home network.
pub struct Ssh {
    pub servers: Vec<crate::quarantine::Remote>,
    pub known_hosts: String,
}

impl Ssh {
    fn command(&self, server: &str, remote: &str) -> Result<std::process::Command> {
        let r = self.servers.iter().find(|r| r.name == server).ok_or_else(|| errf!("{server} is not in your server list"))?;
        let mut c = std::process::Command::new("ssh");
        for o in [
            "BatchMode=yes",
            "ConnectTimeout=8",
            "ProxyJump=none",
            "ForwardAgent=no",
            "StrictHostKeyChecking=yes",
            "GlobalKnownHostsFile=/dev/null",
            "ServerAliveInterval=10",
            "ServerAliveCountMax=3",
            "LogLevel=ERROR",
        ] {
            c.args(["-o", o]);
        }
        c.args(["-o", &format!("UserKnownHostsFile={}", self.known_hosts), "-o", &format!("HostKeyAlias={}", r.name)]);
        c.args(["-p", &r.port]);
        if !r.user.is_empty() {
            c.args(["-l", &r.user]);
        }
        c.arg(&r.addr).arg(remote);
        Ok(c)
    }

    fn run(&self, server: &str, remote: &str, stdin: std::process::Stdio) -> Result<String> {
        let out = self.command(server, remote)?.stdin(stdin).output().map_err(|e| Error::from(e).wrap("ssh"))?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
        let msg: String = String::from_utf8_lossy(&out.stderr).chars().filter(|c| !c.is_control()).take(300).collect();
        if out.status.code() == Some(255) {
            bail!("cannot log in over ssh: {}", msg.trim());
        }
        bail!("{}", msg.trim())
    }
}

impl Servers for Ssh {
    fn names(&self) -> Vec<String> {
        self.servers.iter().filter(|r| !r.coordinator).map(|r| r.name.clone()).collect()
    }

    fn state(&self, _: &Ctx, server: &str) -> Result<State> {
        // A server whose dryserver cannot take images yet would never
        // take what it is sent: said now, not after a long wait.
        let out = self.run(
            server,
            &format!(
                "if /usr/local/bin/dryserver help 2>/dev/null | grep -q '^  images '; then echo CAN; else echo OLD; fi; cat {STATE} 2>/dev/null || echo '{{}}'"
            ),
            std::process::Stdio::null(),
        )?;
        let (first, rest) = out.split_once('\n').unwrap_or((&out, ""));
        if first.trim() != "CAN" {
            bail!("it runs a dryserver that cannot take images yet: publish a release first (dryserver release publish)");
        }
        Ok(State::parse(rest))
    }

    fn send(&self, _: &Ctx, server: &str, file: &Path, sha256: &str, envelope: &str) -> Result<()> {
        if !valid_sha(sha256) {
            bail!("not a sha256");
        }
        let dir = format!("~/{INBOX}");
        // The file first, under a name nobody takes; then its document.
        let f = std::fs::File::open(file).map_err(|e| Error::from(e).wrap(file.display()))?;
        self.run(
            server,
            &format!("umask 077 && mkdir -p {dir} && chmod 700 ~/.dryserver {dir} && cat > {dir}/{sha256}.tar.part && mv -f {dir}/{sha256}.tar.part {dir}/{sha256}.tar"),
            std::process::Stdio::from(f),
        )?;
        let mut c = self.command(
            server,
            &format!("umask 077 && cat > {dir}/{sha256}.json.part && mv -f {dir}/{sha256}.json.part {dir}/{sha256}.json"),
        )?;
        let mut child =
            c.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::piped()).spawn()?;
        child.stdin.take().ok_or_else(|| errf!("ssh: no stdin"))?.write_all(envelope.as_bytes())?;
        let out = child.wait_with_output()?;
        if !out.status.success() {
            bail!("the document did not arrive: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(())
    }

    fn wait(&self, _: &Ctx, server: &str, sha256: &str, max: std::time::Duration) -> Result<Option<State>> {
        if !valid_sha(sha256) {
            bail!("not a sha256");
        }
        // One login that waits on the server (the firewall lets an
        // address open only a few SSH connections a minute), until the
        // server has taken the document out of the inbox.
        let doc = format!("~/{INBOX}/{sha256}.json");
        let out = self.run(
            server,
            &format!(
                "if timeout {} sh -c 'while [ -e {doc} ]; do sleep 3; done'; then echo TAKEN; else echo WAITING; fi; cat {STATE} 2>/dev/null || echo '{{}}'",
                max.as_secs()
            ),
            std::process::Stdio::null(),
        )?;
        let (first, rest) = out.split_once('\n').unwrap_or((&out, ""));
        Ok((first.trim() == "TAKEN").then(|| State::parse(rest)))
    }
}
