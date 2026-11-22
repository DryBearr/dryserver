//! Produces the installer ISO by running mkarchiso inside an Arch Linux
//! container, since the build host (Fedora) cannot run archiso.

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::ctx::Ctx;
use crate::err::{Error, Result};
use crate::gotime::{duration_string, round_ms};
use crate::{assets, errf, fsx, owner};

pub const IMAGE: &str = "docker.io/library/archlinux:latest";
pub const ISO_NAME: &str = "dryserver.iso";
pub const LOG_NAME: &str = "build.log";
pub const KEY_NAME: &str = "registry_ed25519";
/// The keypair that signs the member list. The private half never leaves
/// secrets/ on the desktop; only SIGNING_PUB goes into the ISO.
pub const SIGNING_KEY_NAME: &str = "signing_ed25519";
pub const SIGNING_PUB: &str = "signing_ed25519.pub";
/// The keypair backups of the coordinator are encrypted to. Only the
/// public half goes into the ISO and onto the coordinator, which can then
/// make backups but never read them; the private half stays in secrets/.
/// Not the signing key: a key that opens backups must not also be able to
/// let machines in, and the other way round.
pub const BACKUP_KEY_NAME: &str = "backup_ed25519";
pub const BACKUP_PUB: &str = "backup_ed25519.pub";
/// The secret installers use to prove a join request comes from this
/// stick. On the stick and in secrets/; never on an installed machine.
pub const JOIN_SECRET: &str = "join_secret";
/// The k3s release every machine gets, and the SHA-256 of its amd64
/// binary as published with the release (sha256sum-amd64.txt). The ISO
/// build downloads it and refuses anything else.
pub const K3S_VERSION: &str = "v1.37.2+k3s1";
pub const K3S_SHA256: &str = "265b3ee6a3198ef14033c63ef46cbb32370d83795199fb6d1b01f21575eddbda";

#[derive(Debug, Clone)]
pub struct Options {
    pub config: Config,
    /// Receives dryserver.iso, build.log and the pacman cache.
    pub out_dir: PathBuf,
    /// Holds the registry and signing SSH keypairs, created on first build.
    pub secrets_dir: PathBuf,
}

pub fn iso_path(out_dir: impl AsRef<Path>) -> PathBuf {
    out_dir.as_ref().join(ISO_NAME)
}

/// Runs a closure when dropped (cleanup on every return path).
struct Defer<F: FnMut()>(F);

impl<F: FnMut()> Drop for Defer<F> {
    fn drop(&mut self) {
        (self.0)()
    }
}

/// Writes to the build log file and to the caller's log.
struct Tee<'a> {
    file: File,
    log: &'a mut (dyn Write + Send),
}

impl Write for Tee<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let _ = self.file.write_all(buf);
        self.log.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.log.flush()
    }
}

/// Builds out_dir/dryserver.iso and streams progress lines to log.
pub fn run(ctx: &Ctx, o: &Options, log: &mut (dyn Write + Send)) -> Result<()> {
    if let Err(e) = o.config.validate() {
        return Err(errf!("config is not valid:\n{e}"));
    }
    if !in_path("podman") {
        return Err("podman not found, install it first".into());
    }
    let me = std::env::current_exe()?;
    check_static(&me)?;

    let out_dir = std::path::absolute(&o.out_dir)?;
    let cache = out_dir.join("pkgcache");
    fsx::mkdir_all(&cache, 0o755)?;
    // The image holds the WiFi password, the join secret and the
    // registry key: out/ is the user's alone, also while it is written.
    fsx::chmod(&out_dir, 0o700)?;
    let fix_paths = [out_dir.clone(), o.secrets_dir.clone()];
    let _fix = Defer(|| owner::fix(&fix_paths));

    let log_path = out_dir.join(LOG_NAME);
    let file = File::create(&log_path).map_err(|e| Error::from(e).wrap(format!("open {}", log_path.display())))?;
    let mut tee = Tee { file, log };

    let key = ensure_registry_key(ctx, &o.secrets_dir, &mut tee)?;
    let signing_pub = ensure_signing_key(ctx, &o.secrets_dir, &mut tee)?;
    let backup_pub = ensure_backup_key(ctx, &o.secrets_dir, &mut tee)?;
    let join_secret = ensure_join_secret(&o.secrets_dir, &mut tee)?;

    let stage = out_dir.join("stage");
    let stage_c = stage.clone();
    let _rm = Defer(|| {
        let _ = std::fs::remove_dir_all(&stage_c);
    });
    let staged = Staged { key: &key, signing_pub: &signing_pub, backup_pub: &backup_pub, join_secret: &join_secret };
    write_stage(&stage, &me, &o.config, &staged).map_err(|e| e.wrap("prepare build files"))?;

    let _ = writeln!(tee, "==> Starting {IMAGE} (first run downloads ~1 GB)");
    let start = Instant::now();
    let name = format!("dryserver-build-{}", std::process::id());
    let vol = |a: &Path, b: &str| format!("{}:{b}", a.display());
    let mut cmd = Command::new("podman");
    cmd.args(["run", "--rm", "--name", &name, "--privileged", "--security-opt", "label=disable", "-v"])
        .arg(vol(&stage, "/stage:ro"))
        .arg("-v")
        .arg(vol(&out_dir, "/out"))
        .arg("-v")
        .arg(vol(&cache, "/var/cache/pacman/pkg"))
        .args([IMAGE, "bash", "/stage/build.sh"])
        .stdin(Stdio::null());
    let status = run_streaming(ctx, cmd, &mut tee, &name);
    match status {
        Ok(st) if st.success() => {}
        Ok(st) => {
            ctx.check()?;
            return Err(errf!("container build failed ({}), see {}", crate::runner::exit_text(st), o.out_dir.join(LOG_NAME).display()));
        }
        Err(e) => {
            ctx.check()?;
            return Err(errf!("container build failed ({e}), see {}", o.out_dir.join(LOG_NAME).display()));
        }
    }
    if !iso_path(&out_dir).exists() {
        return Err(errf!("build finished but {} is missing", iso_path(&o.out_dir).display()));
    }
    fsx::chmod(iso_path(&out_dir), 0o600)?;
    let secs = round_ms(start.elapsed().as_millis() as i64, 1000) / 1000;
    let _ = writeln!(tee, "==> Done in {}", duration_string(secs));
    Ok(())
}

/// Runs the container with its output going to w. When ctx is done the
/// container is stopped by name: bash runs as PID 1 inside and ignores
/// forwarded signals, so podman would not stop otherwise.
fn run_streaming(ctx: &Ctx, mut cmd: Command, w: &mut (dyn Write + Send), name: &str) -> Result<std::process::ExitStatus> {
    let (mut r, pw) = io::pipe()?;
    cmd.stderr(pw.try_clone()?).stdout(pw);
    let mut child = cmd.spawn().map_err(|e| Error::from(e).wrap("podman"))?;
    drop(cmd);
    std::thread::scope(|s| {
        s.spawn(move || {
            let mut buf = [0u8; 8192];
            while let Ok(n) = r.read(&mut buf) {
                if n == 0 || w.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        });
        let mut stopped: Option<Instant> = None;
        loop {
            if let Some(st) = child.try_wait()? {
                return Ok(st);
            }
            match stopped {
                None if ctx.done() => {
                    let _ = Command::new("podman").args(["stop", "--time", "2", name]).stdout(Stdio::null()).stderr(Stdio::null()).status();
                    stopped = Some(Instant::now());
                }
                Some(at) if at.elapsed() > Duration::from_secs(30) => {
                    let _ = child.kill();
                    return Ok(child.wait()?);
                }
                _ => {}
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    })
}

pub fn in_path(prog: &str) -> bool {
    std::env::var_os("PATH").map(|p| std::env::split_paths(&p).any(|d| is_executable(&d.join(prog)))).unwrap_or(false)
}

fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false)
}

/// Refuses a dynamically linked binary: it is copied into the ISO and may
/// not find its loader or libc there.
pub fn check_static(path: &Path) -> Result<()> {
    let b = fsx::read(path)?;
    if has_interp(&b).ok_or_else(|| errf!("{} is not an ELF binary", path.display()))? {
        return Err(
            "this dryserver binary is dynamically linked; rebuild it with `make` (a static musl build) so it can run inside the ISO".into(),
        );
    }
    Ok(())
}

/// Whether a 64-bit little-endian ELF file asks for a program interpreter
/// (PT_INTERP), i.e. is dynamically linked. None if it is not such a file.
fn has_interp(b: &[u8]) -> Option<bool> {
    if b.len() < 64 || &b[..4] != b"\x7fELF" || b[4] != 2 || b[5] != 1 {
        return None;
    }
    let u16_at = |o: usize| u16::from_le_bytes([b[o], b[o + 1]]) as usize;
    let phoff = u64::from_le_bytes(b[0x20..0x28].try_into().ok()?) as usize;
    let (phentsize, phnum) = (u16_at(0x36), u16_at(0x38));
    for i in 0..phnum {
        let o = phoff + i * phentsize;
        let typ = u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?);
        if typ == 3 {
            return Some(true);
        }
    }
    Some(false)
}

/// Creates the SSH keypair nodes use to register with the coordinator. The
/// same key is baked into every ISO, so it is kept across builds.
fn ensure_registry_key(ctx: &Ctx, dir: &Path, log: &mut dyn Write) -> Result<PathBuf> {
    let key = dir.join(KEY_NAME);
    if key.exists() {
        return Ok(key);
    }
    fsx::mkdir_all(dir, 0o700)?;
    let _ = writeln!(log, "==> Generating registry key {}", key.display());
    ctx.check()?;
    ssh_keygen(|c| c.args(["-q", "-t", "ed25519", "-N", "", "-C", "dryserver-registry", "-f"]).arg(&key))?;
    Ok(key)
}

/// Runs ssh-keygen and returns its standard output.
fn ssh_keygen(args: impl FnOnce(&mut Command) -> &mut Command) -> Result<String> {
    let mut c = Command::new("ssh-keygen");
    args(&mut c);
    let out = c.stdin(Stdio::null()).output().map_err(|e| Error::from(e).wrap("ssh-keygen (is OpenSSH installed?)"))?;
    if !out.status.success() {
        let msg = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
        return Err(errf!("ssh-keygen: {}: {}", crate::runner::exit_text(out.status), msg.trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// "type base64" of an SSH public key line, without its comment.
fn key_body(line: &str) -> String {
    line.split_whitespace().take(2).collect::<Vec<_>>().join(" ")
}

/// Makes sure secrets/ holds the keypair that signs the member list, and
/// returns the path of its public half. Servers installed from the ISO
/// accept only member lists signed with this key, so:
///
/// - it is created once and never replaced;
/// - a public half without its private half is an error, not a reason to
///   make a new pair (servers already trust the old one);
/// - the two halves must belong together.
fn ensure_signing_key(ctx: &Ctx, dir: &Path, log: &mut dyn Write) -> Result<PathBuf> {
    ensure_keypair(
        ctx,
        dir,
        &Pair {
            name: SIGNING_KEY_NAME,
            pub_name: SIGNING_PUB,
            comment: "dryserver-signing",
            what: "signing key",
            does: "signs the list of machines in your swarm",
            lost: "servers installed with this key accept only lists signed by it",
            lost_new: "servers installed before will not trust the new key",
        },
        log,
    )
}

/// Makes sure secrets/ holds the keypair backups are encrypted to, and
/// returns the path of its public half. The same rules as for the signing
/// key: a coordinator installed with this key makes backups only it opens.
fn ensure_backup_key(ctx: &Ctx, dir: &Path, log: &mut dyn Write) -> Result<PathBuf> {
    ensure_keypair(
        ctx,
        dir,
        &Pair {
            name: BACKUP_KEY_NAME,
            pub_name: BACKUP_PUB,
            comment: "dryserver-backup",
            what: "backup key",
            does: "opens the coordinator's encrypted backups",
            lost: "backups made by a coordinator installed with this key open only with it",
            lost_new: "backups made before open only with the old key",
        },
        log,
    )
}

/// An ed25519 keypair in secrets/ whose private half never leaves it.
struct Pair {
    name: &'static str,
    pub_name: &'static str,
    comment: &'static str,
    what: &'static str,
    /// What the key is for, and what losing it means.
    does: &'static str,
    lost: &'static str,
    lost_new: &'static str,
}

fn ensure_keypair(ctx: &Ctx, dir: &Path, p: &Pair, log: &mut dyn Write) -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let key = dir.join(p.name);
    let pubkey = dir.join(p.pub_name);
    ctx.check()?;
    if !key.exists() {
        if pubkey.exists() {
            return Err(errf!(
                "{} is missing but {} is there. Restore the private key from your backup: {}. To start over with a \
                 new key instead, remove the .pub file ({}).",
                key.display(),
                pubkey.display(),
                p.lost,
                p.lost_new
            ));
        }
        fsx::mkdir_all(dir, 0o700)?;
        let _ = writeln!(
            log,
            "==> Generating {} {} ({}).\n    \
             It stays on this computer; back up {} and keep it private.",
            p.what,
            key.display(),
            p.does,
            dir.display()
        );
        ssh_keygen(|c| c.args(["-q", "-t", "ed25519", "-N", "", "-C", p.comment, "-f"]).arg(&key))?;
    }
    // The private half is for this user only, whatever it was restored as.
    let mode = std::fs::metadata(&key).map(|m| m.permissions().mode() & 0o777).unwrap_or(0);
    if mode & 0o077 != 0 {
        fsx::chmod(&key, 0o600)?;
    }
    let derived = ssh_keygen(|c| c.arg("-y").arg("-f").arg(&key)).map_err(|e| e.wrap(format!("read {}", key.display())))?;
    let derived = key_body(&derived);
    if !derived.starts_with("ssh-ed25519 ") {
        return Err(errf!("{} is not an ed25519 key", key.display()));
    }
    match std::fs::read_to_string(&pubkey) {
        Ok(have) if key_body(&have) == derived => {}
        Ok(_) => {
            return Err(errf!(
                "{} does not belong to {}. Restore the matching pair from your backup, or remove the .pub file to \
                 rewrite it from the private key.",
                pubkey.display(),
                key.display()
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fsx::write_file(&pubkey, format!("{derived} {}\n", p.comment), 0o644)?;
        }
        Err(e) => return Err(Error::from(e).wrap(format!("open {}", pubkey.display()))),
    }
    Ok(pubkey)
}

/// Makes sure secrets/ holds the join secret and returns its path. Created
/// once: machines installed from an older stick carry proofs made with it.
fn ensure_join_secret(dir: &Path, log: &mut dyn Write) -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(JOIN_SECRET);
    if !path.exists() {
        fsx::mkdir_all(dir, 0o700)?;
        let _ = writeln!(log, "==> Generating join secret {}", path.display());
        fsx::write_file(&path, format!("{}\n", fsx::hex(&fsx::random_bytes(32))), 0o600)?;
    }
    let text = fsx::read_string(&path)?;
    let t = text.trim();
    if t.len() < 32 || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(errf!(
            "{} is damaged (not a hex secret). Restore it from your backup, or remove it to make a new one.",
            path.display()
        ));
    }
    let mode = std::fs::metadata(&path).map(|m| m.permissions().mode() & 0o777).unwrap_or(0);
    if mode & 0o077 != 0 {
        fsx::chmod(&path, 0o600)?;
    }
    Ok(path)
}

/// The keys and secrets that go onto the stick.
struct Staged<'a> {
    key: &'a Path,
    signing_pub: &'a Path,
    backup_pub: &'a Path,
    join_secret: &'a Path,
}

/// Lays out the directory mounted at /stage in the container: the embedded
/// assets plus this binary, the config, the registry key and the public
/// halves of the signing and backup keys. Their private halves are never
/// staged.
fn write_stage(stage: &Path, me: &Path, cfg: &Config, k: &Staged) -> Result<()> {
    let Staged { key, signing_pub, backup_pub, join_secret } = *k;
    match std::fs::remove_dir_all(stage) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e.into()),
        _ => {}
    }
    for (name, data) in assets::ARCHISO {
        let dst = stage.join(name);
        fsx::mkdir_all(fsx::dir(&dst), 0o755)?;
        fsx::write_file(&dst, data, 0o644)?;
    }
    let root = stage.join("overlay/airootfs");
    let etc = root.join("etc/dryserver");
    let bin = root.join("usr/local/bin");
    fsx::mkdir_all(&etc, 0o755)?;
    fsx::mkdir_all(&bin, 0o755)?;
    copy_file(me, &bin.join("dryserver"), 0o755)?;
    cfg.save(etc.join("config.env"))?;
    copy_file(key, &etc.join(KEY_NAME), 0o600)?;
    copy_file(&PathBuf::from(format!("{}.pub", key.display())), &etc.join(format!("{KEY_NAME}.pub")), 0o644)?;
    copy_file(signing_pub, &etc.join(SIGNING_PUB), 0o644)?;
    copy_file(backup_pub, &etc.join(BACKUP_PUB), 0o644)?;
    copy_file(join_secret, &etc.join(JOIN_SECRET), 0o600)?;
    fsx::write_file(stage.join("k3s.env"), format!("K3S_VERSION='{K3S_VERSION}'\nK3S_SHA256='{K3S_SHA256}'\n"), 0o644)
}

fn copy_file(src: &Path, dst: &Path, mode: u32) -> Result<()> {
    fsx::write_file(dst, fsx::read(src)?, mode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn stage_layout() {
        let dir = TempDir::new();
        let key = dir.join(KEY_NAME);
        std::fs::write(&key, "private").unwrap();
        std::fs::write(dir.join(format!("{KEY_NAME}.pub")), "public").unwrap();
        let me = dir.join("self");
        std::fs::write(&me, "binary").unwrap();
        let cfg = Config { wifi_ssid: "home".into(), ..Config::default() };
        let stage = dir.join("stage");
        std::fs::write(dir.join(SIGNING_KEY_NAME), "signing private").unwrap();
        std::fs::write(dir.join(SIGNING_PUB), "ssh-ed25519 AAAAsign dryserver-signing\n").unwrap();
        std::fs::write(dir.join(JOIN_SECRET), "0123456789abcdef0123456789abcdef\n").unwrap();
        std::fs::write(dir.join(BACKUP_KEY_NAME), "backup private").unwrap();
        std::fs::write(dir.join(BACKUP_PUB), "ssh-ed25519 AAAAbackup dryserver-backup\n").unwrap();
        let (signing, backup, secret) = (dir.join(SIGNING_PUB), dir.join(BACKUP_PUB), dir.join(JOIN_SECRET));
        write_stage(&stage, &me, &cfg, &Staged { key: &key, signing_pub: &signing, backup_pub: &backup, join_secret: &secret }).unwrap();

        let key_pub = format!("overlay/airootfs/etc/dryserver/{KEY_NAME}.pub");
        let key_priv = format!("overlay/airootfs/etc/dryserver/{KEY_NAME}");
        let signing_pub = format!("overlay/airootfs/etc/dryserver/{SIGNING_PUB}");
        let join_secret = format!("overlay/airootfs/etc/dryserver/{JOIN_SECRET}");
        let backup_pub = format!("overlay/airootfs/etc/dryserver/{BACKUP_PUB}");
        let want: [(&str, u32); 10] = [
            (&join_secret, 0o600),
            (&signing_pub, 0o644),
            (&backup_pub, 0o644),
            ("build.sh", 0),
            ("packages.extra", 0),
            ("overlay/airootfs/etc/motd", 0),
            ("overlay/airootfs/usr/local/bin/dryserver", 0o755),
            ("overlay/airootfs/etc/dryserver/config.env", 0o600),
            (&key_priv, 0o600),
            (&key_pub, 0o644),
        ];
        for (path, mode) in want {
            let st = std::fs::metadata(stage.join(path)).unwrap_or_else(|_| panic!("missing {path}"));
            if mode != 0 {
                assert_eq!(st.permissions().mode() & 0o777, mode, "{path} mode");
            }
        }
        let got = Config::load(stage.join("overlay/airootfs/etc/dryserver/config.env")).unwrap();
        assert_eq!(got.wifi_ssid, "home");
        // The k3s pin the container downloads and checks.
        let pin = std::fs::read_to_string(stage.join("k3s.env")).unwrap();
        assert_eq!(pin, format!("K3S_VERSION='{K3S_VERSION}'\nK3S_SHA256='{K3S_SHA256}'\n"));
        assert!(K3S_SHA256.len() == 64 && K3S_SHA256.bytes().all(|b| b.is_ascii_hexdigit()) && K3S_VERSION.starts_with('v'));
        assert_eq!(std::fs::read_to_string(stage.join(&backup_pub)).unwrap(), "ssh-ed25519 AAAAbackup dryserver-backup\n");
        // The signing and backup private keys must never reach the stick,
        // under any name.
        fn files(d: &Path, out: &mut Vec<PathBuf>) {
            for e in std::fs::read_dir(d).unwrap().flatten() {
                if e.path().is_dir() { files(&e.path(), out) } else { out.push(e.path()) }
            }
        }
        let mut all = Vec::new();
        files(&stage, &mut all);
        for f in all {
            let b = std::fs::read(&f).unwrap();
            for secret in [&b"signing private"[..], b"backup private"] {
                assert!(!b.windows(secret.len()).any(|w| w == secret), "private key staged in {}", f.display());
            }
            assert_ne!(f.file_name().unwrap(), SIGNING_KEY_NAME, "{}", f.display());
            assert_ne!(f.file_name().unwrap(), BACKUP_KEY_NAME, "{}", f.display());
        }
    }

    #[test]
    fn backup_key_lifecycle() {
        if !in_path("ssh-keygen") {
            return;
        }
        let dir = TempDir::new();
        let secrets = dir.join("secrets");
        let ctx = Ctx::new();
        let mut log = Vec::new();
        let signing = ensure_signing_key(&ctx, &secrets, &mut log).unwrap();
        let p = ensure_backup_key(&ctx, &secrets, &mut log).unwrap();
        let text = String::from_utf8_lossy(&log).into_owned();
        assert!(text.contains("backup key") && text.contains("opens the coordinator's encrypted backups"), "{text}");
        let first = std::fs::read_to_string(&p).unwrap();
        assert!(first.starts_with("ssh-ed25519 ") && first.trim_end().ends_with("dryserver-backup"), "{first}");
        assert_ne!(key_body(&first), key_body(&std::fs::read_to_string(&signing).unwrap()), "a key of its own, not the signing key");
        let key = secrets.join(BACKUP_KEY_NAME);
        assert_eq!(std::fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);
        // Kept across builds; a lost public half comes back from the
        // private one; a lost private half never makes a new pair.
        ensure_backup_key(&ctx, &secrets, &mut Vec::new()).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), first);
        std::fs::remove_file(&p).unwrap();
        ensure_backup_key(&ctx, &secrets, &mut Vec::new()).unwrap();
        assert_eq!(key_body(&std::fs::read_to_string(&p).unwrap()), key_body(&first));
        std::fs::remove_file(&key).unwrap();
        let e = ensure_backup_key(&ctx, &secrets, &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("Restore the private key") && e.contains("backups made before open only with the old key"), "{e}");
        assert!(!key.exists());
    }

    #[test]
    fn join_secret_lifecycle() {
        let dir = TempDir::new();
        let secrets = dir.join("secrets");
        let mut log = Vec::new();
        let p = ensure_join_secret(&secrets, &mut log).unwrap();
        let first = std::fs::read_to_string(&p).unwrap();
        assert_eq!(first.trim().len(), 64, "32 random bytes in hex");
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        // Kept across builds.
        ensure_join_secret(&secrets, &mut Vec::new()).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), first);
        // Loose permissions are tightened; junk is refused, not replaced.
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        ensure_join_secret(&secrets, &mut Vec::new()).unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::write(&p, "not hex!\n").unwrap();
        assert!(ensure_join_secret(&secrets, &mut Vec::new()).unwrap_err().to_string().contains("damaged"));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "not hex!\n");
    }

    #[test]
    fn signing_key_lifecycle() {
        if !in_path("ssh-keygen") {
            return;
        }
        let dir = TempDir::new();
        let secrets = dir.join("secrets");
        let ctx = Ctx::new();
        let mut log = Vec::new();
        let p = ensure_signing_key(&ctx, &secrets, &mut log).unwrap();
        assert!(String::from_utf8_lossy(&log).contains("back up"), "first build must tell the admin to back the key up");
        let first = std::fs::read_to_string(&p).unwrap();
        assert!(first.starts_with("ssh-ed25519 "), "{first}");
        let key = secrets.join(SIGNING_KEY_NAME);
        assert_eq!(std::fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(&secrets).unwrap().permissions().mode() & 0o777, 0o700);

        // Kept across builds, silently.
        let mut log = Vec::new();
        ensure_signing_key(&ctx, &secrets, &mut log).unwrap();
        assert!(log.is_empty());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), first);

        // A lost public half is rewritten from the private half.
        std::fs::remove_file(&p).unwrap();
        ensure_signing_key(&ctx, &secrets, &mut Vec::new()).unwrap();
        assert_eq!(key_body(&std::fs::read_to_string(&p).unwrap()), key_body(&first));

        // Loose permissions on a restored key are tightened.
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        ensure_signing_key(&ctx, &secrets, &mut Vec::new()).unwrap();
        assert_eq!(std::fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);

        // A public half from another pair is refused.
        std::fs::write(&p, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtherOtherOtherOtherOtherOtherOtherOtherOtherO x\n").unwrap();
        let e = ensure_signing_key(&ctx, &secrets, &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("does not belong"), "{e}");
        std::fs::write(&p, &first).unwrap();

        // A lost private half never leads to a new pair.
        std::fs::remove_file(&key).unwrap();
        let e = ensure_signing_key(&ctx, &secrets, &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("Restore the private key"), "{e}");
        assert!(!key.exists() && std::fs::read_to_string(&p).unwrap() == first);

        // A file that is not a key is refused.
        std::fs::write(&key, "garbage").unwrap();
        assert!(ensure_signing_key(&ctx, &secrets, &mut Vec::new()).is_err());
    }

    #[test]
    fn dynamic_binary_refused() {
        // /bin/sh is dynamically linked on every normal distro.
        assert!(check_static(Path::new("/bin/sh")).is_err(), "dynamic binary accepted");
    }

    #[test]
    fn elf_interp_detection() {
        // Minimal ELF64 header with one PT_LOAD program header.
        let mut b = vec![0u8; 64 + 56];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
        b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        b[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes());
        b[64..68].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(has_interp(&b), Some(false));
        b[64..68].copy_from_slice(&3u32.to_le_bytes());
        assert_eq!(has_interp(&b), Some(true));
        assert_eq!(has_interp(b"#!/bin/sh"), None);
    }
}
