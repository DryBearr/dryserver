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

#[derive(Debug, Clone)]
pub struct Options {
    pub config: Config,
    /// Receives dryserver.iso, build.log and the pacman cache.
    pub out_dir: PathBuf,
    /// Holds the registry SSH keypair, created on first build.
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
    let fix_paths = [out_dir.clone(), o.secrets_dir.clone()];
    let _fix = Defer(|| owner::fix(&fix_paths));

    let log_path = out_dir.join(LOG_NAME);
    let file = File::create(&log_path).map_err(|e| Error::from(e).wrap(format!("open {}", log_path.display())))?;
    let mut tee = Tee { file, log };

    let key = ensure_registry_key(ctx, &o.secrets_dir, &mut tee)?;

    let stage = out_dir.join("stage");
    let stage_c = stage.clone();
    let _rm = Defer(|| {
        let _ = std::fs::remove_dir_all(&stage_c);
    });
    write_stage(&stage, &me, &o.config, &key).map_err(|e| e.wrap("prepare build files"))?;

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
    let out = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "dryserver-registry", "-f"])
        .arg(&key)
        .output()
        .map_err(|e| Error::from(e).wrap("ssh-keygen"))?;
    if !out.status.success() {
        let msg = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
        return Err(errf!("ssh-keygen: {}: {msg}", crate::runner::exit_text(out.status)));
    }
    Ok(key)
}

/// Lays out the directory mounted at /stage in the container: the embedded
/// assets plus this binary, the config and the registry key.
fn write_stage(stage: &Path, me: &Path, cfg: &Config, key: &Path) -> Result<()> {
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
    copy_file(&PathBuf::from(format!("{}.pub", key.display())), &etc.join(format!("{KEY_NAME}.pub")), 0o644)
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
        write_stage(&stage, &me, &cfg, &key).unwrap();

        let key_pub = format!("overlay/airootfs/etc/dryserver/{KEY_NAME}.pub");
        let key_priv = format!("overlay/airootfs/etc/dryserver/{KEY_NAME}");
        let want: [(&str, u32); 7] = [
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
