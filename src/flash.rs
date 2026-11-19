//! Writes an ISO image to a USB disk and verifies it.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::ctx::Ctx;
use crate::disks::{self, Disk, human_size};
use crate::err::{Error, Result};
use crate::errf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Phase {
    #[default]
    Writing,
    Verifying,
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Phase::Writing => "Writing",
            Phase::Verifying => "Verifying",
        })
    }
}

const CHUNK_SIZE: usize = 4 << 20; // 4 MiB per write
const SYNC_EVERY: u64 = 64 << 20; // flush regularly so progress reflects real writes

// ioctl numbers from linux/fs.h.
const BLKRRPART: libc::c_ulong = 0x125f;
const BLKFLSBUF: libc::c_ulong = 0x1261;

/// Re-checks that target is still a safe USB disk, unmounts it, writes the
/// ISO and reads it back to verify. Needs root.
pub fn write(ctx: &Ctx, iso_path: &str, target: &Disk, progress: &mut dyn FnMut(Phase, u64, u64)) -> Result<()> {
    // The device list may be stale: the stick could have been swapped for
    // another disk that got the same name. Compare against a fresh listing.
    let fresh = disks::find(&target.path)?;
    if fresh.size != target.size || fresh.model != target.model {
        return Err(errf!("{} changed since it was selected, select it again", target.path));
    }
    if disks::usb(std::slice::from_ref(&fresh)).is_empty() {
        return Err(errf!("{} is no longer a safe USB target", target.path));
    }
    for m in fresh.mounts() {
        let out = Command::new("umount").arg(&m).output()?;
        if !out.status.success() {
            let msg = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
            return Err(errf!("umount {m}: {}: {}", crate::runner::exit_text(out.status), msg.trim()));
        }
    }
    write_image(ctx, iso_path, &fresh.path, fresh.size, progress)?;
    reread_partitions(&fresh.path);
    Ok(())
}

pub(crate) fn write_image(
    ctx: &Ctx,
    iso_path: &str,
    dev_path: &str,
    dev_size: u64,
    progress: &mut dyn FnMut(Phase, u64, u64),
) -> Result<()> {
    let mut iso = File::open(iso_path).map_err(|e| Error::from(e).wrap(format!("open {iso_path}")))?;
    let total = iso.metadata()?.len();
    if total > dev_size {
        return Err(errf!("image is {} but {dev_path} is only {}", human_size(total), human_size(dev_size)));
    }
    // O_EXCL on a block device fails with EBUSY if anything still has it
    // mounted or claimed, which is the last guard against writing a disk in use.
    let dev = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_EXCL)
        .open(dev_path)
        .map_err(|e| Error::from(e).wrap(format!("open {dev_path}")))?;

    let mut want = Sha256::new();
    let devr = &dev;
    copy_chunks(
        ctx,
        &mut iso,
        total,
        Phase::Writing,
        progress,
        &mut |buf| {
            want.update(buf);
            Ok((&*devr).write_all(buf)?)
        },
        Some(&mut || Ok(devr.sync_all()?)),
    )?;
    dev.sync_all().map_err(|e| Error::from(e).wrap(format!("sync {dev_path}")))?;
    drop(dev);
    verify(ctx, dev_path, total, &want.finalize(), progress)
}

fn verify(ctx: &Ctx, dev_path: &str, total: u64, want: &[u8], progress: &mut dyn FnMut(Phase, u64, u64)) -> Result<()> {
    let dev = File::open(dev_path).map_err(|e| Error::from(e).wrap(format!("open {dev_path}")))?;
    // Drop the kernel buffer cache for the device so the read-back hits the
    // stick itself and not the pages just written. Not a block device in tests.
    // SAFETY: ioctl on a valid descriptor; failure is ignored.
    unsafe {
        libc::ioctl(dev.as_raw_fd(), BLKFLSBUF as _, 0);
    }
    let mut got = Sha256::new();
    let mut src = dev.take(total);
    copy_chunks(
        ctx,
        &mut src,
        total,
        Phase::Verifying,
        progress,
        &mut |buf| {
            got.update(buf);
            Ok(())
        },
        None,
    )?;
    if got.finalize().as_slice() != want {
        return Err("verification failed: data on the USB does not match the image (bad stick?)".into());
    }
    Ok(())
}

fn copy_chunks(
    ctx: &Ctx,
    src: &mut dyn Read,
    total: u64,
    phase: Phase,
    progress: &mut dyn FnMut(Phase, u64, u64),
    sink: &mut dyn FnMut(&[u8]) -> Result<()>,
    mut flush: Option<&mut dyn FnMut() -> Result<()>>,
) -> Result<()> {
    let mut buf = vec![0u8; CHUNK_SIZE];
    let (mut done, mut since_flush) = (0u64, 0u64);
    progress(phase, 0, total);
    while done < total {
        ctx.check()?;
        let n = read_full(src, &mut buf).map_err(|e| Error::from(e).wrap(phase))?;
        if n > 0 {
            sink(&buf[..n]).map_err(|e| e.wrap(phase))?;
            done += n as u64;
            since_flush += n as u64;
            if since_flush >= SYNC_EVERY {
                if let Some(f) = flush.as_mut() {
                    f().map_err(|e| e.wrap(phase))?;
                }
                since_flush = 0;
            }
            progress(phase, done, total);
        }
        if n < buf.len() {
            break;
        }
    }
    if done != total {
        return Err(errf!("{phase}: short read, {done} of {total} bytes"));
    }
    Ok(())
}

/// Reads until buf is full or the source ends.
fn read_full(src: &mut dyn Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match src.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// Asks the kernel to pick up the new partition table so the stick shows
/// the ISO layout without replugging. Failure is harmless.
fn reread_partitions(dev_path: &str) {
    if let Ok(f) = File::open(dev_path) {
        // SAFETY: ioctl on a valid descriptor; failure is ignored.
        unsafe {
            libc::ioctl(f.as_raw_fd(), BLKRRPART as _, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use std::collections::HashMap;

    // write_image works on regular files too, which stand in for a USB device here.
    #[test]
    fn writes_and_verifies() {
        let dir = TempDir::new();
        let img = crate::fsx::random_bytes((9 << 20) + 123); // not a multiple of the chunk size
        let iso = dir.join("test.iso");
        let dev = dir.join("dev");
        std::fs::write(&iso, &img).unwrap();
        std::fs::write(&dev, vec![0u8; 16 << 20]).unwrap();
        let mut last: HashMap<Phase, u64> = HashMap::new();
        write_image(&Ctx::new(), iso.to_str().unwrap(), dev.to_str().unwrap(), 16 << 20, &mut |p, done, total| {
            assert_eq!(total, img.len() as u64);
            last.insert(p, done);
        })
        .unwrap();
        assert_eq!(last[&Phase::Writing], img.len() as u64);
        assert_eq!(last[&Phase::Verifying], img.len() as u64);
        let got = std::fs::read(&dev).unwrap();
        assert!(got[..img.len()] == img[..], "device content differs from image");
    }

    #[test]
    fn image_too_big() {
        let dir = TempDir::new();
        let iso = dir.join("test.iso");
        std::fs::write(&iso, vec![0u8; 2048]).unwrap();
        let err = write_image(&Ctx::new(), iso.to_str().unwrap(), dir.join("dev").to_str().unwrap(), 1024, &mut |_, _, _| {});
        assert!(err.is_err(), "expected size error");
    }

    #[test]
    fn cancel_stops_writing() {
        let dir = TempDir::new();
        let iso = dir.join("test.iso");
        let dev = dir.join("dev");
        std::fs::write(&iso, vec![0u8; 8 << 20]).unwrap();
        std::fs::write(&dev, b"").unwrap();
        let ctx = Ctx::new();
        ctx.cancel();
        let err = write_image(&ctx, iso.to_str().unwrap(), dev.to_str().unwrap(), 16 << 20, &mut |_, _, _| {}).unwrap_err();
        assert!(err.is_canceled(), "err = {err}");
    }
}
