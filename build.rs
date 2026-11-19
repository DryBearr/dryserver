// Embeds assets/archiso and assets/rootfs into the binary: the ISO build
// and the installer need them wherever the binary runs.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("assets");
    println!("cargo:rerun-if-changed={}", root.display());

    let mut code = String::new();
    for (name, dir) in [("ARCHISO", "archiso"), ("ROOTFS", "rootfs")] {
        let base = root.join(dir);
        let mut files = Vec::new();
        walk(&base, &mut files);
        files.sort();
        writeln!(code, "pub static {name}: &[(&str, &[u8])] = &[").unwrap();
        for f in files {
            println!("cargo:rerun-if-changed={}", f.display());
            let rel = f.strip_prefix(&base).unwrap().to_str().unwrap().to_string();
            writeln!(code, "    ({rel:?}, include_bytes!({:?})),", f.to_str().unwrap()).unwrap();
        }
        writeln!(code, "];").unwrap();
    }
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("assets.rs");
    fs::write(out, code).unwrap();
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    println!("cargo:rerun-if-changed={}", dir.display());
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            walk(&p, out);
        } else {
            out.push(p);
        }
    }
}
