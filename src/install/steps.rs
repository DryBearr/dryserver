//! The install itself: partition, encrypt, pacstrap, configure, boot loader;
//! and joining the mesh afterwards.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::real::InstallState;
use super::*;
use crate::err::{Error, Kind};
use crate::gotime::Time;
use crate::iso;
use crate::mesh::SelfInfo;
use crate::node::{self, Node};
use crate::packages::{self, Plan};
use crate::registry::{self, Member, Store};
use crate::runner::Cmd;
use crate::sysconf::{self, Params, REGISTRY_USER};

struct DataDisk {
    /// Block device holding the filesystem.
    dev: String,
    /// Mount point inside the new system.
    mount: String,
    /// Keyfile for the LUKS container, None if not encrypted.
    key: Option<Vec<u8>>,
    part: String,
}

/// Removes temporary key files when dropped.
struct RemoveFiles(Vec<PathBuf>);

impl Drop for RemoveFiles {
    fn drop(&mut self) {
        for p in &self.0 {
            let _ = std::fs::remove_file(p);
        }
    }
}

impl Real {
    /// Wipes the chosen disks and installs the server. The new system stays
    /// mounted at target so join can finish its mesh config; reboot
    /// unmounts it.
    pub(super) fn install_impl(&self, ctx: &Ctx, cfg: &Config, ch: &Choices, progress: Progress) -> Result<()> {
        let plan = packages::resolve(&cfg.tool_list(), &cfg.extra_list())?;
        let uefi = self.machine.lock().unwrap().uefi;
        let lay = plan_layout(&ch.system_disk, uefi);
        *self.state.lock().unwrap() = InstallState { layout: lay.clone(), ..InstallState::default() };
        let _sink = self.stream_to(&progress);

        let step = |name: &str, f: &mut dyn FnMut() -> Result<()>| -> Result<()> {
            progress(Step::start(name));
            f().map_err(|e| e.wrap(name))?;
            progress(Step::finished(name));
            Ok(())
        };
        let mut data = Vec::new();
        step("Partition disks", &mut || self.partition(ctx, ch, &lay))?;
        step("Set up encryption and filesystems", &mut || {
            data = self.filesystems(ctx, ch, &lay)?;
            Ok(())
        })?;
        step("Install packages (takes a while)", &mut || {
            let mut pkgs = plan.packages.clone();
            if lay.uefi {
                pkgs.extend(["efibootmgr".into(), "systemd-ukify".into()]);
            } else {
                pkgs.push("grub".into());
            }
            if ch.enc() == Encryption::Tpm {
                pkgs.push("tpm2-tss".into());
            }
            let stop = AtomicBool::new(false);
            std::thread::scope(|s| {
                s.spawn(|| self.report_downloads(&stop, Duration::from_secs(5)));
                let res = self.pacstrap(ctx, &pkgs);
                stop.store(true, Ordering::SeqCst);
                res
            })
        })?;
        step("Configure system", &mut || self.configure(ctx, cfg, ch, &plan, &data))?;
        step("Install boot loader", &mut || self.bootloader(ctx, ch))?;
        self.state.lock().unwrap().installed = true;
        Ok(())
    }

    fn partition(&self, ctx: &Ctx, ch: &Choices, lay: &Layout) -> Result<()> {
        // Leftovers from an earlier attempt; not mounted is fine.
        let target = self.target.display().to_string();
        let _ = self.run.run(ctx, &Cmd::new("umount", &["-R", &target]).quiet());
        let mut all = vec![ch.system_disk.clone()];
        all.extend(ch.data_disks.iter().cloned());
        for d in &all {
            self.release_disk(ctx, d)?;
        }
        for d in &all {
            self.cmd(ctx, "wipefs", &["--all", "--force", d])?;
            let script = if *d == ch.system_disk { lay.script.as_str() } else { DATA_SCRIPT };
            let sf = Cmd::new("sfdisk", &["--wipe", "always", "--wipe-partitions", "always", d]).stdin(script);
            self.run.ok(ctx, &sf).map_err(|e| errf!("{e} (something still uses {d}; reboot from the USB and run the setup again)"))?;
        }
        self.cmd(ctx, "udevadm", &["settle"])?;
        self.check_layout(ctx, &ch.system_disk, 2, 1 << 30)?;
        for d in &ch.data_disks {
            self.check_layout(ctx, d, 1, 0)?;
        }
        Ok(())
    }

    fn filesystems(&self, ctx: &Ctx, ch: &Choices, lay: &Layout) -> Result<Vec<DataDisk>> {
        let enc = ch.enc() != Encryption::None;
        let mut root_dev = lay.root.clone();
        if enc {
            self.luks_format(ctx, &lay.root, &ch.disk_passphrase)?;
            self.run
                .ok(ctx, &Cmd::new("cryptsetup", &["open", "--key-file=-", &lay.root, ROOT_MAPPER]).stdin(ch.disk_passphrase.as_str()))?;
            self.state.lock().unwrap().mapped.push(ROOT_MAPPER.into());
            root_dev = format!("/dev/mapper/{ROOT_MAPPER}");
            if ch.enc() == Encryption::Tpm {
                self.add_first_boot_key(ctx, &lay.root, &ch.disk_passphrase)?;
            }
        }
        self.cmd(ctx, "mkfs.ext4", &["-F", "-q", "-L", "root", &root_dev])?;
        if lay.uefi {
            self.cmd(ctx, "mkfs.fat", &["-F", "32", "-n", "EFI", &lay.boot])?;
        } else {
            self.cmd(ctx, "mkfs.ext4", &["-F", "-q", "-L", "boot", &lay.boot])?;
        }
        let data = self.prepare_data(ctx, ch, enc)?;

        self.cmd(ctx, "mount", &[&root_dev, &self.target.display().to_string()])?;
        let _ = fsx::mkdir_all(self.target("/boot"), 0o755);
        // The ESP holds the random seed; keep it private.
        let boot_opts = if lay.uefi { "umask=0077" } else { "defaults" };
        self.cmd(ctx, "mount", &["-o", boot_opts, &lay.boot, &self.target("/boot").display().to_string()])?;
        for d in &data {
            let _ = fsx::mkdir_all(self.target(&d.mount), 0o755);
            self.cmd(ctx, "mount", &[&d.dev, &self.target(&d.mount).display().to_string()])?;
        }
        Ok(data)
    }

    /// Adds a random one-time key to the root container. The installed
    /// system uses it at first boot to enroll the TPM, then removes it.
    fn add_first_boot_key(&self, ctx: &Ctx, dev: &str, passphrase: &str) -> Result<()> {
        let key = fsx::random_bytes(64);
        let tmp = self.key_dir.join("dryserver-tpm-enroll.key");
        let _rm = RemoveFiles(vec![tmp.clone()]);
        fsx::write_file(&tmp, &key, 0o400)?;
        self.run.ok(ctx, &Cmd::new("cryptsetup", &["luksAddKey", "--key-file=-", dev, &tmp.display().to_string()]).stdin(passphrase))?;
        self.state.lock().unwrap().first_boot_key = Some(key);
        Ok(())
    }

    fn luks_format(&self, ctx: &Ctx, dev: &str, passphrase: &str) -> Result<()> {
        let c = Cmd::new("cryptsetup", &["luksFormat", "--type", "luks2", "--pbkdf", "argon2id", "--batch-mode", "--key-file=-", dev]);
        self.run.ok(ctx, &c.stdin(passphrase))
    }

    /// Formats data disks. Encrypted ones get the passphrase (for recovery)
    /// plus a random keyfile, stored on the encrypted root, that unlocks
    /// them at boot.
    fn prepare_data(&self, ctx: &Ctx, ch: &Choices, enc: bool) -> Result<Vec<DataDisk>> {
        let mut out = Vec::new();
        let mut tmp_keys = RemoveFiles(Vec::new());
        for (i, disk) in ch.data_disks.iter().enumerate() {
            let part = part_path(disk, 1);
            let mount = if i == 0 { "/data".to_string() } else { format!("/data{}", i + 1) };
            let mut d = DataDisk { dev: part.clone(), mount, key: None, part };
            if enc {
                self.luks_format(ctx, &d.part, &ch.disk_passphrase)?;
                let key = fsx::random_bytes(512);
                let key_path = self.key_dir.join(format!("dryserver-{DATA_MAPPER}{i}.key"));
                tmp_keys.0.push(key_path.clone());
                fsx::write_file(&key_path, &key, 0o400)?;
                let kp = key_path.display().to_string();
                self.run
                    .ok(ctx, &Cmd::new("cryptsetup", &["luksAddKey", "--key-file=-", &d.part, &kp]).stdin(ch.disk_passphrase.as_str()))?;
                let mapper = format!("{DATA_MAPPER}{i}");
                self.cmd(ctx, "cryptsetup", &["open", "--key-file", &kp, &d.part, &mapper])?;
                self.state.lock().unwrap().mapped.push(mapper.clone());
                d.dev = format!("/dev/mapper/{mapper}");
                d.key = Some(key);
            }
            self.cmd(ctx, "mkfs.ext4", &["-F", "-q", "-L", d.mount.trim_start_matches('/'), &d.dev])?;
            out.push(d);
        }
        Ok(out)
    }

    fn blkid(&self, ctx: &Ctx, dev: &str) -> Result<String> {
        Ok(self.run.output(ctx, &Cmd::new("blkid", &["-s", "UUID", "-o", "value", dev]))?.trim().to_string())
    }

    /// Writes a file in the new system with exactly this mode.
    fn write(&self, path: &str, mode: u32, content: impl AsRef<[u8]>) -> Result<()> {
        let dst = self.target(path);
        fsx::mkdir_all(fsx::dir(&dst), 0o755)?;
        fsx::write_file(&dst, content, mode)?;
        fsx::chmod(&dst, mode) // write_file keeps the old mode of an existing file
    }

    fn configure(&self, ctx: &Ctx, cfg: &Config, ch: &Choices, plan: &Plan, data: &[DataDisk]) -> Result<()> {
        let target = self.target.display().to_string();
        // fstab from what is mounted now.
        let fstab = self.run.output(ctx, &Cmd::new("genfstab", &["-U", &target]).quiet())?;
        self.write("/etc/fstab", 0o644, fstab)?;

        // Files from the tool bundles; /etc/skel ones must exist before the
        // user is created.
        for f in &plan.files {
            let b = self.rootfs.get(f.trim_start_matches('/')).ok_or_else(|| errf!("bundle file {f}: file does not exist"))?;
            self.write(f, 0o644, b)?;
        }

        // Locale and time.
        self.write("/etc/locale.gen", 0o644, "en_US.UTF-8 UTF-8\n")?;
        let _ = self.write("/etc/locale.conf", 0o644, "LANG=en_US.UTF-8\n");
        let _ = self.write("/etc/vconsole.conf", 0o644, "KEYMAP=us\n");
        let zone = format!("/usr/share/zoneinfo/{}", cfg.timezone);
        self.chroot(ctx, &["locale-gen"])?;
        self.chroot(ctx, &["ln", "-sf", &zone, "/etc/localtime"])?;
        self.chroot(ctx, &["hwclock", "--systohc"])?;

        // Admin user: groups from the bundles, password from the setup
        // screen, root locked.
        let mut groups = vec!["wheel".to_string()];
        groups.extend(plan.groups.iter().cloned());
        self.chroot(ctx, &["useradd", "-m", "-G", &groups.join(","), "-s", "/bin/bash", &cfg.username])?;
        let pw = format!("{}:{}\n", cfg.username, ch.user_password);
        self.run.ok(ctx, &Cmd::new("arch-chroot", &[target.as_str(), "chpasswd"]).stdin(pw))?;
        self.chroot(ctx, &["passwd", "-l", "root"])?;

        // System files: firewall, SSH, sysctl, network, docker...
        let switch_mac = node::switch_port(ctx, self.run.as_ref());
        self.state.lock().unwrap().switch_mac = switch_mac.clone();
        self.write(node::SWITCH_MAC_FILE, 0o644, format!("{switch_mac}\n"))?;
        let host_num = if ch.role() == Role::Coordinator { 1 } else { 0 };
        let files = sysconf::render(&Params {
            config: cfg.clone(),
            plan: plan.clone(),
            hostname: ch.hostname.clone(),
            role: ch.role(),
            host_num,
            switch_mac,
        })?;
        for f in files {
            self.write(&f.path, f.mode, &f.content)?;
        }
        let home = format!("/home/{}", cfg.username);
        self.chroot(ctx, &["chown", "-R", &format!("{0}:{0}", cfg.username), &format!("{home}/.ssh")])?;
        let _ = fsx::chmod(self.target(&format!("{home}/.ssh")), 0o700);

        // One-time key for enrolling the TPM at first boot.
        let first_boot = self.state.lock().unwrap().first_boot_key.clone();
        if let Some(key) = first_boot {
            self.write(FIRST_BOOT_KEY, 0o400, key)?;
            let _ = fsx::chmod(self.target("/etc/cryptsetup-keys.d"), 0o700);
            self.chroot(ctx, &["systemctl", "enable", "dryserver-tpm-enroll.service"])?;
        }

        // Data disk keyfiles; crypttab is written with the boot loader.
        let mut uuids = Vec::new();
        if data.first().is_some_and(|d| d.key.is_some()) {
            for (i, d) in data.iter().enumerate() {
                uuids.push(self.blkid(ctx, &d.part)?);
                self.write(&format!("/etc/cryptsetup-keys.d/{DATA_MAPPER}{i}.key"), 0o400, d.key.as_deref().unwrap_or_default())?;
            }
            let _ = fsx::chmod(self.target("/etc/cryptsetup-keys.d"), 0o700);
        }
        self.state.lock().unwrap().data_uuids = uuids;

        // dryserver itself, the registry key and this machine's keys.
        self.write("/usr/local/bin/dryserver", 0o755, fsx::read(&self.self_path)?)?;
        let pub_key = PathBuf::from(format!("{}.pub", self.registry_key.display()));
        for (src, mode) in [(&self.registry_key, 0o600), (&pub_key, 0o644)] {
            let name = src.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            self.write(&format!("/etc/dryserver/{name}"), mode, fsx::read(src)?)?;
        }
        // The public half of the admin's signing key: what this server
        // checks member lists against. Required, so a stick without it
        // cannot install a server that would accept unsigned lists later.
        let signing = fsx::dir(&self.registry_key).join(iso::SIGNING_PUB);
        let line = fsx::read_string(&signing).map_err(|e| e.wrap("this installer has no signing key; build the USB stick again"))?;
        if !line.trim_start().starts_with("ssh-ed25519 ") {
            return Err(errf!("{} is not an ed25519 public key; build the USB stick again", signing.display()));
        }
        self.write(node::SIGNING_PUB, 0o644, line)?;
        let _ = fsx::chmod(self.target("/etc/dryserver"), 0o700);
        self.chroot(ctx, &["ssh-keygen", "-A"])?;
        let host_key = fsx::read_string(self.target("/etc/ssh/ssh_host_ed25519_key.pub"))?;
        self.state.lock().unwrap().host_key = host_key.trim().to_string();
        self.wireguard_key(ctx)?;
        // Proof for the admin that this machine, with these keys, was
        // installed from their stick. Only the proof is stored: the secret
        // stays on the stick.
        let secret_path = fsx::dir(&self.registry_key).join(iso::JOIN_SECRET);
        let secret = fsx::read_string(&secret_path).map_err(|e| e.wrap("this installer has no join secret; build the USB stick again"))?;
        if secret.trim().len() < 32 {
            return Err(errf!("{} is damaged; build the USB stick again", secret_path.display()));
        }
        let (wg, host_key) = {
            let st = self.state.lock().unwrap();
            (st.wg_public.clone(), st.host_key.clone())
        };
        let proof = registry::join_proof(&secret, &ch.hostname, &wg, &host_key);
        if ch.role() == Role::Coordinator {
            self.setup_registry_user(ctx)?;
            self.setup_coordinator_mesh(ctx, ch, &proof)?;
        } else {
            self.write(node::JOIN_PROOF, 0o600, format!("{proof}\n"))?;
        }

        // Services from the bundles.
        let mut enable = vec!["systemctl", "enable"];
        enable.extend(plan.services.iter().map(String::as_str));
        self.chroot(ctx, &enable)?;
        for c in &plan.user_commands {
            self.chroot(ctx, &["runuser", "-u", &cfg.username, "--", "bash", "-lc", c])?;
        }
        // Last: DNS for the chroot came from the live system until now.
        let resolv = self.target("/etc/resolv.conf");
        let _ = std::fs::remove_file(&resolv);
        std::os::unix::fs::symlink("/run/systemd/resolve/stub-resolv.conf", &resolv).map_err(Error::from)
    }

    fn wireguard_key(&self, ctx: &Ctx) -> Result<()> {
        let private = self.run.output(ctx, &Cmd::new("wg", &["genkey"]).quiet())?;
        let public = self.run.output(ctx, &Cmd::new("wg", &["pubkey"]).stdin(private.as_str()).quiet())?;
        self.state.lock().unwrap().wg_public = public.trim().to_string();
        self.write("/etc/wireguard/wg0.key", 0o600, &private)?;
        let _ = fsx::chmod(self.target("/etc/wireguard"), 0o700);
        self.write("/etc/wireguard/wg0.pub", 0o644, &public)
    }

    /// Creates the locked account that runs the registry as a forced SSH
    /// command. Its authorized_keys is owned by root so the account cannot
    /// change it.
    fn setup_registry_user(&self, ctx: &Ctx) -> Result<()> {
        let home = format!("/var/lib/{REGISTRY_USER}");
        self.chroot(ctx, &["useradd", "--system", "-m", "-d", &home, "-s", "/bin/sh", REGISTRY_USER])?;
        self.chroot(ctx, &["passwd", "-l", REGISTRY_USER])?;
        let public = fsx::read_string(format!("{}.pub", self.registry_key.display()))?;
        let line = format!("restrict,command=\"/usr/local/bin/dryserver registry --subnet {}\" {}\n", self.cfg.wg_subnet, public.trim());
        self.write(&format!("{home}/.ssh/authorized_keys"), 0o644, line)?;
        let _ = fsx::chmod(self.target(&format!("{home}/.ssh")), 0o755);
        Ok(())
    }

    fn bootloader(&self, ctx: &Ctx, ch: &Choices) -> Result<()> {
        let (lay, data_uuids) = {
            let st = self.state.lock().unwrap();
            (st.layout.clone(), st.data_uuids.clone())
        };
        let enc = ch.enc() != Encryption::None;
        let root_uuid = self.blkid(ctx, &lay.root)?;
        if enc {
            self.write("/etc/crypttab", 0o600, crypttab(&root_uuid, ch.enc(), &data_uuids))?;
        }
        // The systemd initramfs handles LUKS with TPM or passphrase.
        let conf = fsx::read_string(self.target("/etc/mkinitcpio.conf"))?;
        let lines: Vec<&str> = conf.split('\n').map(|l| if l.starts_with("HOOKS=") { MKINITCPIO_HOOKS } else { l }).collect();
        self.write("/etc/mkinitcpio.conf", 0o644, lines.join("\n"))?;

        if !lay.uefi {
            let grub = fsx::read_or_empty(self.target("/etc/default/grub"));
            let _ = self.write("/etc/default/grub", 0o644, grub.replace("GRUB_TIMEOUT=5", "GRUB_TIMEOUT=1"));
            self.chroot(ctx, &["mkinitcpio", "-P"])?;
            self.chroot(ctx, &["grub-install", "--target=i386-pc", &ch.system_disk])?;
            return self.chroot(ctx, &["grub-mkconfig", "-o", "/boot/grub/grub.cfg"]);
        }

        // UEFI: one unified kernel image, found by systemd-boot on its own.
        self.write("/etc/kernel/cmdline", 0o644, format!("{}\n", kernel_cmdline(enc, &root_uuid)))?;
        self.write("/etc/mkinitcpio.d/linux.preset", 0o644, UKI_PRESET)?;
        if ch.enc() == Encryption::Tpm {
            self.write("/etc/kernel/uki.conf", 0o644, UKI_CONF)?;
            self.chroot(
                ctx,
                &[
                    "ukify",
                    "genkey",
                    "--pcr-private-key=/etc/systemd/tpm2-pcr-private-key.pem",
                    "--pcr-public-key=/etc/systemd/tpm2-pcr-public-key.pem",
                ],
            )?;
            let _ = fsx::chmod(self.target("/etc/systemd/tpm2-pcr-private-key.pem"), 0o600);
        }
        let _ = fsx::mkdir_all(self.target("/boot/EFI/Linux"), 0o755);
        self.chroot(ctx, &["mkinitcpio", "-P"])?;
        self.chroot(ctx, &["bootctl", "install"])?;
        // The default preset's plain initramfs files are not used with a UKI.
        for f in ["/boot/initramfs-linux.img", "/boot/initramfs-linux-fallback.img"] {
            let _ = std::fs::remove_file(self.target(f));
        }
        self.write("/boot/loader/loader.conf", 0o644, LOADER_CONF)
    }

    /// Creates the registry with the coordinator as member 1 and starts its
    /// WireGuard side of the mesh.
    fn setup_coordinator_mesh(&self, ctx: &Ctx, ch: &Choices, proof: &str) -> Result<()> {
        let (wg_public, host_key, switch_mac) = {
            let st = self.state.lock().unwrap();
            (st.wg_public.clone(), st.host_key.clone(), st.switch_mac.clone())
        };
        let now = Time::now();
        let me = Member {
            host: 1,
            name: ch.hostname.clone(),
            wg_key: wg_public,
            ssh_host_key: host_key,
            lan_ip: self.cfg.coord_lan_ip.clone(),
            switch: node::port_link(&switch_mac),
            approved: now,
            last_seen: now,
        };
        let store = Store::new(self.target(registry::DEFAULT_PATH));
        let m = me.clone();
        let proof = proof.to_string();
        store.update(move |s| {
            s.members = vec![m];
            s.coordinator_proof = proof;
            Ok(())
        })?;
        let dir = fsx::dir(registry::DEFAULT_PATH).display().to_string();
        self.chroot(ctx, &["chown", "-R", &format!("{REGISTRY_USER}:{REGISTRY_USER}"), &dir])?;
        let _ = fsx::chmod(self.target(&dir), 0o700);
        let n = Node::new(self.cfg.clone(), &ch.hostname, &self.target, self.run.clone());
        // On the console until the admin signed this coordinator: the code
        // to compare on the desktop. sync removes it once a list is signed.
        let code = registry::coordinator_code(&me.wg_key, &me.ssh_host_key);
        n.write(node::ISSUE_FILE, 0o644, &node::coordinator_issue(&code))?;
        n.apply(SelfInfo { host: 1, switch: me.switch }, &[me])?;
        self.chroot(ctx, &["systemctl", "enable", "wg-quick@wg0.service", "dryserver-sync.timer"])
    }

    /// Asks the coordinator to let the new server in, shows the pairing code
    /// and waits for approval. If joining does not finish here (skipped,
    /// coordinator off), the server keeps trying at boot.
    pub(super) fn join_impl(&self, ctx: &Ctx, cfg: &Config, ch: &Choices, code: &(dyn Fn(String) + Send + Sync)) -> Result<u32> {
        // Not cancelled by skipping: these keep the server able to join later.
        let bg = Ctx::new();
        // Until approved, the installed system retries at every boot.
        self.chroot(&bg, &["systemctl", "enable", "dryserver-join.service"])?;
        let n = Node::new(cfg.clone(), &ch.hostname, &self.target, self.run.clone());
        let lan = node::local_ip(ctx, self.run.as_ref(), &cfg.coord_lan_ip)?;
        let switch_mac = self.state.lock().unwrap().switch_mac.clone();
        let sw = node::port_link(&switch_mac);
        code(n.request(ctx, &lan, sw)?);
        let reply = n
            .wait(ctx, Duration::from_secs(3))
            .map_err(|e| if e.is(Kind::Rejected) { Error::with_kind(Kind::Rejected, REJECTED) } else { e })?;
        let plan = packages::resolve(&cfg.tool_list(), &cfg.extra_list())?;
        let params = Params { config: cfg.clone(), plan, hostname: ch.hostname.clone(), role: Role::Node, host_num: 0, switch_mac };
        n.activate(&reply, SelfInfo { host: 0, switch: sw }, &params)?;
        self.chroot(&bg, &["systemctl", "enable", "wg-quick@wg0.service", "dryserver-sync.timer"])?;
        self.chroot(&bg, &["systemctl", "disable", "dryserver-join.service"])?;
        Ok(reply.host)
    }
}

impl Backend for Real {
    fn probe(&self, ctx: &Ctx) -> Result<Machine> {
        self.probe_impl(ctx)
    }

    fn scan_wifi(&self, ctx: &Ctx) -> Result<Vec<String>> {
        self.scan_wifi_impl(ctx)
    }

    fn connect_wifi(&self, ctx: &Ctx, ssid: &str, pass: &str) -> Result<Machine> {
        self.connect_wifi_impl(ctx, ssid, pass)
    }

    fn precheck(&self, ctx: &Ctx, cfg: &Config, ch: &Choices, progress: Progress) -> Result<()> {
        self.precheck_impl(ctx, cfg, ch, progress)
    }

    fn install(&self, ctx: &Ctx, cfg: &Config, ch: &Choices, progress: Progress) -> Result<()> {
        self.install_impl(ctx, cfg, ch, progress)
    }

    fn join(&self, ctx: &Ctx, cfg: &Config, ch: &Choices, code: &(dyn Fn(String) + Send + Sync)) -> Result<u32> {
        self.join_impl(ctx, cfg, ch, code)
    }

    fn coordinator_code(&self) -> String {
        let st = self.state.lock().unwrap();
        if st.wg_public.is_empty() || st.host_key.is_empty() {
            return String::new();
        }
        registry::coordinator_code(&st.wg_public, &st.host_key)
    }

    fn reboot(&self) -> Result<()> {
        self.reboot_impl()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::Runner;
    use crate::testutil::{TempDir, get, put};
    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Mutex};

    /// Records commands and returns canned output. lsblk answers with
    /// old[disk] until sfdisk has written that disk, then with the new
    /// layout.
    #[derive(Default)]
    struct FakeRunner {
        cmds: Mutex<Vec<Cmd>>,
        old: HashMap<String, String>,
        /// disk -> sfdisk script
        partitioned: Mutex<HashMap<String, String>>,
        /// The kernel keeps the old table: sfdisk "works" but lsblk does
        /// not change.
        stuck: bool,
        /// pacstrap fails with these outputs first.
        failures: Mutex<Vec<String>>,
    }

    impl Runner for FakeRunner {
        fn run(&self, _: &Ctx, c: &Cmd) -> (String, Result<()>) {
            self.cmds.lock().unwrap().push(c.clone());
            let last = c.args.last().cloned().unwrap_or_default();
            let ok = |s: &str| (s.to_string(), Ok(()));
            match (c.name.as_str(), c.args.first().map(String::as_str)) {
                ("sfdisk", _) => {
                    if !self.stuck {
                        self.partitioned.lock().unwrap().insert(last, c.stdin.clone());
                    }
                    ok("")
                }
                ("lsblk", _) => {
                    let dev = last;
                    let script = self.partitioned.lock().unwrap().get(&dev).cloned();
                    match script {
                        Some(s) if s.contains("size=1GiB") => ok(&format!(
                            r#"{{"blockdevices":[{{"name":"{dev}","type":"disk","size":21474836480,"children":[{{"name":"{}","type":"part","size":1073741824}},{{"name":"{}","type":"part","size":20400000000}}]}}]}}"#,
                            part_path(&dev, 1),
                            part_path(&dev, 2)
                        )),
                        Some(_) => ok(&format!(
                            r#"{{"blockdevices":[{{"name":"{dev}","type":"disk","size":21474836480,"children":[{{"name":"{}","type":"part","size":21474000000}}]}}]}}"#,
                            part_path(&dev, 1)
                        )),
                        None => match self.old.get(&dev) {
                            Some(o) => ok(o),
                            None => ok(&format!(
                                r#"{{"blockdevices":[{{"name":"{dev}","type":"disk","size":21474836480,"mountpoints":[null]}}]}}"#
                            )),
                        },
                    }
                }
                ("pacstrap", _) => {
                    let mut f = self.failures.lock().unwrap();
                    if f.is_empty() { ok("") } else { (f.remove(0), Err("pacstrap failed: exit status 1".into())) }
                }
                ("blkid", _) => ok("1111-uuid\n"),
                ("wg", Some("genkey")) => ok("PRIVATEKEY=\n"),
                ("wg", Some("pubkey")) => ok("PUBLICKEY=\n"),
                ("genfstab", _) => ok("UUID=1111-uuid / ext4 rw 0 1\n"),
                _ => ok(""),
            }
        }
    }

    impl FakeRunner {
        fn strings(&self) -> Vec<String> {
            self.cmds.lock().unwrap().iter().map(|c| c.to_string()).collect()
        }

        fn index(&self, prefix: &str) -> usize {
            self.strings().iter().position(|c| c.starts_with(prefix)).unwrap_or_else(|| panic!("command {prefix:?} never ran"))
        }

        fn find(&self, prefix: &str) -> Cmd {
            let i = self.index(prefix);
            self.cmds.lock().unwrap()[i].clone()
        }
    }

    const JOIN_SECRET: &str = "5ec2e75ec2e75ec2e75ec2e75ec2e75ec2e75ec2e75ec2e75ec2e75ec2e75ec2";
    const DISK_PASS: &str = "disk passphrase 123";
    const USER_PASS: &str = "user password 456";

    fn test_real(uefi: bool, fr: FakeRunner) -> (TempDir, Real, Arc<FakeRunner>) {
        let dir = TempDir::new();
        let target = dir.join("mnt");
        put(&target, "etc/mkinitcpio.conf", "MODULES=()\nHOOKS=(base udev autodetect)\n");
        put(&target, "etc/default/grub", "GRUB_TIMEOUT=5\n");
        put(&target, "etc/ssh/ssh_host_ed25519_key.pub", "ssh-ed25519 AAAAhost root@new\n");
        let me = dir.join("dryserver");
        std::fs::write(&me, "binary").unwrap();
        let key = dir.join("registry_ed25519");
        std::fs::write(&key, "private").unwrap();
        std::fs::write(dir.join("registry_ed25519.pub"), "ssh-ed25519 AAAAreg dryserver-registry\n").unwrap();
        std::fs::write(dir.join(iso::SIGNING_PUB), "ssh-ed25519 AAAAsign dryserver-signing\n").unwrap();
        std::fs::write(dir.join(iso::JOIN_SECRET), format!("{JOIN_SECRET}\n")).unwrap();

        let cfg = Config {
            coord_lan_ip: "192.168.1.50".into(),
            admin_ssh_pubkey: "ssh-ed25519 AAAAadmin me@desktop".into(),
            ..Config::default()
        };
        let rootfs = ["etc/skel/.tmux.conf", "etc/skel/.config/nvim/init.lua", "etc/profile.d/editor.sh"]
            .iter()
            .map(|f| (f.to_string(), format!("# {f}").into_bytes()))
            .collect();
        let fr = Arc::new(fr);
        let mut r = Real::new(cfg, rootfs, me, key);
        r.run = fr.clone();
        r.target = target;
        r.key_dir = dir.path().to_path_buf();
        *r.machine.lock().unwrap() = Machine { uefi, tpm2: uefi, ..Machine::default() };
        (dir, r, fr)
    }

    fn mode(p: PathBuf) -> (u32, u64) {
        let m = std::fs::metadata(p).unwrap();
        (m.permissions().mode() & 0o777, m.len())
    }

    #[test]
    fn install_uefi_tpm() {
        let (_dir, r, fr) = test_real(true, FakeRunner::default());
        let ch = Choices {
            role: Some(Role::Node),
            hostname: "node-3a2f".into(),
            system_disk: "/dev/nvme0n1".into(),
            data_disks: vec!["/dev/sda".into()],
            encryption: Some(Encryption::Tpm),
            disk_passphrase: DISK_PASS.into(),
            user_password: USER_PASS.into(),
        };
        let steps: Arc<Mutex<Vec<String>>> = Arc::default();
        let s = steps.clone();
        r.install(
            &Ctx::new(),
            &r.cfg,
            &ch,
            Arc::new(move |st: Step| {
                if st.done {
                    s.lock().unwrap().push(st.name)
                }
            }),
        )
        .unwrap();
        assert_eq!(steps.lock().unwrap().len(), 5);

        // Order: wipe before format, format before mount, packages before config.
        let t = r.target.display().to_string();
        let order = [
            "wipefs --all --force /dev/nvme0n1".to_string(),
            "sfdisk --wipe always --wipe-partitions always /dev/nvme0n1".into(),
            "cryptsetup luksFormat --type luks2 --pbkdf argon2id --batch-mode --key-file=- /dev/nvme0n1p2".into(),
            "cryptsetup open --key-file=- /dev/nvme0n1p2 root".into(),
            "cryptsetup luksAddKey --key-file=- /dev/nvme0n1p2".into(),
            "mkfs.ext4 -F -q -L root /dev/mapper/root".into(),
            "mkfs.fat -F 32 -n EFI /dev/nvme0n1p1".into(),
            "cryptsetup luksAddKey --key-file=- /dev/sda1".into(),
            "mount /dev/mapper/root".into(),
            "pacstrap -K".into(),
            format!("arch-chroot {t} useradd -m -G wheel,docker"),
            format!("arch-chroot {t} chpasswd"),
            format!("arch-chroot {t} passwd -l root"),
            format!("arch-chroot {t} ukify genkey"),
            format!("arch-chroot {t} mkinitcpio -P"),
            format!("arch-chroot {t} bootctl install"),
        ];
        let mut last = 0;
        for prefix in &order {
            let i = fr.index(prefix);
            assert!(i >= last, "{prefix:?} ran out of order");
            last = i;
        }

        let pac = fr.find("pacstrap").args;
        for p in ["efibootmgr", "systemd-ukify", "tpm2-tss", "docker", "openssh"] {
            assert!(pac.iter().any(|a| a == p), "pacstrap missing {p}");
        }
        assert!(!pac.iter().any(|a| a == "grub"), "UEFI install must not use grub");

        // Secrets only through stdin, never in arguments.
        for c in fr.strings() {
            assert!(!c.contains(DISK_PASS) && !c.contains(USER_PASS), "secret in command line: {c}");
        }
        assert_eq!(fr.find("cryptsetup luksFormat").stdin, DISK_PASS);
        assert!(fr.find(&format!("arch-chroot {t} chpasswd")).stdin.contains(&format!("admin:{USER_PASS}")));
        assert!(!fr.strings().iter().any(|c| c.starts_with("systemd-cryptenroll")), "the TPM is enrolled at first boot");
        fr.index(&format!("arch-chroot {t} systemctl enable dryserver-tpm-enroll.service"));
        assert_eq!(mode(r.target(FIRST_BOOT_KEY)), (0o400, 64), "first-boot key");

        // Files in the new system.
        let read = |p: &str| get(&r.target, p);
        assert!(read("/etc/crypttab").contains("x-initrd.attach,tpm2-device=auto"));
        assert!(read("/etc/mkinitcpio.conf").contains("sd-encrypt"), "mkinitcpio hooks not replaced");
        assert!(read("/etc/kernel/uki.conf").contains("PCRPrivateKey"), "UKI not signed for TPM");
        assert_eq!(read("/boot/loader/loader.conf"), LOADER_CONF);
        assert_eq!(mode(r.target("/etc/cryptsetup-keys.d/data0.key")), (0o400, 512), "data keyfile");
        assert!(read("/etc/crypttab").contains("data0 UUID=1111-uuid /etc/cryptsetup-keys.d/data0.key"), "{}", read("/etc/crypttab"));
        assert_eq!(read("/etc/wireguard/wg0.key"), "PRIVATEKEY=\n");
        assert_eq!(r.state.lock().unwrap().wg_public, "PUBLICKEY=");
        // The join proof for this machine's name and keys; the secret
        // itself must not be anywhere in the new system.
        assert_eq!(
            read(node::JOIN_PROOF).trim(),
            registry::join_proof(JOIN_SECRET, "node-3a2f", "PUBLICKEY=", "ssh-ed25519 AAAAhost root@new")
        );
        assert_eq!(mode(r.target(node::JOIN_PROOF)).0, 0o600);
        fn files(d: &std::path::Path, out: &mut Vec<PathBuf>) {
            for e in std::fs::read_dir(d).unwrap().flatten() {
                let p = e.path();
                if p.is_symlink() {
                    continue;
                }
                if p.is_dir() { files(&p, out) } else { out.push(p) }
            }
        }
        let mut all = Vec::new();
        files(&r.target, &mut all);
        for f in all {
            let b = std::fs::read(&f).unwrap_or_default();
            assert!(!b.windows(JOIN_SECRET.len()).any(|w| w == JOIN_SECRET.as_bytes()), "the join secret was copied to {}", f.display());
        }
        assert_eq!(std::fs::read_link(r.target("/etc/resolv.conf")).unwrap(), PathBuf::from("/run/systemd/resolve/stub-resolv.conf"));
        assert!(!read("/etc/skel/.tmux.conf").is_empty(), "bundle files not installed");
        assert!(
            !r.key_dir.join("dryserver-tpm-enroll.key").exists() && !r.key_dir.join("dryserver-data0.key").exists(),
            "temporary keys left behind"
        );
    }

    #[test]
    fn install_bios_plain_coordinator() {
        let (_dir, r, fr) = test_real(false, FakeRunner::default());
        let ch = Choices {
            role: Some(Role::Coordinator),
            hostname: "coord".into(),
            system_disk: "/dev/sda".into(),
            encryption: Some(Encryption::None),
            user_password: USER_PASS.into(),
            ..Choices::default()
        };
        r.install(&Ctx::new(), &r.cfg, &ch, Arc::new(|_| {})).unwrap();
        for c in fr.strings() {
            assert!(
                !c.starts_with("cryptsetup") && !c.starts_with("systemd-cryptenroll") && !c.contains("bootctl"),
                "unexpected for BIOS/unencrypted: {c}"
            );
        }
        let t = r.target.display().to_string();
        fr.index(&format!("arch-chroot {t} grub-install --target=i386-pc /dev/sda"));
        fr.index("mkfs.ext4 -F -q -L boot /dev/sda1");
        fr.index(&format!("arch-chroot {t} useradd --system -m -d /var/lib/dryreg -s /bin/sh dryreg"));

        let ak = get(&r.target, "/var/lib/dryreg/.ssh/authorized_keys");
        assert!(
            ak.starts_with(r#"restrict,command="/usr/local/bin/dryserver registry --subnet 10.66.0.0/24" ssh-ed25519 AAAAreg"#),
            "{ak}"
        );
        assert!(get(&r.target, "/etc/ssh/sshd_config.d/10-dryserver.conf").contains("AllowUsers admin dryreg"));
        assert!(!r.target("/etc/crypttab").exists(), "unencrypted install must not write crypttab");
        // The signing public key, readable by root and the registry user.
        assert_eq!(get(&r.target, node::SIGNING_PUB), "ssh-ed25519 AAAAsign dryserver-signing\n");
        let mode = |p: &str| std::fs::metadata(r.target(p)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(node::SIGNING_PUB), 0o644);
        assert_eq!(mode("/usr/local/share/dryserver") & 0o005, 0o005, "the registry user must be able to reach the key");

        assert!(!r.target(node::JOIN_PROOF).exists(), "a coordinator asks nobody to join");
        // Its proof goes into the registry, for the admin's first signature.
        let proof = registry::join_proof(JOIN_SECRET, "coord", "PUBLICKEY=", "ssh-ed25519 AAAAhost root@new");
        let reg = get(&r.target, "/var/lib/dryserver/registry.json");
        assert!(reg.contains(&format!(r#""coordinator_proof": "{proof}""#)) && !reg.contains(JOIN_SECRET), "{reg}");
        // Coordinator: its code on the console until the admin signs it.
        let issue = get(&r.target, node::ISSUE_FILE);
        assert!(issue.contains("not signed yet") && issue.contains(&r.coordinator_code()) && r.coordinator_code().len() == 7, "{issue}");
        // Coordinator: registry with itself as member 1, mesh config, services.
        let reg = get(&r.target, "/var/lib/dryserver/registry.json");
        assert!(reg.contains(r#""host": 1"#) && reg.contains(r#""wg_key": "PUBLICKEY=""#), "registry: {reg}");
        assert!(get(&r.target, "/etc/wireguard/wg0.conf").contains("Address = 10.66.0.1/24"));
        fr.index(&format!("arch-chroot {t} systemctl enable wg-quick@wg0.service dryserver-sync.timer"));
        fr.index(&format!("arch-chroot {t} chown -R dryreg:dryreg /var/lib/dryserver"));
    }

    // A used laptop: an old LVM volume (mounted), swap, and a LUKS mapping
    // left open by an earlier setup attempt. All must be released before
    // sfdisk.
    #[test]
    fn install_releases_old_disk() {
        let old = r#"{"blockdevices":[{"name":"/dev/nvme0n1","type":"disk","size":256060514304,"mountpoints":[null],"children":[
            {"name":"/dev/nvme0n1p1","type":"part","size":536870912,"mountpoints":[null]},
            {"name":"/dev/nvme0n1p2","type":"part","size":8589934592,"mountpoints":["[SWAP]"]},
            {"name":"/dev/nvme0n1p3","type":"part","size":200000000000,"mountpoints":[null],"children":[
                {"name":"/dev/mapper/oldvg-root","type":"lvm","size":100000000000,"mountpoints":["/run/old"]}]},
            {"name":"/dev/nvme0n1p4","type":"part","size":40000000000,"mountpoints":[null],"children":[
                {"name":"/dev/mapper/root","type":"crypt","size":39000000000,"mountpoints":["/mnt"]}]}]}]}"#;
        let fr = FakeRunner { old: HashMap::from([("/dev/nvme0n1".to_string(), old.to_string())]), ..FakeRunner::default() };
        let (_dir, r, fr) = test_real(true, fr);
        let ch = Choices {
            role: Some(Role::Node),
            hostname: "node-x".into(),
            system_disk: "/dev/nvme0n1".into(),
            encryption: Some(Encryption::None),
            user_password: USER_PASS.into(),
            ..Choices::default()
        };
        r.install(&Ctx::new(), &r.cfg, &ch, Arc::new(|_| {})).unwrap();
        let cmds = fr.strings();
        let mut from = 0;
        for prefix in [
            "swapoff /dev/nvme0n1p2",
            "umount -R /run/old",
            "dmsetup remove --retry /dev/mapper/oldvg-root",
            "umount -R /mnt",
            "dmsetup remove --retry /dev/mapper/root",
            "wipefs --all --force /dev/nvme0n1",
            "sfdisk --wipe always",
        ] {
            let i = cmds[from..].iter().position(|c| c.starts_with(prefix)).unwrap_or_else(|| panic!("{prefix:?} missing or out of order"));
            from += i + 1;
        }
    }

    #[test]
    fn install_stops_when_kernel_keeps_old_partitions() {
        let (_dir, r, fr) = test_real(true, FakeRunner { stuck: true, ..FakeRunner::default() });
        let ch = Choices {
            role: Some(Role::Node),
            hostname: "node-x".into(),
            system_disk: "/dev/sda".into(),
            encryption: Some(Encryption::None),
            user_password: USER_PASS.into(),
            ..Choices::default()
        };
        let err = r.install(&Ctx::new(), &r.cfg, &ch, Arc::new(|_| {})).unwrap_err();
        assert!(err.to_string().contains("still sees the old partitions"), "{err}");
        for c in fr.strings() {
            assert!(!c.starts_with("mkfs.ext4") && !c.starts_with("cryptsetup"), "formatted despite a stale partition table: {c}");
        }
    }

    #[test]
    fn pacstrap_retries() {
        let fr = FakeRunner {
            failures: Mutex::new(vec![
                "error: failed retrieving file 'go-1.26.pkg.tar.zst' from fastly.mirror.pkgbuild.com : Operation too slow\nerror: failed to commit transaction (failed to retrieve some files)\nErrors occurred, no packages were upgraded.".into(),
                "error: go: signature from \"Someone\" is unknown trust\nerror: failed to commit transaction (invalid or corrupted package (PGP signature))\nErrors occurred, no packages were upgraded.".into(),
            ]),
            ..FakeRunner::default()
        };
        let (_dir, mut r, fr) = test_real(true, fr);
        let logs: Arc<Mutex<Vec<String>>> = Arc::default();
        let l = logs.clone();
        r.log.set_sink(Some(Arc::new(move |s: &str| l.lock().unwrap().push(s.to_string()))));
        let down = Arc::new(Mutex::new(2)); // the network is down for the first two checks
        r.net_check = Some(Box::new(move |_| {
            let mut d = down.lock().unwrap();
            *d -= 1;
            *d < 0
        }));
        r.net_poll = Duration::from_millis(1);
        r.pacstrap(&Ctx::new(), &["base".into()]).unwrap();
        let cmds = fr.strings();
        assert_eq!(cmds.iter().filter(|c| c.starts_with("pacstrap")).count(), 3);
        assert!(cmds.iter().any(|c| c == "pacman -Sy --noconfirm archlinux-keyring"), "no keyring refresh");
        let all = logs.lock().unwrap().join("\n");
        for w in ["downloads failed", "attempt 3 of 3", "waiting for the network"] {
            assert!(all.contains(w), "logs:\n{all}");
        }
    }

    #[test]
    fn pacstrap_gives_up() {
        let full = "error: could not extract /mnt/usr/lib/libfoo.so (No space left on device)\nErrors occurred, no packages were upgraded."
            .to_string();
        let fr = FakeRunner { failures: Mutex::new(vec![full.clone(), full.clone(), full]), ..FakeRunner::default() };
        let (_dir, mut r, _) = test_real(true, fr);
        r.net_check = Some(Box::new(|_| true));
        let err = r.pacstrap(&Ctx::new(), &["base".into()]).unwrap_err();
        assert!(err.to_string().contains("the disk is full (after 3 attempts)"), "{err}");
    }
}
