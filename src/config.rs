//! Loads, validates and saves config.env, the settings baked into the
//! installer ISO. The file is plain KEY='value' lines so shell scripts on
//! the nodes can source it.

use std::path::Path;

use crate::cidr::{Cidr, parse_ip4};
use crate::err::{Error, Result};
use crate::{errf, fsx, packages};

/// Uses the switch when both nodes have a cable link on their Ethernet
/// port, and the WiFi/router network otherwise.
pub const TRANSPORT_AUTO: &str = "auto";
/// Always uses the WiFi/router network.
pub const TRANSPORT_LAN: &str = "lan";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub wifi_ssid: String,
    pub wifi_pass: String,
    pub coord_lan_ip: String,
    pub wg_subnet: String,
    pub wg_port: String,
    pub wg_transport: String,
    pub switch_subnet: String,
    /// Space-separated port/proto opened on wg0, e.g. "8080/tcp 53/udp".
    pub mesh_ports: String,
    /// Extra ports the servers and their containers may connect to on the
    /// internet, like "25565/tcp 27015/udp". DNS, time and web are always
    /// allowed.
    pub egress_ports: String,
    /// Space-separated optional bundle IDs, see packages::OPTIONAL.
    pub tools: String,
    /// Space-separated extra Arch packages.
    pub extra_packages: String,
    pub username: String,
    /// Key type and key only, no comment.
    pub admin_ssh_pubkey: String,
    /// Short name shown after the key on servers.
    pub admin_key_label: String,
    pub timezone: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            wifi_ssid: String::new(),
            wifi_pass: String::new(),
            coord_lan_ip: String::new(),
            wg_subnet: "10.66.0.0/24".into(),
            wg_port: "51820".into(),
            wg_transport: TRANSPORT_AUTO.into(),
            switch_subnet: "172.16.66.0/24".into(),
            mesh_ports: String::new(),
            egress_ports: String::new(),
            tools: packages::default_tools().join(" "),
            extra_packages: String::new(),
            username: "admin".into(),
            admin_ssh_pubkey: String::new(),
            admin_key_label: "desktop".into(),
            timezone: "UTC".into(),
        }
    }
}

const KEYS: [&str; 15] = [
    "WIFI_SSID",
    "WIFI_PASS",
    "COORD_LAN_IP",
    "WG_SUBNET",
    "WG_PORT",
    "WG_TRANSPORT",
    "SWITCH_SUBNET",
    "MESH_PORTS",
    "EGRESS_PORTS",
    "TOOLS",
    "EXTRA_PACKAGES",
    "USERNAME",
    "ADMIN_SSH_PUBKEY",
    "ADMIN_KEY_LABEL",
    "TIMEZONE",
];

impl Config {
    /// Each env key with its field, in file order.
    fn field_mut(&mut self, key: &str) -> Option<&mut String> {
        Some(match key {
            "WIFI_SSID" => &mut self.wifi_ssid,
            "WIFI_PASS" => &mut self.wifi_pass,
            "COORD_LAN_IP" => &mut self.coord_lan_ip,
            "WG_SUBNET" => &mut self.wg_subnet,
            "WG_PORT" => &mut self.wg_port,
            "WG_TRANSPORT" => &mut self.wg_transport,
            "SWITCH_SUBNET" => &mut self.switch_subnet,
            "MESH_PORTS" => &mut self.mesh_ports,
            "EGRESS_PORTS" => &mut self.egress_ports,
            "TOOLS" => &mut self.tools,
            "EXTRA_PACKAGES" => &mut self.extra_packages,
            "USERNAME" => &mut self.username,
            "ADMIN_SSH_PUBKEY" => &mut self.admin_ssh_pubkey,
            "ADMIN_KEY_LABEL" => &mut self.admin_key_label,
            "TIMEZONE" => &mut self.timezone,
            _ => return None,
        })
    }

    fn field(&self, key: &str) -> &str {
        match key {
            "WIFI_SSID" => &self.wifi_ssid,
            "WIFI_PASS" => &self.wifi_pass,
            "COORD_LAN_IP" => &self.coord_lan_ip,
            "WG_SUBNET" => &self.wg_subnet,
            "WG_PORT" => &self.wg_port,
            "WG_TRANSPORT" => &self.wg_transport,
            "SWITCH_SUBNET" => &self.switch_subnet,
            "MESH_PORTS" => &self.mesh_ports,
            "EGRESS_PORTS" => &self.egress_ports,
            "TOOLS" => &self.tools,
            "EXTRA_PACKAGES" => &self.extra_packages,
            "USERNAME" => &self.username,
            "ADMIN_SSH_PUBKEY" => &self.admin_ssh_pubkey,
            "ADMIN_KEY_LABEL" => &self.admin_key_label,
            "TIMEZONE" => &self.timezone,
            _ => "",
        }
    }

    /// Reads path. A missing file is an error of kind NotFound.
    pub fn load(path: impl AsRef<Path>) -> Result<Config> {
        let (c, err) = Config::load_partial(path);
        match err {
            Some(e) => Err(e),
            None => Ok(c),
        }
    }

    /// Like load, but also returns what was read before an error (the
    /// defaults for a missing file).
    pub fn load_partial(path: impl AsRef<Path>) -> (Config, Option<Error>) {
        let path = path.as_ref();
        let mut c = Config::default();
        let text = match fsx::read_string(path) {
            Ok(t) => t,
            Err(e) => return (c, Some(e)),
        };
        for (i, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                return (c, Some(errf!("{}:{}: expected KEY=value", path.display(), i + 1)));
            };
            if let Some(dst) = c.field_mut(k.trim()) {
                *dst = unquote(v.trim());
            }
        }
        c.admin_ssh_pubkey = normalize_pubkey(&c.admin_ssh_pubkey);
        (c, None)
    }

    /// Writes the file atomically, readable by the owner only: the
    /// temporary file is made new at 0600, never through a link and never
    /// a file left there with another mode (it holds the WiFi password).
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let tmp = format!("{}.tmp", path.display());
        fsx::write_new(&tmp, self.render(), 0o600)?;
        fsx::rename(&tmp, path)
    }

    /// The config in env-file form.
    pub fn render(&self) -> String {
        let mut c = self.clone();
        c.admin_ssh_pubkey = normalize_pubkey(&c.admin_ssh_pubkey);
        let mut b = String::from("# dryserver config. Keep private: may contain the WiFi password.\n");
        for k in KEYS {
            b += &format!("{k}={}\n", quote(c.field(k)));
        }
        b
    }

    pub fn validate(&self) -> Result<()> {
        let mut errs = Vec::new();
        let mut check = |name: &str, r: Result<()>| {
            if let Err(e) = r {
                errs.push(e.wrap(name));
            }
        };
        if !self.wifi_ssid.is_empty() {
            check("WiFi password", valid_wifi_pass(&self.wifi_pass));
        }
        check("coordinator IP", valid_ipv4(&self.coord_lan_ip));
        check("mesh subnet", valid_mesh_subnet(&self.wg_subnet, &self.coord_lan_ip));
        check("WireGuard port", valid_port(&self.wg_port));
        check("WireGuard transport", valid_transport(&self.wg_transport));
        if self.wg_transport == TRANSPORT_AUTO {
            check("switch subnet", valid_switch_subnet(&self.switch_subnet, &self.wg_subnet, &self.coord_lan_ip));
        }
        check("networks", free_of_cluster_ranges(self));
        check("mesh ports", valid_mesh_ports(&self.mesh_ports));
        check("outgoing ports", valid_mesh_ports(&self.egress_ports));
        check("tools", packages::valid_tools(&self.tool_list()));
        check("extra packages", packages::valid_extra(&self.extra_list()));
        check("username", valid_username(&self.username));
        check("SSH key", valid_pubkey(&self.admin_ssh_pubkey));
        check("key label", valid_key_label(&self.admin_key_label));
        check("timezone", valid_timezone(&self.timezone));
        match Error::join(errs) {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    pub fn tool_list(&self) -> Vec<String> {
        fields(&self.tools)
    }

    pub fn extra_list(&self) -> Vec<String> {
        fields(&self.extra_packages)
    }
}

/// Splits on whitespace, like Go's strings.Fields.
pub fn fields(s: &str) -> Vec<String> {
    s.split_whitespace().map(String::from).collect()
}

/// Checks the space-separated form field.
pub fn valid_extra_packages(s: &str) -> Result<()> {
    packages::valid_extra(&fields(s))
}

pub fn valid_wifi_pass(s: &str) -> Result<()> {
    // WPA2-PSK passphrases are 8 to 63 characters. Empty means an open network.
    if !s.is_empty() && (s.len() < 8 || s.len() > 63) {
        return Err("must be 8 to 63 characters (or empty for an open network)".into());
    }
    Ok(())
}

pub fn valid_ipv4(s: &str) -> Result<()> {
    match ipv4(s) {
        Some(_) => Ok(()),
        None => Err("must be an IPv4 address like 192.168.1.50".into()),
    }
}

/// An IPv4 address in its one plain form, "192.168.1.50". Other spellings
/// (IPv6-mapped "::ffff:192.168.1.50") are refused: what the config holds
/// ends up in the firewall, SSH and WireGuard files, and an nft file that
/// does not load leaves the machine without a firewall.
pub fn ipv4(s: &str) -> Option<std::net::Ipv4Addr> {
    let ip: std::net::Ipv4Addr = s.parse().ok()?;
    (ip.to_string() == s).then_some(ip)
}

/// A port in its one plain form: decimal digits without sign or leading
/// zero, 1 to 65535 (not "+51820", which nft refuses).
pub fn port_number(s: &str) -> Option<u16> {
    let n: u16 = s.parse().ok()?;
    (n > 0 && n.to_string() == s).then_some(n)
}

pub fn valid_subnet(s: &str) -> Result<()> {
    let Some(n) = Cidr::parse(s) else {
        return Err("must be an IPv4 CIDR like 10.66.0.0/24".into());
    };
    if n.prefix > 29 {
        return Err("too small, use /29 or bigger (e.g. /24)".into());
    }
    if n.addr != n.network() {
        return Err(errf!("use the network address {}", n.network_string()));
    }
    Ok(())
}

/// Also rejects a mesh subnet holding the coordinator's LAN IP, which would
/// break routing to the coordinator.
pub fn valid_mesh_subnet(s: &str, coord_ip: &str) -> Result<()> {
    valid_subnet(s)?;
    let n = Cidr::parse(s).expect("checked above");
    if let Some(ip) = parse_ip4(coord_ip)
        && n.contains(ip)
    {
        return Err(errf!("contains the coordinator LAN IP {coord_ip}, pick another range"));
    }
    Ok(())
}

/// Checks the switch range against the mesh range: node N in the mesh gets
/// host N on the switch, so both need the same size, and they must not
/// overlap each other or the coordinator's LAN IP.
pub fn valid_switch_subnet(s: &str, mesh_subnet: &str, coord_ip: &str) -> Result<()> {
    valid_mesh_subnet(s, coord_ip)?;
    let sw = Cidr::parse(s).expect("checked above");
    let Some(mesh) = Cidr::parse(mesh_subnet) else {
        return Ok(()); // reported on the mesh subnet field
    };
    if sw.contains(mesh.network_ip()) || mesh.contains(sw.network_ip()) {
        return Err(errf!("overlaps the mesh subnet {}", mesh.network_string()));
    }
    if sw.prefix != mesh.prefix {
        return Err(errf!("must be the same size as the mesh subnet (/{})", mesh.prefix));
    }
    Ok(())
}

/// One firewall opening: number and protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Port {
    pub num: u16,
    /// tcp or udp
    pub proto: String,
}

/// Parses "8080/tcp 53/udp 9000" (protocol defaults to tcp).
pub fn parse_ports(s: &str) -> Result<Vec<Port>> {
    let mut out = Vec::new();
    for f in s.split_whitespace() {
        let (num, proto) = f.split_once('/').unwrap_or((f, ""));
        let proto = if proto.is_empty() { "tcp" } else { proto };
        match go_atoi(num) {
            Some(n) if (1..=65535).contains(&n) && (proto == "tcp" || proto == "udp") => {
                out.push(Port { num: n as u16, proto: proto.to_string() })
            }
            _ => return Err(errf!("{f:?}: use PORT/tcp or PORT/udp, e.g. 8080/tcp")),
        }
    }
    Ok(out)
}

/// Parses a decimal integer with an optional sign, like Go's strconv.Atoi.
fn go_atoi(s: &str) -> Option<i64> {
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

pub fn valid_mesh_ports(s: &str) -> Result<()> {
    parse_ports(s).map(|_| ())
}

/// k3s uses 10.42.0.0/16 for pods and 10.43.0.0/16 for services on every
/// machine. A mesh, switch or home network inside them would be shadowed.
fn free_of_cluster_ranges(c: &Config) -> Result<()> {
    let cluster = Cidr { addr: u32::from(std::net::Ipv4Addr::new(10, 42, 0, 0)), prefix: 15 };
    let inside = |ip: std::net::Ipv4Addr| cluster.contains(ip);
    let mut nets = vec![("mesh subnet", c.wg_subnet.as_str())];
    if c.wg_transport == TRANSPORT_AUTO {
        nets.push(("switch subnet", c.switch_subnet.as_str()));
    }
    for (what, text) in nets {
        if let Some(n) = Cidr::parse(text)
            && (inside(n.network_ip()) || n.contains(cluster.network_ip()))
        {
            return Err(errf!("the {what} {text} overlaps 10.42.0.0/15, which the cluster uses inside every machine; pick another"));
        }
    }
    if let Some(ip) = parse_ip4(&c.coord_lan_ip)
        && inside(ip)
    {
        return Err(errf!(
            "the coordinator IP {} is inside 10.42.0.0/15, which the cluster uses inside every machine; your home network needs other addresses",
            c.coord_lan_ip
        ));
    }
    Ok(())
}

pub fn valid_transport(s: &str) -> Result<()> {
    if s != TRANSPORT_AUTO && s != TRANSPORT_LAN {
        return Err(errf!("must be {TRANSPORT_AUTO:?} or {TRANSPORT_LAN:?}"));
    }
    Ok(())
}

pub fn valid_port(s: &str) -> Result<()> {
    match port_number(s) {
        Some(_) => Ok(()),
        None => Err("must be a number from 1 to 65535".into()),
    }
}

pub fn valid_username(s: &str) -> Result<()> {
    let mut chars = s.chars();
    let first_ok = matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c == '_');
    let rest_ok = chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if !first_ok || !rest_ok || s.len() > 32 || s == "root" {
        return Err("lowercase letters, digits, _ and -, not root".into());
    }
    Ok(())
}

/// The admin's SSH key: it logs in to the machines and signs for the
/// swarm, and the swarm signs with ed25519 keys only.
pub fn valid_pubkey(s: &str) -> Result<()> {
    if s.contains("PRIVATE KEY") {
        return Err("that is a private key, use the .pub file".into());
    }
    let f: Vec<&str> = s.split_whitespace().collect();
    if f.len() < 2 || !(f[0].starts_with("ssh-") || f[0].starts_with("ecdsa-") || f[0].starts_with("sk-")) {
        return Err("paste the line from ~/.ssh/id_ed25519.pub (starts with ssh-ed25519)".into());
    }
    if f[0] != "ssh-ed25519" {
        return Err(format!(
            "it also signs for your swarm, so it must be an ed25519 key (this is {}): make one with ssh-keygen -t \
             ed25519 and paste ~/.ssh/id_ed25519.pub",
            f[0]
        )
        .into());
    }
    Ok(())
}

/// Accepts zone names found in the system's time zone database.
pub fn valid_timezone(s: &str) -> Result<()> {
    if s.is_empty() || s.starts_with('/') || s.contains("..") {
        return Err("use a zone name like Europe/Berlin or UTC".into());
    }
    if s == "UTC" || zone_exists(s) {
        return Ok(());
    }
    Err("unknown zone, use a name like Europe/Berlin or UTC".into())
}

fn zone_exists(name: &str) -> bool {
    let mut dirs: Vec<String> = Vec::new();
    if let Ok(z) = std::env::var("ZONEINFO") {
        dirs.push(z);
    }
    dirs.extend(["/usr/share/zoneinfo", "/usr/share/lib/zoneinfo", "/usr/lib/locale/TZ", "/etc/zoneinfo"].map(String::from));
    dirs.iter().any(|d| {
        let b = std::fs::read(Path::new(d).join(name)).unwrap_or_default();
        b.starts_with(b"TZif")
    })
}

/// Keeps only the key type and key of an OpenSSH public key line and drops
/// the trailing comment, which is often an email address.
pub fn normalize_pubkey(s: &str) -> String {
    let f: Vec<&str> = s.split_whitespace().collect();
    if f.len() >= 2 { format!("{} {}", f[0], f[1]) } else { s.trim().to_string() }
}

/// Allows a short name like "desktop"; no spaces or @.
pub fn valid_key_label(s: &str) -> Result<()> {
    if s.len() > 32 || !s.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)) {
        return Err("letters, digits, . _ - only (up to 32), e.g. desktop".into());
    }
    Ok(())
}

fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn unquote(s: &str) -> String {
    let b = s.as_bytes();
    if b.len() >= 2 && b[0] == b'\'' && b[b.len() - 1] == b'\'' {
        return s[1..s.len() - 1].replace(r"'\''", "'");
    }
    if b.len() >= 2 && b[0] == b'"' && b[b.len() - 1] == b'"' {
        // Same as Go's strings.NewReplacer: one left-to-right pass.
        let inner = &s[1..s.len() - 1];
        let mut out = String::new();
        let mut it = inner.chars().peekable();
        while let Some(c) = it.next() {
            if c == '\\'
                && let Some(&n) = it.peek()
                && matches!(n, '"' | '\\' | '$' | '`')
            {
                out.push(n);
                it.next();
                continue;
            }
            out.push(c);
        }
        return out;
    }
    s.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use std::os::unix::fs::PermissionsExt;

    fn valid() -> Config {
        Config {
            wifi_ssid: "home".into(),
            wifi_pass: r#"it's "tricky" $HOME"#.into(),
            coord_lan_ip: "192.168.1.50".into(),
            admin_ssh_pubkey: "ssh-ed25519 AAAAC3Nza".into(),
            ..Config::default()
        }
    }

    #[test]
    fn the_admin_key_is_ed25519_because_it_signs() {
        assert!(valid_pubkey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI me@pc").is_ok());
        for k in ["ssh-rsa AAAAB3NzaC1yc2E", "ecdsa-sha2-nistp256 AAAAE2Vj", "sk-ssh-ed25519@openssh.com AAAAGnNr"] {
            let e = valid_pubkey(k).unwrap_err().to_string();
            assert!(e.contains("must be an ed25519 key") && e.contains(k.split(' ').next().unwrap()), "{e}");
        }
        assert!(valid_pubkey("hello").unwrap_err().to_string().contains("paste the line"));
        assert!(valid_pubkey("-----BEGIN OPENSSH PRIVATE KEY-----").unwrap_err().to_string().contains("private key"));
    }

    #[test]
    fn save_load_round_trip() {
        let dir = TempDir::new();
        let path = dir.join("config.env");
        let want = valid();
        want.save(&path).unwrap();
        assert_eq!(Config::load(&path).unwrap(), want);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "file holds the WiFi password");
    }

    // Node scripts source config.env with bash, so quoting must survive that.
    #[test]
    fn shell_sourcing() {
        let dir = TempDir::new();
        let path = dir.join("config.env");
        let c = valid();
        c.save(&path).unwrap();
        let Ok(out) = std::process::Command::new("bash").args(["-c", r#". "$1" && printf %s "$WIFI_PASS""#, "_"]).arg(&path).output()
        else {
            return; // no bash
        };
        assert_eq!(String::from_utf8_lossy(&out.stdout), c.wifi_pass);
    }

    #[test]
    fn load_example() {
        let c = Config::load(concat!(env!("CARGO_MANIFEST_DIR"), "/config.example.env")).unwrap();
        assert_eq!(c.admin_ssh_pubkey, "ssh-ed25519 AAAA...");
        assert_eq!(c.admin_key_label, "desktop");
        assert_eq!(c.wg_port, "51820");
    }

    #[test]
    fn load_missing() {
        let dir = TempDir::new();
        let (c, err) = Config::load_partial(dir.join("nope.env"));
        assert!(err.unwrap().is_not_found());
        assert_eq!(c, Config::default(), "missing file must give defaults");
    }

    #[test]
    fn cluster_ranges_must_stay_free() {
        for (set, want) in [
            ((|c: &mut Config| c.wg_subnet = "10.42.7.0/24".into()) as fn(&mut Config), "mesh subnet 10.42.7.0/24 overlaps"),
            (|c| c.wg_subnet = "10.43.0.0/16".into(), "mesh subnet"),
            (|c| c.wg_subnet = "10.0.0.0/8".into(), "mesh subnet"),
            (|c| c.switch_subnet = "10.43.9.0/24".into(), "switch subnet"),
            (|c| c.coord_lan_ip = "10.42.0.50".into(), "coordinator IP 10.42.0.50 is inside"),
        ] {
            let mut c = valid();
            set(&mut c);
            let e = c.validate().unwrap_err().to_string();
            assert!(e.contains(want), "{want}: {e}");
        }
        // Next to the ranges is fine.
        let mut c = valid();
        c.wg_subnet = "10.44.0.0/24".into();
        c.coord_lan_ip = "10.41.255.9".into();
        c.switch_subnet = "172.16.66.0/24".into();
        assert!(!c.validate().map_err(|e| e.to_string()).err().unwrap_or_default().contains("10.42.0.0/15"));
    }

    #[test]
    fn validate_reports_each_field() {
        valid().validate().unwrap();
        let mut bad = valid();
        bad.coord_lan_ip = "300.1.1.1".into();
        bad.wg_subnet = "10.66.0.5/24".into();
        bad.username = "root".into();
        bad.wifi_pass = "short".into();
        let err = bad.validate().unwrap_err().to_string();
        for want in ["coordinator IP", "mesh subnet", "username", "WiFi password"] {
            assert!(err.contains(want), "missing {want:?} in {err}");
        }
        let mut open = valid();
        open.wifi_pass = String::new();
        open.validate().expect("open network rejected");
    }

    #[test]
    fn transport_validation() {
        type Change = fn(&mut Config);
        let cases: [(&str, Change, &str); 7] = [
            ("defaults", |_| {}, ""),
            (
                "lan ignores switch subnet",
                |c| {
                    c.wg_transport = TRANSPORT_LAN.into();
                    c.switch_subnet = "junk".into();
                },
                "",
            ),
            ("bad transport", |c| c.wg_transport = "carrier-pigeon".into(), "WireGuard transport"),
            ("switch overlaps mesh", |c| c.switch_subnet = "10.66.0.0/25".into(), "overlaps the mesh subnet"),
            ("switch size differs", |c| c.switch_subnet = "172.16.66.0/25".into(), "same size"),
            ("switch holds coordinator", |c| c.switch_subnet = "192.168.1.0/24".into(), "switch subnet: contains the coordinator"),
            ("mesh holds coordinator", |c| c.coord_lan_ip = "10.66.0.9".into(), "mesh subnet: contains the coordinator"),
        ];
        for (name, change, want) in cases {
            let mut c = valid();
            change(&mut c);
            match (want, c.validate()) {
                ("", Err(e)) => panic!("{name}: unexpected error {e}"),
                ("", Ok(())) => {}
                (w, Err(e)) => assert!(e.to_string().contains(w), "{name}: error {e}, want {w:?}"),
                (w, Ok(())) => panic!("{name}: no error, want {w:?}"),
            }
        }
    }

    // Configs saved before WG_TRANSPORT existed load with the defaults.
    #[test]
    fn load_old_config() {
        let dir = TempDir::new();
        let path = dir.join("config.env");
        std::fs::write(&path, "COORD_LAN_IP='192.168.1.50'\n").unwrap();
        let c = Config::load(&path).unwrap();
        assert_eq!(c.wg_transport, TRANSPORT_AUTO);
        assert_eq!(c.switch_subnet, "172.16.66.0/24");
    }

    #[test]
    fn tools_validation() {
        let mut c = valid();
        assert_eq!(c.tool_list().len(), 5, "default tools must be all 5 bundles");
        c.tools = "docker basic".into();
        c.extra_packages = "python node;rm".into();
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains(r#"unknown tool "basic""#), "{err}");
        assert!(err.contains(r#""node;rm" is not a valid package name"#), "{err}");
        c.tools.clear();
        c.extra_packages.clear();
        c.validate().expect("no tools must be valid");
    }

    #[test]
    fn ports() {
        let got = parse_ports("8080/tcp 53/udp 9000").unwrap();
        let want =
            vec![Port { num: 8080, proto: "tcp".into() }, Port { num: 53, proto: "udp".into() }, Port { num: 9000, proto: "tcp".into() }];
        assert_eq!(got, want);
        for bad in ["0/tcp", "70000", "80/sctp", "http"] {
            assert!(parse_ports(bad).is_err(), "{bad:?} accepted");
        }
    }

    // What passes here is written into the firewall as it is: a spelling
    // nft does not take leaves a machine without a firewall at boot.
    #[test]
    fn only_plain_ports_and_addresses() {
        assert_eq!(port_number("51820"), Some(51820));
        for bad in ["+51820", "051820", "-1", "0", "65536", " 51820", "51820 ", "", "5e4"] {
            assert!(valid_port(bad).is_err(), "port {bad:?} accepted");
        }
        assert_eq!(ipv4("192.168.1.50"), Some(std::net::Ipv4Addr::new(192, 168, 1, 50)));
        for bad in
            ["::ffff:192.168.1.50", "::ffff:c0a8:132", "192.168.001.050", "192.168.1", "0x7f.0.0.1", " 192.168.1.50", "192.168.1.50/24"]
        {
            assert!(valid_ipv4(bad).is_err(), "address {bad:?} accepted");
        }
        for c in [Config { wg_port: "+51820".into(), ..valid() }, Config { coord_lan_ip: "::ffff:192.168.1.50".into(), ..valid() }] {
            assert!(c.validate().is_err(), "{c:?}");
        }
    }

    // The comment after a pasted key (often an email) never reaches the file.
    #[test]
    fn pubkey_comment_dropped() {
        let dir = TempDir::new();
        let path = dir.join("config.env");
        let mut c = valid();
        c.admin_ssh_pubkey = "ssh-ed25519 AAAAC3NzaKEY someone@example.com".into();
        c.save(&path).unwrap();
        let b = std::fs::read_to_string(&path).unwrap();
        assert!(!b.contains("example.com"), "email saved:\n{b}");
        std::fs::write(&path, "ADMIN_SSH_PUBKEY='ssh-ed25519 AAAAC3NzaKEY old@example.com'\n").unwrap();
        assert_eq!(Config::load(&path).unwrap().admin_ssh_pubkey, "ssh-ed25519 AAAAC3NzaKEY");
        for bad in ["me@example.com", "two words", &"x".repeat(33)] {
            assert!(valid_key_label(bad).is_err(), "label {bad:?} accepted");
        }
    }

    #[test]
    fn unquote_double_quotes() {
        assert_eq!(unquote(r#""a\"b\\c\$d\`e""#), "a\"b\\c$d`e");
        assert_eq!(unquote("plain"), "plain");
    }

    #[test]
    fn username_rules() {
        for ok in ["admin", "_x", "a-b_c9"] {
            valid_username(ok).unwrap();
        }
        for bad in ["root", "Admin", "9a", "", &"a".repeat(33)] {
            assert!(valid_username(bad).is_err(), "{bad:?} accepted");
        }
    }
}
