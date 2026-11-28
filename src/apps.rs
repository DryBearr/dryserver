//! Apps on the cluster, from the admin's desktop. An app is a container
//! image with a port: dryserver writes the Kubernetes objects for it and
//! applies them with kubectl on the coordinator, over the admin's own SSH
//! login. k3s then picks a server for it and moves it when that server
//! dies.
//!
//! Every app lives in the namespace "apps":
//!
//! - nothing reaches a pod there unless a policy allows it; an app is
//!   reachable from the ingress and from the other apps, on its port;
//! - an app reaches the other apps, DNS and the internet, and nothing
//!   else in the cluster or on the machines;
//! - a public host name makes the ingress (Traefik) route that name to it.
//!   What comes in from outside reaches the ingress through the app's
//!   entrance (src/entrance.rs);
//! - containers may not gain privileges and get no cluster credentials.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde::Deserialize;

use crate::ctx::Ctx;
use crate::err::{Error, Kind, Result};
use crate::{bail, entrance, errf, registry};

pub const NAMESPACE: &str = "apps";
/// Where the ingress pods take plain HTTP (Traefik's "web" entry; the
/// service's port 80 leads there). Its other ports are its own business.
pub(crate) const INGRESS_PORT: u16 = 8000;

/// Addresses that are never "the internet": every private network, so
/// the machines, the mesh and the home network whatever their numbers.
pub(crate) const PRIVATE_RANGES: &str = "[10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16]";

/// How long a pod stays assigned to a server that stopped answering
/// before the cluster starts it elsewhere. Kubernetes waits 5 minutes by
/// itself; a dead or cut machine should cost about a minute.
const MOVE_AFTER_SECONDS: u32 = 30;

/// Pod spec lines: leave a dead server soon.
pub(crate) fn tolerations() -> String {
    let mut y = String::from("      tolerations:\n");
    for taint in ["unreachable", "not-ready"] {
        y += &format!(
            "        - key: node.kubernetes.io/{taint}\n          operator: Exists\n          effect: NoExecute\n          tolerationSeconds: {MOVE_AFTER_SECONDS}\n"
        );
    }
    y
}

/// The egress rule that lets pods ask the cluster's DNS.
pub(crate) const DNS_RULE: &str = r#"    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
"#;

/// One app as the admin describes it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct App {
    pub name: String,
    pub image: String,
    /// The port the container listens on: http://NAME inside the cluster
    /// leads there, and so does every public name without a port of its
    /// own.
    pub port: u16,
    /// The public names routed to it, each to one of its ports. None keeps
    /// it inside the cluster.
    pub hosts: Vec<Host>,
    /// The way in from outside its names come through (entrance::IDS).
    /// Only matters with a name.
    pub entrance: String,
    pub copies: u32,
    /// For an image of the admin's own (localhost/...): the id of the
    /// build the servers hold. A new build under the same name is
    /// another id, so its copies are replaced. Not in the app file: the
    /// desktop takes it from podman or docker when it deploys.
    pub image_id: String,
    /// What the app gets to run with: settings, secrets, its share of a
    /// machine.
    pub run: Runtime,
    /// The repository GitHub builds it from, when it is built there
    /// (REPO and BRANCH in the app file).
    pub source: Option<crate::github::Source>,
    /// For an app built by GitHub: the build it runs and the ones before.
    /// Not in the app file: from GitHub and the cluster when deployed.
    pub gh: crate::github::State,
}

/// The annotation on an app's pods that names the build of its own image.
pub const IMAGE_ID_ANNOTATION: &str = "dryserver/image-id";
/// The annotation on an app's pods that names the version of its secrets:
/// a new value replaces the copies, so they read it.
pub const SECRETS_ANNOTATION: &str = "dryserver/secrets";

/// What an app runs with.
#[derive(Debug, Clone, PartialEq)]
pub struct Runtime {
    /// Settings (env variables), sorted by name, each once. Kept in the
    /// app file, so nothing secret.
    pub env: Vec<(String, String)>,
    /// The names of its secrets, sorted: their values live only in the
    /// cluster (Secret "app-NAME", encrypted there), set with dryserver
    /// app secret.
    pub secrets: Vec<String>,
    /// The most memory a copy may use (MiB); the machine keeps half of it
    /// for the copy in any case.
    pub memory_mib: u32,
    /// The most CPU a copy may use (thousandths of a core).
    pub cpu_milli: u32,
    /// The version of the app's secrets the copies run with (the Secret's
    /// resourceVersion). Not in the app file: read from the cluster when
    /// the app is deployed.
    pub secrets_version: String,
}

impl Default for Runtime {
    fn default() -> Runtime {
        Runtime {
            env: Vec::new(),
            secrets: Vec::new(),
            memory_mib: DEFAULT_MEMORY_MIB,
            cpu_milli: DEFAULT_CPU_MILLI,
            secrets_version: String::new(),
        }
    }
}

/// What an app gets when its file does not say: enough for a Node.js
/// server under light load, and never a whole machine.
pub const DEFAULT_MEMORY_MIB: u32 = 512;
pub const DEFAULT_CPU_MILLI: u32 = 1000;
pub const MIN_MEMORY_MIB: u32 = 32;
pub const MAX_MEMORY_MIB: u32 = 16 * 1024;
pub const MIN_CPU_MILLI: u32 = 50;
pub const MAX_CPU_MILLI: u32 = 8000;
/// Settings and secrets one app may have, and how large they may be.
pub const MAX_ENV: usize = 100;
pub const MAX_SECRETS: usize = 50;
pub const MAX_ENV_VALUE: usize = 32 << 10;
pub const MAX_ENV_TOTAL: usize = 128 << 10;

/// A setting's or secret's name: what a program reads (letters, digits
/// and _, not starting with a digit).
pub fn valid_env_name(s: &str) -> Result<()> {
    let ok =
        !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') && !s.as_bytes()[0].is_ascii_digit();
    if ok { Ok(()) } else { Err(errf!("{s:?}: a name of letters, digits and _, not starting with a digit, like DATABASE_URL")) }
}

/// The name of the Secret that holds an app's secrets.
pub fn secret_name(app: &str) -> String {
    format!("app-{app}")
}

/// "512Mi", "1Gi", "1.5Gi" as MiB.
pub fn parse_memory(s: &str) -> Result<u32> {
    let t = s.trim();
    let (num, unit) = if let Some(n) = t.strip_suffix("Gi") {
        (n, 1024.0)
    } else if let Some(n) = t.strip_suffix("Mi") {
        (n, 1.0)
    } else {
        bail!("{t}: memory in Mi or Gi, like 512Mi or 1Gi");
    };
    let v: f64 = num.trim().parse().map_err(|_| errf!("{t}: memory in Mi or Gi, like 512Mi or 1Gi"))?;
    let mib = (v * unit).round();
    if !mib.is_finite() || mib < f64::from(MIN_MEMORY_MIB) || mib > f64::from(MAX_MEMORY_MIB) {
        bail!("{t}: memory from {MIN_MEMORY_MIB}Mi to {}Gi", MAX_MEMORY_MIB / 1024);
    }
    Ok(mib as u32)
}

/// "500m", "1", "1.5" as thousandths of a core.
pub fn parse_cpu(s: &str) -> Result<u32> {
    let t = s.trim();
    let milli = match t.strip_suffix('m') {
        Some(n) => n.parse::<f64>().map_err(|_| errf!("{t}: CPU in cores (1, 0.5) or thousandths (500m)"))?,
        None => t.parse::<f64>().map_err(|_| errf!("{t}: CPU in cores (1, 0.5) or thousandths (500m)"))? * 1000.0,
    }
    .round();
    if !milli.is_finite() || milli < f64::from(MIN_CPU_MILLI) || milli > f64::from(MAX_CPU_MILLI) {
        bail!("{t}: CPU from {MIN_CPU_MILLI}m to {} cores", MAX_CPU_MILLI / 1000);
    }
    Ok(milli as u32)
}

/// Memory as people write it: "512Mi", "1Gi", "1536Mi".
pub fn memory_text(mib: u32) -> String {
    if mib >= 1024 && mib.is_multiple_of(1024) { format!("{}Gi", mib / 1024) } else { format!("{mib}Mi") }
}

/// CPU as people write it: "1", "2", "500m".
pub fn cpu_text(milli: u32) -> String {
    if milli.is_multiple_of(1000) { format!("{}", milli / 1000) } else { format!("{milli}m") }
}

/// Whether a setting's name says it holds a secret.
pub fn looks_secret(name: &str) -> bool {
    let n = name.to_ascii_uppercase();
    ["SECRET", "PASSWORD", "PASSWD", "TOKEN", "PRIVATE", "API_KEY", "APIKEY", "CREDENTIAL", "DATABASE_URL", "DSN"]
        .iter()
        .any(|w| n.contains(w))
}

impl Runtime {
    pub fn validate(&self, port: u16) -> Result<()> {
        if self.env.len() > MAX_ENV {
            bail!("ENV: at most {MAX_ENV} settings");
        }
        if self.secrets.len() > MAX_SECRETS {
            bail!("SECRET: at most {MAX_SECRETS} secrets");
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut total = 0;
        for (k, v) in &self.env {
            valid_env_name(k).map_err(|e| e.wrap("ENV"))?;
            if !seen.insert(k.as_str()) {
                bail!("ENV: {k} is set twice");
            }
            if v.len() > MAX_ENV_VALUE {
                bail!("ENV: {k} is longer than {} KiB", MAX_ENV_VALUE >> 10);
            }
            if v.chars().any(|c| c.is_control() && c != '\t') {
                bail!("ENV: {k} has a control character in it");
            }
            // The two characters the cluster's YAML cannot carry.
            if v.chars().any(|c| matches!(c, '\u{FFFE}' | '\u{FFFF}')) {
                bail!("ENV: {k} has a character in it that is no character (U+FFFE or U+FFFF)");
            }
            if k == "PORT" && port != NO_PORT && *v != port.to_string() {
                bail!("ENV: PORT is {v}, but the app's PORT is {port}: they must agree (dryserver sets PORT for the app by itself)");
            }
            total += k.len() + v.len();
        }
        if total > MAX_ENV_TOTAL {
            bail!("ENV: more than {} KiB of settings in all", MAX_ENV_TOTAL >> 10);
        }
        for k in &self.secrets {
            valid_env_name(k).map_err(|e| e.wrap("SECRET"))?;
            if !seen.insert(k.as_str()) {
                bail!("SECRET: {k} is a setting or a secret already");
            }
        }
        if !(MIN_MEMORY_MIB..=MAX_MEMORY_MIB).contains(&self.memory_mib) {
            bail!("MEMORY: from {MIN_MEMORY_MIB}Mi to {}Gi", MAX_MEMORY_MIB / 1024);
        }
        if !(MIN_CPU_MILLI..=MAX_CPU_MILLI).contains(&self.cpu_milli) {
            bail!("CPU: from {MIN_CPU_MILLI}m to {} cores", MAX_CPU_MILLI / 1000);
        }
        if !self.secrets_version.bytes().all(|b| b.is_ascii_alphanumeric()) || self.secrets_version.len() > 64 {
            bail!("the version of the secrets is not one");
        }
        Ok(())
    }

    /// The env lines of the container: PORT (the app's port, unless it
    /// listens on none), then its settings, then its secrets from its
    /// Secret. Every value as a JSON string, which YAML
    /// reads as it is: nothing in a value can become YAML.
    fn yaml(&self, app: &str, port: u16) -> String {
        // JSON leaves the line and paragraph separators as they are, and
        // YAML would read them as line breaks: written as escapes.
        let q = |s: &str| {
            serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into()).replace('\u{2028}', "\\u2028").replace('\u{2029}', "\\u2029")
        };
        let mut env: Vec<(String, String)> = Vec::new();
        if port != NO_PORT && !self.env.iter().any(|(k, _)| k == "PORT") {
            env.push(("PORT".into(), port.to_string()));
        }
        env.extend(self.env.iter().cloned());
        let mut y = String::from("          env:\n");
        for (k, v) in &env {
            y += &format!("            - name: {}\n              value: {}\n", q(k), q(v));
        }
        let secret = secret_name(app);
        for k in &self.secrets {
            y += &format!(
                "            - name: {}\n              valueFrom:\n                secretKeyRef:\n                  name: \"{secret}\"\n                  key: {}\n",
                q(k),
                q(k)
            );
        }
        y
    }

    /// What a copy asks the machine for and may never pass: memory is
    /// half reserved (so a machine fits more than one busy app), CPU a
    /// tenth (idle apps use next to none).
    fn resources(&self) -> String {
        let req_mem = (self.memory_mib / 2).max(MIN_MEMORY_MIB);
        let req_cpu = (self.cpu_milli / 10).max(MIN_CPU_MILLI / 2);
        format!(
            "          resources:\n            requests:\n              cpu: {req_cpu}m\n              memory: {req_mem}Mi\n            limits:\n              cpu: {}m\n              memory: {}Mi\n",
            self.cpu_milli, self.memory_mib
        )
    }
}

/// A public name of an app, and the app's port it leads to.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Host {
    pub name: String,
    pub port: u16,
}

/// Public names one app may have.
pub const MAX_HOSTS: usize = 50;
/// Ports one app may take connections on, its main port included.
pub const MAX_PORTS: usize = 10;
/// The annotation that says which dryserver wrote an app's objects: a
/// newer one may write what this one would get wrong, so this one then
/// changes nothing (see Running::newer).
pub const FORMAT_ANNOTATION: &str = "dryserver/format";
/// 2: several public names, each with a port. 3: settings, secrets,
/// limits, PORT=none, builds by GitHub. An app without the annotation is
/// from before (one name, the main port).
pub const FORMAT: u32 = 3;

/// PORT=none: the app listens on no port.
pub const NO_PORT: u16 = 0;

/// The apps' namespace, as every app's manifest has it first. Whatever
/// goes into it before the first app (a secret, the GitHub token) brings
/// it along: on a new cluster it is not there yet.
pub fn namespace_yaml() -> String {
    format!(
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {NAMESPACE}\n  labels:\n    pod-security.kubernetes.io/enforce: baseline\n    \
         pod-security.kubernetes.io/warn: restricted\n"
    )
}

pub fn valid_image(s: &str) -> Result<()> {
    let ok = !s.is_empty()
        && s.len() <= 255
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'/' | b':' | b'@' | b'-'));
    if ok { Ok(()) } else { Err("an image name like nginx:1.27 or ghcr.io/you/app:v1 (lowercase, no spaces)".into()) }
}

/// A DNS name: labels of letters, digits and -, joined by dots. The last
/// label has a letter in it: an IP address is not a host name.
pub fn valid_host(s: &str) -> Result<()> {
    if s.is_empty() {
        return Ok(());
    }
    let ok = s.len() <= 253
        && s.contains('.')
        && s.split('.').all(registry::valid_name)
        && s.rsplit('.').next().is_some_and(|tld| tld.bytes().any(|b| b.is_ascii_lowercase()));
    if ok { Ok(()) } else { Err("a host name like app.example.com, or empty".into()) }
}

/// A public name as people type it, made plain: lowercase, without the
/// dot a name may end with. Says what is wrong with one that is no name.
pub fn clean_host(s: &str) -> Result<String> {
    let t = s.trim();
    let t = t.strip_suffix('.').unwrap_or(t);
    if t.is_empty() {
        bail!("an empty name");
    }
    if !t.is_ascii() {
        bail!(
            "{t}: a name with letters outside a-z is written in its xn-- form (punycode) here; your domain company or \
             Cloudflare shows it"
        );
    }
    let h = t.to_ascii_lowercase();
    if h.contains("://") || h.contains('/') {
        bail!("{h}: only the name, without http:// or a path");
    }
    if h.contains('*') {
        bail!("{h}: names with * (every subdomain) are not supported yet; list each name");
    }
    if h.contains(':') {
        bail!("{h}: a port goes after the name only in an app file (HOST=name:port)");
    }
    if valid_host(&h).is_err() {
        let tld = h.rsplit('.').next().unwrap_or("");
        if h.contains('.') && !tld.is_empty() && tld.bytes().all(|b| b.is_ascii_digit()) {
            bail!("{h}: an IP address is not a host name");
        }
        bail!("{h}: a host name like app.example.com: letters, digits and - between dots, at most 253 characters");
    }
    Ok(h)
}

/// An app's name is a DNS name inside the cluster (http://NAME) and the
/// name of its Kubernetes objects: it starts with a letter.
pub fn valid_app_name(s: &str) -> Result<()> {
    if registry::valid_name(s) && s.len() <= 40 && s.as_bytes()[0].is_ascii_lowercase() {
        Ok(())
    } else {
        Err("starts with a letter, then lowercase letters, digits and -, at most 40".into())
    }
}

impl App {
    /// Everything here ends up in YAML and in command lines: only plain
    /// names pass.
    pub fn validate(&self) -> Result<()> {
        valid_app_name(&self.name).map_err(|e| e.wrap("name"))?;
        valid_image(&self.image).map_err(|e| e.wrap("image"))?;
        if let Some(src) = &self.source {
            let base = src.image();
            let ok = self.image == base || self.image.strip_prefix(&format!("{base}@")).is_some_and(crate::github::valid_digest);
            if !ok {
                bail!("image: an app GitHub builds runs {base} (from REPO), not {}", self.image);
            }
        }
        if crate::images::is_local(&self.image) {
            crate::images::local_name(&self.image).map_err(|e| e.wrap("image"))?;
            if !self.image_id.is_empty() && !crate::images::valid_id(&self.image_id) {
                bail!("image: the id of {} is not one", self.image);
            }
        }
        if self.port == NO_PORT && !self.hosts.is_empty() {
            bail!("PORT=none: an app that listens on no port has no public names (leave the HOST lines out)");
        }
        if self.hosts.len() > MAX_HOSTS {
            bail!("public host name: at most {MAX_HOSTS} per app, this one has {}", self.hosts.len());
        }
        let mut seen = std::collections::BTreeSet::new();
        for h in &self.hosts {
            if h.name.is_empty() {
                bail!("public host name: an empty name");
            }
            valid_host(&h.name).map_err(|e| e.wrap("public host name"))?;
            if !seen.insert(h.name.as_str()) {
                bail!("public host name: {} is listed twice", h.name);
            }
            if h.port == 0 {
                bail!("public host name: {} needs a port, 1 to 65535", h.name);
            }
            // Port 80 of the app's service is the main port (http://NAME
            // inside the cluster): another port cannot have it too.
            if h.port == 80 && self.port != 80 {
                bail!(
                    "public host name: {}: port 80 can only be the app's PORT (inside the cluster, http://{} leads there)",
                    h.name,
                    self.name
                );
            }
            // The ingress speaks https to a service port 443, and checks
            // the app's certificate: it speaks plain http to every other.
            if h.port == 443 && self.port != 443 {
                bail!(
                    "public host name: {}: port 443 would make the ingress speak https to the app; let the app speak plain \
                     http on another port (Cloudflare does the https part)",
                    h.name
                );
            }
        }
        if 1 + self.extra_ports().len() > MAX_PORTS {
            bail!("public host name: at most {MAX_PORTS} ports per app, the main one included");
        }
        if !self.hosts.is_empty() {
            entrance::valid_id(&self.entrance).map_err(|e| e.wrap("entrance"))?;
        }
        if !(1..=20).contains(&self.copies) {
            bail!("copies: 1 to 20");
        }
        self.run.validate(self.port)?;
        Ok(())
    }

    /// The ports names lead to besides the main one, sorted, each once.
    pub fn extra_ports(&self) -> Vec<u16> {
        let mut p: Vec<u16> = self.hosts.iter().map(|h| h.port).filter(|p| *p != self.port).collect();
        p.sort_unstable();
        p.dedup();
        p
    }

    /// The public names, sorted.
    pub fn names(&self) -> Vec<String> {
        let mut n: Vec<String> = self.hosts.iter().map(|h| h.name.clone()).collect();
        n.sort();
        n
    }

    /// The Kubernetes objects for this app.
    pub fn manifest(&self) -> Result<String> {
        self.validate()?;
        let App { name, image, port, hosts, entrance, copies, image_id, run, source, gh } = self;
        // An image of the admin's own is on the servers, put there by
        // dryserver: it is never asked for anywhere else.
        let mut marks = Vec::new();
        if crate::images::is_local(image) {
            marks.push(format!("        {IMAGE_ID_ANNOTATION}: \"{image_id}\"\n"));
        }
        if !run.secrets.is_empty() {
            marks.push(format!("        {SECRETS_ANNOTATION}: \"{}\"\n", run.secrets_version));
        }
        let pod_annotations = if marks.is_empty() { String::new() } else { format!("      annotations:\n{}", marks.concat()) };
        let env = run.yaml(name, *port);
        // An app GitHub builds: where it comes from and which build runs,
        // for the coordinator's watch; the token to pull with.
        let (gh_annotations, pull_secrets) = match source {
            None => (String::new(), String::new()),
            Some(src) => {
                use crate::github as g;
                let q = |s: &str| serde_json::to_string(s).unwrap_or_default();
                let mut a = format!("    {}: {}\n    {}: {}\n", g::A_REPO, q(&src.full()), g::A_BRANCH, q(&src.branch));
                if !gh.repo_id.is_empty() {
                    a += &format!("    {}: \"{}\"\n", g::A_REPO_ID, gh.repo_id);
                }
                if gh.run > 0 {
                    a += &format!("    {}: \"{}\"\n    {}: \"{}\"\n", g::A_RUN, gh.run, g::A_COMMIT, gh.commit);
                }
                if !gh.rolling.is_empty() {
                    a += &format!("    {}: \"{}\"\n", g::A_ROLLING, gh.rolling);
                }
                if gh.hold > 0 {
                    a += &format!("    {}: \"{}\"\n", g::A_HOLD, gh.hold);
                }
                let history: Vec<String> =
                    gh.history.iter().map(|(t, d, c)| format!("{t}@{}@{c}", d.trim_start_matches("sha256:"))).collect();
                a += &format!("    {}: \"{}\"\n", g::A_HISTORY, history.join(","));
                (a, format!("      imagePullSecrets:\n        - name: {}\n", g::PULL_SECRET))
            }
        };
        let resources = run.resources();
        let (_, pull) =
            if crate::images::is_local(image) { ((), "          imagePullPolicy: Never\n".to_string()) } else { ((), String::new()) };
        let mark = entrance::ANNOTATION;
        let tolerations = tolerations();
        let extra = self.extra_ports();
        let container_ports: String = extra.iter().map(|p| format!("            - containerPort: {p}\n")).collect();
        let policy_ports: String = extra.iter().map(|p| format!("        - port: {p}\n")).collect();
        let service_ports: String =
            extra.iter().map(|p| format!("    - name: \"p{p}\"\n      port: {p}\n      targetPort: {p}\n")).collect();
        // PORT=none: an app that takes no connections (a bot, a worker).
        // Nothing reaches it; a new version takes over once it runs.
        let listens = *port != NO_PORT;
        // An app of the VPN: its own Traefik (namespace vpn) brings the
        // devices' requests, never the cluster's.
        let through_vpn = entrance == entrance::VPN && !hosts.is_empty();
        let vpn_from = if through_vpn {
            format!(
                "        - namespaceSelector:\n            matchLabels:\n              kubernetes.io/metadata.name: {}\n          \
                 podSelector:\n            matchLabels:\n              app.kubernetes.io/name: {}\n",
                crate::vpn::NAMESPACE,
                crate::vpn::POD_LABEL
            )
        } else {
            String::new()
        };
        let (policy_note, policy_ingress) = if listens && through_vpn {
            (
                format!(
                    "# {name} is the VPN's: only the VPN's own ingress brings it anything, from\n# the admin's devices; no other app, no other ingress."
                ),
                format!("  ingress:\n    - from:\n{vpn_from}      ports:\n        - port: {port}\n{policy_ports}"),
            )
        } else if listens {
            (
                format!("# {name} takes connections on its port from the ingress and from the\n# other apps."),
                format!(
                    "  ingress:\n    - from:\n        - namespaceSelector:\n            matchLabels:\n              kubernetes.io/metadata.name: \
                     kube-system\n          podSelector:\n            matchLabels:\n              app.kubernetes.io/name: traefik\n        \
                     - podSelector: {{}}\n      ports:\n        - port: {port}\n{policy_ports}"
                ),
            )
        } else {
            (format!("# {name} listens on no port: nothing reaches it."), "  ingress: []\n".to_string())
        };
        let container_ports =
            if listens { format!("          ports:\n            - containerPort: {port}\n{container_ports}") } else { String::new() };
        let probe = if listens {
            format!(
                "          # Ready once it takes connections on its port: until then the\n          # ingress sends nothing to it, and an \
                 update keeps the old copy.\n          readinessProbe:\n            tcpSocket:\n              port: {port}\n            \
                 periodSeconds: 5\n            failureThreshold: 3\n"
            )
        } else {
            String::new()
        };
        let service = if listens {
            format!(
                "---\napiVersion: v1\nkind: Service\nmetadata:\n  name: \"{name}\"\n  namespace: {NAMESPACE}\n  labels:\n    app: \
                 \"{name}\"\nspec:\n  selector:\n    app: \"{name}\"\n  ports:\n    - name: http\n      port: 80\n      targetPort: \
                 {port}\n{service_ports}"
            )
        } else {
            String::new()
        };
        let namespace = namespace_yaml();
        let mut y = format!(
            r#"{namespace}---
# Nothing reaches a pod in this namespace unless another policy allows it.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: {NAMESPACE}
spec:
  podSelector: {{}}
  policyTypes: [Ingress]
---
# What an app may reach: the other apps, the cluster's DNS and the
# internet. Not the machines, not the cluster's own services.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: outgoing
  namespace: {NAMESPACE}
spec:
  podSelector: {{}}
  policyTypes: [Egress]
  egress:
    - to:
        - podSelector: {{}}
{DNS_RULE}    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except: {PRIVATE_RANGES}
---
{policy_note}
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: "app-{name}"
  namespace: {NAMESPACE}
  labels:
    app: "{name}"
spec:
  podSelector:
    matchLabels:
      app: "{name}"
  policyTypes: [Ingress]
{policy_ingress}---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: "{name}"
  namespace: {NAMESPACE}
  labels:
    app: "{name}"
  annotations:
    {FORMAT_ANNOTATION}: "{FORMAT}"
{gh_annotations}spec:
  replicas: {copies}
  # A new version starts beside the old one and takes over once it
  # answers: no moment without a copy.
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 0
      maxSurge: 1
  progressDeadlineSeconds: 600
  # A copy counts once it has kept running (and answering) this long: one
  # that stops right after it starts never takes over.
  minReadySeconds: 20
  selector:
    matchLabels:
      app: "{name}"
  template:
    metadata:
      labels:
        app: "{name}"
{pod_annotations}    spec:
      automountServiceAccountToken: false
      # No variables about the other apps' services: they clash with an
      # app's own (APP_PORT, ...).
      enableServiceLinks: false
{pull_secrets}
      securityContext:
        seccompProfile:
          type: RuntimeDefault
      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: kubernetes.io/hostname
          whenUnsatisfiable: ScheduleAnyway
          labelSelector:
            matchLabels:
              app: "{name}"
{tolerations}      containers:
        - name: "{name}"
          image: "{image}"
{pull}{container_ports}{env}          securityContext:
            allowPrivilegeEscalation: false
            # No raw packets: a taken-over app cannot pose as another
            # address on the pod network.
            capabilities:
              drop: ["NET_RAW"]
{resources}{probe}{service}"#
        );
        if !hosts.is_empty() {
            // The VPN's: its Traefik takes the label, the cluster's never
            // does; https only, with its certificates.
            let (vpn_label, vpn_annotations) = if through_vpn {
                (
                    format!("    {}: \"true\"\n", crate::vpn::LABEL),
                    "    traefik.ingress.kubernetes.io/router.entrypoints: websecure\n    traefik.ingress.kubernetes.io/router.tls: \"true\"\n"
                        .to_string(),
                )
            } else {
                (String::new(), String::new())
            };
            y += &format!(
                r#"---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: "{name}"
  namespace: {NAMESPACE}
  labels:
    app: "{name}"
{vpn_label}  annotations:
    {mark}: "{entrance}"
    {FORMAT_ANNOTATION}: "{FORMAT}"
{vpn_annotations}spec:
  rules:
"#
            );
            let mut sorted = hosts.clone();
            sorted.sort();
            for h in sorted {
                // The service's port 80 is the main port; the others keep
                // their own number.
                let to = if h.port == *port { 80 } else { h.port };
                y += &format!(
                    r#"    - host: "{}"
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: "{name}"
                port:
                  number: {to}
"#,
                    h.name
                );
            }
        }
        Ok(y)
    }

    /// The app as the cluster runs it, to change or keep as a file. None
    /// when the cluster's objects do not say enough (made by hand).
    pub fn of(r: &Running) -> Option<App> {
        if r.port_unknown {
            return None;
        }
        let a = App {
            name: r.name.clone(),
            image: r.image.clone(),
            port: r.port,
            hosts: r.hosts.clone(),
            entrance: r.entrance.clone(),
            copies: r.copies,
            image_id: r.image_id.clone(),
            // An app from before limits gets the ones every app gets.
            run: Runtime {
                memory_mib: if r.run.memory_mib == 0 { DEFAULT_MEMORY_MIB } else { r.run.memory_mib },
                cpu_milli: if r.run.cpu_milli == 0 { DEFAULT_CPU_MILLI } else { r.run.cpu_milli },
                ..r.run.clone()
            },
            source: r.gh.source.clone(),
            gh: crate::github::State { watch: None, rolling: String::new(), ..r.gh.clone() },
        };
        a.validate().is_ok().then_some(a)
    }
}

/// The cluster as the apps screen shows it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Overview {
    pub apps: Vec<Running>,
    /// Tunnel pods ready and wanted; None when no tunnel is set up.
    pub tunnel: Option<(u32, u32)>,
    /// The mark of the token the tunnel pods run with ("" when unknown).
    pub tunnel_mark: String,
}

/// An app as the cluster has it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Running {
    pub name: String,
    pub image: String,
    pub ready: u32,
    pub copies: u32,
    /// Its main port (the container's first); 0 when not known.
    pub port: u16,
    /// Its public names, sorted, each once.
    pub hosts: Vec<Host>,
    /// The entrance its names come through; "?" when its Ingress names
    /// one this dryserver does not know.
    pub entrance: String,
    /// The servers its pods are on.
    pub nodes: Vec<String>,
    /// Written by a newer dryserver (its format annotation is higher than
    /// FORMAT): this one would read it wrong, so it changes nothing.
    pub newer: bool,
    /// Runs without a port, but not as PORT=none (made by hand, or by a
    /// dryserver from before it): no app file says what it is.
    pub port_unknown: bool,
    /// The build of an image of the admin's own that its pods run ("" for
    /// other images, or when not known).
    pub image_id: String,
    /// Its settings, secret names and limits, as its Deployment has them
    /// (0 limits: none set, an app from before limits).
    pub run: Runtime,
    /// Where GitHub builds it from and which build runs (empty when it is
    /// not built by GitHub).
    pub gh: crate::github::State,
}

impl Running {
    /// Whether anything comes to it from outside.
    pub fn public(&self) -> bool {
        !self.hosts.is_empty()
    }

    pub fn names(&self) -> Vec<&str> {
        self.hosts.iter().map(|h| h.name.as_str()).collect()
    }

    /// Its names for people: "a.com, shop.a.com".
    pub fn names_text(&self) -> String {
        self.names().join(", ")
    }

    pub fn has(&self, host: &str) -> bool {
        self.hosts.iter().any(|h| h.name == host)
    }
}

/// What an app's container runs with, as its Deployment says. Only what
/// checks out is taken; PORT as dryserver sets it is not one of the app's
/// own settings.
fn runtime_of(app: &str, container: &serde_json::Value, annotations: &serde_json::Value, port: u16) -> Runtime {
    let limits = &container["resources"]["limits"];
    let memory_mib = limits["memory"].as_str().and_then(|m| parse_memory(m).ok()).unwrap_or(0);
    let cpu_milli = limits["cpu"].as_str().and_then(|c| parse_cpu(c).ok()).unwrap_or(0);
    let mut run = Runtime { memory_mib, cpu_milli, ..Runtime::default() };
    let secret = secret_name(app);
    for e in container["env"].as_array().map(Vec::as_slice).unwrap_or_default().iter().take(MAX_ENV + MAX_SECRETS + 2) {
        let Some(name) = e["name"].as_str().filter(|n| valid_env_name(n).is_ok()) else { continue };
        if let Some(v) = e["value"].as_str() {
            let auto = name == "PORT" && port != NO_PORT && v == port.to_string();
            if !auto && !run.env.iter().any(|(k, _)| k == name) {
                run.env.push((name.to_string(), v.to_string()));
            }
        } else if e["valueFrom"]["secretKeyRef"]["name"].as_str() == Some(secret.as_str())
            && e["valueFrom"]["secretKeyRef"]["key"].as_str() == Some(name)
            && !run.secrets.iter().any(|k| k == name)
        {
            run.secrets.push(name.to_string());
        }
    }
    run.env.sort();
    run.secrets.sort();
    run.secrets_version = annotations[SECRETS_ANNOTATION]
        .as_str()
        .filter(|v| v.len() <= 64 && v.bytes().all(|b| b.is_ascii_alphanumeric()))
        .unwrap_or("")
        .to_string();
    run
}

/// Whether a format annotation says a newer dryserver wrote the object.
fn newer_format(m: &Meta) -> bool {
    m.annotations.get(FORMAT_ANNOTATION).is_some_and(|v| v.trim().parse::<u32>().map_or(true, |n| n > FORMAT))
}

/// A way to run kubectl on the coordinator. The screens call it from a
/// worker thread; ctx carries the time limit, and the cancel when the
/// screen closes.
pub trait Cluster: Send + Sync {
    fn kubectl(&self, ctx: &Ctx, args: &[&str], stdin: &str) -> Result<String>;

    /// Where the coordinator is, for the screens' header ("10.1.0.60");
    /// empty when it is not an address.
    fn address(&self) -> String {
        String::new()
    }
}

/// The most kubectl may answer: a full listing of a busy cluster is a
/// few MiB.
const MAX_ANSWER: usize = 32 << 20;

/// kubectl over the admin's own SSH login to the coordinator. The host key
/// must be the one this desktop pinned for the coordinator.
pub struct SshCluster {
    pub host: String,
    pub port: String,
    pub user: String,
    pub known_hosts: PathBuf,
}

impl SshCluster {
    /// Everything about how to reach the coordinator, before the target.
    /// The check, the shared connection and every call get exactly these:
    /// the socket's name (%C) is made from host, port and user, and a
    /// check that looked under another name would never find the
    /// connection and start one more each time.
    fn options(&self) -> Vec<String> {
        let port = if self.port.is_empty() { "22" } else { &self.port };
        let mut o: Vec<String> = vec!["-p".into(), port.into()];
        for opt in [
            "BatchMode=yes",
            "ConnectTimeout=6",
            "StrictHostKeyChecking=yes",
            "GlobalKnownHostsFile=/dev/null",
            "ForwardAgent=no",
            "ProxyJump=none",
            "LogLevel=ERROR",
            // A coordinator that goes away mid-session: the shared
            // connection notices within 15 seconds and ends.
            "ServerAliveInterval=5",
            "ServerAliveCountMax=3",
        ] {
            o.extend(["-o".into(), opt.into()]);
        }
        o.extend(["-o".into(), format!("UserKnownHostsFile={}", self.known_hosts.display())]);
        o
    }

    /// Where the shared connection's socket goes: a directory of this
    /// user's alone in the user's runtime directory (fsx::socket_dir).
    /// None without one (then every call connects).
    fn control_path(&self, runtime_dir: Option<&std::ffi::OsStr>) -> Option<String> {
        crate::fsx::control_path(runtime_dir, &self.socket_name())
    }

    /// The socket's name.
    ///
    /// The name carries the pinned host key file the connection was made
    /// with: a connection is checked against the pinned key once, when it
    /// is made, and one made from another directory (another stick's
    /// secrets) must never be reused here.
    fn socket_name(&self) -> String {
        format!("k3s-%C-{:016x}", crate::fsx::paths_id(&[&self.known_hosts]))
    }
}

/// At most one try to start the shared connection per half minute,
/// whatever the check says: a second guard against piling up connections.
fn master_due() -> bool {
    use std::sync::Mutex;
    use std::time::{Duration, Instant};
    static LAST: Mutex<Option<Instant>> = Mutex::new(None);
    let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
    if last.is_some_and(|t| t.elapsed() < Duration::from_secs(30)) {
        return false;
    }
    *last = Some(Instant::now());
    true
}

/// What a finished child left.
struct Ran {
    status: std::process::ExitStatus,
    out: Vec<u8>,
    err: Vec<u8>,
}

/// Lets a child die with the thread that waits for it: a desktop killed
/// while a call runs leaves no ssh behind.
fn die_with_parent(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: prctl is async-signal-safe and changes only the new process.
    unsafe {
        cmd.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            Ok(())
        });
    }
}

/// Runs cmd with stdin, keeping at most max bytes of what it prints. The
/// child is killed when ctx is done (the time is up, or the screen
/// closed) and when it prints more than max: no call outlives its screen.
fn run_child(ctx: &Ctx, mut cmd: Command, stdin: &[u8], max: usize) -> Result<Ran> {
    use std::io::{Read, Write};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    die_with_parent(&mut cmd);
    let mut child =
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e| Error::from(e).wrap("ssh"))?;
    let mut pipe = child.stdin.take().ok_or_else(|| Error::new("ssh: no stdin"))?;
    let text = stdin.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = pipe.write_all(&text);
    });
    // The coordinator's answer is kept up to a limit; one that goes on
    // and on ends the call.
    let over = Arc::new(AtomicBool::new(false));
    let reader = |mut pipe: Box<dyn Read + Send>, limit: usize| {
        let over = over.clone();
        std::thread::spawn(move || {
            let mut kept = Vec::new();
            let mut buf = [0u8; 65536];
            loop {
                match pipe.read(&mut buf) {
                    Ok(0) | Err(_) => return kept,
                    Ok(n) if kept.len() + n > limit => {
                        over.store(true, Ordering::SeqCst);
                        return kept;
                    }
                    Ok(n) => kept.extend_from_slice(&buf[..n]),
                }
            }
        })
    };
    let stdout = reader(Box::new(child.stdout.take().ok_or_else(|| Error::new("ssh: no stdout"))?), max);
    let stderr = reader(Box::new(child.stderr.take().ok_or_else(|| Error::new("ssh: no stderr"))?), 65536);
    let too_long = || errf!("the coordinator's answer is longer than {} MiB; stopped reading", max >> 20);
    let why = || {
        if over.load(Ordering::SeqCst) {
            return Some(too_long());
        }
        ctx.err().map(|e| {
            if e.is(Kind::DeadlineExceeded) {
                Error::with_kind(Kind::DeadlineExceeded, "the coordinator did not answer in time")
            } else {
                e
            }
        })
    };
    // Through a shared connection, ssh hands our pipes to the connection
    // itself: they can stay open after this child is gone. So the readers
    // are waited for within ctx too, and left behind when it ends (they
    // end with the connection).
    let mut exited = None;
    loop {
        if exited.is_none() {
            exited = child.try_wait().map_err(|e| Error::from(e).wrap("ssh"))?;
        }
        if exited.is_some() && stdout.is_finished() && stderr.is_finished() {
            break;
        }
        if let Some(e) = why() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
        std::thread::sleep(std::time::Duration::from_millis(15));
    }
    // What was not written is of no use to a child that ended.
    drop(writer);
    let (out, err) = (stdout.join().unwrap_or_default(), stderr.join().unwrap_or_default());
    if over.load(Ordering::SeqCst) {
        return Err(too_long());
    }
    Ok(Ran { status: exited.unwrap_or_default(), out, err })
}

/// Whether a call that was cut off had hung. Such a call still runs
/// through the shared connection, which would live as long as it: the
/// connection goes too, and the next call makes a new one. A call cut off
/// right away (the screen closed or switched during a quick refresh)
/// leaves the connection for the next screen; it ends by itself.
fn hung(e: &Error, ran: std::time::Duration) -> bool {
    e.is(Kind::DeadlineExceeded) || (e.is_canceled() && ran >= std::time::Duration::from_secs(3))
}

/// Runs cmd with nothing attached, within ctx, and says whether it
/// succeeded. The shared connection must start like this: one that
/// inherits our pipes would keep every call waiting until it exits.
fn quiet(ctx: &Ctx, mut cmd: Command) -> bool {
    die_with_parent(&mut cmd);
    let Ok(mut child) = cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn() else { return false };
    loop {
        match child.try_wait() {
            Ok(Some(st)) => return st.success(),
            Ok(None) if ctx.done() => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(15)),
            Err(_) => return false,
        }
    }
}

/// A word for a POSIX shell, quoted unless it is plain.
pub fn sh_word(s: &str) -> String {
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_./=:,@%+".contains(&b)) {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', "'\\''"))
}

impl Cluster for SshCluster {
    fn kubectl(&self, ctx: &Ctx, args: &[&str], stdin: &str) -> Result<String> {
        if !self.known_hosts.exists() {
            bail!("this computer has not met the coordinator yet; open Machines (4) once: it checks the coordinator and remembers its key");
        }
        ctx.check()?;
        let target = format!("{}@{}", self.user, self.host);
        let mut cmd = Command::new("ssh");
        cmd.args(self.options());
        // One connection for the whole session: the screens ask every
        // few seconds, and the coordinator's firewall lets one address
        // open only 10 SSH connections a minute. A master in the
        // background holds it and ends 20 seconds after the last call.
        // When there is none and none starts, the call connects by itself
        // and reports what is wrong.
        let ctl = self.control_path(std::env::var_os("XDG_RUNTIME_DIR").as_deref());
        let mux = |ctl: &str, extra: &[&str]| {
            let mut c = Command::new("ssh");
            c.args(self.options()).args(["-o", ctl]).args(extra).arg(&target);
            c
        };
        let shared = ctl.filter(|ctl| {
            quiet(ctx, mux(ctl, &["-O", "check"])) || (master_due() && quiet(ctx, mux(ctl, &["-M", "-N", "-f", "-o", "ControlPersist=20"])))
        });
        if let Some(ctl) = &shared {
            cmd.args(["-o", "ControlMaster=no", "-o", ctl]);
        }
        // kubectl gives up by itself too, so nothing stays behind on the
        // coordinator.
        // ssh hands the words to the coordinator's shell as one line:
        // each is quoted, so it arrives as it is (a template's $ and
        // spaces too).
        cmd.arg(&target).args(["k3s", "kubectl", "--request-timeout=60s"]).args(args.iter().map(|a| sh_word(a)));
        let started = std::time::Instant::now();
        let ran = match run_child(ctx, cmd, stdin.as_bytes(), MAX_ANSWER) {
            Ok(r) => r,
            Err(e) => {
                if let Some(ctl) = &shared
                    && hung(&e, started.elapsed())
                {
                    quiet(&Ctx::new().with_timeout(std::time::Duration::from_secs(3)), mux(ctl, &["-O", "exit"]));
                }
                return Err(e);
            }
        };
        if ran.status.success() {
            return Ok(String::from_utf8_lossy(&ran.out).into_owned());
        }
        let msg: String = String::from_utf8_lossy(&ran.err).chars().filter(|c| !c.is_control() || *c == '\n').take(400).collect();
        if host_key_changed(&msg) {
            return Err(Error::with_kind(
                Kind::HostKey,
                format!(
                    "The machine at {} does not have the SSH key this computer saw before. Either the coordinator was \
                     reinstalled, or something else answers at its address. Nothing was sent.",
                    self.host
                ),
            ));
        }
        if ran.status.code() == Some(255) {
            bail!("cannot log in to the coordinator at {} with your SSH key: {}", self.host, msg.trim());
        }
        Err(errf!("kubectl: {}", msg.trim()))
    }

    fn address(&self) -> String {
        self.host.clone()
    }
}

/// What ssh says when the machine at the address has another host key
/// than the one pinned.
fn host_key_changed(msg: &str) -> bool {
    msg.contains("Host key verification failed") || msg.contains("HOST IDENTIFICATION HAS CHANGED")
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Meta {
    name: String,
    namespace: String,
    labels: std::collections::HashMap<String, String>,
    annotations: std::collections::HashMap<String, String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Item {
    kind: String,
    metadata: Meta,
    spec: serde_json::Value,
    status: serde_json::Value,
}

/// kubectl's list. items must be there: an answer without it says
/// nothing about what runs.
#[derive(Deserialize)]
struct List {
    items: Vec<Item>,
}

/// The apps and the tunnel, in one question to the cluster (each one is
/// an SSH login). Names and hosts come from the cluster; they are checked
/// before they are shown.
///
/// Only a real list with no items is an empty cluster. An empty or broken
/// answer (a cut connection, a kubectl that printed nothing) is an error:
/// read as "no apps", the sync that follows would delete every DNS name.
pub fn overview(ctx: &Ctx, c: &dyn Cluster) -> Result<Overview> {
    let out = c.kubectl(ctx, &["get", "deployments,ingresses,pods", "-A", "-l", "app", "-o", "json"], "")?;
    if out.trim().is_empty() {
        bail!("the cluster sent an empty answer; what runs there is not known");
    }
    let l: List =
        serde_json::from_str(&out).map_err(|_| errf!("the cluster sent an answer that is not a list; what runs there is not known"))?;
    let mut o = Overview::default();
    for it in l.items.iter().filter(|i| i.kind == "Deployment") {
        let (ready, copies) = (it.status["readyReplicas"].as_u64().unwrap_or(0) as u32, it.spec["replicas"].as_u64().unwrap_or(0) as u32);
        if it.metadata.namespace == entrance::NAMESPACE && it.metadata.name == "cloudflared" {
            o.tunnel = Some((ready, copies));
            let mark = it.spec["template"]["metadata"]["annotations"]["dryserver/token-mark"].as_str().unwrap_or("");
            if mark.len() <= 64 && mark.bytes().all(|b| b.is_ascii_hexdigit()) {
                o.tunnel_mark = mark.to_string();
            }
        }
        if it.metadata.namespace != NAMESPACE || !registry::valid_name(&it.metadata.name) {
            continue;
        }
        let container = &it.spec["template"]["spec"]["containers"][0];
        let image = container["image"].as_str().unwrap_or("").to_string();
        let port = container["ports"][0]["containerPort"].as_u64().and_then(|p| u16::try_from(p).ok()).unwrap_or(NO_PORT);
        // No port, and written by a dryserver that knows PORT=none: an app
        // that listens on none. Without the mark (by hand, or from before):
        // nothing an app file can say.
        let format = it.metadata.annotations.get(FORMAT_ANNOTATION).and_then(|v| v.trim().parse::<u32>().ok()).unwrap_or(0);
        let port_unknown = port == NO_PORT && format < 3;
        o.apps.push(Running {
            name: it.metadata.name.clone(),
            image: if valid_image(&image).is_ok() { image } else { "?".into() },
            ready,
            copies,
            port,
            entrance: entrance::DEFAULT.into(),
            newer: newer_format(&it.metadata),
            image_id: it.spec["template"]["metadata"]["annotations"][IMAGE_ID_ANNOTATION]
                .as_str()
                .filter(|id| crate::images::valid_id(id))
                .unwrap_or("")
                .to_string(),
            run: runtime_of(&it.metadata.name, container, &it.spec["template"]["metadata"]["annotations"], port),
            port_unknown,
            gh: crate::github::state_of(&serde_json::to_value(&it.metadata.annotations).unwrap_or_default()),
            ..Running::default()
        });
    }
    for it in l.items.iter().filter(|i| i.metadata.namespace == NAMESPACE) {
        let Some(app) = it.metadata.labels.get("app").and_then(|n| o.apps.iter_mut().find(|a| a.name == *n)) else { continue };
        match it.kind.as_str() {
            // Only the Ingress named after the app is its own: one made
            // by hand with its label is not read as the app's names.
            "Ingress" if it.metadata.name == app.name => {
                app.newer |= newer_format(&it.metadata);
                // Each rule: a name, and the service port it goes to (80
                // is the main port). A name that is no name is left out;
                // one listed twice counts once, with its first port. No
                // app of dryserver has more than MAX_HOSTS: an answer with
                // more is not read past them.
                let mut seen = std::collections::HashSet::new();
                let rules = it.spec["rules"].as_array().map(Vec::as_slice).unwrap_or_default();
                for rule in rules.iter().take(MAX_HOSTS * 4) {
                    if app.hosts.len() >= MAX_HOSTS {
                        break;
                    }
                    let host = rule["host"].as_str().unwrap_or("");
                    if host.is_empty() || valid_host(host).is_err() || !seen.insert(host) {
                        continue;
                    }
                    let to = rule["http"]["paths"][0]["backend"]["service"]["port"]["number"].as_u64().unwrap_or(80);
                    let port = match u16::try_from(to) {
                        Ok(80) | Err(_) => app.port,
                        Ok(p) => p,
                    };
                    app.hosts.push(Host { name: host.to_string(), port });
                }
                app.hosts.sort();
                // Without the annotation: Cloudflare, as before there was
                // a choice.
                app.entrance = match it.metadata.annotations.get(entrance::ANNOTATION) {
                    None => entrance::DEFAULT.into(),
                    Some(id) if entrance::valid_id(id).is_ok() => id.clone(),
                    Some(_) => "?".into(),
                };
            }
            "Pod" => {
                let node = it.spec["nodeName"].as_str().unwrap_or("");
                if registry::valid_name(node) && !app.nodes.iter().any(|n| n == node) {
                    app.nodes.push(node.to_string());
                }
            }
            _ => {}
        }
    }
    o.apps.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(o)
}

/// The servers apps may run on: the cluster's nodes, the coordinator (its
/// control plane) left out.
pub fn servers(ctx: &Ctx, c: &dyn Cluster) -> Result<Vec<String>> {
    let out = c.kubectl(ctx, &["get", "nodes", "-o", "json"], "")?;
    let l: List = serde_json::from_str(&out).map_err(|_| errf!("the cluster sent a list of servers that is not one"))?;
    Ok(l.items
        .iter()
        .filter(|i| i.kind == "Node" && registry::valid_name(&i.metadata.name))
        .filter(|i| !i.metadata.labels.contains_key("node-role.kubernetes.io/control-plane"))
        .map(|i| i.metadata.name.clone())
        .collect())
}

pub fn deploy(ctx: &Ctx, c: &dyn Cluster, app: &App) -> Result<()> {
    let manifest = app.manifest()?;
    c.kubectl(ctx, &["apply", "-f", "-"], &manifest)?;
    if app.hosts.is_empty() {
        // Started again without a public name: the old way in goes.
        c.kubectl(ctx, &["-n", NAMESPACE, "delete", "ingress", &app.name, "--ignore-not-found"], "")?;
    }
    if app.port == NO_PORT {
        // Started again listening on no port: its service goes.
        c.kubectl(ctx, &["-n", NAMESPACE, "delete", "service", &app.name, "--ignore-not-found"], "")?;
    }
    Ok(())
}

/// Removes an app's objects. The namespace and its default-deny policy
/// stay.
pub fn remove(ctx: &Ctx, c: &dyn Cluster, name: &str) -> Result<()> {
    if !registry::valid_name(name) {
        bail!("not an app name");
    }
    let sel = format!("app={name}");
    c.kubectl(ctx, &["-n", NAMESPACE, "delete", "deployment,service,ingress,networkpolicy,secret", "-l", &sel, "--ignore-not-found"], "")
        .map(|_| ())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::sync::Mutex;

    pub fn app() -> App {
        App {
            name: "blog".into(),
            image: "ghcr.io/me/blog:v2".into(),
            port: 8080,
            hosts: vec![Host { name: "blog.example.com".into(), port: 8080 }],
            entrance: crate::entrance::CLOUDFLARE.into(),
            copies: 2,
            image_id: String::new(),
            run: Runtime::default(),
            source: None,
            gh: Default::default(),
        }
    }

    /// One public name for port.
    pub fn host(name: &str, port: u16) -> Host {
        Host { name: name.into(), port }
    }

    #[test]
    fn an_app_that_listens_on_no_port() {
        // A bot or a worker: nothing reaches it, nothing waits for a port.
        let bot = App { name: "bot".into(), port: NO_PORT, hosts: vec![], ..app() };
        let y = bot.manifest().unwrap();
        for not in ["kind: Service", "readinessProbe", "containerPort", "name: \"PORT\"", "kind: Ingress"] {
            assert!(!y.contains(not), "{not}:\n{y}");
        }
        let policy = &y[y.find("name: \"app-bot\"").unwrap()..y.find("kind: Deployment").unwrap()];
        assert!(policy.contains("  ingress: []\n") && !policy.contains("port:"), "{policy}");
        assert!(y.contains("maxUnavailable: 0"), "a new version still starts beside the old one");
        // Its own PORT setting is its own business then.
        App { run: Runtime { env: vec![("PORT".into(), "9999".into())], ..Runtime::default() }, ..bot.clone() }.manifest().unwrap();
        // Deployed: an old service of it goes; so does its old way in.
        let c = Fake::default();
        deploy(&Ctx::new(), &c, &bot).unwrap();
        let calls: Vec<String> = c.calls.lock().unwrap().iter().map(|(a, _)| a.clone()).collect();
        assert!(calls.contains(&"-n apps delete service bot --ignore-not-found".to_string()), "{calls:?}");
        assert!(calls.contains(&"-n apps delete ingress bot --ignore-not-found".to_string()), "{calls:?}");
        // Read back: an app on no port again, as its file says.
        let c = Fake::default();
        let listing = serde_json::json!({"items": [{
            "kind": "Deployment",
            "metadata": {"name": "bot", "namespace": "apps", "labels": {"app": "bot"}, "annotations": {FORMAT_ANNOTATION: FORMAT.to_string()}},
            "spec": {"replicas": 1, "template": {"spec": {"containers": [{"image": "ghcr.io/me/blog:v2", "resources": {"limits": {"memory": "512Mi", "cpu": "1"}}}]}}},
            "status": {}
        }]});
        *c.listing.lock().unwrap() = listing.to_string();
        let r = overview(&Ctx::new(), &c).unwrap().apps.remove(0);
        assert_eq!(App::of(&r).unwrap(), App { copies: 1, ..bot.clone() });
        // An app that listens keeps its service.
        let c = Fake::default();
        deploy(&Ctx::new(), &c, &App { hosts: vec![], ..app() }).unwrap();
        assert!(!c.calls.lock().unwrap().iter().any(|(a, _)| a.contains("delete service")));
    }

    #[test]
    fn an_app_of_the_vpn_is_served_by_the_vpns_traefik_only() {
        let a = App { entrance: entrance::VPN.into(), ..app() };
        let y = a.manifest().unwrap();
        let ingress = &y[y.find("kind: Ingress").unwrap()..];
        for want in [
            "  labels:\n    app: \"blog\"\n    dryserver/vpn: \"true\"\n",
            "    dryserver/entrance: \"vpn\"\n",
            "    traefik.ingress.kubernetes.io/router.entrypoints: websecure\n",
            "    traefik.ingress.kubernetes.io/router.tls: \"true\"\n",
        ] {
            assert!(ingress.contains(want), "{want:?}:\n{ingress}");
        }
        let policy = &y[y.find("name: \"app-blog\"").unwrap()..y.find("kind: Deployment").unwrap()];
        assert!(
            policy.contains("kubernetes.io/metadata.name: vpn\n          podSelector:\n            matchLabels:\n              app.kubernetes.io/name: dryserver-vpn"),
            "{policy}"
        );
        // Only the VPN's ingress: not the cluster's, not the other apps.
        assert!(!policy.contains("kube-system") && !policy.contains("podSelector: {}"), "{policy}");
        // An app of the tunnel: neither the label nor the VPN's Traefik.
        let y = app().manifest().unwrap();
        assert!(!y.contains("dryserver/vpn") && !y.contains("dryserver-vpn") && !y.contains("router.tls"), "{y}");
        // Inside only: nothing of the VPN either.
        let y = App { entrance: entrance::VPN.into(), hosts: vec![], ..app() }.manifest().unwrap();
        assert!(!y.contains("dryserver-vpn"), "{y}");
    }

    #[test]
    fn words_reach_the_coordinator_as_they_are() {
        assert_eq!(sh_word("--type"), "--type");
        assert_eq!(sh_word("app=shop"), "app=shop");
        assert_eq!(sh_word(""), "''");
        assert_eq!(sh_word("go-template={{$k}} x"), "'go-template={{$k}} x'");
        assert_eq!(sh_word("it's; rm -rf /"), "'it'\\''s; rm -rf /'");
        // What sh makes of them: the words as they were.
        for w in ["a b", "$HOME", "`id`", "it's", "x\ny", "{{range $k, $v := .data}} {{$k}}{{end}}"] {
            let out = std::process::Command::new("sh").arg("-c").arg(format!("printf %s {}", sh_word(w))).output().unwrap();
            assert_eq!(String::from_utf8_lossy(&out.stdout), w);
        }
    }

    #[test]
    fn manifest_has_the_walls() {
        let y = app().manifest().unwrap();
        for want in [
            "kind: Namespace\nmetadata:\n  name: apps\n",
            "pod-security.kubernetes.io/enforce: baseline",
            "name: default-deny\n  namespace: apps\nspec:\n  podSelector: {}\n  policyTypes: [Ingress]",
            "app.kubernetes.io/name: traefik",
            "replicas: 2",
            "topologyKey: kubernetes.io/hostname",
            "- key: node.kubernetes.io/unreachable\n          operator: Exists\n          effect: NoExecute\n          tolerationSeconds: 30\n",
            "- key: node.kubernetes.io/not-ready\n",
            "image: \"ghcr.io/me/blog:v2\"",
            "name: \"app-blog\"\n  namespace: apps\n  labels:\n    app: \"blog\"\nspec:\n  podSelector:",
            "kind: Deployment\nmetadata:\n  name: \"blog\"",
            "capabilities:\n              drop: [\"NET_RAW\"]",
            "containerPort: 8080",
            "automountServiceAccountToken: false",
            "allowPrivilegeEscalation: false",
            "targetPort: 8080",
            "kind: Ingress",
            "  annotations:\n    dryserver/entrance: \"cloudflare\"\n    dryserver/format: \"3\"\nspec:\n  rules:\n    - host: \"blog.example.com\"",
            "kind: Deployment\nmetadata:\n  name: \"blog\"\n  namespace: apps\n  labels:\n    app: \"blog\"\n  annotations:\n    dryserver/format: \"3\"\n",
            "  ports:\n    - name: http\n      port: 80\n      targetPort: 8080\n",
            "                port:\n                  number: 80\n",
        ] {
            assert!(y.contains(want), "manifest missing {want:?}:\n{y}");
        }
        assert_eq!(y.matches("\n---\n").count(), 6);
        // Out: the other apps, DNS, the internet; no private address.
        let out = &y[y.find("name: outgoing").unwrap()..y.find("# blog takes connections").unwrap()];
        for want in [
            "policyTypes: [Egress]",
            "- to:\n        - podSelector: {}\n",
            "k8s-app: kube-dns",
            "cidr: 0.0.0.0/0\n            except: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16]",
        ] {
            assert!(out.contains(want), "outgoing policy missing {want:?}:\n{out}");
        }
        // Without a public name there is no way in from outside.
        let inside = App { hosts: vec![], ..app() }.manifest().unwrap();
        assert!(!inside.contains("kind: Ingress") && inside.matches("\n---\n").count() == 5);
        // Another entrance is another annotation; without a public name
        // the entrance does not matter.
        let vps = App { entrance: "vps".into(), ..app() }.manifest().unwrap();
        assert!(vps.contains("dryserver/entrance: \"vps\""), "{vps}");
        App { hosts: vec![], entrance: String::new(), ..app() }.manifest().unwrap();
    }

    #[test]
    fn only_plain_values_reach_the_manifest() {
        let bad: Vec<(App, &str)> = vec![
            (App { name: "Blog".into(), ..app() }, "name"),
            (App { name: "a\nkind: Secret".into(), ..app() }, "name"),
            (App { name: "x".repeat(41), ..app() }, "name"),
            // A name is a DNS name in the cluster: a letter first.
            (App { name: "123".into(), ..app() }, "name"),
            (App { name: "9lives".into(), ..app() }, "name"),
            (App { image: "nginx; rm -rf /".into(), ..app() }, "image"),
            (App { image: "nginx\"\n  privileged: true".into(), ..app() }, "image"),
            (App { image: String::new(), ..app() }, "image"),
            (App { image: "-evil".into(), ..app() }, "image"),
            (App { port: NO_PORT, ..app() }, "PORT=none: an app that listens on no port has no public names"),
            (App { hosts: vec![host("blog", 8080)], ..app() }, "public host name"),
            (App { hosts: vec![host("a b.example.com", 8080)], ..app() }, "public host name"),
            (App { hosts: vec![host("x.example.com\"\n", 8080)], ..app() }, "public host name"),
            (App { hosts: vec![host("", 8080)], ..app() }, "public host name"),
            (App { hosts: vec![host("10.1.0.60", 8080)], ..app() }, "public host name"),
            (App { hosts: vec![host("a.example.com", 8080), host("a.example.com", 9000)], ..app() }, "public host name"),
            (App { hosts: vec![host("a.example.com", 0)], ..app() }, "public host name"),
            (App { hosts: vec![host("a.example.com", 80)], ..app() }, "public host name"),
            (App { hosts: (0..51).map(|i| host(&format!("n{i}.example.com"), 8080)).collect(), ..app() }, "public host name"),
            (App { hosts: (0..10).map(|i| host(&format!("n{i}.example.com"), 9000 + i)).collect(), ..app() }, "public host name"),
            (App { entrance: String::new(), ..app() }, "entrance"),
            (App { entrance: "cloudflare\"\n  x: y".into(), ..app() }, "entrance"),
            (App { copies: 0, ..app() }, "copies"),
            (App { copies: 500, ..app() }, "copies"),
        ];
        for (a, want) in bad {
            let e = a.manifest().unwrap_err().to_string();
            assert!(e.starts_with(want), "{a:?}: {e}");
        }
        for image in ["nginx", "nginx:1.27", "docker.io/library/nginx@sha256:abc123", "ghcr.io/a_b/c-d:v1.2"] {
            valid_image(image).unwrap();
        }
        // Names that mean something else to YAML or to the namespace
        // stay what they are: quoted, and never the name of a wall.
        for name in ["true", "null", "no", "outgoing", "default-deny"] {
            let y = App { name: name.into(), ..app() }.manifest().unwrap();
            assert!(y.contains(&format!("kind: Deployment\nmetadata:\n  name: \"{name}\"")), "{name}:\n{y}");
            assert!(y.contains(&format!("name: \"app-{name}\"")), "{name}");
            assert_eq!(y.matches("\n  name: default-deny\n").count(), 1, "{name} took the place of a wall");
            assert_eq!(y.matches("\n  name: outgoing\n").count(), 1, "{name} took the place of a wall");
            assert!(
                !y.contains(&format!("name: {name}\n")) || name == "outgoing" || name == "default-deny",
                "{name} is unquoted somewhere"
            );
        }
    }

    /// A listing that makes the fake answer nothing at all.
    pub const SILENT: &str = "(nothing)";

    /// Records kubectl calls and answers "get" with a fixed listing: an
    /// empty cluster until one is set, nothing at all with SILENT.
    #[derive(Default)]
    pub struct Fake {
        pub calls: Mutex<Vec<(String, String)>>,
        pub listing: Mutex<String>,
        /// What "apply" prints.
        pub applied: Mutex<String>,
        pub fail: Mutex<Option<String>>,
        /// A slow coordinator: each call takes this long, or until ctx
        /// gives up.
        pub delay: Mutex<std::time::Duration>,
        /// One that does not even notice ctx: each call takes this long.
        pub stubborn: Mutex<std::time::Duration>,
        /// Calls that have returned, and those that saw ctx end them.
        pub ended: std::sync::atomic::AtomicUsize,
        pub cut_off: std::sync::atomic::AtomicUsize,
        /// The listing once something was deleted.
        pub after_delete: Mutex<Option<String>>,
        /// The listing once a manifest with this text in it was applied
        /// (each is used once).
        pub after_apply: Mutex<Vec<(String, String)>>,
        /// Fixed answers: a call whose arguments contain the first gets
        /// the second (before the listing).
        pub answers: Mutex<Vec<(String, String)>>,
    }

    impl Cluster for Fake {
        fn kubectl(&self, ctx: &Ctx, args: &[&str], stdin: &str) -> Result<String> {
            use std::sync::atomic::Ordering::SeqCst;
            self.calls.lock().unwrap().push((args.join(" "), stdin.to_string()));
            let (delay, stubborn) = (*self.delay.lock().unwrap(), *self.stubborn.lock().unwrap());
            std::thread::sleep(stubborn);
            let slept = ctx.sleep(delay);
            self.ended.fetch_add(1, SeqCst);
            if let Err(e) = slept {
                self.cut_off.fetch_add(1, SeqCst);
                return Err(e);
            }
            if let Some(e) = self.fail.lock().unwrap().clone() {
                return Err(e.into());
            }
            if args.contains(&"delete")
                && let Some(l) = self.after_delete.lock().unwrap().take()
            {
                *self.listing.lock().unwrap() = l;
            }
            if args.contains(&"apply") {
                let mut next = self.after_apply.lock().unwrap();
                if let Some(i) = next.iter().position(|(has, _)| stdin.contains(has.as_str())) {
                    *self.listing.lock().unwrap() = next.remove(i).1;
                }
            }
            let joined = args.join(" ");
            if let Some((_, a)) = self.answers.lock().unwrap().iter().find(|(k, _)| joined.contains(k.as_str())) {
                return Ok(a.clone());
            }
            Ok(if args.contains(&"get") {
                match self.listing.lock().unwrap().as_str() {
                    "" => r#"{"items":[]}"#.into(),
                    SILENT => String::new(),
                    l => l.to_string(),
                }
            } else if args.contains(&"apply") {
                self.applied.lock().unwrap().clone()
            } else {
                String::new()
            })
        }
    }

    pub const LISTING: &str = r#"{"items":[
      {"kind":"Deployment","metadata":{"name":"blog","namespace":"apps","labels":{"app":"blog"}},"spec":{"replicas":2,"template":{"spec":{"containers":[{"image":"ghcr.io/me/blog:v2","ports":[{"containerPort":8080}]}]}}},"status":{"readyReplicas":1}},
      {"kind":"Deployment","metadata":{"name":"api","namespace":"apps","labels":{"app":"api"}},"spec":{"replicas":1,"template":{"spec":{"containers":[{"image":"evil\u001b[2Jimage"}]}}},"status":{}},
      {"kind":"Deployment","metadata":{"name":"Bad Name","namespace":"apps","labels":{}},"spec":{},"status":{}},
      {"kind":"Deployment","metadata":{"name":"local-path-provisioner","namespace":"kube-system","labels":{"app":"local-path-provisioner"}},"spec":{"replicas":1},"status":{"readyReplicas":1}},
      {"kind":"Deployment","metadata":{"name":"cloudflared","namespace":"edge","labels":{"app":"cloudflared"}},"spec":{"replicas":2,"template":{"metadata":{"annotations":{"dryserver/token-mark":"00aa11bb22cc33dd"}}}},"status":{"readyReplicas":1}},
      {"kind":"Ingress","metadata":{"name":"blog","namespace":"apps","labels":{"app":"blog"}},"spec":{"rules":[{"host":"blog.example.com"}]}},
      {"kind":"Ingress","metadata":{"name":"api","namespace":"apps","labels":{"app":"api"},"annotations":{"dryserver/entrance":"elsewhere"}},"spec":{"rules":[{"host":"not a host"}]}},
      {"kind":"Ingress","metadata":{"name":"blog","namespace":"other","labels":{"app":"blog"}},"spec":{"rules":[{"host":"stolen.example.com"}]}},
      {"kind":"Pod","metadata":{"name":"blog-1","namespace":"apps","labels":{"app":"blog"}},"spec":{"nodeName":"node-a"}},
      {"kind":"Pod","metadata":{"name":"blog-2","namespace":"apps","labels":{"app":"blog"}},"spec":{"nodeName":"node-b"}},
      {"kind":"Pod","metadata":{"name":"blog-3","namespace":"apps","labels":{"app":"blog"}},"spec":{"nodeName":"node-a"}}
    ]}"#;

    #[test]
    fn names_as_people_type_them() {
        for (typed, want) in [
            ("Shop.Example.COM", "shop.example.com"),
            ("  shop.example.com.  ", "shop.example.com"),
            ("example.com", "example.com"),
            ("xn--bcher-kva.de", "xn--bcher-kva.de"),
            ("a.b.c.example.com", "a.b.c.example.com"),
        ] {
            assert_eq!(clean_host(typed).unwrap(), want, "{typed:?}");
        }
        for (typed, why) in [
            ("", "an empty name"),
            (".", "an empty name"),
            ("bücher.de", "xn-- form"),
            ("*.example.com", "not supported yet"),
            ("https://shop.example.com", "without http://"),
            ("shop.example.com/admin", "without http://"),
            ("shop.example.com:8080", "only in an app file"),
            ("10.1.0.60", "an IP address"),
            ("localhost", "a host name like"),
            ("shop..example.com", "a host name like"),
            ("-shop.example.com", "a host name like"),
            ("shop_x.example.com", "a host name like"),
            ("shop example.com", "a host name like"),
        ] {
            let e = clean_host(typed).unwrap_err().to_string();
            assert!(e.contains(why), "{typed:?}: {e}");
        }
        let long = format!("{}.example.com", "a".repeat(64));
        assert!(clean_host(&long).is_err(), "a label is at most 63");
        let many = format!("{}example.com", "abcdefghi.".repeat(25));
        assert!(many.len() > 253 && clean_host(&many).is_err());
    }

    #[test]
    fn many_names_and_ports() {
        let a = App {
            hosts: vec![
                host("www.example.com", 8080),
                host("admin.example.com", 9000),
                host("example.com", 8080),
                host("stats.example.net", 9100),
                host("api.example.com", 9000),
            ],
            ..app()
        };
        let y = a.manifest().unwrap();
        // One Ingress, its rules sorted; the main port is the service's
        // port 80, the others keep their number.
        assert_eq!(y.matches("kind: Ingress").count(), 1);
        let rules: Vec<(&str, &str)> = y
            .split("    - host: \"")
            .skip(1)
            .map(|r| (r.split('"').next().unwrap(), r.split("number: ").nth(1).unwrap().lines().next().unwrap()))
            .collect();
        assert_eq!(
            rules,
            vec![
                ("admin.example.com", "9000"),
                ("api.example.com", "9000"),
                ("example.com", "80"),
                ("stats.example.net", "9100"),
                ("www.example.com", "80"),
            ]
        );
        // Every port the names lead to: on the container, in the wall, on
        // the service, each once.
        for want in [
            "            - containerPort: 8080\n            - containerPort: 9000\n            - containerPort: 9100\n          env:",
            "        - port: 8080\n        - port: 9000\n        - port: 9100\n---\n",
            "    - name: http\n      port: 80\n      targetPort: 8080\n    - name: \"p9000\"\n      port: 9000\n      targetPort: 9000\n    - name: \"p9100\"\n      port: 9100\n      targetPort: 9100\n",
        ] {
            assert!(y.contains(want), "missing {want:?}:\n{y}");
        }
        assert_eq!(a.extra_ports(), vec![9000, 9100]);
        assert_eq!(a.names()[0], "admin.example.com");
        // Port 80 is fine as the main port, for every name.
        App { port: 80, hosts: vec![host("a.example.com", 80), host("b.example.com", 80)], ..app() }.manifest().unwrap();
        // Ten ports in all is the most.
        App { hosts: (0..9).map(|i| host(&format!("n{i}.example.com"), 9000 + i)).collect(), ..app() }.manifest().unwrap();
        App { hosts: (0..50).map(|i| host(&format!("n{i}.example.com"), 8080)).collect(), ..app() }.manifest().unwrap();
    }

    #[test]
    fn the_cluster_says_what_names_an_app_has() {
        let dep = |name: &str, port: &str, format: &str| {
            format!(
                r#"{{"kind":"Deployment","metadata":{{"name":"{name}","namespace":"apps","labels":{{"app":"{name}"}}{format}}},"spec":{{"replicas":1,"template":{{"spec":{{"containers":[{{"image":"shop:v1"{port}}}]}}}}}},"status":{{}}}}"#
            )
        };
        let listing = format!(
            r#"{{"items":[{},{},{},{},
            {{"kind":"Ingress","metadata":{{"name":"shop","namespace":"apps","labels":{{"app":"shop"}},"annotations":{{"dryserver/format":"2"}}}},"spec":{{"rules":[
              {{"host":"www.example.com","http":{{"paths":[{{"backend":{{"service":{{"name":"shop","port":{{"number":80}}}}}}}}]}}}},
              {{"host":"admin.example.com","http":{{"paths":[{{"backend":{{"service":{{"name":"shop","port":{{"number":9000}}}}}}}}]}}}},
              {{"host":"admin.example.com","http":{{"paths":[{{"backend":{{"service":{{"name":"shop","port":{{"number":9100}}}}}}}}]}}}},
              {{"host":"Not A Host"}},
              {{"host":""}},
              {{"host":"example.com"}}
            ]}}}},
            {{"kind":"Ingress","metadata":{{"name":"extra","namespace":"apps","labels":{{"app":"shop"}}}},"spec":{{"rules":[{{"host":"sneaky.example.com"}}]}}}},
            {{"kind":"Ingress","metadata":{{"name":"next","namespace":"apps","labels":{{"app":"next"}},"annotations":{{"dryserver/format":"4"}}}},"spec":{{"rules":[{{"host":"next.example.com"}}]}}}}
            ]}}"#,
            dep("shop", r#","ports":[{"containerPort":8080},{"containerPort":9000}]"#, ""),
            dep("old", r#","ports":[{"containerPort":3000}]"#, ""),
            dep("next", r#","ports":[{"containerPort":3000}]"#, ""),
            dep("odd", "", r#","annotations":{"dryserver/format":"two"}"#),
        );
        let c = Fake::default();
        *c.listing.lock().unwrap() = listing;
        let o = overview(&Ctx::new(), &c).unwrap();
        let shop = o.apps.iter().find(|a| a.name == "shop").unwrap();
        assert_eq!(
            shop.hosts,
            vec![host("admin.example.com", 9000), host("example.com", 8080), host("www.example.com", 8080)],
            "every rule, the first port of a name listed twice, never a broken name, never another Ingress's"
        );
        assert_eq!((shop.port, shop.newer, shop.names_text().as_str()), (8080, false, "admin.example.com, example.com, www.example.com"));
        assert!(shop.public() && shop.has("example.com") && !shop.has("sneaky.example.com"));
        let old = o.apps.iter().find(|a| a.name == "old").unwrap();
        assert!(!old.public() && !old.newer, "{old:?}");
        assert!(o.apps.iter().find(|a| a.name == "next").unwrap().newer, "a newer format is seen");
        assert!(o.apps.iter().find(|a| a.name == "odd").unwrap().newer, "a format this one cannot read counts as newer");
        // What runs, as an app to change: the same objects again.
        let back = App::of(shop).unwrap();
        assert_eq!((back.port, back.hosts.len(), back.image.as_str()), (8080, 3, "shop:v1"));
        let again = back.manifest().unwrap();
        assert!(again.contains("number: 9000") && again.contains("- host: \"www.example.com\""), "{again}");
        // Without a port and without the mark of PORT=none: made by hand
        // or from before; it cannot be made again from a file.
        assert!(App::of(o.apps.iter().find(|a| a.name == "odd").unwrap()).is_none());
    }

    #[test]
    fn what_an_app_runs_with() {
        let run = Runtime {
            env: vec![
                ("API".into(), "https://x.example.com/?a=1&b=#frag".into()),
                ("QUOTE".into(), "he said \"hi\"\n- kind: Secret".replace('\n', " ")),
            ],
            secrets: vec!["DATABASE_URL".into(), "TOKEN".into()],
            memory_mib: 1024,
            cpu_milli: 500,
            secrets_version: "4711".into(),
        };
        let a = App { run: run.clone(), ..app() };
        let y = a.manifest().unwrap();
        for want in [
            "            - name: \"PORT\"\n              value: \"8080\"\n",
            "            - name: \"API\"\n              value: \"https://x.example.com/?a=1&b=#frag\"\n",
            "              value: \"he said \\\"hi\\\" - kind: Secret\"\n",
            "            - name: \"TOKEN\"\n              valueFrom:\n                secretKeyRef:\n                  name: \"app-blog\"\n                  key: \"TOKEN\"\n",
            "      annotations:\n        dryserver/secrets: \"4711\"\n",
            "            requests:\n              cpu: 50m\n              memory: 512Mi\n            limits:\n              cpu: 500m\n              memory: 1024Mi\n",
            "          readinessProbe:\n            tcpSocket:\n              port: 8080\n",
            "      maxUnavailable: 0\n      maxSurge: 1\n",
            "  minReadySeconds: 20\n",
            "      enableServiceLinks: false\n",
        ] {
            assert!(y.contains(want), "missing {want:?}:\n{y}");
        }
        // Nothing dryserver sets but PORT: Node.js 20 and newer size their
        // heap to the limit; an image's own NODE_OPTIONS stays its own.
        // No LimitRange: it would limit apps of before at their next start.
        assert!(!y.contains("NODE_OPTIONS") && !y.contains("LimitRange"), "{y}");
        // The app's own PORT is the one; its NODE_OPTIONS goes as it is.
        let own = App {
            run: Runtime {
                env: vec![("NODE_OPTIONS".into(), "--enable-source-maps".into()), ("PORT".into(), "8080".into())],
                ..Runtime::default()
            },
            ..app()
        };
        let y = own.manifest().unwrap();
        assert_eq!(y.matches("name: \"PORT\"").count(), 1);
        assert!(y.contains("value: \"--enable-source-maps\"") && !y.contains("max-old-space-size"), "{y}");
        // What is refused.
        let bad = |r: Runtime| App { run: r, ..app() }.manifest().unwrap_err().to_string();
        assert!(bad(Runtime { env: vec![("PORT".into(), "3000".into())], ..Runtime::default() }).contains("must agree"));
        assert!(bad(Runtime { env: vec![("1X".into(), "a".into())], ..Runtime::default() }).contains("not starting with a digit"));
        assert!(bad(Runtime { env: vec![("A".into(), "a\u{7}".into())], ..Runtime::default() }).contains("control character"));
        assert!(bad(Runtime { env: vec![("A".into(), "a\u{FFFE}".into())], ..Runtime::default() }).contains("no character"));
        // Line and paragraph separators reach the cluster as escapes, which
        // YAML reads back as the same characters (not as line breaks).
        let sep = App { run: Runtime { env: vec![("A".into(), "x\u{2028}y\u{2029}z".into())], ..Runtime::default() }, ..app() };
        let y = sep.manifest().unwrap();
        assert!(y.contains(r#"value: "x\u2028y\u2029z""#) && !y.contains('\u{2028}'), "{y}");
        assert!(bad(Runtime { env: vec![("A".into(), "x".repeat(40 << 10))], ..Runtime::default() }).contains("longer than"));
        assert!(
            bad(Runtime { env: vec![("A".into(), "1".into())], secrets: vec!["A".into()], ..Runtime::default() })
                .contains("a setting or a secret already")
        );
        assert!(bad(Runtime { memory_mib: 8, ..Runtime::default() }).contains("MEMORY"));
        assert!(bad(Runtime { cpu_milli: 9000, ..Runtime::default() }).contains("CPU"));
        assert!(bad(Runtime { secrets: vec!["A".into()], secrets_version: "1; rm".into(), ..Runtime::default() }).contains("version"));
        // Read back from the cluster as written.
        let listing = serde_json::json!({"items": [{
            "kind": "Deployment",
            "metadata": {"name": "blog", "namespace": "apps", "labels": {"app": "blog"}},
            "spec": {"replicas": 2, "template": {
                "metadata": {"annotations": {"dryserver/secrets": "4711"}},
                "spec": {"containers": [{
                    "image": "ghcr.io/me/blog:v2",
                    "ports": [{"containerPort": 8080}],
                    "env": [
                        {"name": "PORT", "value": "8080"},
                        {"name": "NODE_OPTIONS", "value": "--max-old-space-size=768"},
                        {"name": "API", "value": "x=1\u{2028}y"},
                        {"name": "TOKEN", "valueFrom": {"secretKeyRef": {"name": "app-blog", "key": "TOKEN"}}},
                        {"name": "OTHER", "valueFrom": {"secretKeyRef": {"name": "someone-else", "key": "OTHER"}}}
                    ],
                    "resources": {"limits": {"memory": "1Gi", "cpu": "500m"}}
                }]}
            }},
            "status": {}
        }]})
        .to_string();
        let c = Fake::default();
        *c.listing.lock().unwrap() = listing;
        let r = overview(&Ctx::new(), &c).unwrap().apps.remove(0).run;
        assert_eq!(
            r,
            Runtime {
                env: vec![("API".into(), "x=1\u{2028}y".into()), ("NODE_OPTIONS".into(), "--max-old-space-size=768".into())],
                secrets: vec!["TOKEN".into()],
                memory_mib: 1024,
                cpu_milli: 500,
                secrets_version: "4711".into()
            }
        );
        // Units as people write them.
        assert_eq!((parse_memory("512Mi").unwrap(), parse_memory("1Gi").unwrap(), parse_memory("1.5Gi").unwrap()), (512, 1024, 1536));
        assert_eq!((parse_cpu("1").unwrap(), parse_cpu("500m").unwrap(), parse_cpu("0.25").unwrap()), (1000, 500, 250));
        for bad in ["512", "512MB", "1G", "", "-1Gi", "64Gi", "16Mi"] {
            assert!(parse_memory(bad).is_err(), "{bad}");
        }
        for bad in ["", "x", "10", "20m", "1.5.2"] {
            assert!(parse_cpu(bad).is_err(), "{bad}");
        }
        assert_eq!(
            (memory_text(1024), memory_text(1536), cpu_text(1000), cpu_text(250)),
            ("1Gi".into(), "1536Mi".into(), "1".into(), "250m".into())
        );
        assert!(looks_secret("STRIPE_API_KEY") && looks_secret("db_password") && !looks_secret("NODE_ENV"));
    }

    #[test]
    fn another_host_key_is_named() {
        assert!(host_key_changed("Host key verification failed."));
        assert!(host_key_changed("@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @"));
        assert!(!host_key_changed("Permission denied (publickey)."));
    }

    #[test]
    fn list_deploy_remove() {
        let c = Fake::default();
        *c.listing.lock().unwrap() = LISTING.into();
        let o = overview(&Ctx::new(), &c).unwrap();
        assert_eq!((o.tunnel, o.tunnel_mark.as_str()), (Some((1, 2)), "00aa11bb22cc33dd"));
        assert_eq!(
            o.apps,
            vec![
                // Its Ingress names an entrance nobody knows.
                Running {
                    name: "api".into(),
                    image: "?".into(),
                    ready: 0,
                    copies: 1,
                    entrance: "?".into(),
                    run: Runtime { memory_mib: 0, cpu_milli: 0, ..Runtime::default() },
                    // No port, no mark: made by hand.
                    port_unknown: true,
                    ..Running::default()
                },
                // No annotation: Cloudflare, as before entrances.
                Running {
                    name: "blog".into(),
                    image: "ghcr.io/me/blog:v2".into(),
                    ready: 1,
                    copies: 2,
                    port: 8080,
                    hosts: vec![host("blog.example.com", 8080)],
                    entrance: "cloudflare".into(),
                    nodes: vec!["node-a".into(), "node-b".into()],
                    newer: false,
                    image_id: String::new(),
                    run: Runtime { memory_mib: 0, cpu_milli: 0, ..Runtime::default() },
                    port_unknown: false,
                    gh: Default::default(),
                },
            ],
            "what the cluster says is checked before it is shown, and only the apps namespace counts"
        );
        assert_eq!(c.calls.lock().unwrap().len(), 1, "one question to the cluster per refresh");

        deploy(&Ctx::new(), &c, &app()).unwrap();
        let (args, stdin) = c.calls.lock().unwrap().last().unwrap().clone();
        assert_eq!(args, "apply -f -");
        assert_eq!(stdin, app().manifest().unwrap());
        assert!(deploy(&Ctx::new(), &c, &App { name: "no good".into(), ..app() }).is_err());
        // Started again without a public name: the old way in is taken away.
        deploy(&Ctx::new(), &c, &App { hosts: vec![], ..app() }).unwrap();
        assert_eq!(c.calls.lock().unwrap().last().unwrap().0, "-n apps delete ingress blog --ignore-not-found");

        remove(&Ctx::new(), &c, "blog").unwrap();
        assert_eq!(
            c.calls.lock().unwrap().last().unwrap().0,
            "-n apps delete deployment,service,ingress,networkpolicy,secret -l app=blog --ignore-not-found"
        );
        assert!(remove(&Ctx::new(), &c, "blog -A").is_err(), "a name must not carry kubectl arguments");

        // An empty cluster is an empty list; an unreachable one an error.
        *c.listing.lock().unwrap() = r#"{"items":[]}"#.into();
        assert_eq!(overview(&Ctx::new(), &c).unwrap(), Overview::default());
        // An answer that is not a list is not an empty cluster: nothing,
        // blanks, null, no items, half a list.
        for bad in [SILENT, " \n", "null", "{}", r#"{"items":null}"#, r#"{"items":[{"kind":"Deployment""#, "[]"] {
            *c.listing.lock().unwrap() = bad.into();
            let e = overview(&Ctx::new(), &c).unwrap_err().to_string();
            assert!(e.contains("what runs there is not known"), "{bad:?}: {e}");
        }
        *c.fail.lock().unwrap() = Some("connection refused".into());
        assert!(overview(&Ctx::new(), &c).is_err());
    }

    fn sh(script: &str) -> Command {
        let mut c = Command::new("sh");
        c.args(["-c", script]);
        c
    }

    #[test]
    fn a_call_never_outlives_its_time() {
        use std::time::{Duration, Instant};
        // Stdin goes in, stdout and stderr come back apart.
        let r = run_child(&Ctx::new(), sh("cat; echo oops >&2; exit 3"), b"manifest", 1 << 20).unwrap();
        assert_eq!((r.status.code(), r.out.as_slice(), r.err.as_slice()), (Some(3), &b"manifest"[..], &b"oops\n"[..]));
        // A coordinator that does not answer: killed when the time is up,
        // and the error says so.
        let start = Instant::now();
        let e = run_child(&Ctx::new().with_timeout(Duration::from_millis(200)), sh("sleep 30"), b"", 1 << 20).err().unwrap();
        assert!(e.is(Kind::DeadlineExceeded) && e.to_string().contains("did not answer in time"), "{e}");
        assert!(start.elapsed() < Duration::from_secs(3), "{:?}", start.elapsed());
        // The screen closed: cancelled at once, also while stdin is still
        // being written.
        let ctx = Ctx::new();
        let c2 = ctx.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            c2.cancel();
        });
        let start = Instant::now();
        let e = run_child(&ctx, sh("sleep 30"), &vec![b'x'; 4 << 20], 1 << 20).err().unwrap();
        assert!(e.is_canceled() && start.elapsed() < Duration::from_secs(3), "{e} {:?}", start.elapsed());
        // An answer that never ends.
        let e = run_child(&Ctx::new(), sh("yes"), b"", 1 << 20).err().unwrap();
        assert!(e.to_string().contains("longer than 1 MiB"), "{e}");
        // Done before it starts: nothing runs.
        let done = Ctx::new();
        done.cancel();
        let c = SshCluster { host: "192.0.2.1".into(), port: String::new(), user: "admin".into(), known_hosts: "/dev/null".into() };
        assert!(c.kubectl(&done, &["get", "pods"], "").unwrap_err().is_canceled());
    }

    #[test]
    fn the_shared_connection() {
        let c = SshCluster { host: "192.168.1.50".into(), port: "22".into(), user: "admin".into(), known_hosts: "a/known_hosts".into() };
        let o = c.options().join(" ");
        for want in ["StrictHostKeyChecking=yes", "BatchMode=yes", "ServerAliveInterval=5", "UserKnownHostsFile=a/known_hosts"] {
            assert!(o.contains(want), "{o}");
        }
        assert_eq!(c.control_path(None), None, "without a private runtime directory every call connects");
        assert_eq!(c.control_path(Some("".as_ref())), None);
        let run = std::path::Path::new("/run/user/1000/dryserver");
        let p = crate::fsx::socket_in(run, &c.socket_name()).unwrap();
        assert!(p.starts_with("ControlPath=/run/user/1000/dryserver/k3s-%C-"), "{p}");
        // Another stick's pinned key file: another connection.
        let name = c.socket_name();
        let other = SshCluster { known_hosts: "b/known_hosts".into(), ..c };
        assert_ne!(other.socket_name(), name);
        // The runtime directory is used through a directory of ours
        // (fsx::socket_dir; the temporary directory may be too deep for a
        // socket).
        let t = crate::testutil::TempDir::new();
        let ours = crate::fsx::socket_dir(t.path(), crate::fsx::geteuid()).unwrap();
        assert_eq!(other.control_path(Some(t.path().as_os_str())), crate::fsx::socket_in(&ours, &other.socket_name()));
        // Without a safe directory, kubectl connects by itself.
        std::fs::set_permissions(&ours, std::os::unix::fs::PermissionsExt::from_mode(0o750)).unwrap();
        assert_eq!(other.control_path(Some(t.path().as_os_str())), None);
        // Which cut-off calls take the shared connection down.
        use std::time::Duration;
        assert!(hung(&Error::with_kind(Kind::DeadlineExceeded, "late"), Duration::from_secs(15)));
        assert!(hung(&Error::canceled(), Duration::from_secs(5)), "quit during a call that hangs");
        assert!(!hung(&Error::canceled(), Duration::from_millis(200)), "quit during a quick refresh");
        assert!(!hung(&Error::new("too long"), Duration::from_secs(5)));
    }
}
