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
    /// The port the container listens on.
    pub port: u16,
    /// Public host name routed to it; "" keeps it inside the cluster.
    pub host: String,
    /// The way in from outside its host name comes through
    /// (entrance::IDS). Only matters with a host name.
    pub entrance: String,
    pub copies: u32,
}

pub fn valid_image(s: &str) -> Result<()> {
    let ok = !s.is_empty()
        && s.len() <= 255
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'/' | b':' | b'@' | b'-'));
    if ok { Ok(()) } else { Err("an image name like nginx:1.27 or ghcr.io/you/app:v1 (lowercase, no spaces)".into()) }
}

/// A DNS name: labels of letters, digits and -, joined by dots.
pub fn valid_host(s: &str) -> Result<()> {
    if s.is_empty() {
        return Ok(());
    }
    let ok = s.len() <= 253 && s.contains('.') && s.split('.').all(registry::valid_name);
    if ok { Ok(()) } else { Err("a host name like app.example.com, or empty".into()) }
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
        if self.port == 0 {
            bail!("port: 1 to 65535");
        }
        valid_host(&self.host).map_err(|e| e.wrap("public host name"))?;
        if !self.host.is_empty() {
            entrance::valid_id(&self.entrance).map_err(|e| e.wrap("entrance"))?;
        }
        if !(1..=20).contains(&self.copies) {
            bail!("copies: 1 to 20");
        }
        Ok(())
    }

    /// The Kubernetes objects for this app.
    pub fn manifest(&self) -> Result<String> {
        self.validate()?;
        let App { name, image, port, host, entrance, copies } = self;
        let mark = entrance::ANNOTATION;
        let tolerations = tolerations();
        let mut y = format!(
            r#"apiVersion: v1
kind: Namespace
metadata:
  name: {NAMESPACE}
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/warn: restricted
---
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
# {name} takes connections on its port from the ingress and from the
# other apps.
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
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              app.kubernetes.io/name: traefik
        - podSelector: {{}}
      ports:
        - port: {port}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: "{name}"
  namespace: {NAMESPACE}
  labels:
    app: "{name}"
spec:
  replicas: {copies}
  selector:
    matchLabels:
      app: "{name}"
  template:
    metadata:
      labels:
        app: "{name}"
    spec:
      automountServiceAccountToken: false
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
          ports:
            - containerPort: {port}
          securityContext:
            allowPrivilegeEscalation: false
            # No raw packets: a taken-over app cannot pose as another
            # address on the pod network.
            capabilities:
              drop: ["NET_RAW"]
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
---
apiVersion: v1
kind: Service
metadata:
  name: "{name}"
  namespace: {NAMESPACE}
  labels:
    app: "{name}"
spec:
  selector:
    app: "{name}"
  ports:
    - port: 80
      targetPort: {port}
"#
        );
        if !host.is_empty() {
            y += &format!(
                r#"---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: "{name}"
  namespace: {NAMESPACE}
  labels:
    app: "{name}"
  annotations:
    {mark}: "{entrance}"
spec:
  rules:
    - host: "{host}"
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: "{name}"
                port:
                  number: 80
"#
            );
        }
        Ok(y)
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
    pub host: String,
    /// The entrance its host name comes through; "?" when its Ingress
    /// names one this dryserver does not know.
    pub entrance: String,
    /// The servers its pods are on.
    pub nodes: Vec<String>,
}

/// A way to run kubectl on the coordinator. The screens call it from a
/// worker thread; ctx carries the time limit, and the cancel when the
/// screen closes.
pub trait Cluster: Send + Sync {
    fn kubectl(&self, ctx: &Ctx, args: &[&str], stdin: &str) -> Result<String>;
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

impl Cluster for SshCluster {
    fn kubectl(&self, ctx: &Ctx, args: &[&str], stdin: &str) -> Result<String> {
        if !self.known_hosts.exists() {
            bail!("this computer has not met the coordinator yet; run ./dryserver approve first");
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
        cmd.arg(&target).args(["k3s", "kubectl", "--request-timeout=60s"]).args(args);
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
        if ran.status.code() == Some(255) {
            bail!("cannot log in to the coordinator at {} with your SSH key: {}", self.host, msg.trim());
        }
        Err(errf!("kubectl: {}", msg.trim()))
    }
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
        let image = it.spec["template"]["spec"]["containers"][0]["image"].as_str().unwrap_or("").to_string();
        o.apps.push(Running {
            name: it.metadata.name.clone(),
            image: if valid_image(&image).is_ok() { image } else { "?".into() },
            ready,
            copies,
            entrance: entrance::DEFAULT.into(),
            ..Running::default()
        });
    }
    for it in l.items.iter().filter(|i| i.metadata.namespace == NAMESPACE) {
        let Some(app) = it.metadata.labels.get("app").and_then(|n| o.apps.iter_mut().find(|a| a.name == *n)) else { continue };
        match it.kind.as_str() {
            "Ingress" => {
                let host = it.spec["rules"][0]["host"].as_str().unwrap_or("");
                if !host.is_empty() && valid_host(host).is_ok() {
                    app.host = host.to_string();
                }
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

pub fn deploy(ctx: &Ctx, c: &dyn Cluster, app: &App) -> Result<()> {
    let manifest = app.manifest()?;
    c.kubectl(ctx, &["apply", "-f", "-"], &manifest)?;
    if app.host.is_empty() {
        // Started again without a public name: the old way in goes.
        c.kubectl(ctx, &["-n", NAMESPACE, "delete", "ingress", &app.name, "--ignore-not-found"], "")?;
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
    c.kubectl(ctx, &["-n", NAMESPACE, "delete", "deployment,service,ingress,networkpolicy", "-l", &sel, "--ignore-not-found"], "")
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
            host: "blog.example.com".into(),
            entrance: crate::entrance::CLOUDFLARE.into(),
            copies: 2,
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
            "  annotations:\n    dryserver/entrance: \"cloudflare\"\nspec:\n  rules:\n    - host: \"blog.example.com\"",
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
        let inside = App { host: String::new(), ..app() }.manifest().unwrap();
        assert!(!inside.contains("kind: Ingress") && inside.matches("\n---\n").count() == 5);
        // Another entrance is another annotation; without a public name
        // the entrance does not matter.
        let vps = App { entrance: "vps".into(), ..app() }.manifest().unwrap();
        assert!(vps.contains("dryserver/entrance: \"vps\""), "{vps}");
        App { host: String::new(), entrance: String::new(), ..app() }.manifest().unwrap();
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
            (App { port: 0, ..app() }, "port"),
            (App { host: "blog".into(), ..app() }, "public host name"),
            (App { host: "a b.example.com".into(), ..app() }, "public host name"),
            (App { host: "x.example.com\"\n".into(), ..app() }, "public host name"),
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
      {"kind":"Deployment","metadata":{"name":"blog","namespace":"apps","labels":{"app":"blog"}},"spec":{"replicas":2,"template":{"spec":{"containers":[{"image":"ghcr.io/me/blog:v2"}]}}},"status":{"readyReplicas":1}},
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
                    host: String::new(),
                    entrance: "?".into(),
                    nodes: vec![]
                },
                // No annotation: Cloudflare, as before entrances.
                Running {
                    name: "blog".into(),
                    image: "ghcr.io/me/blog:v2".into(),
                    ready: 1,
                    copies: 2,
                    host: "blog.example.com".into(),
                    entrance: "cloudflare".into(),
                    nodes: vec!["node-a".into(), "node-b".into()]
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
        deploy(&Ctx::new(), &c, &App { host: String::new(), ..app() }).unwrap();
        assert_eq!(c.calls.lock().unwrap().last().unwrap().0, "-n apps delete ingress blog --ignore-not-found");

        remove(&Ctx::new(), &c, "blog").unwrap();
        assert_eq!(
            c.calls.lock().unwrap().last().unwrap().0,
            "-n apps delete deployment,service,ingress,networkpolicy -l app=blog --ignore-not-found"
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
