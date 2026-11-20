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
//!   What comes in from outside reaches the ingress through the tunnel;
//! - containers may not gain privileges and get no cluster credentials.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde::Deserialize;

use crate::err::{Error, Result};
use crate::registry;
use crate::{bail, errf};

pub const NAMESPACE: &str = "apps";
/// Where the way in from outside lives.
pub const TUNNEL_NAMESPACE: &str = "edge";
/// Where the ingress pods take plain HTTP (Traefik's "web" entry; the
/// service's port 80 leads there). Its other ports are its own business.
const INGRESS_PORT: u16 = 8000;
/// One pinned cloudflared release: the tag for people, the digest for the
/// machine (the image index, so it fits every CPU type). A changed image
/// under the same tag is refused.
pub const TUNNEL_IMAGE: &str =
    "docker.io/cloudflare/cloudflared:2026.11.1@sha256:e613aadbc2d9511785d2e67a86b0c8ac18dd63a3f9af0d06faf04cbfdcb35f2d";
/// The admin puts the tunnel's token here, in secrets/.
pub const TUNNEL_TOKEN_FILE: &str = "cloudflare_tunnel_token";
/// What the tunnel's public host names point at, in the Cloudflare
/// dashboard: the cluster's ingress.
pub const TUNNEL_TARGET: &str = "http://traefik.kube-system.svc.cluster.local:80";

/// Addresses that are never "the internet": every private network, so
/// the machines, the mesh and the home network whatever their numbers.
const PRIVATE_RANGES: &str = "[10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16]";

/// How long a pod stays assigned to a server that stopped answering
/// before the cluster starts it elsewhere. Kubernetes waits 5 minutes by
/// itself; a dead or cut machine should cost about a minute.
const MOVE_AFTER_SECONDS: u32 = 30;

/// Pod spec lines: leave a dead server soon.
fn tolerations() -> String {
    let mut y = String::from("      tolerations:\n");
    for taint in ["unreachable", "not-ready"] {
        y += &format!(
            "        - key: node.kubernetes.io/{taint}\n          operator: Exists\n          effect: NoExecute\n          tolerationSeconds: {MOVE_AFTER_SECONDS}\n"
        );
    }
    y
}

/// The egress rule that lets pods ask the cluster's DNS.
const DNS_RULE: &str = r#"    - to:
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
        if !(1..=20).contains(&self.copies) {
            bail!("copies: 1 to 20");
        }
        Ok(())
    }

    /// The Kubernetes objects for this app.
    pub fn manifest(&self) -> Result<String> {
        self.validate()?;
        let App { name, image, port, host, copies } = self;
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

/// The token from what the admin saved. The dashboard shows it inside a
/// command ("cloudflared service install eyJ..."); pasting that whole
/// line works too.
pub fn tunnel_token(text: &str) -> Result<String> {
    let token = text.split_whitespace().last().unwrap_or("");
    valid_tunnel_token(token)?;
    Ok(token.to_string())
}

/// A Cloudflare Tunnel token: base64, nothing else.
pub fn valid_tunnel_token(t: &str) -> Result<()> {
    let ok =
        (40..=4096).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'));
    if ok { Ok(()) } else { Err("not a tunnel token (copy the long token from the tunnel's page in the Cloudflare dashboard)".into()) }
}

/// cloudflared as pods: the only way in from outside. It dials out to
/// Cloudflare, so no machine opens a port; Cloudflare sends what arrives
/// for your host names through it to the ingress.
///
/// - Namespace "edge" with the strictest pod security level; nothing may
///   connect to these pods.
/// - The token is a Secret (encrypted in the cluster's database).
/// - Runs as a plain user, read-only, with no privileges and no cluster
///   credentials. Two copies on different servers, so one can die.
/// - A copy counts as running only while it holds a connection to
///   Cloudflare (cloudflared's own /ready answer).
pub fn tunnel_manifest(token: &str) -> Result<String> {
    let token = token.trim();
    valid_tunnel_token(token)?;
    let tolerations = tolerations();
    // Changes with the token and says nothing about it: Kubernetes starts
    // new pods when the pod template changes, and only then.
    let mark = crate::fsx::hex(&registry::hmac_sha256(b"dryserver-tunnel-token", token.as_bytes())[..8]);
    Ok(format!(
        r#"apiVersion: v1
kind: Namespace
metadata:
  name: {TUNNEL_NAMESPACE}
  labels:
    pod-security.kubernetes.io/enforce: restricted
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: {TUNNEL_NAMESPACE}
spec:
  podSelector: {{}}
  policyTypes: [Ingress]
---
# The tunnel may reach Cloudflare, the cluster's DNS and the ingress.
# Nothing else: it is the one thing here that talks to the internet all
# day.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: outgoing
  namespace: {TUNNEL_NAMESPACE}
spec:
  podSelector: {{}}
  policyTypes: [Egress]
  egress:
{DNS_RULE}    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              app.kubernetes.io/name: traefik
      ports:
        - port: {INGRESS_PORT}
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except: {PRIVATE_RANGES}
      ports:
        - port: 7844
          protocol: TCP
        - port: 7844
          protocol: UDP
---
apiVersion: v1
kind: Secret
metadata:
  name: tunnel
  namespace: {TUNNEL_NAMESPACE}
stringData:
  token: "{token}"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cloudflared
  namespace: {TUNNEL_NAMESPACE}
  labels:
    app: cloudflared
spec:
  replicas: 2
  selector:
    matchLabels:
      app: cloudflared
  template:
    metadata:
      labels:
        app: cloudflared
      annotations:
        dryserver/token-mark: "{mark}"
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        seccompProfile:
          type: RuntimeDefault
      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: kubernetes.io/hostname
          whenUnsatisfiable: ScheduleAnyway
          labelSelector:
            matchLabels:
              app: cloudflared
{tolerations}      containers:
        - name: cloudflared
          image: "{TUNNEL_IMAGE}"
          args: ["tunnel", "--no-autoupdate", "--metrics", "0.0.0.0:2000", "run"]
          readinessProbe:
            httpGet:
              path: /ready
              port: 2000
            periodSeconds: 10
          env:
            - name: TUNNEL_TOKEN
              valueFrom:
                secretKeyRef:
                  name: tunnel
                  key: token
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            requests:
              cpu: 20m
              memory: 32Mi
"#
    ))
}

/// Starts the tunnel, or gives it another token. The pods carry a mark
/// made from the token, so another token starts new pods by itself.
pub fn connect_tunnel(c: &dyn Cluster, token: &str) -> Result<()> {
    let manifest = tunnel_manifest(token)?;
    c.kubectl(&["apply", "-f", "-"], &manifest).map(|_| ())
}

/// Closes the way in from outside. The apps keep running.
pub fn remove_tunnel(c: &dyn Cluster) -> Result<()> {
    c.kubectl(&["-n", TUNNEL_NAMESPACE, "delete", "deployment/cloudflared", "secret/tunnel", "--ignore-not-found"], "").map(|_| ())
}

/// The cluster as the apps screen shows it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Overview {
    pub apps: Vec<Running>,
    /// Tunnel pods ready and wanted; None when no tunnel is set up.
    pub tunnel: Option<(u32, u32)>,
}

/// An app as the cluster has it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Running {
    pub name: String,
    pub image: String,
    pub ready: u32,
    pub copies: u32,
    pub host: String,
    /// The servers its pods are on.
    pub nodes: Vec<String>,
}

/// A way to run kubectl on the coordinator.
pub trait Cluster {
    fn kubectl(&self, args: &[&str], stdin: &str) -> Result<String>;
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

impl Cluster for SshCluster {
    fn kubectl(&self, args: &[&str], stdin: &str) -> Result<String> {
        use std::io::Write;
        if !self.known_hosts.exists() {
            bail!("this computer has not met the coordinator yet; run ./dryserver approve first");
        }
        let port = if self.port.is_empty() { "22" } else { &self.port };
        let mut child = Command::new("ssh")
            .args(["-p", port])
            .args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=yes"])
            .args(["-o", "GlobalKnownHostsFile=/dev/null", "-o", "ForwardAgent=no", "-o", "LogLevel=ERROR"])
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", self.known_hosts.display()))
            .arg(format!("{}@{}", self.user, self.host))
            .args(["k3s", "kubectl"])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::from(e).wrap("ssh"))?;
        let mut pipe = child.stdin.take().ok_or_else(|| Error::new("ssh: no stdin"))?;
        let text = stdin.to_string();
        let writer = std::thread::spawn(move || {
            let _ = pipe.write_all(text.as_bytes());
        });
        // The coordinator's answer is kept up to a limit; one that goes on
        // and on ends the call.
        let over = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reader = |mut pipe: Box<dyn std::io::Read + Send>, limit: usize| {
            let over = over.clone();
            std::thread::spawn(move || {
                let mut kept = Vec::new();
                let mut buf = [0u8; 65536];
                loop {
                    match pipe.read(&mut buf) {
                        Ok(0) | Err(_) => return kept,
                        Ok(n) if kept.len() + n > limit => {
                            over.store(true, std::sync::atomic::Ordering::SeqCst);
                            return kept;
                        }
                        Ok(n) => kept.extend_from_slice(&buf[..n]),
                    }
                }
            })
        };
        let stdout = reader(Box::new(child.stdout.take().ok_or_else(|| Error::new("ssh: no stdout"))?), MAX_ANSWER);
        let stderr = reader(Box::new(child.stderr.take().ok_or_else(|| Error::new("ssh: no stderr"))?), 65536);
        let status = loop {
            if let Some(st) = child.try_wait().map_err(|e| Error::from(e).wrap("ssh"))? {
                break st;
            }
            if over.load(std::sync::atomic::Ordering::SeqCst) {
                let _ = child.kill();
                let _ = child.wait();
                bail!("the coordinator's answer is longer than {} MiB; stopped reading", MAX_ANSWER >> 20);
            }
            std::thread::sleep(std::time::Duration::from_millis(15));
        };
        let _ = writer.join();
        let (out, err) = (stdout.join().unwrap_or_default(), stderr.join().unwrap_or_default());
        if over.load(std::sync::atomic::Ordering::SeqCst) {
            bail!("the coordinator's answer is longer than {} MiB; stopped reading", MAX_ANSWER >> 20);
        }
        if status.success() {
            return Ok(String::from_utf8_lossy(&out).into_owned());
        }
        let msg: String = String::from_utf8_lossy(&err).chars().filter(|c| !c.is_control() || *c == '\n').take(400).collect();
        if status.code() == Some(255) {
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
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Item {
    kind: String,
    metadata: Meta,
    spec: serde_json::Value,
    status: serde_json::Value,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct List {
    items: Vec<Item>,
}

/// The apps and the tunnel, in one question to the cluster (each one is
/// an SSH login). Names and hosts come from the cluster; they are checked
/// before they are shown.
pub fn overview(c: &dyn Cluster) -> Result<Overview> {
    let out = c.kubectl(&["get", "deployments,ingresses,pods", "-A", "-l", "app", "-o", "json"], "")?;
    if out.trim().is_empty() {
        return Ok(Overview::default());
    }
    let l: List = serde_json::from_str(&out).map_err(|e| Error::from(e).wrap("kubectl output"))?;
    let mut o = Overview::default();
    for it in l.items.iter().filter(|i| i.kind == "Deployment") {
        let (ready, copies) = (it.status["readyReplicas"].as_u64().unwrap_or(0) as u32, it.spec["replicas"].as_u64().unwrap_or(0) as u32);
        if it.metadata.namespace == TUNNEL_NAMESPACE && it.metadata.name == "cloudflared" {
            o.tunnel = Some((ready, copies));
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

pub fn deploy(c: &dyn Cluster, app: &App) -> Result<()> {
    let manifest = app.manifest()?;
    c.kubectl(&["apply", "-f", "-"], &manifest)?;
    if app.host.is_empty() {
        // Started again without a public name: the old way in goes.
        c.kubectl(&["-n", NAMESPACE, "delete", "ingress", &app.name, "--ignore-not-found"], "")?;
    }
    Ok(())
}

/// Removes an app's objects. The namespace and its default-deny policy
/// stay.
pub fn remove(c: &dyn Cluster, name: &str) -> Result<()> {
    if !registry::valid_name(name) {
        bail!("not an app name");
    }
    let sel = format!("app={name}");
    c.kubectl(&["-n", NAMESPACE, "delete", "deployment,service,ingress,networkpolicy", "-l", &sel, "--ignore-not-found"], "").map(|_| ())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::sync::Mutex;

    pub fn app() -> App {
        App { name: "blog".into(), image: "ghcr.io/me/blog:v2".into(), port: 8080, host: "blog.example.com".into(), copies: 2 }
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
            "- host: \"blog.example.com\"",
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

    /// Records kubectl calls and answers "get" with a fixed listing.
    #[derive(Default)]
    pub struct Fake {
        pub calls: Mutex<Vec<(String, String)>>,
        pub listing: Mutex<String>,
        /// What "apply" prints.
        pub applied: Mutex<String>,
        pub fail: Mutex<Option<String>>,
    }

    impl Cluster for Fake {
        fn kubectl(&self, args: &[&str], stdin: &str) -> Result<String> {
            self.calls.lock().unwrap().push((args.join(" "), stdin.to_string()));
            if let Some(e) = self.fail.lock().unwrap().clone() {
                return Err(e.into());
            }
            Ok(if args.contains(&"get") {
                self.listing.lock().unwrap().clone()
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
      {"kind":"Deployment","metadata":{"name":"cloudflared","namespace":"edge","labels":{"app":"cloudflared"}},"spec":{"replicas":2},"status":{"readyReplicas":1}},
      {"kind":"Ingress","metadata":{"name":"blog","namespace":"apps","labels":{"app":"blog"}},"spec":{"rules":[{"host":"blog.example.com"}]}},
      {"kind":"Ingress","metadata":{"name":"api","namespace":"apps","labels":{"app":"api"}},"spec":{"rules":[{"host":"not a host"}]}},
      {"kind":"Ingress","metadata":{"name":"blog","namespace":"other","labels":{"app":"blog"}},"spec":{"rules":[{"host":"stolen.example.com"}]}},
      {"kind":"Pod","metadata":{"name":"blog-1","namespace":"apps","labels":{"app":"blog"}},"spec":{"nodeName":"node-a"}},
      {"kind":"Pod","metadata":{"name":"blog-2","namespace":"apps","labels":{"app":"blog"}},"spec":{"nodeName":"node-b"}},
      {"kind":"Pod","metadata":{"name":"blog-3","namespace":"apps","labels":{"app":"blog"}},"spec":{"nodeName":"node-a"}}
    ]}"#;

    #[test]
    fn list_deploy_remove() {
        let c = Fake::default();
        *c.listing.lock().unwrap() = LISTING.into();
        let o = overview(&c).unwrap();
        assert_eq!(o.tunnel, Some((1, 2)));
        assert_eq!(
            o.apps,
            vec![
                Running { name: "api".into(), image: "?".into(), ready: 0, copies: 1, host: String::new(), nodes: vec![] },
                Running {
                    name: "blog".into(),
                    image: "ghcr.io/me/blog:v2".into(),
                    ready: 1,
                    copies: 2,
                    host: "blog.example.com".into(),
                    nodes: vec!["node-a".into(), "node-b".into()]
                },
            ],
            "what the cluster says is checked before it is shown, and only the apps namespace counts"
        );
        assert_eq!(c.calls.lock().unwrap().len(), 1, "one question to the cluster per refresh");

        deploy(&c, &app()).unwrap();
        let (args, stdin) = c.calls.lock().unwrap().last().unwrap().clone();
        assert_eq!(args, "apply -f -");
        assert_eq!(stdin, app().manifest().unwrap());
        assert!(deploy(&c, &App { name: "no good".into(), ..app() }).is_err());
        // Started again without a public name: the old way in is taken away.
        deploy(&c, &App { host: String::new(), ..app() }).unwrap();
        assert_eq!(c.calls.lock().unwrap().last().unwrap().0, "-n apps delete ingress blog --ignore-not-found");

        remove(&c, "blog").unwrap();
        assert_eq!(
            c.calls.lock().unwrap().last().unwrap().0,
            "-n apps delete deployment,service,ingress,networkpolicy -l app=blog --ignore-not-found"
        );
        assert!(remove(&c, "blog -A").is_err(), "a name must not carry kubectl arguments");

        // An empty cluster is an empty list; an unreachable one an error.
        *c.listing.lock().unwrap() = r#"{"items":[]}"#.into();
        assert_eq!(overview(&c).unwrap(), Overview::default());
        *c.fail.lock().unwrap() = Some("connection refused".into());
        assert!(overview(&c).is_err());
    }

    #[test]
    fn tunnel() {
        let token = "eyJhIjoiMTIzNDU2Nzg5MGFiY2RlZiIsInQiOiJhYmNkZWYiLCJzIjoiWldGemVTQjBieUJ6WldVPSJ9";
        let y = tunnel_manifest(&format!("{token}\n")).unwrap();
        for want in [
            "name: edge\n  labels:\n    pod-security.kubernetes.io/enforce: restricted",
            "policyTypes: [Ingress]",
            "policyTypes: [Egress]",
            "app.kubernetes.io/name: traefik",
            "- port: 7844\n          protocol: UDP",
            "app.kubernetes.io/name: traefik\n      ports:\n        - port: 8000\n",
            &format!("token: \"{token}\""),
            "image: \"docker.io/cloudflare/cloudflared:2026.11.1@sha256:",
            "args: [\"tunnel\", \"--no-autoupdate\", \"--metrics\", \"0.0.0.0:2000\", \"run\"]",
            "path: /ready",
            "topologyKey: kubernetes.io/hostname",
            "tolerationSeconds: 30",
            "runAsNonRoot: true",
            "readOnlyRootFilesystem: true",
            "drop: [\"ALL\"]",
            "automountServiceAccountToken: false",
            "replicas: 2",
        ] {
            assert!(y.contains(want), "tunnel manifest missing {want:?}:\n{y}");
        }
        for bad in [
            "",
            "short",
            "has space in it aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "quote\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "line\nbreakaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: x",
        ] {
            assert!(tunnel_manifest(bad).is_err(), "{bad:?}");
        }
        // The dashboard's whole command line works as well as the bare token.
        assert_eq!(tunnel_token(&format!("sudo cloudflared service install {token}\n")).unwrap(), token);
        assert_eq!(tunnel_token(&format!("  {token}  ")).unwrap(), token);
        assert!(tunnel_token("").is_err() && tunnel_token("cloudflared service install").is_err());
        valid_image(TUNNEL_IMAGE).unwrap();
        // The pods carry a mark of the token: another token is another
        // pod template, so Kubernetes starts new pods by itself. The mark
        // gives the token away to nobody.
        let mark = |y: &str| y.lines().find(|l| l.contains("dryserver/token-mark")).unwrap().to_string();
        let other = tunnel_manifest(&token.replace("eyJh", "eyJi")).unwrap();
        assert_eq!(mark(&y), mark(&tunnel_manifest(token).unwrap()));
        assert_ne!(mark(&y), mark(&other));
        assert!(mark(&y).len() < 60 && !mark(&y).contains(&token[..12]), "{}", mark(&y));
        let c = Fake::default();
        connect_tunnel(&c, token).unwrap();
        assert_eq!(c.calls.lock().unwrap().iter().map(|(a, _)| a.as_str()).collect::<Vec<_>>(), vec!["apply -f -"]);
        remove_tunnel(&c).unwrap();
        assert_eq!(c.calls.lock().unwrap().last().unwrap().0, "-n edge delete deployment/cloudflared secret/tunnel --ignore-not-found");
    }
}
