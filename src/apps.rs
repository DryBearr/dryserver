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

impl App {
    /// Everything here ends up in YAML and in command lines: only plain
    /// names pass.
    pub fn validate(&self) -> Result<()> {
        if !registry::valid_name(&self.name) || self.name.len() > 40 {
            bail!("name: lowercase letters, digits and -, at most 40");
        }
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
# {name} takes connections on its port from the ingress and from the
# other apps.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {name}
  namespace: {NAMESPACE}
  labels:
    app: {name}
spec:
  podSelector:
    matchLabels:
      app: {name}
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
  name: {name}
  namespace: {NAMESPACE}
  labels:
    app: {name}
spec:
  replicas: {copies}
  selector:
    matchLabels:
      app: {name}
  template:
    metadata:
      labels:
        app: {name}
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
              app: {name}
      containers:
        - name: {name}
          image: "{image}"
          ports:
            - containerPort: {port}
          securityContext:
            allowPrivilegeEscalation: false
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
---
apiVersion: v1
kind: Service
metadata:
  name: {name}
  namespace: {NAMESPACE}
  labels:
    app: {name}
spec:
  selector:
    app: {name}
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
  name: {name}
  namespace: {NAMESPACE}
  labels:
    app: {name}
spec:
  rules:
    - host: "{host}"
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: {name}
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
      containers:
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

/// Starts the tunnel, or gives it another token.
pub fn connect_tunnel(c: &dyn Cluster, token: &str) -> Result<()> {
    let manifest = tunnel_manifest(token)?;
    let out = c.kubectl(&["apply", "-f", "-"], &manifest)?;
    // A changed token only reaches pods that start after it. (A new
    // tunnel starts its pods with the token it was made with.)
    if out.lines().any(|l| l.trim() == "secret/tunnel configured") {
        c.kubectl(&["-n", TUNNEL_NAMESPACE, "rollout", "restart", "deployment/cloudflared"], "")?;
    }
    Ok(())
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
        let out = child.wait_with_output().map_err(|e| Error::from(e).wrap("ssh"))?;
        let _ = writer.join();
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
        let msg: String = String::from_utf8_lossy(&out.stderr).chars().filter(|c| !c.is_control() || *c == '\n').take(400).collect();
        if out.status.code() == Some(255) {
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
    c.kubectl(&["apply", "-f", "-"], &manifest).map(|_| ())
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
            "image: \"ghcr.io/me/blog:v2\"",
            "containerPort: 8080",
            "automountServiceAccountToken: false",
            "allowPrivilegeEscalation: false",
            "targetPort: 8080",
            "kind: Ingress",
            "- host: \"blog.example.com\"",
        ] {
            assert!(y.contains(want), "manifest missing {want:?}:\n{y}");
        }
        assert_eq!(y.matches("\n---\n").count(), 5);
        // Without a public name there is no way in from outside.
        let inside = App { host: String::new(), ..app() }.manifest().unwrap();
        assert!(!inside.contains("kind: Ingress") && inside.matches("\n---\n").count() == 4);
    }

    #[test]
    fn only_plain_values_reach_the_manifest() {
        let bad: Vec<(App, &str)> = vec![
            (App { name: "Blog".into(), ..app() }, "name"),
            (App { name: "a\nkind: Secret".into(), ..app() }, "name"),
            (App { name: "x".repeat(41), ..app() }, "name"),
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
            &format!("token: \"{token}\""),
            "image: \"docker.io/cloudflare/cloudflared:2026.11.1@sha256:",
            "args: [\"tunnel\", \"--no-autoupdate\", \"--metrics\", \"0.0.0.0:2000\", \"run\"]",
            "path: /ready",
            "topologyKey: kubernetes.io/hostname",
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
        let c = Fake::default();
        // A new tunnel: its pods start with the token.
        *c.applied.lock().unwrap() = "namespace/edge created\nsecret/tunnel created\ndeployment.apps/cloudflared created\n".into();
        connect_tunnel(&c, token).unwrap();
        assert_eq!(c.calls.lock().unwrap().iter().map(|(a, _)| a.as_str()).collect::<Vec<_>>(), vec!["apply -f -"]);
        // The same token again changes nothing.
        *c.applied.lock().unwrap() = "namespace/edge unchanged\nsecret/tunnel unchanged\ndeployment.apps/cloudflared unchanged\n".into();
        connect_tunnel(&c, token).unwrap();
        assert_eq!(c.calls.lock().unwrap().len(), 2);
        // Another token reaches only pods that start after it.
        *c.applied.lock().unwrap() = "namespace/edge unchanged\nsecret/tunnel configured\ndeployment.apps/cloudflared unchanged\n".into();
        connect_tunnel(&c, token).unwrap();
        assert_eq!(
            c.calls.lock().unwrap().last().unwrap().0,
            "-n edge rollout restart deployment/cloudflared",
            "a new token needs new pods"
        );
        remove_tunnel(&c).unwrap();
        assert_eq!(c.calls.lock().unwrap().last().unwrap().0, "-n edge delete deployment/cloudflared secret/tunnel --ignore-not-found");
    }
}
