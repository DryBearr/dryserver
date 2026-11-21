//! The Cloudflare Tunnel entrance: cloudflared as pods in the cluster. It
//! dials out to Cloudflare, so no machine opens a port; Cloudflare sends
//! what arrives for your host names through it to the ingress.
//!
//! The tunnel's token is saved on the desktop in secrets/. The host names
//! are routed in the Cloudflare dashboard, each pointed at TARGET.

use std::path::PathBuf;

use super::{Entrance, Health, NAMESPACE, Report, State, Traffic, Want};
use crate::apps::{self, Cluster, Overview};
use crate::ctx::Ctx;
use crate::err::Result;
use crate::registry;

/// One pinned cloudflared release: the tag for people, the digest for the
/// machine (the image index, so it fits every CPU type). A changed image
/// under the same tag is refused.
pub const IMAGE: &str =
    "docker.io/cloudflare/cloudflared:2026.11.1@sha256:e613aadbc2d9511785d2e67a86b0c8ac18dd63a3f9af0d06faf04cbfdcb35f2d";
/// The admin puts the tunnel's token here, in secrets/.
pub const TOKEN_FILE: &str = "cloudflare_tunnel_token";
/// What the tunnel's public host names point at: the cluster's ingress.
pub const TARGET: &str = "http://traefik.kube-system.svc.cluster.local:80";

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

/// Changes with the token and says nothing about it: the pods carry it,
/// so Kubernetes starts new pods when the token changes, and only then.
pub fn token_mark(token: &str) -> String {
    crate::fsx::hex(&registry::hmac_sha256(b"dryserver-tunnel-token", token.trim().as_bytes())[..8])
}

/// cloudflared as pods: the only way in from outside.
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
    let tolerations = apps::tolerations();
    let mark = token_mark(token);
    let (dns_rule, private, ingress_port) = (apps::DNS_RULE, apps::PRIVATE_RANGES, apps::INGRESS_PORT);
    Ok(format!(
        r#"apiVersion: v1
kind: Namespace
metadata:
  name: {NAMESPACE}
  labels:
    pod-security.kubernetes.io/enforce: restricted
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: {NAMESPACE}
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
  namespace: {NAMESPACE}
spec:
  podSelector: {{}}
  policyTypes: [Egress]
  egress:
{dns_rule}    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              app.kubernetes.io/name: traefik
      ports:
        - port: {ingress_port}
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except: {private}
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
  namespace: {NAMESPACE}
stringData:
  token: "{token}"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cloudflared
  namespace: {NAMESPACE}
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
          image: "{IMAGE}"
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
pub fn connect_tunnel(ctx: &Ctx, c: &dyn Cluster, token: &str) -> Result<()> {
    let manifest = tunnel_manifest(token)?;
    c.kubectl(ctx, &["apply", "-f", "-"], &manifest).map(|_| ())
}

/// Closes the way in from outside. The apps keep running.
pub fn remove_tunnel(ctx: &Ctx, c: &dyn Cluster) -> Result<()> {
    c.kubectl(ctx, &["-n", NAMESPACE, "delete", "deployment/cloudflared", "secret/tunnel", "--ignore-not-found"], "").map(|_| ())
}

/// The tunnel as the cluster runs it: copies ready and wanted.
pub fn tunnel_state(tunnel: Option<(u32, u32)>) -> State {
    let (health, summary) = match tunnel {
        None => (Health::NotSetUp, "not set up".to_string()),
        Some((ready, want)) if ready > 0 && ready == want => (Health::Up, format!("connected, {ready} of {want} copies")),
        Some((0, want)) => (Health::Down, format!("not connected, 0 of {want} copies (wrong token, or no way out to Cloudflare)")),
        Some((ready, want)) => (Health::Partly, format!("connected with {ready} of {want} copies")),
    };
    State { health, summary, notes: Vec::new() }
}

/// The Cloudflare entrance of this desktop.
pub struct Cloudflare {
    /// Where the admin saves the tunnel's token (in secrets/).
    pub token_file: PathBuf,
}

impl Cloudflare {
    /// The token the admin saved, checked.
    pub fn saved_token(&self) -> Result<String> {
        let text = std::fs::read_to_string(&self.token_file).map_err(|_| {
            crate::errf!(
                "No tunnel token yet. In the Cloudflare dashboard (Zero Trust, Networks, Tunnels) create a tunnel\nand save its token as {}. Then press o again.",
                self.token_file.display()
            )
        })?;
        tunnel_token(&text).map_err(|e| e.wrap(self.token_file.display()))
    }
}

impl Entrance for Cloudflare {
    fn id(&self) -> &'static str {
        super::CLOUDFLARE
    }
    fn title(&self) -> &'static str {
        "Cloudflare Tunnel"
    }
    fn carries(&self) -> &'static [Traffic] {
        &[Traffic::Web]
    }
    /// Always: an app may pick it before the tunnel runs, as before.
    fn ready(&self) -> bool {
        true
    }
    fn state(&self, _: &Ctx, seen: &Overview) -> State {
        tunnel_state(seen.tunnel)
    }
    fn open_question(&self, seen: &Overview) -> Result<String> {
        self.saved_token()?;
        let what = if seen.tunnel.is_some() { "Give the tunnel the token from" } else { "Open the tunnel with the token from" };
        Ok(format!(
            "{what} {}? Cloudflare then sends what arrives for your public host names to the ingress. y to confirm",
            self.token_file.display()
        ))
    }
    fn open(&self, ctx: &Ctx, c: &dyn Cluster) -> Result<String> {
        connect_tunnel(ctx, c, &self.saved_token()?)?;
        Ok(format!("Tunnel starting. In the Cloudflare dashboard, point each public host name at {TARGET}"))
    }
    /// Without the API the host names are routed in the dashboard: there
    /// is nothing to change from here.
    fn sync(&self, _: &Ctx, _: &dyn Cluster, _: &Overview, want: &Want, _: bool) -> Result<Report> {
        let mut r = Report::default();
        if !want.names.is_empty() {
            r.notes.push(format!(
                "In the Cloudflare dashboard (Zero Trust, Networks, Tunnels, your tunnel, Public Hostname) point each of {} at {TARGET}",
                want.names.iter().map(|n| n.host.as_str()).collect::<Vec<_>>().join(", ")
            ));
        }
        Ok(r)
    }
    fn close(&self, ctx: &Ctx, c: &dyn Cluster) -> Result<()> {
        remove_tunnel(ctx, c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apps::tests::Fake;

    pub const TOKEN: &str = "eyJhIjoiMTIzNDU2Nzg5MGFiY2RlZiIsInQiOiJhYmNkZWYiLCJzIjoiWldGemVTQjBieUJ6WldVPSJ9";

    #[test]
    fn tunnel() {
        let token = TOKEN;
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
        apps::valid_image(IMAGE).unwrap();
        // The pods carry a mark of the token: another token is another
        // pod template, so Kubernetes starts new pods by itself. The mark
        // gives the token away to nobody.
        let mark = |y: &str| y.lines().find(|l| l.contains("dryserver/token-mark")).unwrap().to_string();
        let other = tunnel_manifest(&token.replace("eyJh", "eyJi")).unwrap();
        assert_eq!(mark(&y), mark(&tunnel_manifest(token).unwrap()));
        assert_ne!(mark(&y), mark(&other));
        assert!(mark(&y).len() < 60 && !mark(&y).contains(&token[..12]), "{}", mark(&y));
        assert!(mark(&y).contains(&token_mark(token)));
        let c = Fake::default();
        connect_tunnel(&Ctx::new(), &c, token).unwrap();
        assert_eq!(c.calls.lock().unwrap().iter().map(|(a, _)| a.as_str()).collect::<Vec<_>>(), vec!["apply -f -"]);
        remove_tunnel(&Ctx::new(), &c).unwrap();
        assert_eq!(c.calls.lock().unwrap().last().unwrap().0, "-n edge delete deployment/cloudflared secret/tunnel --ignore-not-found");
    }

    #[test]
    fn what_the_screens_say() {
        assert_eq!(tunnel_state(None).health, Health::NotSetUp);
        assert_eq!(tunnel_state(Some((2, 2))).summary, "connected, 2 of 2 copies");
        assert_eq!(tunnel_state(Some((1, 2))).health, Health::Partly);
        assert!(tunnel_state(Some((0, 2))).summary.contains("wrong token, or no way out to Cloudflare"));
        let dir = crate::testutil::TempDir::new();
        let cf = Cloudflare { token_file: dir.join(TOKEN_FILE) };
        assert!(cf.saved_token().unwrap_err().to_string().contains("No tunnel token yet"));
        std::fs::write(dir.join(TOKEN_FILE), "my password").unwrap();
        assert!(cf.saved_token().unwrap_err().to_string().contains("not a tunnel token"));
        std::fs::write(dir.join(TOKEN_FILE), format!("cloudflared service install {TOKEN}\n")).unwrap();
        assert_eq!(cf.saved_token().unwrap(), TOKEN);
        // Without the API, the names are the admin's to route.
        let want = Want { names: vec![super::super::Name { host: "blog.example.com".into(), app: "blog".into() }], ..Want::default() };
        let r = cf.sync(&Ctx::new(), &Fake::default(), &Overview::default(), &want, true).unwrap();
        assert!(r.changes.is_empty() && r.notes[0].contains("point each of blog.example.com at http://traefik"), "{r:?}");
    }
}
