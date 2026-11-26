//! The cluster's DNS on two machines. k3s runs CoreDNS as one copy, and
//! that copy may sit on the coordinator. When its machine dies no pod can
//! look up a name: the tunnel loses the ingress, apps lose each other.
//!
//! How, and why this way (k3s v1.37):
//!
//! - CoreDNS stays k3s's own. k3s writes its manifest (coredns.yaml) into
//!   the server's manifests directory at every start and applies it, with
//!   the image that k3s release ships and was tested with. An upgrade of
//!   k3s brings the new image by itself. A copy of our own (coredns.yaml.skip
//!   plus our own manifest, or `--disable coredns` plus our own deployment)
//!   would keep the image of the day it was written, also after an upgrade,
//!   and would have to fill in k3s's own values (the DNS address) itself.
//! - What dryserver adds are fields k3s's manifest does not set: the number
//!   of copies and where they prefer to run. k3s applies its manifest as a
//!   three-way merge that only touches the fields the manifest sets, so
//!   ours survive a restart and an upgrade. A timer sets them again anyway,
//!   for an upgrade that replaces the deployment.
//! - k3s's manifest already spreads copies over machines: at most one copy
//!   more on any machine than on any other. That never keeps a copy from
//!   running when there is one machine (both copies run there), and a dead
//!   machine at worst leaves a copy waiting until it is back. dryserver's
//!   own additions are preferences only: copies apart, and on servers
//!   rather than on the coordinator. With the coordinator down nothing in
//!   the cluster moves; a copy on a server keeps answering, one on the
//!   coordinator does not.
//! - A PodDisruptionBudget (a manifest of ours, beside k3s's) keeps one
//!   copy through a drain.
//! - Copies are only placed when they start. Copies that ended up together
//!   (the coordinator was the only machine at first, or a machine was
//!   down) are moved apart again by the timer: one copy per run, only when
//!   every copy is ready, and never a young one, so a move that did not
//!   help is not repeated every few minutes.
//! - Nothing else had to change for a copy on another machine: the apps'
//!   and the tunnel's NetworkPolicies allow DNS to CoreDNS's pods by their
//!   label, not by machine, and every machine's firewall passes the pod
//!   network over the mesh (tested in sysconf).

use std::collections::BTreeMap;
use std::io::Write;
use std::time::Duration;

use chrono::TimeDelta;
use serde::Deserialize;
use serde_json::Value;

use crate::ctx::Ctx;
use crate::err::Result;
use crate::gotime::Time;
use crate::runner::{Cmd, Runner};
use crate::{bail, registry};

/// k3s applies what it finds in this directory on the coordinator. Not
/// named coredns.yaml: k3s writes that one itself at every start.
pub const PDB_PATH: &str = "/var/lib/rancher/k3s/server/manifests/dryserver-coredns.yaml";

/// The label k3s gives the CoreDNS pods, its deployment and its service.
/// The NetworkPolicies of the apps and the tunnel allow DNS to pods with
/// this label, wherever they run.
pub const LABEL: &str = "k8s-app=kube-dns";

/// Copies of CoreDNS.
pub const COPIES: u32 = 2;

/// A copy younger than this is not moved: it was just placed, and moving
/// it again at once would only repeat what the scheduler decided.
pub const MIN_AGE_MINUTES: i64 = 10;

/// k3s's label on the machine that runs the control plane.
const CONTROL_PLANE: &str = "node-role.kubernetes.io/control-plane";

/// At least one copy stays through a drain or another planned eviction.
/// Our own file: k3s never rewrites it.
pub const PDB: &str = "# dryserver: the cluster's DNS keeps at least one copy through a drain.
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: coredns
  namespace: kube-system
spec:
  minAvailable: 1
  selector:
    matchLabels:
      k8s-app: kube-dns
";

/// Where the copies prefer to run: not together, and not on the
/// coordinator. Preferences only; never a rule that keeps a copy from
/// starting.
pub fn affinity() -> Value {
    serde_json::json!({
        "nodeAffinity": {
            "preferredDuringSchedulingIgnoredDuringExecution": [{
                "weight": 50,
                "preference": {"matchExpressions": [{"key": CONTROL_PLANE, "operator": "DoesNotExist"}]}
            }]
        },
        "podAntiAffinity": {
            "preferredDuringSchedulingIgnoredDuringExecution": [{
                "weight": 100,
                "podAffinityTerm": {
                    "labelSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
                    "topologyKey": "kubernetes.io/hostname"
                }
            }]
        }
    })
}

/// The patch that sets our fields on k3s's deployment: at least COPIES
/// copies (more if the admin chose more) and our preferences. Fields
/// k3s's manifest sets (image, tolerations, its spread rule) are not in
/// it.
pub fn patch(replicas: u32) -> String {
    serde_json::json!({"spec": {"replicas": replicas.max(COPIES), "template": {"spec": {"affinity": affinity()}}}}).to_string()
}

/// Whether have holds everything in want. The API server may add fields
/// of its own to what we set; those do not count as a difference, or the
/// patch would be sent again on every run.
fn holds(have: &Value, want: &Value) -> bool {
    match (have, want) {
        (Value::Object(h), Value::Object(w)) => w.iter().all(|(k, v)| h.get(k).is_some_and(|hv| holds(hv, v))),
        (Value::Array(h), Value::Array(w)) => h.len() == w.len() && h.iter().zip(w).all(|(a, b)| holds(a, b)),
        _ => have == want,
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Meta {
    pub name: String,
    pub labels: BTreeMap<String, String>,
    #[serde(rename = "creationTimestamp")]
    pub created: Option<Time>,
    #[serde(rename = "deletionTimestamp")]
    pub deleting: Option<Time>,
    pub generation: i64,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Toleration {
    pub key: String,
    pub operator: String,
    pub value: String,
    pub effect: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct PodSpec {
    pub node_name: String,
    pub affinity: Value,
    pub tolerations: Vec<Toleration>,
    pub node_selector: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Template {
    pub spec: PodSpec,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct DeploySpec {
    pub replicas: Option<u32>,
    pub template: Template,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct DeployStatus {
    pub observed_generation: i64,
    pub replicas: u32,
    pub updated_replicas: u32,
    pub ready_replicas: u32,
    pub available_replicas: u32,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Deployment {
    pub metadata: Meta,
    pub spec: DeploySpec,
    pub status: DeployStatus,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Condition {
    #[serde(rename = "type")]
    pub kind: String,
    pub status: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct PodStatus {
    pub phase: String,
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Pod {
    pub metadata: Meta,
    pub spec: PodSpec,
    pub status: PodStatus,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Taint {
    pub key: String,
    pub value: String,
    pub effect: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct NodeSpec {
    pub unschedulable: bool,
    pub taints: Vec<Taint>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct NodeStatus {
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Node {
    pub metadata: Meta,
    pub spec: NodeSpec,
    pub status: NodeStatus,
}

fn condition(cs: &[Condition], kind: &str) -> bool {
    cs.iter().any(|c| c.kind == kind && c.status == "True")
}

impl Pod {
    fn ready(&self) -> bool {
        self.status.phase == "Running" && condition(&self.status.conditions, "Ready")
    }

    fn old_enough(&self, now: Time) -> bool {
        self.metadata.created.is_some_and(|c| now.since(c) >= TimeDelta::minutes(MIN_AGE_MINUTES))
    }
}

/// Whether a pod with these tolerations may run despite the taint, by
/// Kubernetes's rules.
fn tolerates(tols: &[Toleration], t: &Taint) -> bool {
    tols.iter().any(|x| {
        let exists = x.operator == "Exists";
        let key = if x.key.is_empty() { exists } else { x.key == t.key };
        let value = exists || x.value == t.value;
        let effect = x.effect.is_empty() || x.effect == t.effect;
        key && value && effect
    })
}

impl Node {
    fn control_plane(&self) -> bool {
        self.metadata.labels.contains_key(CONTROL_PLANE)
    }

    /// Whether a new CoreDNS copy could start here now.
    fn takes(&self, pod: &PodSpec) -> bool {
        condition(&self.status.conditions, "Ready")
            && !self.spec.unschedulable
            && self
                .spec
                .taints
                .iter()
                .filter(|t| t.effect == "NoSchedule" || t.effect == "NoExecute")
                .all(|t| tolerates(&pod.tolerations, t))
            && pod.node_selector.iter().all(|(k, v)| self.metadata.labels.get(k) == Some(v))
    }
}

/// What the timer does in one run.
#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    /// Nothing now, and why.
    Wait(String),
    /// Set the number of copies and the preferences (patch).
    Patch,
    /// Move one copy: evict its pod, the scheduler places it again.
    Evict { pod: String, node: String, why: String },
    /// The copies are where they should be.
    Fine,
}

/// Decides the next step from what the cluster says. Pure, so every case
/// is tested without a cluster.
pub fn plan(d: Option<&Deployment>, pods: &[Pod], nodes: &[Node], now: Time) -> Step {
    let Some(d) = d else {
        return Step::Wait("k3s has not deployed CoreDNS yet".into());
    };
    let want = d.spec.replicas.unwrap_or(1);
    if want < COPIES || !holds(&d.spec.template.spec.affinity, &affinity()) {
        return Step::Patch;
    }
    let s = &d.status;
    if s.observed_generation < d.metadata.generation
        || s.updated_replicas != want
        || s.ready_replicas != want
        || s.available_replicas != want
    {
        return Step::Wait("CoreDNS is starting or changing".into());
    }
    if pods.iter().any(|p| p.metadata.deleting.is_some()) || pods.len() != want as usize || !pods.iter().all(Pod::ready) {
        return Step::Wait("not every copy of CoreDNS is ready".into());
    }
    let pod_spec = &d.spec.template.spec;
    let usable: Vec<&Node> = nodes.iter().filter(|n| n.takes(pod_spec)).collect();
    let mut on: BTreeMap<&str, Vec<&Pod>> = BTreeMap::new();
    for p in pods {
        on.entry(p.spec.node_name.as_str()).or_default().push(p);
    }
    let empty: Vec<&Node> = usable.iter().copied().filter(|n| !on.contains_key(n.metadata.name.as_str())).collect();
    if empty.is_empty() {
        return Step::Fine;
    }
    let control_plane = |name: &str| nodes.iter().any(|n| n.metadata.name == name && n.control_plane());
    // Copies together on one machine while another could take one. The
    // coordinator's first, so the copy that moves leaves it.
    let mut crowded: Vec<(&str, &Vec<&Pod>)> = on.iter().filter(|(_, ps)| ps.len() > 1).map(|(n, ps)| (*n, ps)).collect();
    crowded.sort_by_key(|(n, _)| !control_plane(n));
    let mut candidates: Vec<(&Pod, String)> = Vec::new();
    for (node, ps) in crowded {
        for p in ps {
            candidates.push((*p, format!("{} copies on {node}, none on {}", ps.len(), empty[0].metadata.name)));
        }
    }
    // A copy on the coordinator while two servers could hold both: with
    // the coordinator down, a copy there no longer answers but stays in
    // every machine's list of DNS servers. With one server, k3s's spread
    // keeps one copy on each machine.
    let empty_servers: Vec<&&Node> = empty.iter().filter(|n| !n.control_plane()).collect();
    if usable.iter().filter(|n| !n.control_plane()).count() >= COPIES as usize && !empty_servers.is_empty() {
        for p in pods.iter().filter(|p| control_plane(&p.spec.node_name)) {
            candidates.push((p, format!("a copy on the coordinator {}, none on {}", p.spec.node_name, empty_servers[0].metadata.name)));
        }
    }
    if candidates.is_empty() {
        return Step::Fine;
    }
    match candidates.iter().find(|(p, _)| p.old_enough(now)) {
        Some((p, why)) => Step::Evict { pod: p.metadata.name.clone(), node: p.spec.node_name.clone(), why: why.clone() },
        None => Step::Wait(format!("{}; the copy is younger than {MIN_AGE_MINUTES} minutes", candidates[0].1)),
    }
}

/// What `kubectl get -o json` returns, one kind or several.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct List {
    items: Vec<Value>,
}

fn kubectl_json(ctx: &Ctx, run: &dyn Runner, args: &[&str]) -> Result<Vec<Value>> {
    let mut all = vec!["kubectl"];
    all.extend(args);
    all.extend(["-o", "json"]);
    let out = run.output(ctx, &Cmd::new("k3s", &all).stdout_only())?;
    let list: List = serde_json::from_str(&out).map_err(|e| crate::errf!("kubectl {}: {e}", args.join(" ")))?;
    Ok(list.items)
}

/// One run of the timer on the coordinator: looks, decides, does at most
/// one thing, and says what.
pub fn tend(ctx: &Ctx, run: &dyn Runner, now: Time, out: &mut dyn Write) -> Result<Step> {
    let items = kubectl_json(ctx, run, &["-n", "kube-system", "get", "deployments,pods", "-l", LABEL])?;
    let mut deploy = None;
    let mut pods = Vec::new();
    for it in items {
        match it.get("kind").and_then(Value::as_str) {
            Some("Deployment") => {
                let d: Deployment = serde_json::from_value(it)?;
                if d.metadata.name == "coredns" {
                    deploy = Some(d);
                }
            }
            Some("Pod") => pods.push(serde_json::from_value::<Pod>(it)?),
            _ => {}
        }
    }
    let nodes: Vec<Node> = kubectl_json(ctx, run, &["get", "nodes"])?.into_iter().map(serde_json::from_value).collect::<Result<_, _>>()?;
    let step = plan(deploy.as_ref(), &pods, &nodes, now);
    match &step {
        Step::Patch => {
            let p = patch(deploy.as_ref().and_then(|d| d.spec.replicas).unwrap_or(1));
            run.ok(
                ctx,
                &Cmd::new("k3s", &["kubectl", "-n", "kube-system", "patch", "deployment", "coredns", "--type=strategic", "-p", &p]),
            )?;
            let _ = writeln!(out, "CoreDNS: set to {COPIES} copies, apart and off the coordinator where possible");
        }
        Step::Evict { pod, node, why } => {
            // The name goes into a URL: only a plain pod name passes.
            if !pod.split('.').all(registry::valid_name) || pod.len() > 253 {
                bail!("CoreDNS pod with a strange name: {pod:?}");
            }
            let eviction = serde_json::json!({
                "apiVersion": "policy/v1",
                "kind": "Eviction",
                "metadata": {"name": pod, "namespace": "kube-system"}
            });
            let path = format!("/api/v1/namespaces/kube-system/pods/{pod}/eviction");
            run.ok(ctx, &Cmd::new("k3s", &["kubectl", "create", "--raw", &path, "-f", "-"]).stdin(eviction.to_string()))?;
            let _ = writeln!(out, "CoreDNS: moving the copy {pod} away from {node} ({why})");
        }
        Step::Wait(why) => {
            let _ = writeln!(out, "CoreDNS: waiting: {why}");
        }
        Step::Fine => {}
    }
    Ok(step)
}

/// How long one run may take.
pub const RUN_TIMEOUT: Duration = Duration::from_secs(90);

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn now() -> Time {
        Time::ymd_hms(2026, 11, 21, 12, 0, 0)
    }

    fn deploy(replicas: u32) -> Deployment {
        let mut d: Deployment = serde_json::from_value(serde_json::json!({
            "kind": "Deployment",
            "metadata": {"name": "coredns", "generation": 3, "labels": {"k8s-app": "kube-dns"}},
            "spec": {"replicas": replicas, "template": {"spec": {
                "tolerations": [
                    {"key": "CriticalAddonsOnly", "operator": "Exists"},
                    {"key": "node-role.kubernetes.io/control-plane", "operator": "Exists", "effect": "NoSchedule"}
                ],
                "nodeSelector": {"kubernetes.io/os": "linux"}
            }}},
            "status": {"observedGeneration": 3, "replicas": replicas, "updatedReplicas": replicas, "readyReplicas": replicas, "availableReplicas": replicas}
        }))
        .unwrap();
        d.spec.template.spec.affinity = affinity();
        d
    }

    fn pod(name: &str, node: &str, age_min: i64) -> Pod {
        serde_json::from_value(serde_json::json!({
            "kind": "Pod",
            "metadata": {"name": name, "creationTimestamp": now().add(TimeDelta::minutes(-age_min))},
            "spec": {"nodeName": node},
            "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}]}
        }))
        .unwrap()
    }

    /// The coordinator as k3s registers it: control-plane label and the
    /// taint that keeps apps off it.
    fn coord() -> Node {
        let mut n = server("coord");
        n.metadata.labels.insert(CONTROL_PLANE.into(), "true".into());
        n.spec.taints.push(Taint { key: "CriticalAddonsOnly".into(), value: "true".into(), effect: "NoExecute".into() });
        n
    }

    fn server(name: &str) -> Node {
        serde_json::from_value(serde_json::json!({
            "kind": "Node",
            "metadata": {"name": name, "labels": {"kubernetes.io/os": "linux", "kubernetes.io/hostname": name}},
            "status": {"conditions": [{"type": "Ready", "status": "True"}]}
        }))
        .unwrap()
    }

    /// A machine that stopped answering, as the cluster marks it.
    fn dead(mut n: Node) -> Node {
        n.status.conditions = vec![Condition { kind: "Ready".into(), status: "Unknown".into() }];
        n.spec.taints.push(Taint { key: "node.kubernetes.io/unreachable".into(), value: String::new(), effect: "NoSchedule".into() });
        n
    }

    fn evicts(s: &Step, want: &str) -> bool {
        matches!(s, Step::Evict { pod, .. } if pod == want)
    }

    #[test]
    fn patch_sets_only_our_fields() {
        let p: Value = serde_json::from_str(&patch(1)).unwrap();
        assert_eq!(p["spec"]["replicas"], 2);
        let a = &p["spec"]["template"]["spec"]["affinity"];
        // Preferences only: a rule ("required...") would keep the second
        // copy from starting on a swarm of one machine.
        let text = p.to_string();
        assert!(!text.contains("requiredDuringScheduling"), "{text}");
        assert_eq!(
            a["podAntiAffinity"]["preferredDuringSchedulingIgnoredDuringExecution"][0]["podAffinityTerm"]["topologyKey"],
            "kubernetes.io/hostname"
        );
        assert_eq!(
            a["nodeAffinity"]["preferredDuringSchedulingIgnoredDuringExecution"][0]["preference"]["matchExpressions"][0],
            serde_json::json!({"key": CONTROL_PLANE, "operator": "DoesNotExist"})
        );
        // k3s's fields stay k3s's: the image follows the k3s release, the
        // toleration for the coordinator's taint stays as k3s wrote it.
        for k3s_owns in ["image", "tolerations", "containers", "topologySpreadConstraints"] {
            assert!(!text.contains(k3s_owns), "the patch must not set {k3s_owns}: {text}");
        }
    }

    #[test]
    fn pdb_keeps_one_copy() {
        for want in ["kind: PodDisruptionBudget", "namespace: kube-system", "minAvailable: 1", "k8s-app: kube-dns"] {
            assert!(PDB.contains(want), "{want}: {PDB}");
        }
        assert!(PDB_PATH.starts_with("/var/lib/rancher/k3s/server/manifests/") && !PDB_PATH.ends_with("/coredns.yaml"));
        assert_eq!(LABEL, "k8s-app=kube-dns");
    }

    #[test]
    fn k3s_restart_or_upgrade_brings_the_patch_back() {
        // A k3s that replaced the deployment: one copy, no preferences.
        let mut d = deploy(1);
        assert_eq!(plan(Some(&d), &[pod("a", "coord", 60)], &[coord()], now()), Step::Patch);
        d = deploy(2);
        d.spec.template.spec.affinity = Value::Null;
        assert_eq!(plan(Some(&d), &[], &[coord()], now()), Step::Patch);
        // No replicas field at all: Kubernetes's default of one.
        d = deploy(2);
        d.spec.replicas = None;
        assert_eq!(plan(Some(&d), &[], &[coord()], now()), Step::Patch);
        // More copies than ours, set by the admin: left alone.
        let d = deploy(3);
        let ps = [pod("a", "coord", 60), pod("b", "coord", 60), pod("c", "coord", 60)];
        assert_eq!(plan(Some(&d), &ps, &[coord()], now()), Step::Fine);
        assert!(patch(3).contains(r#""replicas":3"#) && patch(0).contains(r#""replicas":2"#));
        // Fields the API server adds to ours are no difference; a changed
        // preference is.
        let mut d = deploy(2);
        d.spec.template.spec.affinity["podAntiAffinity"]["preferredDuringSchedulingIgnoredDuringExecution"][0]["podAffinityTerm"]["namespaces"] =
            serde_json::json!(["kube-system"]);
        d.spec.template.spec.affinity["nodeAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"] = Value::Null;
        let ps2 = [pod("a", "coord", 60), pod("b", "coord", 60)];
        assert_eq!(plan(Some(&d), &ps2, &[coord()], now()), Step::Fine);
        d.spec.template.spec.affinity["podAntiAffinity"]["preferredDuringSchedulingIgnoredDuringExecution"][0]["weight"] = 1.into();
        assert_eq!(plan(Some(&d), &ps2, &[coord()], now()), Step::Patch);
        // Nothing deployed yet (k3s still starting).
        assert!(matches!(plan(None, &[], &[coord()], now()), Step::Wait(_)));
    }

    #[test]
    fn one_machine_keeps_both_copies() {
        let d = deploy(2);
        assert_eq!(plan(Some(&d), &[pod("a", "coord", 60), pod("b", "coord", 60)], &[coord()], now()), Step::Fine);
    }

    #[test]
    fn second_machine_takes_a_copy() {
        // The coordinator was alone when both copies started.
        let d = deploy(2);
        let ps = [pod("a", "coord", 60), pod("b", "coord", 30)];
        let s = plan(Some(&d), &ps, &[coord(), server("node-a")], now());
        assert!(evicts(&s, "a"), "{s:?}");
        // Then one copy on each: k3s's spread allows nothing else with two
        // machines, so the copy on the coordinator stays.
        let ps = [pod("a2", "node-a", 60), pod("b", "coord", 60)];
        assert_eq!(plan(Some(&d), &ps, &[coord(), server("node-a")], now()), Step::Fine);
    }

    #[test]
    fn copies_leave_the_coordinator_when_two_servers_can_hold_them() {
        let d = deploy(2);
        let nodes = [coord(), server("node-a"), server("node-b")];
        let s = plan(Some(&d), &[pod("a", "node-a", 60), pod("b", "coord", 60)], &nodes, now());
        assert!(evicts(&s, "b"), "{s:?}");
        assert_eq!(plan(Some(&d), &[pod("a", "node-a", 60), pod("b", "node-b", 60)], &nodes, now()), Step::Fine);
    }

    #[test]
    fn dead_machine_is_no_place_for_a_copy() {
        let d = deploy(2);
        // node-b died; its copy was placed again next to node-a's. With
        // node-b down there is nowhere better.
        let nodes = [coord(), server("node-a"), dead(server("node-b"))];
        let ps = [pod("a", "node-a", 60), pod("b2", "coord", 60)];
        assert_eq!(plan(Some(&d), &ps, &nodes, now()), Step::Fine);
        let ps = [pod("a", "node-a", 60), pod("b2", "node-a", 60)];
        let nodes2 = [dead(coord()), server("node-a"), dead(server("node-b"))];
        assert_eq!(plan(Some(&d), &ps, &nodes2, now()), Step::Fine);
        // Back again: the doubled copies spread out.
        let nodes = [coord(), server("node-a"), server("node-b")];
        let s = plan(Some(&d), &ps, &nodes, now());
        assert!(matches!(&s, Step::Evict { node, .. } if node == "node-a"), "{s:?}");
        // Cordoned or tainted for something CoreDNS does not tolerate: no
        // place either.
        let mut cordoned = server("node-b");
        cordoned.spec.unschedulable = true;
        let mut tainted = server("node-c");
        tainted.spec.taints.push(Taint { key: "disk".into(), value: "full".into(), effect: "NoSchedule".into() });
        let mut soft = server("node-d");
        soft.spec.taints.push(Taint { key: "slow".into(), value: String::new(), effect: "PreferNoSchedule".into() });
        let ps = [pod("a", "node-a", 60), pod("b", "node-a", 60)];
        assert_eq!(plan(Some(&d), &ps, &[dead(coord()), server("node-a"), cordoned.clone(), tainted.clone()], now()), Step::Fine);
        assert!(matches!(plan(Some(&d), &ps, &[server("node-a"), cordoned, tainted, soft], now()), Step::Evict { .. }));
    }

    #[test]
    fn nothing_moves_while_copies_are_not_ready() {
        let d = deploy(2);
        let nodes = [coord(), server("node-a")];
        let mut not_ready = pod("b", "coord", 60);
        not_ready.status.conditions[0].status = "False".into();
        let mut leaving = pod("b", "coord", 60);
        leaving.metadata.deleting = Some(now());
        let pending: Pod = serde_json::from_value(serde_json::json!({"metadata": {"name": "c"}, "status": {"phase": "Pending"}})).unwrap();
        for ps in [
            vec![pod("a", "coord", 60), not_ready],
            vec![pod("a", "coord", 60), leaving],
            vec![pod("a", "coord", 60)],
            vec![pod("a", "coord", 60), pod("b", "coord", 60), pending],
        ] {
            assert!(matches!(plan(Some(&d), &ps, &nodes, now()), Step::Wait(_)), "{ps:?}");
        }
        // A rollout under way.
        let mut d2 = deploy(2);
        d2.metadata.generation = 4;
        assert!(matches!(plan(Some(&d2), &[pod("a", "coord", 60), pod("b", "coord", 60)], &nodes, now()), Step::Wait(_)));
        let mut d3 = deploy(2);
        d3.status.ready_replicas = 1;
        assert!(matches!(plan(Some(&d3), &[pod("a", "coord", 60), pod("b", "coord", 60)], &nodes, now()), Step::Wait(_)));
    }

    #[test]
    fn young_copies_stay() {
        let d = deploy(2);
        let nodes = [coord(), server("node-a")];
        let s = plan(Some(&d), &[pod("a", "coord", 9), pod("b", "coord", 2)], &nodes, now());
        assert!(matches!(&s, Step::Wait(w) if w.contains("younger")), "{s:?}");
        // The clock went back: the copies look like they come from the
        // future. Nothing moves until they are old enough by this clock.
        let s = plan(Some(&d), &[pod("a", "coord", -600), pod("b", "coord", -600)], &nodes, now());
        assert!(matches!(s, Step::Wait(_)), "{s:?}");
        // No start time known: never moved.
        let mut p = pod("a", "coord", 60);
        p.metadata.created = None;
        assert!(matches!(plan(Some(&d), &[p, pod("b", "coord", 1)], &nodes, now()), Step::Wait(_)));
    }

    #[test]
    fn tolerations_follow_kubernetes() {
        let t = Taint { key: "CriticalAddonsOnly".into(), value: "true".into(), effect: "NoExecute".into() };
        let tol =
            |k: &str, op: &str, v: &str, e: &str| Toleration { key: k.into(), operator: op.into(), value: v.into(), effect: e.into() };
        assert!(tolerates(&[tol("CriticalAddonsOnly", "Exists", "", "")], &t));
        assert!(tolerates(&[tol("", "Exists", "", "")], &t), "an empty key with Exists tolerates everything");
        assert!(tolerates(&[tol("CriticalAddonsOnly", "Equal", "true", "NoExecute")], &t));
        assert!(tolerates(&[tol("CriticalAddonsOnly", "", "true", "")], &t), "no operator means Equal");
        assert!(!tolerates(&[tol("CriticalAddonsOnly", "Equal", "false", "")], &t));
        assert!(!tolerates(&[tol("CriticalAddonsOnly", "Exists", "", "NoSchedule")], &t));
        assert!(!tolerates(&[tol("", "Equal", "", "")], &t));
        assert!(!tolerates(&[], &t));
        // The coordinator takes a copy (k3s's toleration), as long as it
        // is ready.
        let d = deploy(2);
        assert!(coord().takes(&d.spec.template.spec));
        assert!(!dead(coord()).takes(&d.spec.template.spec));
        let mut no_os = server("x");
        no_os.metadata.labels.clear();
        assert!(!no_os.takes(&d.spec.template.spec), "the deployment's node selector counts");
    }

    struct Fake {
        calls: Mutex<Vec<Cmd>>,
        answers: Vec<(&'static str, String)>,
    }

    impl Runner for Fake {
        fn run(&self, _: &Ctx, c: &Cmd) -> (String, Result<()>) {
            self.calls.lock().unwrap().push(c.clone());
            let line = c.to_string();
            for (prefix, out) in &self.answers {
                if line.starts_with(prefix) {
                    return (out.clone(), Ok(()));
                }
            }
            (String::new(), Ok(()))
        }
    }

    fn list(items: Vec<Value>) -> String {
        serde_json::json!({"apiVersion": "v1", "kind": "List", "items": items}).to_string()
    }

    fn cluster(d: Value, pods: Vec<Value>, nodes: Vec<Value>) -> Fake {
        let mut objs = vec![d];
        objs.extend(pods);
        Fake {
            calls: Mutex::default(),
            answers: vec![
                ("k3s kubectl -n kube-system get deployments,pods -l k8s-app=kube-dns -o json", list(objs)),
                ("k3s kubectl get nodes -o json", list(nodes)),
            ],
        }
    }

    fn json_pod(name: &str, node: &str) -> Value {
        serde_json::json!({
            "kind": "Pod",
            "metadata": {"name": name, "creationTimestamp": "2026-11-21T10:00:00Z", "labels": {"k8s-app": "kube-dns"}},
            "spec": {"nodeName": node},
            "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}]}
        })
    }

    fn json_node(name: &str, coordinator: bool) -> Value {
        let mut labels = serde_json::json!({"kubernetes.io/os": "linux"});
        let mut taints = serde_json::json!([]);
        if coordinator {
            labels[CONTROL_PLANE] = "true".into();
            taints = serde_json::json!([{"key": "CriticalAddonsOnly", "value": "true", "effect": "NoExecute"}]);
        }
        serde_json::json!({"kind": "Node", "metadata": {"name": name, "labels": labels}, "spec": {"taints": taints},
            "status": {"conditions": [{"type": "Ready", "status": "True"}]}})
    }

    fn json_deploy(replicas: u32, ours: bool) -> Value {
        let mut spec = serde_json::json!({"tolerations": [{"key": "CriticalAddonsOnly", "operator": "Exists"}], "nodeSelector": {"kubernetes.io/os": "linux"}});
        if ours {
            spec["affinity"] = affinity();
        }
        serde_json::json!({"kind": "Deployment", "metadata": {"name": "coredns", "generation": 1},
            "spec": {"replicas": replicas, "template": {"spec": spec}},
            "status": {"observedGeneration": 1, "updatedReplicas": replicas, "readyReplicas": replicas, "availableReplicas": replicas}})
    }

    #[test]
    fn tend_patches_k3s_deployment() {
        let f = cluster(json_deploy(1, false), vec![json_pod("coredns-1", "coord")], vec![json_node("coord", true)]);
        let mut out = Vec::new();
        assert_eq!(tend(&Ctx::new(), &f, now(), &mut out).unwrap(), Step::Patch);
        let calls = f.calls.lock().unwrap();
        let p = calls.iter().find(|c| c.args.contains(&"patch".to_string())).expect("no patch");
        assert_eq!(&p.args[..7], ["kubectl", "-n", "kube-system", "patch", "deployment", "coredns", "--type=strategic"]);
        assert_eq!(p.args[8], patch(1));
        assert!(String::from_utf8_lossy(&out).contains("2 copies"));
    }

    #[test]
    fn tend_evicts_through_the_disruption_budget() {
        let f = cluster(
            json_deploy(2, true),
            vec![json_pod("coredns-1", "coord"), json_pod("coredns-2", "coord")],
            vec![json_node("coord", true), json_node("node-a", false)],
        );
        let mut out = Vec::new();
        let s = tend(&Ctx::new(), &f, now(), &mut out).unwrap();
        assert!(evicts(&s, "coredns-1"), "{s:?}");
        let calls = f.calls.lock().unwrap();
        // An eviction, not a delete: it asks the disruption budget.
        let e = calls.iter().find(|c| c.args.contains(&"--raw".to_string())).expect("no eviction");
        assert_eq!(e.args, ["kubectl", "create", "--raw", "/api/v1/namespaces/kube-system/pods/coredns-1/eviction", "-f", "-"]);
        assert!(e.stdin.contains(r#""kind":"Eviction""#) && e.stdin.contains(r#""name":"coredns-1""#), "{}", e.stdin);
        assert!(!calls.iter().any(|c| c.args.contains(&"delete".to_string())));
        assert!(String::from_utf8_lossy(&out).contains("moving the copy coredns-1 away from coord"));
    }

    #[test]
    fn tend_refuses_strange_names_and_bad_answers() {
        let f = cluster(
            json_deploy(2, true),
            vec![json_pod("../../nodes/x", "coord"), json_pod("coredns-2", "coord")],
            vec![json_node("coord", true), json_node("node-a", false)],
        );
        assert!(tend(&Ctx::new(), &f, now(), &mut Vec::new()).unwrap_err().to_string().contains("strange name"));
        assert!(!f.calls.lock().unwrap().iter().any(|c| c.args.contains(&"--raw".to_string())));
        let f = Fake { calls: Mutex::default(), answers: vec![("k3s kubectl", "not json".into())] };
        assert!(tend(&Ctx::new(), &f, now(), &mut Vec::new()).is_err());
    }

    #[test]
    fn dns_policies_of_apps_and_tunnel_follow_the_copies() {
        // The apps and the tunnel may reach DNS by the pods' label, not by
        // a machine or an address: wherever the copies run, it is allowed.
        let app =
            crate::apps::App { name: "blog".into(), image: "nginx:1".into(), port: 80, hosts: vec![], entrance: String::new(), copies: 1 };
        let tunnel = crate::entrance::cloudflare::tunnel_manifest(&"a".repeat(64)).unwrap();
        for m in [app.manifest().unwrap(), tunnel] {
            let rule = "kubernetes.io/metadata.name: kube-system\n          podSelector:\n            matchLabels:\n              k8s-app: kube-dns\n      ports:\n        - port: 53";
            assert!(m.contains(rule), "{m}");
        }
    }
}
