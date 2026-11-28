use std::sync::Mutex;

use super::*;
use crate::apps::tests::Fake as FakeCluster;
use crate::testutil::TempDir;

const K1: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const K2: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=";
const K3: &str = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=";
const MESH_KEY: &str = "MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMA=";

fn plan() -> Plan {
    Plan::new("node-a", "vpn.example.com")
}

fn dev(name: &str, key: &str, addr: &str) -> Device {
    Device { name: name.into(), key: key.into(), addr: addr.into() }
}

fn members() -> Vec<(&'static str, u32, &'static str)> {
    vec![("coord", 1, MESH_KEY), ("node-a", 2, K3)]
}

#[test]
fn a_plan_is_checked() {
    let p = plan();
    p.check().unwrap();
    assert_eq!((p.gateway_addr(), p.dial_port()), (Some(Ipv4Addr::new(10, 99, 0, 1)), DEFAULT_PORT));
    assert_eq!(Plan { public_port: 443, ..plan() }.dial_port(), 443);
    let bad = |p: Plan, why: &str| {
        let e = p.check().unwrap_err().to_string();
        assert!(e.contains(why), "{why}: {e}");
    };
    bad(Plan { gateway: "Node A".into(), ..plan() }, "not a machine name");
    bad(Plan { port: 53, ..plan() }, "1024 to 65535");
    bad(Plan { subnet: "10.99.0.5/24".into(), ..plan() }, "not a network");
    bad(Plan { subnet: "nonsense".into(), ..plan() }, "not a network");
    bad(Plan { subnet: "10.0.0.0/8".into(), ..plan() }, "/16 to /28");
    bad(Plan { subnet: "10.99.0.0/30".into(), ..plan() }, "/16 to /28");
    bad(Plan { subnet: "10.42.7.0/24".into(), ..plan() }, "overlaps 10.42.0.0/16");
    bad(Plan { subnet: "10.43.0.0/16".into(), ..plan() }, "overlaps 10.43.0.0/16");
    bad(Plan { subnet: "172.17.5.0/24".into(), ..plan() }, "overlaps 172.17.0.0/16");
    // Only private ranges: a public one takes real addresses away.
    for public in ["127.0.0.0/16", "8.8.8.0/24", "100.64.0.0/24", "169.254.0.0/24", "172.32.0.0/24"] {
        bad(Plan { subnet: public.into(), ..plan() }, "not a private one");
    }
    for private in ["10.200.0.0/24", "172.20.0.0/16", "192.168.77.0/24"] {
        Plan { subnet: private.into(), ..plan() }.check().unwrap();
    }
    for e in ["", "vpn", "vpn.example.com:51821", "VPN.example.com", "a..b", "1.2.3.4.5", "10.0.0.300", "-x.example.com"] {
        bad(Plan { endpoint: e.into(), ..plan() }, "not a DNS name or an IPv4 address");
    }
    Plan { endpoint: "203.0.113.7".into(), ..plan() }.check().unwrap();
    // Another network of the swarm.
    assert!(plan().clashes("the mesh", "10.99.0.0/16").unwrap_err().to_string().contains("overlaps the mesh"));
    plan().clashes("the mesh", "10.66.0.0/24").unwrap();
    plan().clashes("the home network", "not a network").unwrap();
}

#[test]
fn devices_are_checked_with_the_plan() {
    let p = plan();
    check(Some(&p), &[dev("phone", K1, "10.99.0.2"), dev("laptop", K2, "10.99.0.254")], &members()).unwrap();
    // Devices may stay listed while the VPN is off.
    check(None, &[dev("phone", K1, "10.99.0.2")], &members()).unwrap();
    let bad = |plan: Option<&Plan>, devs: &[Device], why: &str| {
        let e = check(plan, devs, &members()).unwrap_err().to_string();
        assert!(e.contains(why), "{why}: {e}");
    };
    bad(Some(&Plan { gateway: "nope".into(), ..plan() }), &[], "not a machine of the swarm");
    bad(Some(&Plan { gateway: "coord".into(), ..plan() }), &[], "cannot be the coordinator");
    bad(Some(&p), &[dev("phone", K1, "10.99.0.2"), dev("phone", K2, "10.99.0.3")], "bad or repeated name");
    bad(Some(&p), &[dev("Phone", K1, "10.99.0.2")], "bad or repeated name");
    bad(Some(&p), &[dev("phone", K1, "10.99.0.2"), dev("tab", K1, "10.99.0.3")], "bad key");
    bad(Some(&p), &[dev("phone", K3, "10.99.0.2")], "one another device or a machine has");
    bad(Some(&p), &[dev("phone", "short", "10.99.0.2")], "bad key");
    bad(Some(&p), &[dev("phone", K1, "10.99.0.2"), dev("tab", K2, "10.99.0.2")], "an address another device has");
    for addr in ["10.99.0.0", "10.99.0.1", "10.99.0.255", "10.98.0.2"] {
        bad(Some(&p), &[dev("phone", K1, addr)], "outside the VPN's subnet");
    }
    bad(Some(&p), &[dev("phone", K1, "x")], "has no address");
    let many: Vec<Device> = (0..=MAX_DEVICES).map(|i| dev(&format!("d{i}"), K1, "10.99.0.2")).collect();
    bad(Some(&p), &many, "more than 100");
}

#[test]
fn addresses_are_handed_out_in_order() {
    let p = Plan { subnet: "10.99.0.0/28".into(), ..plan() };
    assert_eq!(next_addr(&p, &[]), Some(Ipv4Addr::new(10, 99, 0, 2)));
    let some = [dev("a", K1, "10.99.0.2"), dev("b", K2, "10.99.0.4")];
    assert_eq!(next_addr(&p, &some), Some(Ipv4Addr::new(10, 99, 0, 3)));
    // .2 to .14 in a /28: 13 devices, then no more.
    let full: Vec<Device> = (2..=14).map(|i| dev(&format!("d{i}"), K1, &format!("10.99.0.{i}"))).collect();
    assert_eq!(next_addr(&p, &full), None);
}

#[test]
fn a_device_gets_a_config_without_dns() {
    let d = dev("phone", K1, "10.99.0.2");
    let c = client_config(&Plan { public_port: 443, ..plan() }, &d, Some("PRIVATE=\n"), MESH_KEY);
    for want in [
        "[Interface]\nPrivateKey = PRIVATE=\nAddress = 10.99.0.2/32\nMTU = 1380\n",
        &format!("[Peer]\nPublicKey = {MESH_KEY}\nAllowedIPs = 10.99.0.1/32\nEndpoint = vpn.example.com:443\nPersistentKeepalive = 25\n"),
    ] {
        assert!(c.contains(want), "{want:?}:\n{c}");
    }
    // Only the gateway through the tunnel, and no DNS server: with the
    // gateway down, the device's internet still works.
    assert!(!c.contains("DNS") && !c.contains("0.0.0.0/0"), "{c}");
    let own = client_config(&plan(), &d, None, MESH_KEY);
    assert!(own.contains("# PrivateKey: the one this device has already") && !own.contains("PrivateKey ="), "{own}");
}

#[test]
fn the_interface_has_exactly_the_listed_devices() {
    let c = wg_config("PRIV=", 51821, &[dev("phone", K1, "10.99.0.2"), dev("laptop", K2, "10.99.0.3")]);
    assert!(c.starts_with("[Interface]\nPrivateKey = PRIV=\nListenPort = 51821\n"), "{c}");
    assert!(c.contains(&format!("[Peer]\n# phone\nPublicKey = {K1}\nAllowedIPs = 10.99.0.2/32\n")), "{c}");
    assert_eq!(c.matches("[Peer]").count(), 2);
    let d = dump(&format!(
        "PRIV=\tPUB=\t51821\toff\n{K1}\t(none)\t198.51.100.4:4500\t10.99.0.2/32\t1764300000\t1200\t3400\t25\n{K2}\t(none)\t(none)\t10.99.0.3/32\t0\t0\t0\t25\nnot a key\tx\tx\tx\t1\t2\t3\t4\n"
    ));
    // The keys' start only: the report has a size limit.
    assert_eq!(d, vec![Seen { key: K1[..KEY_PREFIX].into(), handshake: 1764300000 }, Seen { key: K2[..KEY_PREFIX].into(), handshake: 0 }]);
}

#[derive(Default)]
struct Fake {
    ran: Mutex<Vec<String>>,
    iface: Mutex<bool>,
    addrs: Mutex<String>,
    nft_fails: Mutex<bool>,
    stdin: Mutex<Vec<String>>,
}

impl Runner for Fake {
    fn run(&self, _: &Ctx, c: &Cmd) -> (String, Result<()>) {
        let line = format!("{} {}", c.name, c.args.join(" "));
        self.ran.lock().unwrap().push(line.clone());
        if !c.stdin.is_empty() {
            self.stdin.lock().unwrap().push(c.stdin.clone());
        }
        match (c.name.as_str(), line.as_str()) {
            ("ip", l) if l.contains("link show dev wgp") => {
                if *self.iface.lock().unwrap() {
                    ("1: wgp: <POINTOPOINT>\n".into(), Ok(()))
                } else {
                    (String::new(), Err("does not exist".into()))
                }
            }
            ("ip", l) if l.contains("link add dev wgp") => {
                *self.iface.lock().unwrap() = true;
                (String::new(), Ok(()))
            }
            ("ip", l) if l.contains("link del dev wgp") => {
                *self.iface.lock().unwrap() = false;
                (String::new(), Ok(()))
            }
            ("ip", l) if l.contains("address show dev wgp") => (self.addrs.lock().unwrap().clone(), Ok(())),
            ("ip", l) if l.contains("address add") => {
                *self.addrs.lock().unwrap() = format!("5: wgp    inet {}/24 scope global wgp\n", c.args[3].split('/').next().unwrap());
                (String::new(), Ok(()))
            }
            ("nft", _) if *self.nft_fails.lock().unwrap() => (String::new(), Err("No such file or directory: set vpn_ports".into())),
            ("wg", l) if l.starts_with("wg syncconf") => {
                let conf = std::fs::read_to_string(&c.args[2]).unwrap_or_default();
                self.stdin.lock().unwrap().push(conf);
                (String::new(), Ok(()))
            }
            ("wg", l) if l.contains("dump") => {
                (format!("PRIV=\tPUB=\t51821\toff\n{K1}\t(none)\t(none)\t10.99.0.2/32\t0\t0\t0\t25\n"), Ok(()))
            }
            _ => (String::new(), Ok(())),
        }
    }
}

fn here<'a>(t: &'a TempDir, run: &'a Fake, name: &'a str) -> Here<'a> {
    Here { root: t.path(), run, name, coordinator: false, mesh_port: 51820, key_file: "/etc/wireguard/wg0.key".into(), tmp: t.join("tmp") }
}

fn ran(f: &Fake) -> Vec<String> {
    std::mem::take(&mut *f.ran.lock().unwrap())
}

#[test]
fn the_gateway_brings_its_interface_up_and_keeps_it() {
    let t = TempDir::new();
    fsx::mkdir_all(t.join("etc/wireguard"), 0o700).unwrap();
    std::fs::write(t.join("etc/wireguard/wg0.key"), format!("{MESH_KEY}\n")).unwrap();
    let f = Fake::default();
    let devs = [dev("phone", K1, "10.99.0.2")];
    let st = here(&t, &f, "node-a").reconcile(&Ctx::new(), Some(&plan()), &devs);
    assert!(st.gateway && st.problem.is_empty(), "{st:?}");
    assert_eq!(st.devices.len(), 1);
    let r = ran(&f);
    for want in [
        "ip link add dev wgp type wireguard",
        "ip link set dev wgp mtu 1380",
        "ip -4 address flush dev wgp",
        "ip -4 address add 10.99.0.1/24 dev wgp",
        "ip link set dev wgp up",
        "nft -f -",
    ] {
        assert!(r.iter().any(|l| l == want), "{want}: {r:?}");
    }
    assert!(r.iter().any(|l| l.starts_with("wg syncconf wgp ")), "{r:?}");
    let inputs = f.stdin.lock().unwrap().clone();
    assert!(inputs.iter().any(|c| c.contains(&format!("PrivateKey = {MESH_KEY}\nListenPort = 51821")) && c.contains(K1)), "{inputs:?}");
    assert!(
        inputs.iter().any(|c| c
            == "flush set inet dryserver vpn_ports\nflush set inet dryserver vpn_addrs\nadd element inet dryserver vpn_ports { 51821 }\nadd element inet dryserver vpn_addrs { 10.99.0.1 }\n"),
        "{inputs:?}"
    );
    // The firewall's sets before the interface: without its rules, none.
    let nft = r.iter().position(|l| l == "nft -f -").unwrap();
    assert!(nft < r.iter().position(|l| l == "ip link add dev wgp type wireguard").unwrap(), "{r:?}");
    // The key's file went away again; the certificates' folder is there.
    assert!(std::fs::read_dir(t.join("tmp")).unwrap().next().is_none());
    assert!(t.join("var/lib/dryserver-vpn/secrets").is_dir());
    let kept: Status = serde_json::from_str(&std::fs::read_to_string(t.join("run/dryserver/vpn-status.json")).unwrap()).unwrap();
    assert!(kept.gateway && kept.devices.len() == 1, "for the report: {kept:?}");
    assert!(t.join("var/lib/dryserver-vpn/acme").is_dir());
    // The next minute: up already, its address right, nothing made again.
    here(&t, &f, "node-a").reconcile(&Ctx::new(), Some(&plan()), &devs);
    let r = ran(&f);
    assert!(!r.iter().any(|l| l.contains("link add") || l.contains("address flush")), "{r:?}");
    // Another subnet: the address follows.
    here(&t, &f, "node-a").reconcile(&Ctx::new(), Some(&Plan { subnet: "10.98.0.0/24".into(), ..plan() }), &[]);
    let r = ran(&f);
    assert!(r.iter().any(|l| l == "ip -4 address add 10.98.0.1/24 dev wgp"), "{r:?}");
    // Not the gateway any more: the interface goes, the port closes.
    let st = here(&t, &f, "node-a").reconcile(&Ctx::new(), Some(&Plan { gateway: "node-b".into(), ..plan() }), &devs);
    assert_eq!(st, Status::default());
    let r = ran(&f);
    assert!(r.iter().any(|l| l == "ip link del dev wgp"), "{r:?}");
    assert_eq!(f.stdin.lock().unwrap().last().unwrap(), "flush set inet dryserver vpn_ports\nflush set inet dryserver vpn_addrs\n");
    // Its certificates and token go with it: the gateway's alone.
    assert!(!t.join("var/lib/dryserver-vpn/acme").exists() && !t.join("var/lib/dryserver-vpn/secrets").exists());
    // No VPN at all, interface gone already: only the set is emptied.
    here(&t, &f, "node-a").reconcile(&Ctx::new(), None, &devs);
    assert!(!ran(&f).iter().any(|l| l.contains("link del")));
    assert!(!t.join("run/dryserver/vpn-status.json").exists(), "no gateway: nothing to report");
}

#[test]
fn what_keeps_a_machine_from_being_the_gateway_is_said() {
    let t = TempDir::new();
    let f = Fake::default();
    // No mesh key.
    let st = here(&t, &f, "node-a").reconcile(&Ctx::new(), Some(&plan()), &[]);
    assert!(!st.gateway && st.problem.contains("no mesh key"), "{st:?}");
    // The mesh's own port.
    let st = here(&t, &f, "node-a").reconcile(&Ctx::new(), Some(&Plan { port: 51820, ..plan() }), &[]);
    assert!(st.problem.contains("is the mesh's"), "{st:?}");
    // A firewall from before the VPN.
    fsx::mkdir_all(t.join("etc/wireguard"), 0o700).unwrap();
    std::fs::write(t.join("etc/wireguard/wg0.key"), format!("{MESH_KEY}\n")).unwrap();
    *f.nft_fails.lock().unwrap() = true;
    let st = here(&t, &f, "node-a").reconcile(&Ctx::new(), Some(&plan()), &[]);
    assert!(st.problem.contains("from before the VPN"), "{st:?}");
    // No interface made for it either.
    assert!(!ran(&f).iter().any(|l| l.contains("link add")));
    // The coordinator is never the gateway (with a firewall that would
    // take it, too).
    *f.nft_fails.lock().unwrap() = false;
    let mut h = here(&t, &f, "coord");
    h.coordinator = true;
    let st = h.reconcile(&Ctx::new(), Some(&Plan { gateway: "coord".into(), ..plan() }), &[]);
    assert_eq!(st, Status::default());
    assert!(!ran(&f).iter().any(|l| l.contains("link add")));
}

#[test]
fn the_vpn_ingress_is_on_the_gateway_and_serves_only_its_own() {
    let m = cluster_manifest(&plan()).unwrap();
    for want in [
        "nodeName: \"node-a\"",
        "hostPort: 443\n              hostIP: \"10.99.0.1\"",
        "hostPort: 80\n              hostIP: \"10.99.0.1\"",
        &format!("containerPort: {HTTPS_PORT}"),
        "--providers.kubernetesingress.labelselector=dryserver/vpn=true",
        "--providers.kubernetesingress.namespaces=apps",
        "--certificatesresolvers.dryserver.acme.dnschallenge.provider=cloudflare",
        "--entrypoints.web.http.redirections.entrypoint.to=:443",
        TRAEFIK_IMAGE,
        "runAsNonRoot: true",
        "readOnlyRootFilesystem: true",
        "drop: [\"ALL\"]",
        "type: Recreate",
        "path: /var/lib/dryserver-vpn/acme\n            type: Directory",
        "name: CF_DNS_API_TOKEN_FILE\n              value: /secrets/cloudflare-token",
        "path: /var/lib/dryserver-vpn/secrets\n            type: Directory",
        "resources: [nodes]\n    verbs: [get, list, watch]",
        // Only the devices reach it: not the gateway's own address, no
        // pod, no machine.
        "  ingress:\n    - from:\n        - ipBlock:\n            cidr: \"10.99.0.0/24\"\n            except: [\"10.99.0.1/32\"]\n      ports:\n        - port: 18000\n        - port: 18443\n",
    ] {
        assert!(m.contains(want), "{want:?}:\n{m}");
    }
    // The apps' namespace first (a new cluster has none before the first
    // app); every part of the VPN's carries the label its removal finds
    // it by.
    assert!(m.starts_with(&crate::apps::namespace_yaml()), "{m}");
    assert_eq!(m.matches("\n---\n").count(), m.matches("app.kubernetes.io/part-of: dryserver-vpn").count() - 1);
    assert!(cluster_manifest(&Plan { gateway: "Bad Name".into(), ..plan() }).is_err());
    // The token is never a secret in the cluster; no label moves the pod.
    assert!(!m.contains("secretKeyRef") && !m.contains("nodeSelector"), "{m}");
}

#[test]
fn the_coordinator_applies_the_vpn_ingress_and_takes_it_down() {
    let t = TempDir::new();
    let c = FakeCluster::default();
    let calls = |c: &FakeCluster| c.calls.lock().unwrap().iter().map(|(a, _)| a.clone()).collect::<Vec<_>>();
    assert!(cluster_on_coordinator(&Ctx::new(), &c, Some(&plan()), t.path(), 1000).is_empty());
    assert_eq!(calls(&c), vec!["apply -f -"]);
    // The same within ten minutes: nothing; after, again.
    cluster_on_coordinator(&Ctx::new(), &c, Some(&plan()), t.path(), 1300);
    assert_eq!(calls(&c).len(), 1);
    cluster_on_coordinator(&Ctx::new(), &c, Some(&plan()), t.path(), 1700);
    assert_eq!(calls(&c).len(), 2);
    // Changed: at once.
    cluster_on_coordinator(&Ctx::new(), &c, Some(&Plan { gateway: "node-b".into(), ..plan() }), t.path(), 1710);
    assert_eq!(calls(&c).len(), 3);
    // Gone from the plan: taken down, the token's namespace left.
    cluster_on_coordinator(&Ctx::new(), &c, None, t.path(), 1720);
    let all = calls(&c);
    assert!(
        all[3..]
            .iter()
            .any(|a| a.contains("-n vpn delete deployment,serviceaccount,networkpolicy -l app.kubernetes.io/part-of=dryserver-vpn")),
        "{all:?}"
    );
    assert!(all.iter().all(|a| !a.contains("delete namespace")));
    // Once: nothing to take down after.
    cluster_on_coordinator(&Ctx::new(), &c, None, t.path(), 1730);
    assert_eq!(calls(&c).len(), all.len());
    // A failure is said, and tried again next time.
    let c = FakeCluster::default();
    *c.fail.lock().unwrap() = Some("connection refused".into());
    let log = cluster_on_coordinator(&Ctx::new(), &c, Some(&plan()), t.path(), 2000);
    assert!(log.iter().any(|l| l.contains("not applied: connection refused")), "{log:?}");
}

#[test]
fn the_token_goes_to_the_gateway_alone() {
    let t = TempDir::new();
    let f = Fake::default();
    // Not the gateway (its folder is not there): refused.
    let e = put_token(&Ctx::new(), t.path(), &f, "tok").unwrap_err().to_string();
    assert!(e.contains("not the VPN's gateway"), "{e}");
    fsx::mkdir_all(t.join("var/lib/dryserver-vpn/secrets"), 0o700).unwrap();
    put_token(&Ctx::new(), t.path(), &f, "  a-token\n").unwrap();
    let file = t.join("var/lib/dryserver-vpn/secrets/cloudflare-token");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o400);
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "a-token\n");
    // Its Traefik is started again, to read it.
    let r = ran(&f);
    assert!(r.iter().any(|l| l.starts_with("k3s crictl ps -q --label io.kubernetes.pod.namespace=vpn")), "{r:?}");
}
