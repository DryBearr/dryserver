//! The VPN tab: the VPN for your own devices, its gateway and every
//! device, each with when it was last seen. Setting it up, adding and
//! taking off devices and turning it off sign the member list, and ask
//! for y first. A device whose key is made here gets its config whole,
//! with a QR code for the WireGuard app: shown once, never kept.

use std::path::PathBuf;

use ratatui::style::{Color, Style};

use super::{Act, Admin, Ask, Desk, Do, Entry, Row, Screen, Shown, Tab, dim, err, txt};
use crate::err::Result;
use crate::tui::app::Size;
use crate::tui::form::{Field, Form, Group, Status};
use crate::tui::frame::{self, Back, Focus, Notice, Page, col};
use crate::tui::theme::{self, Mark};
use crate::tui::{Doc, Key, Seg, plain};
use crate::{bail, errf, fsx, qr, registry, vpn};

/// A device seen this recently is connected (WireGuard shakes hands
/// every two minutes while a tunnel is up).
const CONNECTED: i64 = 180;

/// The gateway's answers, while they are given.
#[derive(Debug, Clone)]
pub struct PlanDraft {
    pub gateway: String,
    pub endpoint: String,
    pub port: String,
    pub public_port: String,
    pub subnet: String,
}

impl PlanDraft {
    fn of(p: Option<&vpn::Plan>, first: &str) -> PlanDraft {
        match p {
            Some(p) => PlanDraft {
                gateway: p.gateway.clone(),
                endpoint: p.endpoint.clone(),
                port: p.port.to_string(),
                public_port: if p.public_port == 0 { String::new() } else { p.public_port.to_string() },
                subnet: p.subnet.clone(),
            },
            None => PlanDraft {
                gateway: first.into(),
                endpoint: String::new(),
                port: vpn::DEFAULT_PORT.to_string(),
                public_port: String::new(),
                subnet: vpn::DEFAULT_SUBNET.into(),
            },
        }
    }

    fn plan(&self) -> Result<vpn::Plan> {
        let port = |s: &str, what: &str| s.trim().parse::<u16>().ok().filter(|p| *p > 0).ok_or_else(|| errf!("{what}: 1 to 65535"));
        Ok(vpn::Plan {
            gateway: self.gateway.clone(),
            port: port(&self.port, "the VPN's port")?,
            public_port: if self.public_port.trim().is_empty() { 0 } else { port(&self.public_port, "the port on your router")? },
            subnet: self.subnet.trim().to_string(),
            endpoint: self.endpoint.trim().to_ascii_lowercase(),
        })
    }
}

/// A new device's answers.
#[derive(Debug, Clone, Default)]
pub struct DeviceDraft {
    pub name: String,
    /// "here": its key is made on this computer; "own": the device made it.
    pub how: String,
    pub key: String,
}

/// A device's config on the screen, whole.
pub struct ShownView {
    name: String,
    conf: String,
    /// It holds the device's private key: shown once, never kept.
    private: bool,
    /// The text instead of the QR code.
    text: bool,
    /// esc was pressed once without the config written anywhere.
    armed: bool,
    wrote: Option<PathBuf>,
}

impl ShownView {
    pub fn new(name: String, conf: String, private: bool) -> ShownView {
        ShownView { name, conf, private, text: !private, armed: false, wrote: None }
    }

    #[cfg(test)]
    pub fn conf_for_tests(&self) -> &str {
        &self.conf
    }
}

/// Adds the device (its key made here when key is None) and puts its
/// config into shown. Nothing is signed when the key cannot be made.
pub fn add_device(admin: &mut Admin, desk: Option<&Desk>, name: &str, key: Option<String>, shown: &mut Option<Shown>) -> Result<String> {
    let Some(plan) = admin.vpn().cloned() else { bail!("set the VPN up first (g)") };
    let gateway_key = admin.machine_key(&plan.gateway).ok_or_else(|| errf!("the gateway {} is not in your signed list", plan.gateway))?;
    let (private, public) = match key {
        Some(k) => (None, k),
        None => {
            let d = desk.ok_or_else(|| errf!("this screen cannot make keys"))?;
            let (private, public) = (d.make_key)().map_err(|e| {
                errf!("{e}. Install wireguard-tools here, or let the device make its own key (its WireGuard app shows it)")
            })?;
            (Some(private), public)
        }
    };
    let (d, _) = admin.vpn_add(name, &public)?;
    let conf = vpn::client_config(&plan, &d, private.as_deref(), &gateway_key);
    *shown = Some(Shown::Device { name: name.into(), conf, private: private.is_some() });
    Ok(format!("{name} is on the VPN at {}; the gateway lets it in within a minute.", d.addr))
}

fn plan_form(d: PlanDraft, gateways: Vec<(String, String)>, mesh_port: String, clear: Vec<(String, String)>) -> Form<PlanDraft> {
    type D = PlanDraft;
    let mesh = mesh_port.clone();
    Form::new(
        d,
        vec![
            Group::new(vec![Field::select("Gateway", move |_| gateways.clone(), |d: &D| d.gateway.clone(), |d, v| d.gateway = v).desc(
                "The server your router forwards the VPN's port to; never the coordinator. It keeps running its apps; the VPN \
                 needs little (about 100 MB of memory).",
            )])
            .title("The gateway"),
            Group::new(vec![
                Field::input("Address for devices", |d: &D| d.endpoint.clone(), |d, v| d.endpoint = v)
                    .placeholder("203.0.113.7, or vpn.example.com")
                    .desc(
                        "Where devices find your home from the internet: your line's public IPv4 address (curl -s \
                         https://ifconfig.me shows it) or a DNS name kept pointed at it. If your router's WAN address is \
                         another one (100.64.x.x, 10.x.x.x...), your provider shares it (CGNAT) and no port forward reaches you.",
                    )
                    .validate(|v, _| {
                        if vpn::valid_endpoint(&v.trim().to_ascii_lowercase()) {
                            Ok(())
                        } else {
                            Err(errf!("an IPv4 address like 203.0.113.7, or a DNS name like vpn.example.com"))
                        }
                    }),
            ])
            .title("Where devices dial"),
            Group::new(vec![
                Field::input("The gateway's UDP port", |d: &D| d.port.clone(), |d, v| d.port = v)
                    .placeholder("51821")
                    .desc("The port the gateway listens on. Not the mesh's.")
                    .validate(move |v, _| match v.trim().parse::<u16>() {
                        Ok(p) if p.to_string() == mesh.trim() => Err(errf!("that is the mesh's port; the VPN needs one of its own")),
                        Ok(p) if p >= 1024 => Ok(()),
                        _ => Err(errf!("1024 to 65535")),
                    }),
                Field::input("The port on your router (optional)", |d: &D| d.public_port.clone(), |d, v| d.public_port = v)
                    .placeholder("the same")
                    .when_empty("the same")
                    .desc("Only when your router forwards another outside port to the gateway's.")
                    .validate(|v, _| match v.trim() {
                        "" => Ok(()),
                        v => match v.parse::<u16>() {
                            Ok(p) if p > 0 => Ok(()),
                            _ => Err(errf!("1 to 65535, or empty")),
                        },
                    }),
            ])
            .title("Ports"),
            Group::new(vec![
                Field::input("The devices' subnet", |d: &D| d.subnet.clone(), |d, v| d.subnet = v)
                    .placeholder(vpn::DEFAULT_SUBNET)
                    .desc("Private, and in use nowhere your devices go. The gateway is its first address.")
                    .validate(move |v, d| {
                        let p = vpn::Plan {
                            gateway: if d.gateway.is_empty() { "gateway".into() } else { d.gateway.clone() },
                            port: vpn::DEFAULT_PORT,
                            public_port: 0,
                            subnet: v.trim().into(),
                            endpoint: "example.com".into(),
                        };
                        p.check()?;
                        for (what, net) in &clear {
                            p.clashes(what, net)?;
                        }
                        Ok(())
                    }),
            ])
            .title("Subnet"),
        ],
        "cancel",
    )
    .done_label("sign it")
}

fn device_form(d: DeviceDraft, names: Vec<String>, keys: Vec<String>) -> Form<DeviceDraft> {
    type D = DeviceDraft;
    Form::new(
        d,
        vec![
            Group::new(vec![
                Field::input("Name", |d: &D| d.name.clone(), |d, v| d.name = v)
                    .placeholder("phone")
                    .desc("Lowercase letters, digits and -, at most 32: like phone or ana-laptop.")
                    .validate(move |v, _| {
                        let v = v.trim();
                        if !vpn::valid_device_name(v) {
                            bail!("lowercase letters, digits and -, at most 32");
                        }
                        if names.iter().any(|n| n == v) {
                            bail!("a device is called {v} already");
                        }
                        Ok(())
                    }),
                Field::select(
                    "Its key",
                    |_| {
                        vec![
                            ("Made here: its config shows next, with a QR code to scan".into(), "here".into()),
                            ("The device made its own: paste its public key".into(), "own".into()),
                        ]
                    },
                    |d: &D| d.how.clone(),
                    |d, v| d.how = v,
                ),
            ])
            .title("A new device"),
            Group::new(vec![
                Field::input("Its public key", |d: &D| d.key.clone(), |d, v| d.key = v)
                    .placeholder("44 characters ending in =")
                    .desc("In the WireGuard app: + (add a tunnel), Create from scratch; it shows the public key. Its private key stays on the device.")
                    .validate(move |v, _| {
                        let v = v.trim();
                        if !registry::valid_wg_key(v) {
                            bail!("not a WireGuard public key (44 characters of base64, ending in =)");
                        }
                        if keys.iter().any(|k| k == v) {
                            bail!("that key is another device's or a machine's: every device needs its own");
                        }
                        Ok(())
                    }),
            ])
            .title("Its own key")
            .hide_if(|d| d.how != "own"),
        ],
        "cancel",
    )
    .done_label("sign it")
}

impl Screen {
    fn device(&self, r: Option<Row>) -> Option<&vpn::Device> {
        match r {
            Some(Row::VpnDevice(i)) => self.view.devices.get(i),
            _ => None,
        }
    }

    /// The servers that may be the gateway: every signed one but the
    /// coordinator, as (label, name).
    fn gateways(&self) -> Vec<(String, String)> {
        let coord = self.coordinator_name();
        let now = (self.now)();
        self.view
            .servers
            .iter()
            .filter(|s| Some(&s.name) != coord.as_ref())
            .map(|s| {
                let mut about: Vec<String> = Vec::new();
                if !s.lan_ip.is_empty() {
                    about.push(s.lan_ip.clone());
                }
                // A server that is off cannot open the VPN: said before it is chosen.
                if let Some((m, _)) = self.view.members.iter().find(|(m, _)| m.name == s.name) {
                    let quiet = now.since(m.last_seen).num_seconds();
                    if m.last_seen.is_zero() {
                        about.push("never seen".into());
                    } else if quiet > super::STALE {
                        about.push(format!("silent for {}", crate::report::short_age(quiet as u64)));
                    }
                }
                let label = if about.is_empty() { s.name.clone() } else { format!("{} ({})", s.name, about.join(", ")) };
                (label, s.name.clone())
            })
            .collect()
    }

    fn lan_of(&self, name: &str) -> Option<String> {
        self.view.servers.iter().find(|s| s.name == name).map(|s| s.lan_ip.clone()).filter(|l| !l.is_empty())
    }

    /// What the gateway says about the VPN in its report.
    fn gateway_status(&self) -> Option<&vpn::Status> {
        let plan = self.view.vpn.as_ref()?;
        self.view.members.iter().find(|(m, _)| m.name == plan.gateway).and_then(|(m, _)| m.report.as_ref()).and_then(|r| r.vpn.as_ref())
    }

    /// How the VPN is, as a mark and words.
    fn gateway_state(&self) -> (Mark, String) {
        let Some(plan) = &self.view.vpn else {
            return match self.view.devices.len() {
                0 => (Mark::Off, "No VPN".into()),
                n => (Mark::Off, format!("Off; {n} device{} kept for it", if n == 1 { "" } else { "s" })),
            };
        };
        let gw = &plan.gateway;
        let Some((m, _)) = self.view.members.iter().find(|(m, _)| m.name == *gw) else {
            return (Mark::Bad, format!("{gw} is not on the coordinator's list of machines"));
        };
        let quiet = (self.now)().since(m.last_seen).num_seconds();
        if !m.last_seen.is_zero() && quiet > super::STALE {
            return (Mark::Bad, format!("{gw} is silent for {}", crate::report::short_age(quiet as u64)));
        }
        match self.gateway_status() {
            None => (Mark::Wait, format!("{gw} has not said it is up yet: within a minute, once it runs a dryserver with the VPN")),
            Some(s) if !s.problem.is_empty() => (Mark::Bad, format!("{gw}: not up: {}", s.problem)),
            Some(s) if !s.gateway => (Mark::Wait, format!("{gw}: not up yet")),
            Some(s) if !s.token => (Mark::Act, format!("{gw}: up; no token for the certificates yet (t), so browsers warn")),
            Some(_) => (Mark::Done, format!("{gw}: up, with the certificates' token")),
        }
    }

    /// When a device was last seen, as the gateway says.
    fn device_seen(&self, d: &vpn::Device) -> (Mark, String) {
        let Some(s) = self.gateway_status().filter(|s| s.gateway) else {
            return (Mark::Off, if self.view.vpn.is_none() { "the VPN is off".into() } else { "not known yet".into() });
        };
        let now = (self.now)().0.timestamp();
        match s.devices.iter().find(|x| !x.key.is_empty() && d.key.starts_with(&x.key)).map(|x| x.handshake) {
            Some(t) if t > 0 && now - t < CONNECTED => (Mark::Done, "connected".into()),
            Some(t) if t > 0 => (Mark::Off, format!("last seen {} ago", crate::tui::home::age((now - t).max(0) as u64))),
            Some(_) => (Mark::Wait, "never connected".into()),
            None => (Mark::Wait, "not on the gateway yet (within a minute)".into()),
        }
    }

    fn open_plan_form(&mut self) {
        let gateways = self.gateways();
        let first = gateways.first().map(|g| g.1.clone()).unwrap_or_default();
        let d = PlanDraft::of(self.view.vpn.as_ref(), &first);
        self.open_plan_form_with(d);
    }

    fn open_plan_form_with(&mut self, d: PlanDraft) {
        let Some(desk) = self.desk.clone() else { return };
        let clear = vec![("the mesh".to_string(), self.subnet.clone()), ("the home network".to_string(), desk.home.clone())];
        self.opened = None;
        self.entry = Some(Entry::Plan(plan_form(d, self.gateways(), desk.mesh_port.clone(), clear)));
    }

    fn plan_done(&mut self, d: PlanDraft) {
        let Some(desk) = self.desk.clone() else { return };
        let checked = d.plan().and_then(|p| {
            p.check()?;
            p.clashes("the mesh", &self.subnet)?;
            vpn::fits(&p, &self.view.servers, &self.coordinator_name().unwrap_or_default(), &desk.mesh_port, &desk.home)?;
            Ok(p)
        });
        let plan = match checked {
            Ok(p) => p,
            Err(e) => {
                self.notice = Some(Notice::bad(format!("Nothing was signed: {e}. Change it and enter again.")));
                self.open_plan_form_with(d);
                return;
            }
        };
        let old = self.view.vpn.clone();
        if let Some(c) = plan.cidr()
            && let Some(d) = self.view.devices.iter().find(|d| d.addr.parse().is_ok_and(|ip| !c.contains(ip)))
        {
            self.notice = Some(Notice::bad(format!(
                "Nothing was signed: {} has the address {}, outside {}. Keep the subnet, or take the devices off first (d).",
                d.name, d.addr, plan.subnet
            )));
            self.open_plan_form_with(d_draft(&plan));
            return;
        }
        if old.as_ref() == Some(&plan) {
            self.notice = Some(Notice::info("Nothing was signed: that is how the VPN is already."));
            return;
        }
        let gw = plan.gateway.clone();
        let lan = self.lan_of(&gw).map(|l| format!(" ({l})")).unwrap_or_default();
        let mut c = Vec::new();
        match &old {
            None => c.push(format!("{gw} opens the VPN within a minute, at {}; it keeps running its apps.", gateway_addr(&plan))),
            Some(o) if o.gateway != gw => c.push(format!(
                "{gw} opens it within a minute; {} closes it, and its certificates' token goes: {gw} needs it again (t).",
                o.gateway
            )),
            Some(_) => c.push(format!("{gw} follows within a minute.")),
        }
        c.push(format!("On your router: forward UDP port {} to {gw}{lan}, port {}.", plan.dial_port(), plan.port));
        if lan.is_empty() || old.as_ref().is_none_or(|o| o.gateway != gw) {
            c.push(format!("Give {gw} a fixed address on your network (a DHCP reservation in the router) if it has none."));
        }
        c.push(format!("Devices dial {}:{}.", plan.endpoint, plan.dial_port()));
        let moved = old.as_ref().is_some_and(|o| o.gateway != gw || o.endpoint != plan.endpoint || o.dial_port() != plan.dial_port());
        if moved && !self.view.devices.is_empty() {
            c.push("Each device needs its new config: c on it shows it (its [Peer] part changes; its own key stays).".into());
        }
        if old.is_none() {
            c.push("Then: the certificates' token on the gateway (t), and your devices (a).".into());
        }
        let question = match &old {
            None => format!("Make {gw} the VPN's gateway?"),
            Some(o) if o.gateway != gw => format!("Move the VPN to {gw}?"),
            Some(_) => "Change the VPN?".into(),
        };
        self.tab = Tab::Vpn;
        self.ask = Some(self.with_drops(Ask { question, consequences: c, act: Act::VpnOn(plan) }));
    }

    fn device_done(&mut self, d: DeviceDraft) {
        let Some(plan) = self.view.vpn.clone() else {
            self.notice = Some(Notice::bad("Nothing was signed: the VPN is off now."));
            return;
        };
        let name = d.name.trim().to_string();
        let addr = vpn::next_addr(&plan, &self.view.devices).map(|a| a.to_string()).unwrap_or_else(|| "?".into());
        let (key, how) = if d.how == "own" {
            (Some(d.key.trim().to_string()), "It keeps its own private key: its config shows next, for the [Peer] part in its app.")
        } else {
            (None, "Its key is made here: its config shows next, with a QR code. The private key is shown once and never kept.")
        };
        self.tab = Tab::Vpn;
        self.pick[Tab::Vpn.at()] = Some(format!("v:{name}"));
        self.ask = Some(self.with_drops(Ask {
            question: format!("Add {name} to the VPN?"),
            consequences: vec![format!("It gets the address {addr}; {} lets it in within a minute.", plan.gateway), how.into()],
            act: Act::AddDevice { name, key },
        }));
    }

    pub(super) fn plan_form_key(&mut self, mut f: Form<PlanDraft>, k: &Key) {
        f.update(k);
        match f.status {
            Status::Completed => self.plan_done(f.state.clone()),
            Status::Aborted => self.notice = Some(Notice::info("Nothing was signed.")),
            Status::Active => self.entry = Some(Entry::Plan(f)),
        }
    }

    pub(super) fn device_form_key(&mut self, mut f: Form<DeviceDraft>, k: &Key) {
        f.update(k);
        match f.status {
            Status::Completed => self.device_done(f.state.clone()),
            Status::Aborted => self.notice = Some(Notice::info("Nothing was signed.")),
            Status::Active => self.entry = Some(Entry::Device(f)),
        }
    }

    // ---- the actions ----

    pub(super) fn vpn_label(&self, d: Do, r: Option<Row>) -> String {
        let name = self.device(r).map(|d| d.name.clone()).unwrap_or_default();
        let gw = self.view.vpn.as_ref().map(|p| p.gateway.clone()).unwrap_or_else(|| "the gateway".into());
        match d {
            Do::Gateway if self.view.vpn.is_none() => "set the VPN up: its gateway and the address devices dial".into(),
            Do::Gateway => "change the gateway, the address devices dial or the ports".into(),
            Do::Token => format!("set the certificates' token on {gw} (over ssh; sudo asks there)"),
            Do::VpnOff => "turn the VPN off (the devices stay listed)".into(),
            Do::AddDevice => "add a device: a phone, a laptop".into(),
            Do::DeviceConfig => format!("show {name}'s config (without its private key)"),
            Do::RemoveDevice => format!("take {name} off the VPN"),
            _ => String::new(),
        }
    }

    /// Some: decided here, without the coordinator; None: the usual checks.
    pub(super) fn vpn_why_not(&self, d: Do, r: Option<Row>) -> Option<Option<String>> {
        let no_vpn = self.view.vpn.is_none();
        // The VPN may be changing: what shows now may not be what it becomes.
        let changing = self.queue.change().map(|w| format!("Still {w}: once that is done."));
        match d {
            Do::Token | Do::DeviceConfig if changing.is_some() => Some(changing),
            Do::Token => Some(if self.desk.is_none() {
                Some("This screen cannot reach the gateway: on it, sudo dryserver vpn token does.".into())
            } else if self.answered.is_none() {
                Some("The coordinator has not answered yet: wait for it.".into())
            } else if no_vpn {
                Some("Set the VPN up first (g).".into())
            } else {
                None
            }),
            Do::DeviceConfig => Some(match self.device(r) {
                None => Some("Select a device first (VPN tab).".into()),
                Some(_) if no_vpn => Some("The VPN is off: a config needs its gateway (g sets it up).".into()),
                Some(_) if self.view.gateway_key.is_empty() => Some("The gateway is not in your signed list.".into()),
                Some(_) => None,
            }),
            _ => None,
        }
    }

    pub(super) fn vpn_why_not_signed(&self, d: Do, r: Option<Row>) -> Option<String> {
        if self.desk.is_none() {
            return Some("This screen cannot change the VPN: dryserver vpn in a terminal does.".into());
        }
        let v = &self.view;
        match d {
            Do::Gateway if v.version == 0 => Some("Sign the coordinator first (Machines tab).".into()),
            Do::Gateway if self.gateways().is_empty() => {
                Some("The VPN needs a server besides the coordinator: approve one first (Machines tab).".into())
            }
            Do::Gateway => None,
            Do::VpnOff => no_vpn(v),
            Do::AddDevice => match &v.vpn {
                None => Some("Set the VPN up first (g): a device needs its gateway.".into()),
                Some(_) if v.devices.len() >= vpn::MAX_DEVICES => Some(format!("The VPN has the most devices it takes ({}).", vpn::MAX_DEVICES)),
                Some(p) if vpn::next_addr(p, &v.devices).is_none() => Some("The VPN's subnet has no free address left.".into()),
                Some(_) => None,
            },
            Do::RemoveDevice => self.device(r).is_none().then(|| "Select a device first (VPN tab).".into()),
            _ => None,
        }
    }

    pub(super) fn vpn_act(&mut self, d: Do, r: Option<Row>) -> Option<Ask> {
        let v = &self.view;
        match d {
            Do::Gateway => self.open_plan_form(),
            Do::Token => {
                let (Some(desk), Some(p)) = (self.desk.clone(), v.vpn.as_ref()) else { return None };
                let gw = p.gateway.clone();
                self.job = Some(crate::tui::Job {
                    title: format!("The VPN certificates' token, on {gw}"),
                    run: Box::new(move || (desk.token)(&gw)),
                });
            }
            Do::VpnOff => {
                let gw = v.vpn.as_ref().map(|p| p.gateway.clone()).unwrap_or_default();
                return Some(Ask {
                    question: "Turn the VPN off?".into(),
                    consequences: vec![
                        format!("{gw} closes it within a minute: no device reaches anything through it."),
                        "The devices stay listed, for when it is set up again.".into(),
                        "Apps with ENTRANCE=vpn keep running; their names reach nothing until then.".into(),
                    ],
                    act: Act::VpnOff,
                });
            }
            Do::AddDevice => {
                let names = v.devices.iter().map(|d| d.name.clone()).collect();
                let mut keys: Vec<String> = v.devices.iter().map(|d| d.key.clone()).collect();
                keys.extend(v.members.iter().map(|(m, _)| m.wg_key.clone()));
                self.opened = None;
                let draft = DeviceDraft { how: "here".into(), ..DeviceDraft::default() };
                self.entry = Some(Entry::Device(device_form(draft, names, keys)));
            }
            Do::DeviceConfig => {
                let (Some(p), Some(dev)) = (v.vpn.as_ref(), self.device(r)) else { return None };
                let conf = vpn::client_config(p, dev, None, &v.gateway_key);
                self.shown = Some(ShownView::new(dev.name.clone(), conf, false));
            }
            Do::RemoveDevice => {
                let dev = self.device(r).cloned().expect("why_not checked it");
                let gw = v.vpn.as_ref().map(|p| p.gateway.clone()).unwrap_or_else(|| "The gateway".into());
                return Some(Ask {
                    question: format!("Take {} off the VPN?", dev.name),
                    consequences: vec![
                        format!("{gw} forgets its key within a minute: {} reaches nothing through it any more.", dev.name),
                        "Delete the tunnel in its WireGuard app too.".into(),
                    ],
                    act: Act::RemoveDevice(dev.name),
                });
            }
            _ => {}
        }
        None
    }

    /// The terminal is back from the token.
    pub(super) fn token_back(&mut self, res: Result<()>) {
        let gw = self.view.vpn.as_ref().map(|p| p.gateway.clone()).unwrap_or_else(|| "the gateway".into());
        self.notice = Some(match res {
            Ok(()) => Notice::ok(format!(
                "The token is on {gw}: the certificates come from Let's Encrypt within a few minutes. This tab says so once {gw} reports it."
            )),
            Err(e) => Notice::bad(format!("The token was not set: {}", super::words(&e.to_string()))),
        });
        self.look();
    }

    // ---- a device's config ----

    pub(super) fn shown_key(&mut self, k: Key) -> crate::tui::Flow {
        let Some(sv) = self.shown.as_mut() else { return crate::tui::Flow::Continue };
        let armed = std::mem::take(&mut sv.armed);
        self.notice = None;
        match k {
            Key::Tab | Key::BackTab if sv.private => sv.text = !sv.text,
            Key::Char('w') => {
                let Some(dir) = self.desk.as_ref().and_then(|d| d.files.clone()) else {
                    self.notice = Some(Notice::bad("There is no home folder to write it in."));
                    return crate::tui::Flow::Continue;
                };
                // The WireGuard apps name the tunnel after the file. Never
                // over a file that is there: it may hold a key still needed.
                let path = dir.join(format!("dryserver-{}.conf", sv.name));
                self.notice = Some(if path.symlink_metadata().is_ok() {
                    Notice::bad(format!("Not written: there is a file at {} already; move it away first.", path.display()))
                } else {
                    match fsx::create_file(&path, &sv.conf, 0o600) {
                        Ok(()) => {
                            sv.wrote = Some(path.clone());
                            Notice::ok(format!("Wrote {} (yours alone): import it in the WireGuard app, then delete it.", path.display()))
                        }
                        Err(e) => Notice::bad(format!("Not written: {e}")),
                    }
                });
            }
            Key::Esc | Key::Enter if sv.private && sv.wrote.is_none() && !armed => {
                sv.armed = true;
                self.notice = Some(Notice::bad(format!(
                    "{} again closes it, and {}'s private key is gone: dryserver keeps it nowhere. w writes the config to a file first.",
                    k.name(),
                    sv.name
                )));
            }
            Key::Esc | Key::Enter => {
                let name = sv.name.clone();
                self.shown = None;
                self.notice = Some(Notice::info(format!("{name}'s config is closed.")));
            }
            _ => {}
        }
        crate::tui::Flow::Continue
    }

    pub(super) fn shown_page(&self, sv: &ShownView, page: &mut Page, size: Size) {
        let p = theme::palette();
        let mut b = Doc::new();
        frame::section(&mut b, &format!("{}'s config, for the WireGuard app", sv.name), None);
        let mut qr_fits = false;
        if sv.private && !sv.text {
            let lines: Vec<String> =
                qr::encode(vpn::qr_text(&sv.conf).as_bytes()).map(|c| qr::terminal(&c).lines().map(String::from).collect()).unwrap_or_default();
            let wide = lines.iter().map(|l| l.chars().count()).max().unwrap_or(0);
            // The code whole, with the lines above and below it.
            qr_fits = !lines.is_empty() && wide <= size.width && lines.len() + 6 <= size.rows;
            if qr_fits {
                b.add(txt("Scan it in the WireGuard app: + (add a tunnel), Scan from QR code.")).nl();
                // Light modules light and dark ones dark, whatever the
                // theme; without colours (NO_COLOR) as the terminal has it.
                let code = if p.tier == theme::Tier::Plain { Style::new() } else { Style::new().fg(Color::White).bg(Color::Black) };
                for l in lines {
                    b.add(Seg(l, code)).nl();
                }
            } else if lines.is_empty() {
                b.add(err("The config is too long for a QR code: tab shows it as text, w writes it to a file.")).nl();
            } else {
                b.add(err(format!(
                    "The QR code needs a window of {} columns and {} rows: make it bigger, or tab shows the config as text.",
                    wide + 8,
                    lines.len() + 10
                )))
                .nl();
            }
        } else {
            if !sv.private {
                b.add(txt(
                    "Type it into the device's WireGuard app, or change its tunnel to this: its own private key stays as it is.",
                ))
                .nl();
            }
            b.nl();
            for l in sv.conf.lines() {
                b.add(Seg(l.to_string(), if l.starts_with('#') { p.hint() } else { p.text() })).nl();
            }
        }
        b.nl();
        if sv.private {
            b.add(err(format!(
                "It holds {}'s private key, which dryserver does not keep: once this closes, it is gone. Lost: take the device off (d) \
                 and add it again.",
                sv.name
            )))
            .nl();
        }
        if let Some(path) = &sv.wrote {
            b.add(dim(format!("Written to {}: delete it once the device has it.", path.display()))).nl();
        }
        page.body = b;
        page.focus = Some(Focus::keep(0..1));
        if sv.private {
            page.key("tab", if sv.text || !qr_fits { "QR code" } else { "as text" });
        }
        page.key("w", "write to a file").key("esc", "done");
        page.back = Back::Nothing;
        page.help = None;
    }

    // ---- the page ----

    pub(super) fn vpn_body(&self, w: usize) -> (Doc, Option<Focus>) {
        let p = theme::palette();
        let mut b = Doc::new();
        self.top_cards(&mut b, w);
        if self.answered.is_none() {
            return (b, None);
        }
        let v = &self.view;
        let sel = self.selected();
        let mut focus = None;
        frame::section(&mut b, "VPN", None);
        let (mark, state) = self.gateway_state();
        if sel == Some(Row::Gateway) {
            focus = Some(Focus::row(b.lines.len() - 1));
        }
        b.append(frame::row(w, mark, vec![col(Seg(state, p.text()), 0)])).nl();
        match &v.vpn {
            None => {
                b.add(dim(
                    "Your phones and laptops reach the apps you choose (ENTRANCE=vpn) over a WireGuard VPN of their own, from \
                     anywhere: nothing else on your network. g sets it up, on a server your router forwards one UDP port to.",
                ))
                .nl();
            }
            Some(plan) => {
                let lan = self.lan_of(&plan.gateway).unwrap_or_else(|| "its address".into());
                b.add(dim(format!("   Devices dial {}:{}", plan.endpoint, plan.dial_port()))).nl();
                b.add(dim(format!("   Your router forwards UDP {} to {} ({lan}), port {}", plan.dial_port(), plan.gateway, plan.port))).nl();
                b.add(dim(format!("   Subnet {}; the gateway is {} on it", plan.subnet, gateway_addr(plan)))).nl();
            }
        }
        frame::section(&mut b, "Devices", Some(v.devices.len()));
        if v.devices.is_empty() {
            b.append(frame::empty(if v.vpn.is_none() { "No devices." } else { "No devices yet. a adds one: a phone, a laptop." })).nl();
        }
        for (i, d) in v.devices.iter().enumerate() {
            if sel == Some(Row::VpnDevice(i)) {
                focus = Some(Focus::row(b.lines.len() - 1));
            }
            let (m, seen) = self.device_seen(d);
            b.append(frame::row(
                w,
                m,
                vec![col(Seg(d.name.clone(), p.text()), 16), col(Seg(d.addr.clone(), p.hint()), 15), col(Seg(seen, p.hint()), 0)],
            ))
            .nl();
        }
        b.nl();
        b.add(dim("On the VPN, a device reaches the apps with ENTRANCE=vpn, on https, and nothing else.")).nl();
        (b, focus)
    }

    /// The sheet's words about the VPN; returns its title.
    pub(super) fn gateway_about(&self, about: &mut Vec<Vec<Seg>>) -> String {
        let v = &self.view;
        let (mark, state) = self.gateway_state();
        about.push(vec![theme::mark(mark), plain(" "), txt(state)]);
        match &v.vpn {
            None => {
                if !v.devices.is_empty() {
                    let names: Vec<&str> = v.devices.iter().map(|d| d.name.as_str()).collect();
                    about.push(vec![dim(format!("Kept for it: {}.", names.join(", ")))]);
                }
                about.push(vec![txt("Set up, a device on it reaches the apps with ENTRANCE=vpn, on https, and nothing else.")]);
            }
            Some(plan) => {
                let lan = self.lan_of(&plan.gateway).unwrap_or_else(|| "?".into());
                about.push(Vec::new());
                about.push(vec![txt(format!("Gateway {} at {lan} on your network; on the VPN {}.", plan.gateway, gateway_addr(plan)))]);
                about.push(vec![txt(format!("Devices dial {}:{}.", plan.endpoint, plan.dial_port()))]);
                about.push(vec![txt(format!(
                    "Your router forwards UDP {} to {} ({lan}), port {}: only this one port.",
                    plan.dial_port(),
                    plan.gateway,
                    plan.port
                ))]);
                about.push(vec![dim(format!("Subnet {}. The devices' configs have no DNS server: with the VPN down, only its apps stop.", plan.subnet))]);
                if self.gateway_status().is_some_and(|s| s.gateway && !s.token) {
                    about.push(Vec::new());
                    about.push(vec![err(
                        "No token for the certificates yet: browsers warn until it is there. t sets it on the gateway: a Cloudflare \
                         token with Zone: DNS: Edit and Zone: Zone: Read, for your apps' domains only.",
                    )]);
                }
            }
        }
        "VPN".into()
    }

    /// The sheet's words about device i; returns its title.
    pub(super) fn device_about(&self, i: usize, about: &mut Vec<Vec<Seg>>) -> String {
        let Some(d) = self.view.devices.get(i) else { return String::new() };
        let (mark, seen) = self.device_seen(d);
        about.push(vec![theme::mark(mark), plain(" "), txt(seen)]);
        about.push(vec![txt(format!("Address {} on the VPN.", d.addr))]);
        about.push(vec![dim(format!("Its public key {}", d.key))]);
        about.push(vec![dim("Its private key is on the device alone: c shows its config without it.")]);
        d.name.clone()
    }
}

/// The form's answers again, from a plan.
fn d_draft(p: &vpn::Plan) -> PlanDraft {
    PlanDraft::of(Some(p), &p.gateway)
}

/// The gateway's VPN address, in words.
fn gateway_addr(p: &vpn::Plan) -> String {
    p.gateway_addr().map(|a| a.to_string()).unwrap_or_else(|| "?".into())
}

fn no_vpn(v: &crate::admin::View) -> Option<String> {
    v.vpn.is_none().then(|| "The VPN is not set up.".into())
}
