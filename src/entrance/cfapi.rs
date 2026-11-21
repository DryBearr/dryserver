//! The Cloudflare API, from the desktop, with the admin's API token.
//!
//! There is no HTTP library here: curl runs on the desktop with all its
//! options on stdin (`curl --config -`), so the token never shows in a
//! command line. HTTPS only (redirects too), TLS 1.2 or newer, a time
//! limit per request and a cap on the answer, which this side enforces as
//! well. Everything Cloudflare answers is checked before it is used: ids
//! before they go into a path, names before they are compared, messages
//! before they are shown.
//!
//! The Http trait is the seam: tests talk to a fake Cloudflare.

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::ctx::Ctx;
use crate::err::{Error, Kind, Result};
use crate::runner::{Cmd, Runner};
use crate::{apps, bail, errf};

pub const BASE: &str = "https://api.cloudflare.com/client/v4";
/// The most one answer may be. A zone's records, a page at a time, stay
/// far below.
pub const MAX_BODY: usize = 4 << 20;
/// Seconds one request may take, connecting included.
const REQUEST_SECONDS: u32 = 30;
/// Pages read of one listing at most.
const MAX_PAGES: u32 = 20;
/// How often a request that Cloudflare answered with 429 (too many) is
/// tried again, waiting 1, 2, then 4 seconds.
const RETRIES: u32 = 3;

/// The permissions the token needs, as the dashboard names them.
pub const NEED_ZONE_READ: &str = "Zone: Zone: Read";
pub const NEED_DNS: &str = "Zone: DNS: Edit";
pub const NEED_TUNNEL: &str = "Account: Cloudflare Tunnel: Edit";

/// One request to the Cloudflare API.
pub trait Http: Send + Sync {
    /// method and path under BASE, with an optional JSON body. Returns
    /// the HTTP status and the body.
    fn call(&self, ctx: &Ctx, method: &str, path: &str, body: Option<&str>) -> Result<(u16, String)>;
}

/// An API token as Cloudflare makes them: letters, digits, - and _.
pub fn valid_api_token(t: &str) -> Result<()> {
    let ok = (20..=200).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    if ok { Ok(()) } else { Err("not a Cloudflare API token (copy it from My Profile, API Tokens, after you create it)".into()) }
}

/// A string for curl's config file: in double quotes, with \ and "
/// escaped. Nothing else needs it: what goes in is checked or JSON.
fn quoted(s: &str) -> String {
    let mut q = String::with_capacity(s.len() + 2);
    q.push('"');
    for c in s.chars() {
        match c {
            '\\' => q.push_str("\\\\"),
            '"' => q.push_str("\\\""),
            '\n' => q.push_str("\\n"),
            '\r' => q.push_str("\\r"),
            '\t' => q.push_str("\\t"),
            c => q.push(c),
        }
    }
    q.push('"');
    q
}

/// curl on the desktop.
pub struct Curl {
    pub token: String,
    pub run: Arc<dyn Runner>,
}

impl Curl {
    /// What curl reads from stdin: the whole request.
    fn config(&self, method: &str, path: &str, body: Option<&str>) -> String {
        self.config_at(BASE, method, path, body)
    }

    fn config_at(&self, base: &str, method: &str, path: &str, body: Option<&str>) -> String {
        let mut c = String::new();
        let mut line = |k: &str, v: &str| c.push_str(&format!("{k} = {}\n", quoted(v)));
        line("url", &format!("{base}{path}"));
        line("request", method);
        line("header", &format!("Authorization: Bearer {}", self.token));
        line("header", "Accept: application/json");
        if let Some(b) = body {
            line("header", "Content-Type: application/json");
            line("data-raw", b);
        }
        line("proto", "=https");
        line("proto-redir", "=https");
        line("max-time", &REQUEST_SECONDS.to_string());
        line("connect-timeout", "10");
        line("max-filesize", &MAX_BODY.to_string());
        line("write-out", "\n%{http_code}");
        c.push_str("tlsv1.2\nsilent\nshow-error\n");
        c
    }
}

/// What curl's exit code means for the admin.
fn curl_failure(code: Option<u32>) -> String {
    match code {
        Some(6) => "cannot find api.cloudflare.com (is this computer online?)".into(),
        Some(7) => "cannot connect to api.cloudflare.com".into(),
        Some(28) => format!("Cloudflare did not answer within {REQUEST_SECONDS}s"),
        Some(35 | 51 | 53 | 54 | 58 | 59 | 60 | 66 | 77 | 80 | 83 | 90 | 91) => {
            "the secure connection to api.cloudflare.com failed (its certificate, or something in between)".into()
        }
        Some(63) => format!("Cloudflare's answer is longer than {} MiB; not read", MAX_BODY >> 20),
        Some(c) => format!("curl failed with exit status {c}"),
        None => "curl failed".into(),
    }
}

impl Http for Curl {
    fn call(&self, ctx: &Ctx, method: &str, path: &str, body: Option<&str>) -> Result<(u16, String)> {
        // -q first: the user's ~/.curlrc has no say.
        let cmd = Cmd::new("curl", &["-q", "--config", "-"]).stdin(self.config(method, path, body)).quiet().stdout_only();
        let (out, res) = self.run.run(ctx, &cmd);
        if let Err(e) = res {
            if let Some(why) = ctx.err() {
                return Err(why);
            }
            let msg = e.to_string();
            let code = msg.rsplit("exit status ").next().and_then(|c| c.trim().parse().ok()).filter(|_| msg.contains("exit status"));
            if msg.contains("executable file not found") {
                bail!("curl is not installed on this computer");
            }
            bail!("{}", curl_failure(code));
        }
        if out.len() > MAX_BODY + 16 {
            bail!("{}", curl_failure(Some(63)));
        }
        let (body, code) = out.rsplit_once('\n').unwrap_or(("", out.as_str()));
        let status: u16 = code.trim().parse().map_err(|_| errf!("curl gave no HTTP status"))?;
        if status == 0 {
            bail!("no answer from api.cloudflare.com");
        }
        Ok((status, body.to_string()))
    }
}

/// Cloudflare's words, made safe to show: no control characters, short.
pub fn clean(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(200).collect()
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Message {
    code: i64,
    message: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Info {
    total_pages: u32,
}

#[derive(Deserialize)]
struct Envelope<T> {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    errors: Vec<Message>,
    result: Option<T>,
    #[serde(default)]
    result_info: Option<Info>,
}

/// The API, call by call, with what each one needs from the token.
pub struct Api<'a> {
    pub http: &'a dyn Http,
    pub ctx: &'a Ctx,
}

impl Api<'_> {
    /// One call, tried again when Cloudflare says "too many requests".
    /// need names the permission a refusal points at.
    fn call<T: DeserializeOwned>(&self, method: &str, path: &str, body: Option<&str>, need: &str) -> Result<(T, Option<Info>)> {
        let mut wait = Duration::from_secs(1);
        let mut tries = 0;
        let (status, text) = loop {
            let (status, text) = self.http.call(self.ctx, method, path, body)?;
            if status != 429 || tries == RETRIES {
                break (status, text);
            }
            tries += 1;
            self.ctx.sleep(wait)?;
            wait *= 2;
        };
        let env: Option<Envelope<T>> = serde_json::from_str(&text).ok();
        let said = env
            .as_ref()
            .and_then(|e| e.errors.first())
            .map(|m| format!("{} (code {})", clean(&m.message), m.code))
            .unwrap_or_else(|| format!("HTTP {status}"));
        match status {
            200..=299 => {}
            401 | 403 => {
                return Err(Error::with_kind(
                    Kind::Rejected,
                    format!("Cloudflare refused: {said}. The API token needs the permission {need}, or it was revoked"),
                ));
            }
            429 => bail!("Cloudflare asks to slow down (too many requests); try again in a minute"),
            500..=599 => bail!("Cloudflare is having trouble ({said}); the tunnel keeps running, try again later"),
            _ => bail!("Cloudflare said no: {said}"),
        }
        let env = env.ok_or_else(|| errf!("Cloudflare's answer is not what the API answers ({method} {})", path_name(path)))?;
        if !env.success {
            bail!("Cloudflare said no: {said}");
        }
        let result = env.result.ok_or_else(|| errf!("Cloudflare's answer has no result ({method} {})", path_name(path)))?;
        Ok((result, env.result_info))
    }

    pub fn get<T: DeserializeOwned>(&self, path: &str, need: &str) -> Result<T> {
        self.call("GET", path, None, need).map(|(t, _)| t)
    }

    pub fn send<T: DeserializeOwned>(&self, method: &str, path: &str, body: &serde_json::Value, need: &str) -> Result<T> {
        self.call(method, path, Some(&body.to_string()), need).map(|(t, _)| t)
    }

    pub fn delete<T: DeserializeOwned>(&self, path: &str, need: &str) -> Result<T> {
        self.call("DELETE", path, None, need).map(|(t, _)| t)
    }

    /// Every page of a listing. path has its query, without page.
    pub fn list<T: DeserializeOwned>(&self, path: &str, need: &str) -> Result<Vec<T>> {
        let mut all = Vec::new();
        for page in 1..=MAX_PAGES {
            let sep = if path.contains('?') { '&' } else { '?' };
            let (items, info): (Vec<T>, _) = self.call("GET", &format!("{path}{sep}page={page}"), None, need)?;
            let empty = items.is_empty();
            all.extend(items);
            if empty || info.is_none_or(|i| page >= i.total_pages) {
                return Ok(all);
            }
        }
        bail!("Cloudflare's list at {} goes on for more than {MAX_PAGES} pages; not read", path_name(path))
    }
}

/// The path without its query, for messages.
fn path_name(path: &str) -> &str {
    path.split('?').next().unwrap_or(path)
}

/// Ids Cloudflare hands out: 32 hex digits for zones, accounts and
/// records, a UUID for tunnels. Checked before they go into a path.
pub fn valid_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn valid_uuid(s: &str) -> bool {
    s.len() == 36 && s.bytes().enumerate().all(|(i, b)| if matches!(i, 8 | 13 | 18 | 23) { b == b'-' } else { b.is_ascii_hexdigit() })
}

/// A host name from Cloudflare, lower case, if it is one.
pub fn host(s: &str) -> Option<String> {
    let h = s.trim_end_matches('.').to_ascii_lowercase();
    (apps::valid_host(&h).is_ok() && !h.is_empty()).then_some(h)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::runner::Cmd;
    use std::sync::Mutex;

    pub const API_TOKEN: &str = "Zx9_secret-api-token-0123456789abcdefABCD";

    /// A runner that plays curl: records what it was given and answers.
    struct FakeCurl {
        got: Mutex<Vec<Cmd>>,
        answer: Mutex<(String, Result<()>)>,
    }

    impl Runner for FakeCurl {
        fn run(&self, _: &Ctx, c: &Cmd) -> (String, Result<()>) {
            self.got.lock().unwrap().push(c.clone());
            self.answer.lock().unwrap().clone()
        }
    }

    #[test]
    fn the_token_never_shows_in_a_command_line() {
        let fake = Arc::new(FakeCurl { got: Mutex::default(), answer: Mutex::new(("{\"ok\":1}\n200".into(), Ok(()))) });
        let curl = Curl { token: API_TOKEN.into(), run: fake.clone() };
        let body = r#"{"name":"a \"quoted\" \\ name"}"#;
        let (status, text) = curl.call(&Ctx::new(), "POST", "/zones?name=example.com", Some(body)).unwrap();
        assert_eq!((status, text.as_str()), (200, "{\"ok\":1}"));
        let c = fake.got.lock().unwrap()[0].clone();
        assert_eq!((c.name.as_str(), c.args.clone()), ("curl", vec!["-q".to_string(), "--config".into(), "-".into()]));
        assert!(c.quiet && c.stdout_only, "nothing of it is logged");
        for want in [
            "url = \"https://api.cloudflare.com/client/v4/zones?name=example.com\"\n",
            "request = \"POST\"\n",
            &format!("header = \"Authorization: Bearer {API_TOKEN}\"\n"),
            "data-raw = \"{\\\"name\\\":\\\"a \\\\\\\"quoted\\\\\\\" \\\\\\\\ name\\\"}\"\n",
            "proto = \"=https\"\n",
            "proto-redir = \"=https\"\n",
            "tlsv1.2\n",
            "max-time = \"30\"\n",
            "max-filesize = \"4194304\"\n",
            "write-out = \"\\n%{http_code}\"\n",
        ] {
            assert!(c.stdin.contains(want), "config missing {want:?}:\n{}", c.stdin);
        }
        assert!(!c.args.iter().any(|a| a.contains(API_TOKEN)));
        // A GET has no body.
        curl.call(&Ctx::new(), "GET", "/user/tokens/verify", None).unwrap();
        assert!(!fake.got.lock().unwrap()[1].stdin.contains("data-raw"));
    }

    #[test]
    fn real_curl_reads_the_config() {
        // Every option name and quoting as curl itself reads them, against
        // a port where nothing listens (never Cloudflare). Plain HTTP is
        // refused outright.
        use crate::runner::ExecRunner;
        if std::process::Command::new("curl").arg("--version").output().is_err() {
            return;
        }
        let curl = Curl { token: API_TOKEN.into(), run: Arc::new(ExecRunner::silent()) };
        let run = |base: &str| {
            let cmd =
                Cmd::new("curl", &["-q", "--config", "-"]).stdin(curl.config_at(base, "PUT", "/x", Some(r#"{"a":"\"q\" \\"}"#))).quiet();
            ExecRunner::silent().run(&Ctx::new(), &cmd).1.unwrap_err().to_string()
        };
        assert!(run("https://127.0.0.1:9").contains("exit status 7"), "curl did not take the config: {}", run("https://127.0.0.1:9"));
        assert!(run("http://127.0.0.1:9").contains("exit status 1"), "plain HTTP must be refused: {}", run("http://127.0.0.1:9"));
    }

    #[test]
    fn what_curl_says_when_it_fails() {
        let fake =
            Arc::new(FakeCurl { got: Mutex::default(), answer: Mutex::new((String::new(), Err("curl failed: exit status 28".into()))) });
        let curl = Curl { token: API_TOKEN.into(), run: fake.clone() };
        let e = curl.call(&Ctx::new(), "GET", "/x", None).unwrap_err().to_string();
        assert!(e.contains("did not answer within 30s"), "{e}");
        *fake.answer.lock().unwrap() = (String::new(), Err("curl failed: exit status 60".into()));
        assert!(curl.call(&Ctx::new(), "GET", "/x", None).unwrap_err().to_string().contains("secure connection"));
        *fake.answer.lock().unwrap() = (String::new(), Err("exec: \"curl\": executable file not found in $PATH".into()));
        assert!(curl.call(&Ctx::new(), "GET", "/x", None).unwrap_err().to_string().contains("curl is not installed"));
        // Too long, also when curl did not stop it.
        *fake.answer.lock().unwrap() = ("x".repeat(MAX_BODY + 100) + "\n200", Ok(()));
        assert!(curl.call(&Ctx::new(), "GET", "/x", None).unwrap_err().to_string().contains("longer than 4 MiB"));
        *fake.answer.lock().unwrap() = ("no status".into(), Ok(()));
        assert!(curl.call(&Ctx::new(), "GET", "/x", None).is_err());
        // The screen closed: the cancel is the answer.
        let done = Ctx::new();
        done.cancel();
        *fake.answer.lock().unwrap() = (String::new(), Err("curl failed: signal: killed".into()));
        assert!(curl.call(&done, "GET", "/x", None).unwrap_err().is_canceled());
    }

    /// Answers each call from a list, in order.
    pub struct Script(pub Mutex<Vec<(u16, String)>>, pub Mutex<usize>);

    impl Http for Script {
        fn call(&self, _: &Ctx, _: &str, _: &str, _: Option<&str>) -> Result<(u16, String)> {
            *self.1.lock().unwrap() += 1;
            let mut l = self.0.lock().unwrap();
            if l.is_empty() { Ok((500, String::new())) } else { Ok(l.remove(0)) }
        }
    }

    fn script(answers: &[(u16, &str)]) -> Script {
        Script(Mutex::new(answers.iter().map(|(s, b)| (*s, b.to_string())).collect()), Mutex::new(0))
    }

    #[test]
    fn answers_and_refusals() {
        let ctx = Ctx::new();
        let ok = r#"{"success":true,"errors":[],"result":{"id":"x","status":"active"}}"#;
        // Too many requests: tried again after a wait, a bounded number of times.
        let s = script(&[(429, ""), (429, ""), (200, ok)]);
        let start = std::time::Instant::now();
        let v: serde_json::Value = Api { http: &s, ctx: &ctx }.get("/user/tokens/verify", "x").unwrap();
        assert_eq!(v["status"], "active");
        assert!(start.elapsed() >= Duration::from_secs(3), "waited 1 then 2 seconds");
        let s = script(&[(429, ""); 5]);
        let short = ctx.with_timeout(Duration::from_millis(1500));
        assert!(Api { http: &s, ctx: &short }.get::<serde_json::Value>("/x", "x").is_err());
        assert!(*s.1.lock().unwrap() <= 2, "the wait stops with ctx");
        // A missing permission says which.
        let s = script(&[(403, r#"{"success":false,"errors":[{"code":10000,"message":"Authentication error\u001b[2J"}]}"#)]);
        let e = Api { http: &s, ctx: &ctx }.get::<serde_json::Value>("/zones/x/dns_records", NEED_DNS).unwrap_err();
        assert!(e.is(Kind::Rejected), "{e}");
        let e = e.to_string();
        assert!(e.contains("Authentication error") && e.contains("Zone: DNS: Edit") && !e.contains('\u{1b}'), "{e}");
        // An outage keeps the tunnel: the message says so.
        let s = script(&[(502, "<html>bad gateway</html>")]);
        let e = Api { http: &s, ctx: &ctx }.get::<serde_json::Value>("/x", "x").unwrap_err().to_string();
        assert!(e.contains("having trouble (HTTP 502)") && e.contains("tunnel keeps running"), "{e}");
        // Success without success, or without a result.
        let s = script(&[
            (200, r#"{"success":false,"errors":[{"code":7003,"message":"no route"}]}"#),
            (200, r#"{"success":true}"#),
            (200, "[]"),
        ]);
        let api = Api { http: &s, ctx: &ctx };
        assert!(api.get::<serde_json::Value>("/x", "x").unwrap_err().to_string().contains("no route (code 7003)"));
        assert!(api.get::<serde_json::Value>("/x", "x").unwrap_err().to_string().contains("no result"));
        assert!(api.get::<serde_json::Value>("/x", "x").is_err());
    }

    #[test]
    fn listings_page_by_page() {
        let ctx = Ctx::new();
        let page = |items: &str, pages: u32| format!(r#"{{"success":true,"result":[{items}],"result_info":{{"total_pages":{pages}}}}}"#);
        let s = script(&[(200, &page("1,2", 2)), (200, &page("3", 2))]);
        let got: Vec<u32> = Api { http: &s, ctx: &ctx }.list("/zones?per_page=2", "x").unwrap();
        assert_eq!(got, vec![1, 2, 3]);
        // A listing that claims to go on for ever is cut.
        let pages: Vec<(u16, String)> = (0..MAX_PAGES + 2).map(|_| (200, page("1", 1000))).collect();
        let s = Script(Mutex::new(pages), Mutex::new(0));
        assert!(Api { http: &s, ctx: &ctx }.list::<u32>("/zones", "x").unwrap_err().to_string().contains("more than 20 pages"));
    }

    #[test]
    fn checked_before_use() {
        assert!(valid_id("023e105f4ecef8ad9ca31a8372d0c353") && !valid_id("023e105f4ecef8ad9ca31a8372d0c35/") && !valid_id(""));
        assert!(valid_uuid("f70ff985-a4ef-4643-bbbc-4a0ed4fc8415") && !valid_uuid("f70ff985-a4ef-4643-bbbc-4a0ed4fc841/"));
        assert!(!valid_uuid("../../accounts/x/cfd_tunnel/aaaaaaaaaaaaaaaaaa"));
        assert_eq!(host("Blog.Example.com."), Some("blog.example.com".into()));
        assert_eq!(host("bad name.example.com"), None);
        assert_eq!(host(""), None);
        valid_api_token(API_TOKEN).unwrap();
        for bad in
            ["", "short", "has space aaaaaaaaaaaaaaaaaaaaaaaaaa", "quote\"aaaaaaaaaaaaaaaaaaaaaaaa", "line\naaaaaaaaaaaaaaaaaaaaaaaaaaa"]
        {
            assert!(valid_api_token(bad).is_err(), "{bad:?}");
        }
    }
}
