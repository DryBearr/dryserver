//! An app as a file the admin keeps and edits, read by `dryserver app
//! deploy FILE` and written by `dryserver app show NAME`. Plain lines in
//! the style of config.env:
//!
//! ```text
//! NAME=shop
//! IMAGE=ghcr.io/you/shop:v1
//! PORT=8080
//! COPIES=2
//! HOST=shop.example.com
//! HOST=www.example.com example.com
//! HOST=admin.example.com:9000
//! ```
//!
//! - NAME, IMAGE and PORT are needed; COPIES is 1 and ENTRANCE cloudflare
//!   unless the file says otherwise.
//! - HOST may come as often as needed, with one or more names on a line
//!   (spaces or commas between). A name without a port leads to PORT;
//!   name:port leads to another port of the app.
//! - Keys may be written in any case. A line starting with # is a
//!   comment, and so is what follows " #" on a line.
//! - Anything the reader does not know is refused, not passed over: a
//!   key it skipped would start the app without what the admin wrote.

use crate::apps::{self, App, Host};
use crate::entrance;
use crate::err::Result;
use crate::{bail, errf};

/// Larger than any app file needs.
pub const MAX_LEN: usize = 64 << 10;

const KEYS: [&str; 12] = ["NAME", "IMAGE", "REPO", "BRANCH", "PORT", "COPIES", "HOST", "ENTRANCE", "ENV", "SECRET", "MEMORY", "CPU"];

/// Reads an app file. Errors name the line.
pub fn parse(text: &str) -> Result<App> {
    if text.len() > MAX_LEN {
        bail!("an app file is at most {} KiB; this one is larger", MAX_LEN >> 10);
    }
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    // key -> (value, line)
    let mut one: std::collections::BTreeMap<&str, (String, usize)> = std::collections::BTreeMap::new();
    // (name, port as written, line)
    let mut hosts: Vec<(String, Option<u16>, usize)> = Vec::new();
    // (name, value, line)
    let mut env: Vec<(String, String, usize)> = Vec::new();
    let mut secrets: Vec<(String, usize)> = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let n = i + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            bail!("line {n}: KEY=value expected, like NAME=shop");
        };
        let key = k.trim().to_ascii_uppercase();
        let Some(key) = KEYS.iter().find(|x| **x == key) else {
            let hint = if key == "HOSTS" { " (one HOST= per line, or several names after one HOST=)" } else { "" };
            bail!("line {n}: {} is not a key of an app file{hint}; the keys are {}", k.trim(), KEYS.join(", "));
        };
        // A setting's value is taken as written, # and all: only a pair of
        // quotes around it is dropped (to keep spaces at its ends).
        if *key == "ENV" {
            let v = v.trim();
            let Some((name, value)) = v.split_once('=') else {
                bail!("line {n}: ENV: NAME=value after it, like ENV=NODE_ENV=production");
            };
            let name = name.trim();
            apps::valid_env_name(name).map_err(|e| errf!("line {n}: ENV: {e}"))?;
            let value = value.trim();
            let value = match (value.chars().next(), value.chars().last()) {
                (Some(q @ ('"' | '\'')), Some(e)) if value.len() >= 2 && q == e => &value[1..value.len() - 1],
                _ => value,
            };
            if let Some((_, _, first)) = env.iter().find(|(k, _, _)| k == name) {
                bail!("line {n}: ENV: {name} is set twice (line {first} first)");
            }
            env.push((name.to_string(), value.to_string(), n));
            continue;
        }
        let value = unquote(strip_comment(v.trim())).map_err(|e| errf!("line {n}: {key}: {e}"))?;
        if *key == "SECRET" {
            let names: Vec<&str> = value.split(|c: char| c.is_whitespace() || c == ',').filter(|s| !s.is_empty()).collect();
            if names.is_empty() {
                bail!("line {n}: SECRET: a name after the =, like SECRET=DATABASE_URL (its value: dryserver app secret APP DATABASE_URL)");
            }
            for name in names {
                if let Some((k, _)) = name.split_once('=') {
                    bail!("line {n}: SECRET: only the name goes in the app file; its value: dryserver app secret APP {k}");
                }
                apps::valid_env_name(name).map_err(|e| errf!("line {n}: SECRET: {e}"))?;
                if let Some((_, first)) = secrets.iter().find(|(k, _)| k == name) {
                    bail!("line {n}: SECRET: {name} is listed twice (line {first} first)");
                }
                secrets.push((name.to_string(), n));
            }
            continue;
        }
        if *key == "HOST" {
            if value.is_empty() {
                bail!("line {n}: HOST: a name after the =, like HOST=shop.example.com");
            }
            let items: Vec<&str> = value.split(|c: char| c.is_whitespace() || c == ',').filter(|s| !s.is_empty()).collect();
            if items.is_empty() {
                bail!("line {n}: HOST: a name after the =, like HOST=shop.example.com");
            }
            for item in items {
                let (name, port) = match item.rsplit_once(':').filter(|_| !item.contains("://")) {
                    Some((name, p)) => {
                        let port = p
                            .parse::<u16>()
                            .ok()
                            .filter(|p| *p > 0)
                            .ok_or_else(|| errf!("line {n}: HOST: {item}: the port after : is 1 to 65535"))?;
                        (name, Some(port))
                    }
                    None => (item, None),
                };
                let name = apps::clean_host(name).map_err(|e| e.wrap(format!("line {n}: HOST")))?;
                if let Some((_, _, first)) = hosts.iter().find(|(h, _, _)| *h == name) {
                    bail!("line {n}: HOST: {name} is listed twice (line {first} first)");
                }
                hosts.push((name, port, n));
            }
            continue;
        }
        if let Some((_, first)) = one.get(key) {
            bail!("line {n}: {key} is set twice (line {first} first)");
        }
        one.insert(key, (value, n));
    }
    let get = |k: &str| one.get(k).map(|(v, n)| (v.as_str(), *n));
    let need = |k: &str, example: &str| get(k).ok_or_else(|| errf!("{k} is missing: add a line like {k}={example}"));
    let (name, line) = need("NAME", "shop")?;
    apps::valid_app_name(name).map_err(|e| errf!("line {line}: NAME: {e}"))?;
    // Built by GitHub (REPO), or an image (IMAGE): one or the other.
    let source = match (get("REPO"), get("IMAGE"), get("BRANCH")) {
        (Some((_, rline)), Some((_, iline)), _) => {
            bail!("line {iline}: IMAGE: an app with REPO (line {rline}) runs what GitHub builds; leave IMAGE out")
        }
        (Some((repo, line)), None, branch) => Some(
            crate::github::Source::parse(repo, branch.map(|(b, _)| b).unwrap_or("main"))
                .map_err(|e| errf!("line {line}: REPO/BRANCH: {e}"))?,
        ),
        (None, _, Some((_, line))) => bail!("line {line}: BRANCH: only with REPO (the repository GitHub builds the app from)"),
        (None, _, None) => None,
    };
    let image_owned = source.as_ref().map(|s| s.image());
    let (image, line) = match &image_owned {
        Some(i) => (i.as_str(), 0),
        None => need("IMAGE", "ghcr.io/you/shop:v1 (or REPO=github.com/you/shop)")?,
    };
    apps::valid_image(image).map_err(|e| errf!("line {line}: IMAGE: {e}"))?;
    let (port, line) = need("PORT", "8080 (or none, for an app that listens on no port)")?;
    let port = if port.eq_ignore_ascii_case("none") {
        apps::NO_PORT
    } else {
        port.parse::<u16>().ok().filter(|p| *p > 0).ok_or_else(|| {
            errf!("line {line}: PORT: the port the app listens on, 1 to 65535, or none (a bot or a worker that takes no connections)")
        })?
    };
    let copies = match get("COPIES") {
        None => 1,
        Some((c, line)) => c.parse::<u32>().ok().filter(|c| (1..=20).contains(c)).ok_or_else(|| errf!("line {line}: COPIES: 1 to 20"))?,
    };
    let entrance = match get("ENTRANCE") {
        None => entrance::DEFAULT.to_string(),
        Some((e, line)) => {
            let e = e.to_ascii_lowercase();
            entrance::valid_id(&e).map_err(|err| errf!("line {line}: ENTRANCE: {err}"))?;
            e
        }
    };
    for (k, _, line) in &env {
        if let Some((_, first)) = secrets.iter().find(|(s, _)| s == k) {
            bail!("line {line}: ENV: {k} is a SECRET too (line {first}): one or the other");
        }
    }
    let memory_mib = match get("MEMORY") {
        None => apps::DEFAULT_MEMORY_MIB,
        Some((m, line)) => apps::parse_memory(m).map_err(|e| errf!("line {line}: MEMORY: {e}"))?,
    };
    let cpu_milli = match get("CPU") {
        None => apps::DEFAULT_CPU_MILLI,
        Some((c, line)) => apps::parse_cpu(c).map_err(|e| errf!("line {line}: CPU: {e}"))?,
    };
    if let Some((k, v, line)) = env.iter().find(|(k, _, _)| k == "PORT")
        && port != apps::NO_PORT
    {
        if *v != port.to_string() {
            bail!("line {line}: ENV: {k} is {v}, but PORT is {port}: they must agree (dryserver sets PORT for the app by itself)");
        }
        // The same as dryserver sets: one line less to compare.
        env.retain(|(k, _, _)| k != "PORT");
    }
    let mut run = apps::Runtime {
        env: env.into_iter().map(|(k, v, _)| (k, v)).collect(),
        secrets: secrets.into_iter().map(|(k, _)| k).collect(),
        memory_mib,
        cpu_milli,
        secrets_version: String::new(),
    };
    run.env.sort();
    run.secrets.sort();
    let mut app = App {
        name: name.into(),
        image: image.into(),
        port,
        hosts: hosts.into_iter().map(|(name, p, _)| Host { name, port: p.unwrap_or(port) }).collect(),
        entrance,
        copies,
        image_id: String::new(),
        run,
        source,
        gh: Default::default(),
    };
    app.hosts.sort();
    app.validate()?;
    Ok(app)
}

/// What follows " #" is a comment. No value of an app file has a # in it.
fn strip_comment(v: &str) -> &str {
    match v.find(" #").or_else(|| v.find("\t#")) {
        Some(i) => v[..i].trim_end(),
        None => v,
    }
}

/// One pair of quotes around a value is dropped, as in config.env.
fn unquote(v: &str) -> Result<String> {
    for q in ['"', '\''] {
        if let Some(rest) = v.strip_prefix(q) {
            return match rest.strip_suffix(q) {
                Some(inner) if !inner.contains(q) => Ok(inner.trim().to_string()),
                _ => Err(errf!("a quote that does not close")),
            };
        }
    }
    if v.contains('"') || v.contains('\'') {
        bail!("quotes only around the whole value");
    }
    Ok(v.to_string())
}

/// The file for an app: what `app show` prints, read back the same by
/// parse.
pub fn render(app: &App) -> String {
    let mut s = String::from("# A dryserver app. Change it, then: dryserver app deploy THIS-FILE\n");
    let port = if app.port == apps::NO_PORT { "none".to_string() } else { app.port.to_string() };
    match &app.source {
        Some(src) => {
            s += &format!("NAME={}\nREPO={}\n", app.name, src.text());
            if src.branch != "main" {
                s += &format!("BRANCH={}\n", src.branch);
            }
            s += &format!("PORT={port}\nCOPIES={}\n", app.copies);
        }
        None => s += &format!("NAME={}\nIMAGE={}\nPORT={port}\nCOPIES={}\n", app.name, app.image, app.copies),
    }
    let mut hosts = app.hosts.clone();
    hosts.sort();
    for h in &hosts {
        if h.port == app.port {
            s += &format!("HOST={}\n", h.name);
        } else {
            s += &format!("HOST={}:{}\n", h.name, h.port);
        }
    }
    if !hosts.is_empty() && app.entrance != entrance::DEFAULT {
        s += &format!("ENTRANCE={}\n", app.entrance);
    }
    s += &format!("MEMORY={}\nCPU={}\n", apps::memory_text(app.run.memory_mib), apps::cpu_text(app.run.cpu_milli));
    for (k, v) in &app.run.env {
        // Quoted when its ends are spaces or quotes, so it reads back the same.
        let quote = v.starts_with(char::is_whitespace) || v.ends_with(char::is_whitespace) || v.starts_with(['"', '\'']);
        if quote {
            let q = if v.contains('"') { '\'' } else { '"' };
            s += &format!("ENV={k}={q}{v}{q}\n");
        } else {
            s += &format!("ENV={k}={v}\n");
        }
    }
    for k in &app.run.secrets {
        s += &format!("SECRET={k}\n");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apps::tests::host;

    #[test]
    fn a_whole_file() {
        let a = parse(
            "\u{feff}# my shop\r\n\
             name = shop\r\n\
             IMAGE=\"ghcr.io/you/shop:v1\"   # the release\n\
             Port=8080\n\
             COPIES='2'\n\
             \n\
             HOST=shop.example.com\n\
             HOST=WWW.Example.com example.com.,shop.example.net\n\
             HOST = admin.example.com:9000\n",
        )
        .unwrap();
        assert_eq!(
            (a.name.as_str(), a.image.as_str(), a.port, a.copies, a.entrance.as_str()),
            ("shop", "ghcr.io/you/shop:v1", 8080, 2, "cloudflare")
        );
        assert_eq!(
            a.hosts,
            vec![
                host("admin.example.com", 9000),
                host("example.com", 8080),
                host("shop.example.com", 8080),
                host("shop.example.net", 8080),
                host("www.example.com", 8080),
            ]
        );
        // What show prints is read back the same.
        let text = render(&a);
        assert_eq!(parse(&text).unwrap(), a, "{text}");
        assert!(text.contains("HOST=admin.example.com:9000\nHOST=example.com\n") && !text.contains("ENTRANCE"), "{text}");
        // The least an app needs: no names, one copy.
        let small = parse("NAME=db\nIMAGE=postgres:17\nPORT=5432\n").unwrap();
        assert_eq!((small.copies, small.hosts.len()), (1, 0));
        assert_eq!(parse(&render(&small)).unwrap(), small);
        let vps = parse("NAME=game\nIMAGE=g:1\nPORT=80\nHOST=play.example.com\nENTRANCE=VPS\n").unwrap();
        assert_eq!(vps.entrance, "vps");
        assert!(render(&vps).contains("\nENTRANCE=vps\n"));
    }

    #[test]
    fn settings_secrets_and_limits() {
        let a = parse(
            "NAME=shop\nIMAGE=shop:v1\nPORT=3000\n\
             ENV=API_URL=https://api.example.com/v1?a=1&b=2#top\n\
             ENV = GREETING = \"  hello # world  \"\n\
             env=NODE_ENV=production\n\
             ENV=EMPTY=\n\
             SECRET=DATABASE_URL, STRIPE_KEY\n\
             SECRET=TOKEN   # the bot's token\n\
             MEMORY=1Gi\nCPU=500m\n",
        )
        .unwrap();
        assert_eq!(
            a.run.env,
            vec![
                ("API_URL".to_string(), "https://api.example.com/v1?a=1&b=2#top".to_string()),
                ("EMPTY".to_string(), String::new()),
                ("GREETING".to_string(), "  hello # world  ".to_string()),
                ("NODE_ENV".to_string(), "production".to_string()),
            ]
        );
        assert_eq!(a.run.secrets, vec!["DATABASE_URL", "STRIPE_KEY", "TOKEN"]);
        assert_eq!((a.run.memory_mib, a.run.cpu_milli), (1024, 500));
        let text = render(&a);
        assert_eq!(parse(&text).unwrap(), a, "{text}");
        assert!(text.contains("ENV=GREETING=\"  hello # world  \"\n") && text.contains("MEMORY=1Gi\nCPU=500m\n"), "{text}");
        // The defaults.
        let d = parse("NAME=shop\nIMAGE=shop:v1\nPORT=3000\n").unwrap();
        assert_eq!((d.run.memory_mib, d.run.cpu_milli, d.run.env.len(), d.run.secrets.len()), (512, 1000, 0, 0));
        let base = "NAME=shop\nIMAGE=shop:v1\nPORT=3000\n";
        for (text, why) in [
            (format!("{base}ENV=NOVALUE\n"), "line 4: ENV: NAME=value after it"),
            (format!("{base}ENV=1BAD=x\n"), "not starting with a digit"),
            (format!("{base}ENV=A-B=x\n"), "letters, digits and _"),
            (format!("{base}ENV=A=1\nENV=A=2\n"), "line 5: ENV: A is set twice (line 4 first)"),
            (format!("{base}ENV=TOKEN=x\nSECRET=TOKEN\n"), "TOKEN is a SECRET too"),
            (format!("{base}SECRET=\n"), "a name after the ="),
            (format!("{base}SECRET=A\nSECRET=A\n"), "A is listed twice"),
            (format!("{base}SECRET=TOKEN=abc\n"), "only the name goes in the app file; its value: dryserver app secret APP TOKEN"),
            (format!("{base}SECRET=to-ken\n"), "letters, digits and _"),
            (format!("{base}ENV=PORT=8080\n"), "they must agree"),
            (format!("{base}MEMORY=lots\n"), "line 4: MEMORY"),
            (format!("{base}MEMORY=100Gi\n"), "from 32Mi"),
            (format!("{base}CPU=99\n"), "line 4: CPU"),
            (format!("{base}MEMORY=1Gi\nMEMORY=2Gi\n"), "MEMORY is set twice"),
        ] {
            let e = parse(&text).unwrap_err().to_string();
            assert!(e.contains(why), "{text:?}: {e}");
        }
        // The app's own PORT setting, when it agrees, is fine.
        // ... and is one line less to compare: dryserver sets the same.
        assert!(parse(&format!("{base}ENV=PORT=3000\n")).unwrap().run.env.is_empty());
        // A bot or a worker listens on no port, and has no public names.
        let bot = parse("NAME=bot\nIMAGE=bot:1\nPORT=none\nSECRET=TOKEN\n").unwrap();
        assert_eq!(bot.port, apps::NO_PORT);
        assert!(render(&bot).contains("PORT=none\n"));
        assert_eq!(parse(&render(&bot)).unwrap(), bot);
        let e = parse("NAME=bot\nIMAGE=bot:1\nPORT=None\nHOST=bot.example.com\n").unwrap_err().to_string();
        assert!(e.contains("listens on no port has no public names"), "{e}");
        let e = parse("NAME=bot\nIMAGE=bot:1\nPORT=0\n").unwrap_err().to_string();
        assert!(e.contains("or none"), "{e}");
    }

    #[test]
    fn what_is_refused() {
        let base = "NAME=shop\nIMAGE=shop:v1\nPORT=8080\n";
        for (text, why) in [
            (String::new(), "NAME is missing"),
            ("NAME=shop\nPORT=1\n".into(), "IMAGE is missing"),
            ("NAME=shop\nIMAGE=a\n".into(), "PORT is missing"),
            (format!("{base}NAME=other\n"), "line 4: NAME is set twice (line 1 first)"),
            (format!("{base}HOSTS=a.example.com\n"), "HOSTS is not a key of an app file (one HOST= per line"),
            (format!("{base}ENV_X=1\n"), "ENV_X is not a key of an app file"),
            (format!("{base}just words\n"), "line 4: KEY=value expected"),
            (format!("{base}HOST=\n"), "line 4: HOST: a name after the ="),
            (format!("{base}HOST=, ,\n"), "line 4: HOST: a name after the ="),
            (format!("{base}HOST=a.example.com:443\n"), "port 443 would make the ingress speak https"),
            (format!("{base}HOST=a.example.com\nHOST=A.example.com.\n"), "line 5: HOST: a.example.com is listed twice (line 4 first)"),
            (format!("{base}HOST=a.example.com a.example.com:9000\n"), "is listed twice"),
            (format!("{base}HOST=a.example.com:0\n"), "the port after : is 1 to 65535"),
            (format!("{base}HOST=a.example.com:70000\n"), "the port after : is 1 to 65535"),
            (format!("{base}HOST=a.example.com:x\n"), "the port after : is 1 to 65535"),
            (format!("{base}HOST=*.example.com\n"), "not supported yet"),
            (format!("{base}HOST=bücher.de\n"), "xn-- form"),
            (format!("{base}HOST=https://a.example.com\n"), "only the name"),
            (format!("{base}HOST=10.1.0.60\n"), "an IP address"),
            (format!("{base}HOST=a.example.com:80\n"), "port 80 can only be the app's PORT"),
            (format!("{base}COPIES=0\n"), "COPIES: 1 to 20"),
            (format!("{base}COPIES=21\n"), "COPIES: 1 to 20"),
            (format!("{base}ENTRANCE=somewhere\n"), "ENTRANCE: an entrance"),
            ("NAME=Shop\nIMAGE=a\nPORT=1\n".into(), "line 1: NAME: starts with a letter"),
            ("NAME=shop\nIMAGE=a b\nPORT=1\n".into(), "line 2: IMAGE"),
            ("NAME=shop\nIMAGE=a\nPORT=99999\n".into(), "line 3: PORT"),
            ("NAME=\"shop\nIMAGE=a\nPORT=1\n".into(), "a quote that does not close"),
            ("NAME=sh\"op\nIMAGE=a\nPORT=1\n".into(), "quotes only around the whole value"),
            (format!("{base}{}", (0..51).map(|i| format!("HOST=n{i}.example.com\n")).collect::<String>()), "at most 50"),
            (format!("{base}{}", (0..10).map(|i| format!("HOST=n{i}.example.com:{}\n", 9000 + i)).collect::<String>()), "at most 10 ports"),
            ("#".repeat(MAX_LEN + 1), "at most 64 KiB"),
        ] {
            let e = parse(&text).unwrap_err().to_string();
            assert!(e.contains(why), "{text:?}: {e}");
        }
        // A # inside a value that is not after a space stays (and is then
        // refused as part of the value).
        assert!(parse(&format!("{base}HOST=a#b.example.com\n")).is_err());
    }
}
