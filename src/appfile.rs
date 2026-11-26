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

const KEYS: [&str; 6] = ["NAME", "IMAGE", "PORT", "COPIES", "HOST", "ENTRANCE"];

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
        let value = unquote(strip_comment(v.trim())).map_err(|e| errf!("line {n}: {key}: {e}"))?;
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
    let (image, line) = need("IMAGE", "ghcr.io/you/shop:v1")?;
    apps::valid_image(image).map_err(|e| errf!("line {line}: IMAGE: {e}"))?;
    let (port, line) = need("PORT", "8080")?;
    let port =
        port.parse::<u16>().ok().filter(|p| *p > 0).ok_or_else(|| errf!("line {line}: PORT: the port the app listens on, 1 to 65535"))?;
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
    let mut app = App {
        name: name.into(),
        image: image.into(),
        port,
        hosts: hosts.into_iter().map(|(name, p, _)| Host { name, port: p.unwrap_or(port) }).collect(),
        entrance,
        copies,
        image_id: String::new(),
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
    s += &format!("NAME={}\nIMAGE={}\nPORT={}\nCOPIES={}\n", app.name, app.image, app.port, app.copies);
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
        assert!(render(&vps).ends_with("ENTRANCE=vps\n"));
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
