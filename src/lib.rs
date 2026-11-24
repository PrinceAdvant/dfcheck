//! A small, dependency free Dockerfile checker for production habits.
//!
//! It reads a Dockerfile, joins continuation lines and reports findings with
//! the line number where each instruction starts. Rules are deliberately few
//! and practical: pinned base images, a non-root `USER` in the final stage,
//! lean `apt-get` and `apk` installs, `COPY` instead of `ADD`, exec form
//! `CMD` and `ENTRYPOINT`, a `HEALTHCHECK`, and no secrets baked into `ENV`
//! or `ARG` defaults.
//!
//! ```
//! let src = "FROM node:latest\nRUN apt-get update && apt-get install -y curl\nCMD npm start\n";
//! let findings = dfcheck::check(src);
//! let codes: Vec<&str> = findings.iter().map(|f| f.code).collect();
//! assert!(codes.contains(&"DF001"));
//! assert!(codes.contains(&"DF003"));
//! assert!(codes.contains(&"DF008"));
//! ```
//!
//! Why these rules matter on a production server is explained in
//! [Docker security best practices for production](https://peon.sh/blogs/docker-security-best-practices-production),
//! and scanning the built image is covered in the
//! [Trivy image scanning guide](https://peon.sh/blogs/docker-image-scanning-trivy).

/// Severity of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Warning,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Warning => "warning",
            Severity::Info => "info",
        }
    }
}

/// One reported issue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub line: usize,
    pub code: &'static str,
    pub severity: Severity,
    pub message: String,
}

/// A logical instruction after joining continuation lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    pub line: usize,
    pub keyword: String,
    pub args: String,
}

/// Split a Dockerfile into instructions, joining lines that end with a backslash
/// and skipping comments and blank lines.
pub fn parse(src: &str) -> Vec<Instruction> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut start = 0;
    for (i, raw) in src.lines().enumerate() {
        let line = raw.trim();
        if buf.is_empty() && (line.is_empty() || line.starts_with('#')) {
            continue;
        }
        if !buf.is_empty() && line.starts_with('#') {
            continue;
        }
        if buf.is_empty() {
            start = i + 1;
        }
        if let Some(stripped) = line.strip_suffix('\\') {
            buf.push_str(stripped);
            buf.push(' ');
            continue;
        }
        buf.push_str(line);
        push(&mut out, start, &buf);
        buf.clear();
    }
    if !buf.is_empty() {
        push(&mut out, start, &buf);
    }
    out
}

fn push(out: &mut Vec<Instruction>, line: usize, text: &str) {
    let text = text.trim();
    let (kw, args) = match text.find(char::is_whitespace) {
        Some(p) => (&text[..p], text[p..].trim()),
        None => (text, ""),
    };
    out.push(Instruction { line, keyword: kw.to_ascii_uppercase(), args: args.to_string() });
}

fn has_word(s: &str, w: &str) -> bool {
    s.split(|c: char| c.is_whitespace() || c == ';' || c == '&' || c == '|').any(|t| t == w)
}

const SECRET_HINTS: [&str; 6] = ["PASSWORD", "PASSWD", "SECRET", "TOKEN", "API_KEY", "PRIVATE_KEY"];

/// Check a Dockerfile and return findings in line order.
pub fn check(src: &str) -> Vec<Finding> {
    let ins = parse(src);
    let mut f = Vec::new();
    let mut add = |line, code, severity, message: String| f.push(Finding { line, code, severity, message });
    let mut stage_aliases: Vec<String> = Vec::new();
    let mut last_from = 0usize;
    let mut last_user: Option<(usize, String)> = None;
    let mut healthcheck = false;
    for i in &ins {
        let a = i.args.as_str();
        match i.keyword.as_str() {
            "FROM" => {
                last_from = i.line;
                last_user = None;
                let toks: Vec<&str> = a.split_whitespace().filter(|t| !t.starts_with("--")).collect();
                let image = toks.first().copied().unwrap_or("");
                if toks.len() >= 3 && toks[1].eq_ignore_ascii_case("as") {
                    stage_aliases.push(toks[2].to_ascii_lowercase());
                }
                let is_stage = stage_aliases.iter().any(|s| s == &image.to_ascii_lowercase());
                if image != "scratch" && !is_stage && !image.contains('$') && !image.contains('@') {
                    let name_part = image.rsplit('/').next().unwrap_or(image);
                    match name_part.split_once(':') {
                        None => add(i.line, "DF001", Severity::Warning, format!("base image `{}` has no tag; pin a version", image)),
                        Some((_, "latest")) => add(i.line, "DF001", Severity::Warning, format!("base image `{}` uses `latest`; pin a version", image)),
                        _ => {}
                    }
                }
            }
            "USER" => last_user = Some((i.line, a.split(':').next().unwrap_or("").trim().to_string())),
            "HEALTHCHECK" => healthcheck = true,
            "RUN" => {
                if a.contains("apt-get install") || (a.contains("apt install") && !a.contains("apt installed")) {
                    if !a.contains("--no-install-recommends") {
                        add(i.line, "DF003", Severity::Warning, "apt install without --no-install-recommends pulls in extra packages".into());
                    }
                    if !a.contains("/var/lib/apt/lists") {
                        add(i.line, "DF004", Severity::Warning, "apt lists are not removed in the same RUN; add `rm -rf /var/lib/apt/lists/*`".into());
                    }
                }
                if a.contains("apk add") && !a.contains("--no-cache") {
                    add(i.line, "DF009", Severity::Warning, "apk add without --no-cache leaves the index in the image".into());
                }
                if has_word(a, "sudo") {
                    add(i.line, "DF010", Severity::Warning, "sudo inside a build is unnecessary; RUN already has the current USER's rights".into());
                }
            }
            "ADD" => {
                let src0 = a.split_whitespace().find(|t| !t.starts_with("--")).unwrap_or("");
                let archive = [".tar", ".tar.gz", ".tgz", ".tar.xz", ".tar.bz2"].iter().any(|e| src0.ends_with(e));
                if src0.starts_with("http://") || src0.starts_with("https://") {
                    add(i.line, "DF005", Severity::Warning, "ADD from a URL skips checksum checks; download with curl and verify, or use ADD --checksum".into());
                } else if !archive {
                    add(i.line, "DF005", Severity::Warning, "use COPY for local files; ADD has implicit extraction behaviour".into());
                }
            }
            "ENV" | "ARG" => {
                for part in a.split_whitespace() {
                    if let Some((k, v)) = part.split_once('=') {
                        let ku = k.to_ascii_uppercase();
                        if !v.is_empty() && SECRET_HINTS.iter().any(|h| ku.contains(h)) {
                            add(i.line, "DF007", Severity::Warning, format!("`{}` looks like a secret baked into the image; pass it at runtime", k));
                        }
                    }
                }
            }
            "CMD" | "ENTRYPOINT" => {
                if !a.starts_with('[') {
                    add(i.line, "DF008", Severity::Warning, format!("{} uses shell form; exec form `[\"...\"]` lets the process receive SIGTERM", i.keyword));
                }
            }
            _ => {}
        }
    }
    if last_from > 0 {
        match &last_user {
            None => add(last_from, "DF002", Severity::Warning, "final stage has no USER; the container runs as root".into()),
            Some((l, u)) if u == "root" || u == "0" => add(*l, "DF002", Severity::Warning, "final stage switches to root".into()),
            _ => {}
        }
        if !healthcheck {
            add(last_from, "DF006", Severity::Info, "no HEALTHCHECK; add one or define it in Compose".into());
        }
    }
    f.sort_by_key(|x| x.line);
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    fn codes(s: &str) -> Vec<&'static str> { check(s).into_iter().map(|f| f.code).collect() }

    #[test]
    fn clean_file_has_no_warnings() {
        let s = "FROM node:22-slim\nWORKDIR /app\nCOPY . .\nRUN apt-get update && apt-get install -y --no-install-recommends curl \\\n  && rm -rf /var/lib/apt/lists/*\nUSER node\nHEALTHCHECK CMD curl -f http://localhost:3000/ || exit 1\nCMD [\"node\", \"server.js\"]\n";
        assert!(codes(s).is_empty(), "{:?}", check(s));
    }
    #[test]
    fn continuation_keeps_start_line() {
        let s = "FROM alpine:3.20\nRUN apk add \\\n  curl\nUSER 1000\nHEALTHCHECK NONE\n";
        let f = check(s);
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].line, f[0].code), (2, "DF009"));
    }
    #[test]
    fn multistage_aliases_and_final_user() {
        let s = "FROM golang:1.23 AS build\nRUN go build -o /app\nFROM build AS test\nFROM gcr.io/distroless/static:nonroot\nCOPY --from=build /app /app\nENTRYPOINT [\"/app\"]\n";
        let c = codes(s);
        assert!(!c.contains(&"DF001"));
        assert!(c.contains(&"DF002"));
    }
    #[test]
    fn secrets_and_add() {
        let s = "FROM python:3.12\nENV DB_PASSWORD=hunter2 DEBUG=0\nARG GITHUB_TOKEN\nADD app.py /app/\nADD https://example.com/x.sh /x.sh\nADD vendor.tar.gz /opt/\nUSER root\nCMD python app.py\n";
        let c = codes(s);
        assert_eq!(c.iter().filter(|x| **x == "DF007").count(), 1);
        assert_eq!(c.iter().filter(|x| **x == "DF005").count(), 2);
        assert!(c.contains(&"DF002") && c.contains(&"DF008"));
    }
    #[test]
    fn untagged_registry_port() {
        assert!(codes("FROM localhost:5000/app\nUSER app\nHEALTHCHECK NONE\n").contains(&"DF001"));
        assert!(!codes("FROM localhost:5000/app:1.2\nUSER app\nHEALTHCHECK NONE\n").contains(&"DF001"));
    }
}
