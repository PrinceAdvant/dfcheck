use std::process::exit;

fn usage() -> ! {
    eprintln!("usage: dfcheck [--ignore CODE[,CODE]] [--no-info] [Dockerfile ...]\nDefaults to ./Dockerfile. Exit 1 when warnings are found, 2 on bad arguments or unreadable files.");
    exit(2)
}

fn main() {
    let mut files = Vec::new();
    let mut ignore: Vec<String> = Vec::new();
    let mut no_info = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--ignore" => ignore.extend(args.next().unwrap_or_else(|| usage()).split(',').map(|s| s.trim().to_uppercase())),
            "--no-info" => no_info = true,
            "-h" | "--help" => usage(),
            "-V" | "--version" => { println!("dfcheck {}", env!("CARGO_PKG_VERSION")); return; }
            s if s.starts_with('-') => usage(),
            _ => files.push(a),
        }
    }
    if files.is_empty() { files.push("Dockerfile".into()); }
    let mut warnings = 0;
    for path in &files {
        let src = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => { eprintln!("dfcheck: {}: {}", path, e); exit(2) }
        };
        for f in dfcheck::check(&src) {
            if ignore.iter().any(|c| c == f.code) { continue; }
            if no_info && f.severity == dfcheck::Severity::Info { continue; }
            if f.severity == dfcheck::Severity::Warning { warnings += 1; }
            println!("{}:{}: {} {}: {}", path, f.line, f.code, f.severity.as_str(), f.message);
        }
    }
    if warnings > 0 { exit(1) }
}
