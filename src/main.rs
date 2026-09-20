use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use sshkeyaudit::audit::Severity;
use sshkeyaudit::scan::scan_path;

#[derive(Parser)]
#[command(
    name = "sshkeyaudit",
    about = "Scans an authorized_keys file or a directory of .pub files and flags weak SSH keys"
)]
struct Cli {
    /// Path to an authorized_keys file, a single .pub file, or a
    /// directory containing .pub files.
    path: PathBuf,

    /// Also fail (exit 1) on Warning-level findings (missing comment,
    /// unrecognized key type), not just Weak ones.
    #[arg(long)]
    strict: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let findings = match scan_path(&cli.path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("sshkeyaudit: {e:#}");
            return ExitCode::FAILURE;
        }
    };

    if findings.is_empty() {
        println!("no keys found at {}", cli.path.display());
        return ExitCode::SUCCESS;
    }

    let mut worst = Severity::Ok;
    for f in &findings {
        let bits = f
            .bits
            .map(|b| format!("{b} bits"))
            .unwrap_or_else(|| "? bits".to_string());
        let comment = f.comment.as_deref().unwrap_or("(none)");
        println!(
            "[{}] {} - {} ({}) comment: {}",
            f.severity.label(),
            f.source,
            f.key_label,
            bits,
            comment
        );
        for reason in &f.reasons {
            println!("       - {reason}");
        }
        if f.severity > worst {
            worst = f.severity;
        }
    }

    println!();
    let weak_count = findings
        .iter()
        .filter(|f| f.severity == Severity::Weak)
        .count();
    let warn_count = findings
        .iter()
        .filter(|f| f.severity == Severity::Warning)
        .count();
    let ok_count = findings
        .iter()
        .filter(|f| f.severity == Severity::Ok)
        .count();
    println!(
        "{} key(s) scanned: {} ok, {} warning(s), {} weak",
        findings.len(),
        ok_count,
        warn_count,
        weak_count
    );

    let fail = weak_count > 0 || (cli.strict && warn_count > 0);
    if fail {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
