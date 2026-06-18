use crate::json::ps_str;
use crate::models::{DefenderEvent, FileScore};
use serde_json::Value;

fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

fn verdict(score: u32) -> (&'static str, &'static str) {
    match score {
        0..=30 => ("FYI", "Likely clean ??keep as reference."),
        31..=60 => ("Suspicious", "Manually verify the file path and signature."),
        61..=80 => (
            "Strong suspicion",
            "Terminate the process and run a full AV scan.",
        ),
        _ => (
            "Quarantine",
            "Terminate, quarantine the file, remove autorun, and rotate passwords.",
        ),
    }
}

pub(crate) fn build_score(
    path: String,
    source: String,
    meta: Option<&Value>,
    defender_events: &[DefenderEvent],
) -> FileScore {
    let sig = meta
        .map(|v| ps_str(v, "sig"))
        .unwrap_or_else(|| "NotSigned".into());
    let is_recent = meta
        .and_then(|v| v.get("is_recent")?.as_bool())
        .unwrap_or(false);
    let has_net = meta
        .and_then(|v| v.get("has_net")?.as_bool())
        .unwrap_or(false);
    let after_extract = meta
        .and_then(|v| v.get("after_extract")?.as_bool())
        .unwrap_or(false);

    let mut score = 0u32;
    let mut factors: Vec<String> = Vec::new();
    let path_lower = path.to_lowercase();
    let fname_stem = file_name(&path_lower).trim_end_matches(".exe");

    if [
        "\\appdata\\",
        "\\temp\\",
        "\\downloads\\",
        "\\programdata\\",
    ]
    .iter()
    .any(|p| path_lower.contains(p))
    {
        score += 30;
        factors.push("+30  runs from AppData/Temp/Downloads/ProgramData".into());
    }

    score += 20;
    factors.push(format!("+20  autorun registered ({})", source));

    if sig != "Valid" {
        score += 20;
        factors.push(format!("+20  no valid signature ({})", sig));
    }

    if is_recent {
        score += 15;
        factors.push("+15  created within the last 24 hours".into());
    }

    const MASQUERADE: &[&str] = &[
        "svchost",
        "chrome",
        "discord",
        "update",
        "explorer",
        "lsass",
        "winlogon",
        "csrss",
        "services",
        "spoolsv",
        "taskhost",
        "runtimebroker",
        "msedge",
        "firefox",
        "steam",
    ];
    let in_legit_dir = path_lower.contains("\\windows\\")
        || path_lower.contains("\\program files")
        || path_lower.contains("\\google\\chrome")
        || path_lower.contains("\\mozilla firefox");
    if !in_legit_dir {
        if let Some(name) = MASQUERADE.iter().find(|&&n| fname_stem == n) {
            score += 15;
            factors.push(format!("+15  impersonates a legitimate process: {}", name));
        }
    }

    if defender_events
        .iter()
        .any(|e| e.message.to_lowercase().contains(&path_lower))
    {
        score += 15;
        factors.push("+15  path found in Defender detection log".into());
    }

    if has_net {
        score += 10;
        factors.push("+10  process has established network connections".into());
    }

    if after_extract {
        score += 10;
        factors.push("+10  archive file found in the same dir with a close mtime".into());
    }

    let (v, rec) = verdict(score);
    FileScore {
        path,
        source,
        score,
        verdict: v,
        recommendation: rec,
        factors,
    }
}
