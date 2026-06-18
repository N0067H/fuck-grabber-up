use crate::models::{RegistryEntry, ScheduledTask, StartupEntry};
use std::collections::HashSet;

fn extract_exe_path(s: &str) -> String {
    let s = s.trim();
    if s.starts_with('"') {
        s[1..].split('"').next().unwrap_or("").to_string()
    } else {
        s.split_whitespace().next().unwrap_or("").to_string()
    }
}

pub(crate) fn collect_candidates(
    registry_entries: &[RegistryEntry],
    startup_entries: &[StartupEntry],
    tasks: &[ScheduledTask],
) -> Vec<(String, String)> {
    let mut candidates: Vec<(String, String)> = Vec::new();
    for e in registry_entries {
        let p = extract_exe_path(&e.value);
        if !p.is_empty() {
            candidates.push((p, format!("registry {} / {}", e.hive, e.name)));
        }
    }
    for e in startup_entries {
        candidates.push((e.path.clone(), "startup folder".into()));
    }
    for t in tasks.iter().filter(|t| t.suspicious) {
        for action in &t.actions {
            let p = extract_exe_path(action);
            if !p.is_empty() {
                candidates.push((p, format!("scheduled task: {}", t.task_name)));
            }
        }
    }

    let mut seen: HashSet<String> = HashSet::new();
    candidates.retain(|(p, _)| seen.insert(p.to_lowercase()));
    candidates
}
