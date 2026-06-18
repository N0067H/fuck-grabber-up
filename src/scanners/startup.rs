use crate::models::StartupEntry;
use std::fs;

pub(crate) fn scan_startup_folder() -> Vec<StartupEntry> {
    let appdata = std::env::var("APPDATA").unwrap_or_default();
    let path = format!("{appdata}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
    fs::read_dir(path)
        .map(|e| {
            e.flatten()
                .map(|e| StartupEntry {
                    path: e.path().display().to_string(),
                })
                .collect()
        })
        .unwrap_or_default()
}
