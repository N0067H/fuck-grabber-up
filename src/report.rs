use crate::models::Report;
use crate::powershell::run_powershell;
use std::fs;

pub(crate) fn get_timestamp() -> String {
    run_powershell(
        "$__ts=(Get-Date).ToString('o'); [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($__ts))",
    )
}

pub(crate) fn save_report(report: &Report) -> Result<String, String> {
    let json = serde_json::to_string_pretty(report).map_err(|e| e.to_string())?;
    let ts: String = report
        .generated_at
        .chars()
        .take(19)
        .map(|c| if c == ':' { '-' } else { c })
        .collect();
    let path = format!("ir_report_{ts}.json");
    fs::write(&path, json).map_err(|e| e.to_string())?;
    Ok(path)
}
