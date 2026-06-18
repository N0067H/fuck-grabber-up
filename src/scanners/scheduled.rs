use crate::json::{parse_array, ps_str, ps_str_arr};
use crate::models::ScheduledTask;
use crate::powershell::run_powershell;

fn looks_random(name: &str) -> bool {
    let clean: String = name.chars().filter(|c| c.is_alphanumeric()).collect();
    if clean.len() < 10 {
        return false;
    }
    let hex = clean.chars().filter(|c| c.is_ascii_hexdigit()).count();
    (hex as f32 / clean.len() as f32) > 0.75
}

fn analyze_suspicious(actions: &[String], name: &str) -> (bool, Vec<String>) {
    let mut reasons = Vec::new();
    let acts = actions.join(" ").to_lowercase();
    for path in ["appdata", "\\temp\\", "\\downloads\\", "programdata"] {
        if acts.contains(path) {
            reasons.push(format!("runs from suspicious path: {path}"));
        }
    }
    for exe in [
        "powershell.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
    ] {
        if acts.contains(exe) {
            reasons.push(format!("uses suspicious executable: {exe}"));
        }
    }
    if looks_random(name) {
        reasons.push("task name looks randomly generated".into());
    }
    let suspicious = !reasons.is_empty();
    (suspicious, reasons)
}

const SCHTASK_SCRIPT: &str = r#"
$result = @(Get-ScheduledTask | ForEach-Object {
    $t = $_
    $info = $null
    try { $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop } catch {}
    $acts = @($t.Actions | ForEach-Object {
        try {
            $exe = if ($_.Execute) { $_.Execute } else { '' }
            $arg = if ($_.Arguments) { $_.Arguments } else { '' }
            "$exe $arg".Trim()
        } catch { '<non-exec action>' }
    })
    @{
        task_name     = $t.TaskName
        task_path     = [string]$t.TaskPath
        state         = [string]$t.State
        actions       = $acts
        run_as_user   = if ($t.Principal -and $t.Principal.UserId) { $t.Principal.UserId } else { '' }
        author        = if ($t.Author) { [string]$t.Author } else { '' }
        last_run_time = if ($info) { try { $info.LastRunTime.ToString('o') } catch { '' } } else { '' }
        next_run_time = if ($info) { try { $info.NextRunTime.ToString('o') } catch { '' } } else { '' }
    }
})
$__json = if ($result.Count -eq 0) { '[]' } else { ConvertTo-Json -InputObject $result -Depth 3 -Compress }
[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($__json))
"#;

pub(crate) fn scan_scheduled_tasks() -> Vec<ScheduledTask> {
    let output = run_powershell(SCHTASK_SCRIPT);
    if output.is_empty() {
        eprintln!("    [!] no PowerShell output ??check execution policy");
        return vec![];
    }
    parse_array(&output)
        .into_iter()
        .map(|v| {
            let task_name = ps_str(&v, "task_name");
            let actions = ps_str_arr(&v, "actions");
            let (suspicious, suspicious_reasons) = analyze_suspicious(&actions, &task_name);
            ScheduledTask {
                task_name,
                task_path: ps_str(&v, "task_path"),
                state: ps_str(&v, "state"),
                actions,
                run_as_user: ps_str(&v, "run_as_user"),
                author: ps_str(&v, "author"),
                last_run_time: ps_str(&v, "last_run_time"),
                next_run_time: ps_str(&v, "next_run_time"),
                suspicious,
                suspicious_reasons,
            }
        })
        .collect()
}
