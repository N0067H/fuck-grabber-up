use crate::powershell::{ps_inject, run_ps_plain};
use std::fs;

const KILL_TPL: &str = r#"
$p = '__PATH__'
$procs = @(Get-Process -EA SilentlyContinue | Where-Object { $_.Path -eq $p })
if ($procs.Count -eq 0) { 'no running process found' }
else { $procs | Stop-Process -Force -EA SilentlyContinue; "killed $($procs.Count) process(es)" }
"#;

const FIREWALL_TPL: &str = r#"
try {
    $p    = '__PATH__'
    $rule = 'StealerGuard Block ' + (Split-Path -Leaf $p)
    if (Get-NetFirewallRule -DisplayName $rule -EA SilentlyContinue) {
        'rule already exists ??skipped'
    } else {
        New-NetFirewallRule -DisplayName $rule -Direction Outbound -Action Block -Program $p -EA Stop | Out-Null
        'outbound blocked'
    }
} catch [System.UnauthorizedAccessException] { 'needs elevation (run as Administrator)' }
  catch { "error: $_" }
"#;

const AUTORUN_TPL: &str = r#"
$p = '__PATH__'
$n = 0
foreach ($h in @('HKCU', 'HKLM')) {
    foreach ($s in @('Run', 'RunOnce')) {
        $k = $h + ':\Software\Microsoft\Windows\CurrentVersion\' + $s
        try {
            (Get-ItemProperty $k -EA Stop).PSObject.Properties |
                Where-Object { $_.Name -notlike 'PS*' -and $_.Value -like "*$p*" } |
                ForEach-Object { Remove-ItemProperty -Path $k -Name $_.Name -EA SilentlyContinue; $n++ }
        } catch {}
    }
}
Get-ScheduledTask -EA SilentlyContinue | Where-Object {
    @($_.Actions | Where-Object { $_.Execute -and $_.Execute -like "*$p*" }).Count -gt 0
} | ForEach-Object {
    Disable-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -EA SilentlyContinue | Out-Null
    $n++
}
"removed/disabled $n autorun entry/entries"
"#;

pub(crate) fn kill_process(path: &str) -> String {
    run_ps_plain(&ps_inject(KILL_TPL, path))
}

pub(crate) fn block_outbound(path: &str) -> String {
    run_ps_plain(&ps_inject(FIREWALL_TPL, path))
}

pub(crate) fn remove_autorun(path: &str) -> String {
    run_ps_plain(&ps_inject(AUTORUN_TPL, path))
}

pub(crate) fn quarantine_file(path: &str) -> Result<String, String> {
    let new_path = format!("{}.quarantined", path);
    fs::rename(path, &new_path).map_err(|e| e.to_string())?;
    Ok(new_path)
}
