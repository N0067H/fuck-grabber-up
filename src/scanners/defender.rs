use crate::json::{parse_array, ps_str};
use crate::models::DefenderEvent;
use crate::powershell::run_powershell;

const DEFENDER_SCRIPT: &str = r#"
try {
    $evts = @(Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -MaxEvents 200 -ErrorAction Stop |
        Where-Object { $_.Id -in @(1116, 1117, 5007) } |
        ForEach-Object {
            @{
                time_created = $_.TimeCreated.ToString('o')
                id           = [int]$_.Id
                message      = ($_.Message -replace '\r?\n', ' ' -replace '\s{2,}', ' ').Trim()
            }
        })
    $__json = if ($evts.Count -eq 0) { '[]' } else { ConvertTo-Json -InputObject $evts -Depth 2 -Compress }
    [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($__json))
} catch { [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('[]')) }
"#;

pub(crate) fn scan_defender_logs() -> Vec<DefenderEvent> {
    let output = run_powershell(DEFENDER_SCRIPT);
    if output.is_empty() {
        return vec![];
    }
    parse_array(&output)
        .into_iter()
        .filter_map(|v| {
            Some(DefenderEvent {
                time_created: ps_str(&v, "time_created"),
                id: v.get("id")?.as_u64()?,
                message: ps_str(&v, "message"),
            })
        })
        .collect()
}
