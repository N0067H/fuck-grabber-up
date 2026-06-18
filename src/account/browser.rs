use crate::json::{parse_array, ps_str};
use crate::models::BrowserCloseResult;
use crate::powershell::run_powershell;

const CLOSE_BROWSERS_SCRIPT: &str = r#"
$names = @('chrome','msedge','firefox','brave','brave-browser','opera','opera_gx','vivaldi')
$out = @()
foreach ($name in $names) {
    $procs = @(Get-Process -Name $name -EA SilentlyContinue)
    if ($procs.Count -eq 0) {
        $out += @{ browser=$name; result='not running' }
        continue
    }
    try {
        $procs | Stop-Process -Force -EA Stop
        $out += @{ browser=$name; result=("closed " + $procs.Count + " process(es)") }
    } catch {
        $out += @{ browser=$name; result=("failed: " + $_.Exception.Message) }
    }
}
$__json = ConvertTo-Json -InputObject $out -Depth 2 -Compress
[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($__json))
"#;

pub(crate) fn close_browsers() -> Vec<BrowserCloseResult> {
    let output = run_powershell(CLOSE_BROWSERS_SCRIPT);
    if output.is_empty() {
        return vec![BrowserCloseResult {
            browser: "all".into(),
            result: "no PowerShell output".into(),
        }];
    }

    parse_array(&output)
        .into_iter()
        .map(|v| BrowserCloseResult {
            browser: ps_str(&v, "browser"),
            result: ps_str(&v, "result"),
        })
        .collect()
}
