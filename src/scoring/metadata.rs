use crate::json::{parse_array, ps_str};
use crate::powershell::run_powershell;
use serde_json::Value;
use std::collections::HashMap;

pub(crate) type FileMetaMap = HashMap<String, Value>;

const FILESCORE_SCRIPT_TPL: &str = r"
$__paths = @(__PATHS__)
$__now = Get-Date
$__r = @($__paths | ForEach-Object {
    $p = $_
    $sig = 'NotSigned'; $created_iso = ''; $is_recent = $false
    $has_net = $false; $after_extract = $false
    if (Test-Path -LiteralPath $p -PathType Leaf) {
        try {
            $item = Get-Item -LiteralPath $p -EA Stop
            $created_iso = $item.CreationTime.ToString('o')
            $is_recent   = $item.CreationTime -gt $__now.AddHours(-24)
            $dir = $item.DirectoryName
            if ($dir) {
                $arc = @(Get-ChildItem -LiteralPath $dir -File -EA SilentlyContinue |
                    Where-Object { $_.Extension -in @('.zip','.rar','.7z') -and
                                   $_.LastWriteTime -le $item.CreationTime -and
                                   ($item.CreationTime - $_.LastWriteTime).TotalHours -lt 1 })
                $after_extract = $arc.Count -gt 0
            }
        } catch {}
        try { $sig = (Get-AuthenticodeSignature -FilePath $p -EA Stop).Status.ToString() } catch {}
        try {
            $pids2 = @(Get-Process -EA SilentlyContinue | Where-Object { $_.Path -eq $p } | ForEach-Object { $_.Id })
            if ($pids2.Count -gt 0) {
                $has_net = @(Get-NetTCPConnection -OwningProcess $pids2 -State Established -EA SilentlyContinue).Count -gt 0
            }
        } catch {}
    }
    @{ path=$p; sig=$sig; created_iso=$created_iso; is_recent=[bool]$is_recent; has_net=[bool]$has_net; after_extract=[bool]$after_extract }
})
$__json = ConvertTo-Json -InputObject $__r -Depth 2 -Compress
[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($__json))
";

pub(crate) fn load_metadata(candidates: &[(String, String)]) -> FileMetaMap {
    let ps_arr = candidates
        .iter()
        .map(|(p, _)| format!("'{}'", p.replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(",");
    let script = FILESCORE_SCRIPT_TPL.replace("__PATHS__", &ps_arr);
    let output = run_powershell(&script);
    if output.is_empty() {
        return HashMap::new();
    }

    parse_array(&output)
        .into_iter()
        .filter_map(|v| {
            let p = ps_str(&v, "path").to_lowercase();
            if p.is_empty() { None } else { Some((p, v)) }
        })
        .collect()
}
