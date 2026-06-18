use serde::Serialize;
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::io::{self, Write as IoWrite};
use std::process::Command;
use winreg::RegKey;
use winreg::enums::*;

// ── Data structures ───────────────────────────────────────────────────────────

#[derive(Serialize)]
struct RegistryEntry {
    hive: String,
    key: String,
    name: String,
    value: String,
}

#[derive(Serialize)]
struct StartupEntry {
    path: String,
}

#[derive(Serialize)]
struct ScheduledTask {
    task_name: String,
    task_path: String,
    state: String,
    actions: Vec<String>,
    run_as_user: String,
    author: String,
    last_run_time: String,
    next_run_time: String,
    suspicious: bool,
    suspicious_reasons: Vec<String>,
}

#[derive(Serialize)]
struct DefenderEvent {
    time_created: String,
    id: u64,
    message: String,
}

#[derive(Serialize)]
struct FileScore {
    path: String,
    source: String,
    score: u32,
    verdict: &'static str,
    recommendation: &'static str,
    factors: Vec<String>,
}

#[derive(Serialize)]
struct LogoutLink {
    service: &'static str,
    purpose: &'static str,
    url: &'static str,
}

#[derive(Serialize)]
struct CookieCleanupGuide {
    browser: &'static str,
    steps: Vec<&'static str>,
}

#[derive(Serialize)]
struct SecurityChecklistItem {
    category: &'static str,
    task: &'static str,
    why: &'static str,
    done: bool,
}

#[derive(Serialize)]
struct BrowserCloseResult {
    browser: String,
    result: String,
}

#[derive(Serialize)]
struct AccountRecoveryGuide {
    logout_links: Vec<LogoutLink>,
    cookie_cleanup_guides: Vec<CookieCleanupGuide>,
    security_checklist: Vec<SecurityChecklistItem>,
    browser_close_results: Vec<BrowserCloseResult>,
}

#[derive(Serialize)]
struct Report {
    generated_at: String,
    registry_run_entries: Vec<RegistryEntry>,
    startup_folder_entries: Vec<StartupEntry>,
    scheduled_tasks: Vec<ScheduledTask>,
    defender_events: Vec<DefenderEvent>,
    file_scores: Vec<FileScore>,
    account_recovery: AccountRecoveryGuide,
}

// ── Base64 ────────────────────────────────────────────────────────────────────

fn base64_encode(data: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(A[(n >> 18 & 0x3f) as usize] as char);
        out.push(A[(n >> 12 & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            A[(n >> 6 & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            A[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn base64_decode(s: &str) -> Vec<u8> {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for b in s.bytes() {
        if b == b'=' {
            break;
        }
        let Some(v) = A.iter().position(|&a| a == b) else {
            continue;
        };
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    out
}

// ── PowerShell helpers ────────────────────────────────────────────────────────

// For scan scripts: output must be [Convert]::ToBase64String(UTF8.GetBytes($json))
// so we can safely decode regardless of the console OEM codepage.
fn run_powershell(script: &str) -> String {
    let utf16: Vec<u16> = script.encode_utf16().collect();
    let bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
    let encoded = base64_encode(&bytes);
    let raw = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let b64 = raw.lines().last().unwrap_or("").trim();
    String::from_utf8(base64_decode(b64)).unwrap_or(raw)
}

// For remediation scripts that output plain ASCII status strings.
fn run_ps_plain(script: &str) -> String {
    let utf16: Vec<u16> = script.encode_utf16().collect();
    let bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
    let encoded = base64_encode(&bytes);
    Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

// Embed a file path into a PS script template, escaping single quotes.
fn ps_inject(template: &str, path: &str) -> String {
    template.replace("__PATH__", &path.replace('\'', "''"))
}

// ── Scheduled-task pre-filter heuristics ─────────────────────────────────────

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

// ── Scanners ──────────────────────────────────────────────────────────────────

fn read_run_key(hive: &RegKey, hive_name: &str, path: &str, out: &mut Vec<RegistryEntry>) {
    let Ok(key) = hive.open_subkey_with_flags(path, KEY_READ) else {
        return;
    };
    for item in key.enum_values() {
        let Ok((name, value)) = item else { continue };
        out.push(RegistryEntry {
            hive: hive_name.into(),
            key: path.into(),
            name,
            value: value.to_string(),
        });
    }
}

fn scan_registry() -> Vec<RegistryEntry> {
    let mut out = Vec::new();
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let run = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    let run_once = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
    read_run_key(&hkcu, "HKCU", run, &mut out);
    read_run_key(&hkcu, "HKCU", run_once, &mut out);
    read_run_key(&hklm, "HKLM", run, &mut out);
    read_run_key(&hklm, "HKLM", run_once, &mut out);
    out
}

fn scan_startup_folder() -> Vec<StartupEntry> {
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

fn ps_str(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_string()
}

fn ps_str_arr(v: &Value, key: &str) -> Vec<String> {
    match v.get(key) {
        Some(Value::Array(arr)) => arr
            .iter()
            .map(|s| s.as_str().unwrap_or("").to_string())
            .collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => vec![],
    }
}

fn parse_array(raw: &str) -> Vec<Value> {
    match serde_json::from_str(raw) {
        Ok(Value::Array(a)) => a,
        Ok(obj @ Value::Object(_)) => vec![obj],
        _ => vec![],
    }
}

fn scan_scheduled_tasks() -> Vec<ScheduledTask> {
    let output = run_powershell(SCHTASK_SCRIPT);
    if output.is_empty() {
        eprintln!("    [!] no PowerShell output — check execution policy");
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

fn scan_defender_logs() -> Vec<DefenderEvent> {
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

// ── File scoring ──────────────────────────────────────────────────────────────

fn extract_exe_path(s: &str) -> String {
    let s = s.trim();
    if s.starts_with('"') {
        s[1..].split('"').next().unwrap_or("").to_string()
    } else {
        s.split_whitespace().next().unwrap_or("").to_string()
    }
}

fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

fn verdict(score: u32) -> (&'static str, &'static str) {
    match score {
        0..=30 => ("FYI", "Likely clean — keep as reference."),
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

fn scan_file_scores(
    registry_entries: &[RegistryEntry],
    startup_entries: &[StartupEntry],
    tasks: &[ScheduledTask],
    defender_events: &[DefenderEvent],
) -> Vec<FileScore> {
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
    if candidates.is_empty() {
        return vec![];
    }

    let ps_arr = candidates
        .iter()
        .map(|(p, _)| format!("'{}'", p.replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(",");
    let script = FILESCORE_SCRIPT_TPL.replace("__PATHS__", &ps_arr);
    let output = run_powershell(&script);
    if output.is_empty() {
        return vec![];
    }

    let ps_map: std::collections::HashMap<String, Value> = parse_array(&output)
        .into_iter()
        .filter_map(|v| {
            let p = ps_str(&v, "path").to_lowercase();
            if p.is_empty() { None } else { Some((p, v)) }
        })
        .collect();

    let mut scores: Vec<FileScore> = candidates
        .into_iter()
        .map(|(path, source)| {
            let meta = ps_map.get(&path.to_lowercase());
            let sig = meta
                .map(|v| ps_str(v, "sig"))
                .unwrap_or_else(|| "NotSigned".into());
            let is_recent = meta
                .and_then(|v| v.get("is_recent")?.as_bool())
                .unwrap_or(false);
            let has_net = meta
                .and_then(|v| v.get("has_net")?.as_bool())
                .unwrap_or(false);
            let after_extr = meta
                .and_then(|v| v.get("after_extract")?.as_bool())
                .unwrap_or(false);
            build_score(
                path,
                source,
                &sig,
                is_recent,
                has_net,
                after_extr,
                defender_events,
            )
        })
        .collect();

    scores.sort_by(|a, b| b.score.cmp(&a.score));
    scores
}

fn build_score(
    path: String,
    source: String,
    sig: &str,
    is_recent: bool,
    has_net: bool,
    after_extract: bool,
    defender_events: &[DefenderEvent],
) -> FileScore {
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

// ── Remediation ───────────────────────────────────────────────────────────────

// 1. Kill all running instances of the executable.
const KILL_TPL: &str = r#"
$p = '__PATH__'
$procs = @(Get-Process -EA SilentlyContinue | Where-Object { $_.Path -eq $p })
if ($procs.Count -eq 0) { 'no running process found' }
else { $procs | Stop-Process -Force -EA SilentlyContinue; "killed $($procs.Count) process(es)" }
"#;

// 2. Add a Windows Firewall outbound block rule.
//    Requires elevation; outputs 'needs elevation' if access denied.
const FIREWALL_TPL: &str = r#"
try {
    $p    = '__PATH__'
    $rule = 'StealerGuard Block ' + (Split-Path -Leaf $p)
    if (Get-NetFirewallRule -DisplayName $rule -EA SilentlyContinue) {
        'rule already exists — skipped'
    } else {
        New-NetFirewallRule -DisplayName $rule -Direction Outbound -Action Block -Program $p -EA Stop | Out-Null
        'outbound blocked'
    }
} catch [System.UnauthorizedAccessException] { 'needs elevation (run as Administrator)' }
  catch { "error: $_" }
"#;

// 3. Remove Run/RunOnce registry entries pointing to this path,
//    and disable any scheduled tasks whose action matches the path.
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

// 4. Rename the file to <path>.quarantined so it can no longer be executed
//    but is not permanently deleted.
fn quarantine_file(path: &str) -> Result<String, String> {
    let new_path = format!("{}.quarantined", path);
    fs::rename(path, &new_path).map_err(|e| e.to_string())?;
    Ok(new_path)
}

fn remediate(path: &str) {
    println!("    [1/4] killing process...");
    let r = run_ps_plain(&ps_inject(KILL_TPL, path));
    println!("          {}", if r.is_empty() { "no output" } else { &r });

    println!("    [2/4] blocking outbound firewall...");
    let r = run_ps_plain(&ps_inject(FIREWALL_TPL, path));
    println!("          {}", if r.is_empty() { "no output" } else { &r });

    println!("    [3/4] removing autorun entries...");
    let r = run_ps_plain(&ps_inject(AUTORUN_TPL, path));
    println!("          {}", if r.is_empty() { "no output" } else { &r });

    println!("    [4/4] quarantining file (renaming)...");
    match quarantine_file(path) {
        Ok(new_path) => println!("          renamed → {}", new_path),
        Err(e) => println!("          failed: {}", e),
    }
}

// ── Report ────────────────────────────────────────────────────────────────────

fn logout_links() -> Vec<LogoutLink> {
    vec![
        LogoutLink {
            service: "Google",
            purpose: "Review devices, sessions, and account activity",
            url: "https://myaccount.google.com/security",
        },
        LogoutLink {
            service: "Microsoft",
            purpose: "Review sign-ins and sign out of active sessions",
            url: "https://account.microsoft.com/security",
        },
        LogoutLink {
            service: "Discord",
            purpose: "Change password to invalidate sessions, then review devices",
            url: "https://discord.com/channels/@me",
        },
        LogoutLink {
            service: "GitHub",
            purpose: "Review sessions, SSH keys, PATs, OAuth apps, and 2FA",
            url: "https://github.com/settings/security",
        },
        LogoutLink {
            service: "Steam",
            purpose: "Deauthorize devices and review Steam Guard",
            url: "https://store.steampowered.com/twofactor/manage",
        },
        LogoutLink {
            service: "Facebook",
            purpose: "Review logged-in devices and security settings",
            url: "https://www.facebook.com/settings?tab=security",
        },
        LogoutLink {
            service: "Instagram",
            purpose: "Review login activity and 2FA",
            url: "https://accountscenter.instagram.com/password_and_security",
        },
        LogoutLink {
            service: "X / Twitter",
            purpose: "Review sessions, connected apps, and 2FA",
            url: "https://x.com/settings/security_and_account_access",
        },
    ]
}

fn cookie_cleanup_guides() -> Vec<CookieCleanupGuide> {
    vec![
        CookieCleanupGuide {
            browser: "Chrome / Chromium / Brave",
            steps: vec![
                "Open Settings > Privacy and security > Delete browsing data.",
                "Set Time range to All time.",
                "Select Cookies and other site data.",
                "Delete data, then restart the browser.",
            ],
        },
        CookieCleanupGuide {
            browser: "Microsoft Edge",
            steps: vec![
                "Open Settings > Privacy, search, and services.",
                "Under Clear browsing data, choose what to clear.",
                "Set Time range to All time.",
                "Select Cookies and other site data, clear it, then restart Edge.",
            ],
        },
        CookieCleanupGuide {
            browser: "Firefox",
            steps: vec![
                "Open Settings > Privacy & Security.",
                "Under Cookies and Site Data, click Clear Data.",
                "Select Cookies and Site Data.",
                "Clear it, then restart Firefox.",
            ],
        },
    ]
}

fn security_checklist() -> Vec<SecurityChecklistItem> {
    vec![
        SecurityChecklistItem {
            category: "Password",
            task: "Change passwords for email, password manager, banking, work, social, gaming, and developer accounts.",
            why: "A stolen browser session often exposes saved passwords or account reset paths.",
            done: false,
        },
        SecurityChecklistItem {
            category: "Password",
            task: "Use unique passwords generated by a password manager.",
            why: "Reuse lets one stolen password unlock other accounts.",
            done: false,
        },
        SecurityChecklistItem {
            category: "2FA",
            task: "Verify 2FA is enabled on every important account.",
            why: "Info stealers can bypass some active sessions, but 2FA still protects fresh sign-ins.",
            done: false,
        },
        SecurityChecklistItem {
            category: "2FA",
            task: "Rotate recovery codes and remove unknown authenticators or phone numbers.",
            why: "Attackers may add fallback methods after gaining access.",
            done: false,
        },
        SecurityChecklistItem {
            category: "Passkey",
            task: "Add passkeys where supported, starting with email and password manager accounts.",
            why: "Passkeys reduce phishing and password replay risk.",
            done: false,
        },
        SecurityChecklistItem {
            category: "Access tokens",
            task: "Revoke unknown OAuth apps, browser extensions, API tokens, PATs, SSH keys, and app passwords.",
            why: "Tokens can stay valid even after a password change.",
            done: false,
        },
        SecurityChecklistItem {
            category: "Sessions",
            task: "Use each service security page to sign out other devices and review recent activity.",
            why: "This invalidates stolen sessions that are still accepted by the service.",
            done: false,
        },
    ]
}

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

fn close_browsers() -> Vec<BrowserCloseResult> {
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

fn print_account_recovery_guide(guide: &AccountRecoveryGuide) {
    println!("\n=== Account/session recovery guide ===");
    println!("\n[Logout/session links]");
    for link in &guide.logout_links {
        println!("  - {}: {}", link.service, link.url);
        println!("    {}", link.purpose);
    }

    println!("\n[Cookie cleanup]");
    for browser in &guide.cookie_cleanup_guides {
        println!("  - {}", browser.browser);
        for step in &browser.steps {
            println!("    * {}", step);
        }
    }

    println!("\n[Password / 2FA / passkey checklist]");
    for (idx, item) in guide.security_checklist.iter().enumerate() {
        println!("  {}. [{}] {}", idx + 1, item.category, item.task);
        println!("     {}", item.why);
    }
}

fn build_account_recovery_guide(
    browser_close_results: Vec<BrowserCloseResult>,
) -> AccountRecoveryGuide {
    AccountRecoveryGuide {
        logout_links: logout_links(),
        cookie_cleanup_guides: cookie_cleanup_guides(),
        security_checklist: security_checklist(),
        browser_close_results,
    }
}

fn get_timestamp() -> String {
    run_powershell(
        "$__ts=(Get-Date).ToString('o'); [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($__ts))",
    )
}

fn save_report(report: &Report) -> Result<String, String> {
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

fn prompt_yn(msg: &str) -> bool {
    print!("{} [y/N]: ", msg);
    io::stdout().flush().ok();
    let mut line = String::new();
    io::stdin().read_line(&mut line).ok();
    line.trim().eq_ignore_ascii_case("y")
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    println!("=== fuck-grabber-up IR Scanner ===\n");

    print!("[1/5] scanning Run/RunOnce registry...");
    let registry_entries = scan_registry();
    println!(" {} entries", registry_entries.len());
    for e in &registry_entries {
        println!("      {} \\{}: {} = {}", e.hive, e.key, e.name, e.value);
    }

    print!("\n[2/5] scanning startup folder...");
    let startup_entries = scan_startup_folder();
    println!(" {} entries", startup_entries.len());
    for e in &startup_entries {
        println!("      {}", e.path);
    }

    print!("\n[3/5] scanning scheduled tasks (may take a moment)...");
    let tasks = scan_scheduled_tasks();
    let n_suspicious = tasks.iter().filter(|t| t.suspicious).count();
    println!(" {} tasks / {} suspicious", tasks.len(), n_suspicious);
    for t in tasks.iter().filter(|t| t.suspicious) {
        println!("      [!] {}{}", t.task_path, t.task_name);
        for r in &t.suspicious_reasons {
            println!("          - {}", r);
        }
    }

    print!("\n[4/5] scanning Windows Defender logs...");
    let defender_events = scan_defender_logs();
    println!(" {} events (ID 1116/1117/5007)", defender_events.len());
    for e in &defender_events {
        let preview: String = e.message.chars().take(120).collect();
        println!("      [ID:{}] {} — {}", e.id, e.time_created, preview);
    }

    print!("\n[5/5] scoring files (checking signatures & metadata)...");
    let file_scores = scan_file_scores(
        &registry_entries,
        &startup_entries,
        &tasks,
        &defender_events,
    );
    println!(" {} files scored\n", file_scores.len());

    for f in &file_scores {
        let bar = match f.score {
            0..=30 => "[ FYI              ]",
            31..=60 => "[!  SUSPICIOUS     ]",
            61..=80 => "[!! STRONG SUSPICION]",
            _ => "[!!!QUARANTINE     ]",
        };
        println!("  {} score={:>3}  {}", bar, f.score, f.path);
        for factor in &f.factors {
            println!("      {}", factor);
        }
        println!("      => {}", f.recommendation);
        println!();
    }

    // ── Remediation ───────────────────────────────────────────────────────────
    let targets: Vec<&FileScore> = file_scores.iter().filter(|f| f.score >= 61).collect();
    if !targets.is_empty() {
        println!("─────────────────────────────────────────────────────────────");
        println!("  Remediation candidates (score >= 61): {}", targets.len());
        println!("  Actions: kill process · block outbound · remove autorun · rename file");
        println!("  Note: firewall rules require Administrator privileges.");
        println!("─────────────────────────────────────────────────────────────\n");

        for f in targets {
            println!("  [score={} / {}] {}", f.score, f.verdict, f.path);
            if prompt_yn("  Apply all remediation actions?") {
                println!();
                remediate(&f.path);
                println!();
            }
        }
    }

    let browser_close_results =
        if prompt_yn("\nClose running browsers now? Unsaved browser work may be lost.") {
            println!("    closing browsers...");
            let results = close_browsers();
            for r in &results {
                println!("      {}: {}", r.browser, r.result);
            }
            results
        } else {
            vec![BrowserCloseResult {
                browser: "all".into(),
                result: "skipped by user".into(),
            }]
        };

    let account_recovery = build_account_recovery_guide(browser_close_results);
    print_account_recovery_guide(&account_recovery);

    let report = Report {
        generated_at: get_timestamp(),
        registry_run_entries: registry_entries,
        startup_folder_entries: startup_entries,
        scheduled_tasks: tasks,
        defender_events,
        file_scores,
        account_recovery,
    };

    println!();
    match save_report(&report) {
        Ok(path) => println!("[+] report saved: {}", path),
        Err(e) => eprintln!("[!] failed to save report: {}", e),
    }
}
