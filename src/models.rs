use serde::Serialize;

#[derive(Serialize)]
pub struct RegistryEntry {
    pub hive: String,
    pub key: String,
    pub name: String,
    pub value: String,
}

#[derive(Serialize)]
pub struct StartupEntry {
    pub path: String,
}

#[derive(Serialize)]
pub struct ScheduledTask {
    pub task_name: String,
    pub task_path: String,
    pub state: String,
    pub actions: Vec<String>,
    pub run_as_user: String,
    pub author: String,
    pub last_run_time: String,
    pub next_run_time: String,
    pub suspicious: bool,
    pub suspicious_reasons: Vec<String>,
}

#[derive(Serialize)]
pub struct DefenderEvent {
    pub time_created: String,
    pub id: u64,
    pub message: String,
}

#[derive(Serialize)]
pub struct FileScore {
    pub path: String,
    pub source: String,
    pub score: u32,
    pub verdict: &'static str,
    pub recommendation: &'static str,
    pub factors: Vec<String>,
}

#[derive(Serialize)]
pub struct LogoutLink {
    pub service: &'static str,
    pub purpose: &'static str,
    pub url: &'static str,
}

#[derive(Serialize)]
pub struct CookieCleanupGuide {
    pub browser: &'static str,
    pub steps: Vec<&'static str>,
}

#[derive(Serialize)]
pub struct SecurityChecklistItem {
    pub category: &'static str,
    pub task: &'static str,
    pub why: &'static str,
    pub done: bool,
}

#[derive(Serialize)]
pub struct BrowserCloseResult {
    pub browser: String,
    pub result: String,
}

#[derive(Serialize)]
pub struct AccountRecoveryGuide {
    pub logout_links: Vec<LogoutLink>,
    pub cookie_cleanup_guides: Vec<CookieCleanupGuide>,
    pub security_checklist: Vec<SecurityChecklistItem>,
    pub browser_close_results: Vec<BrowserCloseResult>,
}

#[derive(Serialize)]
pub struct Report {
    pub generated_at: String,
    pub registry_run_entries: Vec<RegistryEntry>,
    pub startup_folder_entries: Vec<StartupEntry>,
    pub scheduled_tasks: Vec<ScheduledTask>,
    pub defender_events: Vec<DefenderEvent>,
    pub file_scores: Vec<FileScore>,
    pub account_recovery: AccountRecoveryGuide,
}
