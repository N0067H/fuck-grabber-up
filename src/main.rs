mod account;
mod encoding;
mod json;
mod models;
mod powershell;
mod remediation;
mod report;
mod scanners;
mod scoring;

use account::{build_account_recovery_guide, close_browsers, print_account_recovery_guide};
use models::{BrowserCloseResult, FileScore, Report};
use remediation::remediate;
use report::{get_timestamp, save_report};
use scanners::{scan_defender_logs, scan_registry, scan_scheduled_tasks, scan_startup_folder};
use scoring::scan_file_scores;
use std::io::{self, Write as IoWrite};

fn prompt_yn(msg: &str) -> bool {
    print!("{} [y/N]: ", msg);
    io::stdout().flush().ok();
    let mut line = String::new();
    io::stdin().read_line(&mut line).ok();
    line.trim().eq_ignore_ascii_case("y")
}

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
        println!("      [ID:{}] {} ??{}", e.id, e.time_created, preview);
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

    let targets: Vec<&FileScore> = file_scores.iter().filter(|f| f.score >= 61).collect();
    if !targets.is_empty() {
        println!("------------------------------------------------------------");
        println!("  Remediation candidates (score >= 61): {}", targets.len());
        println!("  Actions: kill process / block outbound / remove autorun / rename file");
        println!("  Note: firewall rules require Administrator privileges.");
        println!("------------------------------------------------------------\n");

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
