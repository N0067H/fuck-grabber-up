mod actions;

use actions::{block_outbound, kill_process, quarantine_file, remove_autorun};

pub(crate) fn remediate(path: &str) {
    println!("    [1/4] killing process...");
    let r = kill_process(path);
    println!("          {}", if r.is_empty() { "no output" } else { &r });

    println!("    [2/4] blocking outbound firewall...");
    let r = block_outbound(path);
    println!("          {}", if r.is_empty() { "no output" } else { &r });

    println!("    [3/4] removing autorun entries...");
    let r = remove_autorun(path);
    println!("          {}", if r.is_empty() { "no output" } else { &r });

    println!("    [4/4] quarantining file (renaming)...");
    match quarantine_file(path) {
        Ok(new_path) => println!("          renamed ??{}", new_path),
        Err(e) => println!("          failed: {}", e),
    }
}
