use crate::models::AccountRecoveryGuide;

pub(crate) fn print_account_recovery_guide(guide: &AccountRecoveryGuide) {
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
