mod browser;
mod checklist;
mod display;
mod links;

pub(crate) use browser::close_browsers;
pub(crate) use display::print_account_recovery_guide;

use crate::models::{AccountRecoveryGuide, BrowserCloseResult};

pub(crate) fn build_account_recovery_guide(
    browser_close_results: Vec<BrowserCloseResult>,
) -> AccountRecoveryGuide {
    AccountRecoveryGuide {
        logout_links: links::logout_links(),
        cookie_cleanup_guides: checklist::cookie_cleanup_guides(),
        security_checklist: checklist::security_checklist(),
        browser_close_results,
    }
}
