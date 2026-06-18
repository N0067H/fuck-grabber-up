use crate::models::LogoutLink;

pub(crate) fn logout_links() -> Vec<LogoutLink> {
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
