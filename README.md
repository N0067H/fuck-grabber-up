# Fuck Grabber Up

A Windows incident-response CLI for finding suspicious stealer persistence, scoring risky files, and guiding session recovery.

## What it does

This tool helps you check a Windows PC after a possible info-stealer infection.

- Checks common auto-start locations.
- Checks suspicious scheduled tasks.
- Reads important Windows Defender events.
- Scores risky files and explains why they look risky.
- Can help stop and quarantine high-risk files after asking you first.
- Shows links and steps to log out sessions, clear cookies, change passwords, check 2FA, and add passkeys.
- Saves the results to a JSON report.
