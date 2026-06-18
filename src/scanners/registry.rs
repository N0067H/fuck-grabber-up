use crate::models::RegistryEntry;
use winreg::RegKey;
use winreg::enums::*;

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

pub(crate) fn scan_registry() -> Vec<RegistryEntry> {
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
