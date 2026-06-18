use crate::encoding::{base64_decode, base64_encode};
use std::process::Command;

pub(crate) fn run_powershell(script: &str) -> String {
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

pub(crate) fn run_ps_plain(script: &str) -> String {
    let utf16: Vec<u16> = script.encode_utf16().collect();
    let bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
    let encoded = base64_encode(&bytes);
    Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

pub(crate) fn ps_inject(template: &str, path: &str) -> String {
    template.replace("__PATH__", &path.replace('\'', "''"))
}
