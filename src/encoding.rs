pub(crate) fn base64_encode(data: &[u8]) -> String {
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

pub(crate) fn base64_decode(s: &str) -> Vec<u8> {
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
