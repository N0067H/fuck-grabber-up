use serde_json::Value;

pub(crate) fn ps_str(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_string()
}

pub(crate) fn ps_str_arr(v: &Value, key: &str) -> Vec<String> {
    match v.get(key) {
        Some(Value::Array(arr)) => arr
            .iter()
            .map(|s| s.as_str().unwrap_or("").to_string())
            .collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => vec![],
    }
}

pub(crate) fn parse_array(raw: &str) -> Vec<Value> {
    match serde_json::from_str(raw) {
        Ok(Value::Array(a)) => a,
        Ok(obj @ Value::Object(_)) => vec![obj],
        _ => vec![],
    }
}
