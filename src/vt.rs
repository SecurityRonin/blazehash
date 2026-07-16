use serde_json::Value;

#[derive(Debug, PartialEq)]
pub enum VtResult {
    Clean(u64),
    Malicious { count: u64, total: u64 },
    Unknown,
}

pub fn classify_vt_response(json: &Value) -> VtResult {
    match json.pointer("/data/attributes/last_analysis_stats") {
        None => VtResult::Unknown,
        Some(s) => {
            let malicious = s["malicious"].as_u64().unwrap_or(0);
            let undetected = s["undetected"].as_u64().unwrap_or(0);
            let suspicious = s["suspicious"].as_u64().unwrap_or(0);
            let harmless = s["harmless"].as_u64().unwrap_or(0);
            let total = malicious + undetected + suspicious + harmless;
            if malicious > 0 {
                VtResult::Malicious {
                    count: malicious,
                    total,
                }
            } else {
                VtResult::Clean(total)
            }
        }
    }
}
