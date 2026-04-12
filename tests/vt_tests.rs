use blazehash::vt::{classify_vt_response, VtResult};

#[test]
fn test_classify_clean() {
    let json = serde_json::json!({
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "undetected": 70,
                    "harmless": 0,
                    "suspicious": 0
                }
            }
        }
    });
    let result = classify_vt_response(&json);
    assert_eq!(result, VtResult::Clean(70));
}

#[test]
fn test_classify_malicious() {
    let json = serde_json::json!({
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 35,
                    "undetected": 30,
                    "harmless": 0,
                    "suspicious": 0
                }
            }
        }
    });
    let result = classify_vt_response(&json);
    assert!(matches!(result, VtResult::Malicious { .. }));
    if let VtResult::Malicious { count, total } = result {
        assert_eq!(count, 35);
        assert_eq!(total, 65);
    }
}

#[test]
fn test_classify_unknown_on_missing_data() {
    let json = serde_json::json!({});
    let result = classify_vt_response(&json);
    assert_eq!(result, VtResult::Unknown);
}
