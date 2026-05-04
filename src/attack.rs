//! MITRE ATT&CK technique lookup.

/// A resolved MITRE ATT&CK technique entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackTechnique {
    /// ATT&CK technique ID, e.g. `"T1486"` or `"T1059.001"`.
    pub technique_id: &'static str,
    /// ATT&CK tactic (lowercase kebab-case), e.g. `"impact"`.
    pub tactic: &'static str,
    /// Human-readable technique name, e.g. `"Data Encrypted for Impact"`.
    pub name: &'static str,
}

/// Look up an ATT&CK technique for a YARA match.
///
/// Uses technique tags (T####) embedded in the match tags.
#[cfg(feature = "yara")]
pub fn lookup_attack_for_match(m: &crate::yara_scan::YaraMatch) -> Option<AttackTechnique> {
    for tag in &m.tags {
        if is_technique_id(tag) {
            return Some(AttackTechnique {
                technique_id: Box::leak(tag.clone().into_boxed_str()),
                tactic: "unknown",
                name: Box::leak(tag.clone().into_boxed_str()),
            });
        }
    }
    None
}

fn is_technique_id(s: &str) -> bool {
    let s = s.trim();
    if !s.starts_with('T') {
        return false;
    }
    let rest = &s[1..];
    let base = rest.split('.').next().unwrap_or("");
    base.len() == 4 && base.chars().all(|c| c.is_ascii_digit())
}

/// Look up an ATT&CK technique by rule name.
///
/// Returns `None` — rule-name prefix table removed with forensicnomicon dependency.
#[allow(dead_code)]
pub fn lookup_attack(_rule_name: &str) -> Option<AttackTechnique> {
    None
}
