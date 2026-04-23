//! MITRE ATT&CK technique lookup — thin delegation to forensicnomicon::mitre.

pub use forensicnomicon::mitre::AttackTechnique;

/// Look up an ATT&CK technique for a YARA match.
///
/// Priority: technique tag (T####) embedded in the match tags > rule name prefix table.
#[cfg(feature = "yara")]
pub fn lookup_attack_for_match(m: &crate::yara_scan::YaraMatch) -> Option<AttackTechnique> {
    // 1. Check tags for a T#### or T####.### pattern (e.g. T1486, T1059.001).
    for tag in &m.tags {
        if is_technique_id(tag) {
            return Some(AttackTechnique {
                technique_id: Box::leak(tag.clone().into_boxed_str()),
                tactic: "unknown",
                name: Box::leak(tag.clone().into_boxed_str()),
            });
        }
    }
    // 2. Fall back to forensicnomicon's prefix table.
    forensicnomicon::mitre::lookup_attack_for_rule_name(&m.rule_name)
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

/// Look up an ATT&CK technique by rule name prefix.
///
/// Delegates to `forensicnomicon::mitre::lookup_attack_for_rule_name`.
pub fn lookup_attack(rule_name: &str) -> Option<AttackTechnique> {
    forensicnomicon::mitre::lookup_attack_for_rule_name(rule_name)
}
