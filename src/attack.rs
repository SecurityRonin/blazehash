/// A MITRE ATT&CK technique mapping entry.
pub struct AttackTechnique {
    pub technique_id: String,
    pub tactic: String,
    pub name: String,
}

/// Look up an ATT&CK technique for a YARA match.
/// Priority: technique tag (T####) > name prefix table.
#[cfg(feature = "yara")]
pub fn lookup_attack_for_match(m: &crate::yara_scan::YaraMatch) -> Option<AttackTechnique> {
    // 1. Check tags for T#### pattern (e.g. T1486, T1059.001)
    for tag in &m.tags {
        if is_technique_id(tag) {
            return Some(AttackTechnique {
                technique_id: tag.clone(),
                tactic: "unknown".to_string(),
                name: tag.clone(),
            });
        }
    }
    // 2. Fall back to name-prefix table
    lookup_attack(&m.rule_name)
}

fn is_technique_id(s: &str) -> bool {
    // Matches T1234 or T1234.001
    let s = s.trim();
    if !s.starts_with('T') {
        return false;
    }
    let rest = &s[1..];
    let base = rest.split('.').next().unwrap_or("");
    base.len() == 4 && base.chars().all(|c| c.is_ascii_digit())
}

/// Static prefix → technique mapping entries.
static ATTACK_PREFIXES: &[(&str, &str, &str, &str)] = &[
    ("rat_",          "T1219",     "command-and-control", "Remote Access Software"),
    ("ransomware_",   "T1486",     "impact",              "Data Encrypted for Impact"),
    ("wiper_",        "T1485",     "impact",              "Data Destruction"),
    ("creddump_",     "T1003",     "credential-access",   "OS Credential Dumping"),
    ("keylogger_",    "T1056.001", "collection",          "Input Capture: Keylogging"),
    ("rootkit_",      "T1014",     "defense-evasion",     "Rootkit"),
    ("backdoor_",     "T1505",     "persistence",         "Server Software Component"),
    ("dropper_",      "T1105",     "command-and-control", "Ingress Tool Transfer"),
    ("miner_",        "T1496",     "impact",              "Resource Hijacking"),
    ("stealer_",      "T1041",     "exfiltration",        "Exfiltration Over C2 Channel"),
    ("exploit_",      "T1203",     "execution",           "Exploitation for Client Execution"),
    ("loader_",       "T1129",     "execution",           "Shared Modules"),
    ("persistence_",  "T1547",     "persistence",         "Boot or Logon Autostart Execution"),
    ("injection_",    "T1055",     "defense-evasion",     "Process Injection"),
    ("shellcode_",    "T1059",     "execution",           "Command and Scripting Interpreter"),
    ("webshell_",     "T1505.003", "persistence",         "Server Software Component: Web Shell"),
    ("powershell_",   "T1059.001", "execution",           "PowerShell"),
    ("maldoc_",       "T1566.001", "initial-access",      "Phishing: Spearphishing Attachment"),
    ("botnet_",       "T1571",     "command-and-control", "Non-Standard Port"),
    ("antiav_",       "T1562",     "defense-evasion",     "Impair Defenses"),
];

/// Look up an ATT&CK technique by matching the start of `rule_name`
/// case-insensitively against known prefixes.
///
/// Returns `None` if no prefix matches.
pub fn lookup_attack(rule_name: &str) -> Option<AttackTechnique> {
    let lower = rule_name.to_lowercase();
    for &(prefix, technique_id, tactic, name) in ATTACK_PREFIXES {
        if lower.starts_with(prefix) {
            return Some(AttackTechnique {
                technique_id: technique_id.to_string(),
                tactic: tactic.to_string(),
                name: name.to_string(),
            });
        }
    }
    None
}
