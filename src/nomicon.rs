//! forensicnomicon integration — path annotation, LOLBin detection, catalog
//! YARA scanner, and YARA-match enrichment.
//!
//! Gated on the `nomicon` feature flag. The `build_catalog_scanner` function
//! additionally requires the `yara` feature.

use forensicnomicon::catalog::{ArtifactType, TriagePriority, CATALOG};
use forensicnomicon::lolbins::{is_linux_lolbin, is_windows_lolbin};
use std::path::Path;

// ── NomiconMatch ──────────────────────────────────────────────────────────────

/// Catalog annotation for a hashed file that matched a forensicnomicon artifact.
#[derive(Debug, Clone)]
pub struct NomiconMatch {
    /// Short catalog artifact ID (e.g. `"chrome_history"`).
    pub artifact_id: &'static str,
    /// Human-readable artifact name.
    pub artifact_name: &'static str,
    /// Triage priority as a lowercase string: `"critical"`, `"high"`, `"medium"`, `"low"`.
    pub triage_priority: String,
    /// First MITRE ATT&CK technique ID, or empty string if none.
    pub mitre_technique: String,
    /// Artifact type as a lowercase string (e.g. `"file"`, `"registry_key"`).
    pub artifact_type: String,
}

// ── YaraEnrichment ───────────────────────────────────────────────────────────

/// Enrichment data for a YARA rule match, pulled from the forensicnomicon catalog.
#[derive(Debug, Clone)]
pub struct YaraEnrichment {
    pub artifact_id: &'static str,
    pub triage_priority: &'static str,
    pub mitre_techniques: Vec<&'static str>,
    pub sigma_rule_id: Option<&'static str>,
    pub sigma_title: Option<&'static str>,
    pub velociraptor_artifacts: Vec<&'static str>,
    pub kape_targets: Vec<&'static str>,
    pub playbook_id: Option<&'static str>,
    pub playbook_name: Option<&'static str>,
}

// ── Helper: TriagePriority → &'static str ────────────────────────────────────

fn priority_str(p: TriagePriority) -> &'static str {
    match p {
        TriagePriority::Critical => "critical",
        TriagePriority::High => "high",
        TriagePriority::Medium => "medium",
        TriagePriority::Low => "low",
        // TriagePriority is #[non_exhaustive]; cover any future variants.
        _ => "unknown",
    }
}

fn priority_string(p: TriagePriority) -> String {
    priority_str(p).to_string()
}

fn artifact_type_str(t: ArtifactType) -> &'static str {
    match t {
        ArtifactType::File => "file",
        ArtifactType::Directory => "directory",
        ArtifactType::RegistryKey => "registry_key",
        ArtifactType::RegistryValue => "registry_value",
        ArtifactType::EventLog => "event_log",
        ArtifactType::MemoryRegion => "memory_region",
        // Non-exhaustive enum — cover any future variants gracefully.
        _ => "unknown",
    }
}

// ── Feature 1: Path annotation ────────────────────────────────────────────────

/// Match a file path against the forensicnomicon CATALOG.
///
/// Extracts the filename component from `path` and checks whether any catalog
/// artifact's `file_path` field contains that filename (case-insensitive).
/// Returns the first (highest triage priority) match, or `None`.
pub fn match_path(path: &Path) -> Option<NomiconMatch> {
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if filename.is_empty() {
        return None;
    }

    // Collect all matching descriptors, then sort by triage priority descending
    // so we return the most important one.
    //
    // Matching strategy: extract the filename component from the catalog's `file_path`
    // (after normalizing backslashes to forward slashes and stripping environment variable
    // prefixes like `%LOCALAPPDATA%`).  A hit requires that the catalog filename exactly
    // equals (case-insensitive) the query filename, OR that the catalog's full `file_path`
    // (lowercased) contains our filename as a substring — but NOT the reverse (we do NOT
    // check whether our query filename contains a catalog component, as that produces
    // too many spurious matches for short names like "bin", "sh", or "lib").
    let mut matches: Vec<_> = CATALOG
        .list()
        .iter()
        .filter(|desc| {
            if let Some(fp) = desc.file_path {
                let fp_lower = fp.to_ascii_lowercase();
                // Extract the tail filename from the catalog path (normalize separators
                // and strip environment variable placeholders like %LOCALAPPDATA%).
                let normalized = fp_lower.replace('\\', "/");
                let catalog_filename = normalized
                    .split('/')
                    .last()
                    .unwrap_or("")
                    // Strip any trailing env-var suffix after the actual filename
                    // (e.g. "history" from "%LOCALAPPDATA%/.../history").
                    .trim_matches('%');

                // Primary match: catalog file_path contains our query filename.
                if fp_lower.contains(filename.as_str()) {
                    return true;
                }

                // Secondary match: catalog filename exactly equals query filename.
                if !catalog_filename.is_empty() && catalog_filename == filename.as_str() {
                    return true;
                }

                false
            } else {
                false
            }
        })
        .collect();

    // Sort by triage priority descending (Critical=3 > High=2 > Medium=1 > Low=0)
    matches.sort_by(|a, b| b.triage_priority.cmp(&a.triage_priority));

    matches.first().map(|desc| NomiconMatch {
        artifact_id: desc.id,
        artifact_name: desc.name,
        triage_priority: priority_string(desc.triage_priority),
        mitre_technique: desc
            .mitre_techniques
            .first()
            .copied()
            .unwrap_or("")
            .to_string(),
        artifact_type: artifact_type_str(desc.artifact_type).to_string(),
    })
}

// ── Feature 2: LOLBin detection ──────────────────────────────────────────────

/// Returns `true` if the filename component of `path` matches a known Windows
/// or Linux LOLBin (case-insensitive).
pub fn is_lolbin(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    is_windows_lolbin(name) || is_linux_lolbin(name)
}

// ── Feature 3: Catalog YARA scanner ──────────────────────────────────────────

/// Build a `YaraScanner` pre-loaded with all forensicnomicon YARA rule templates.
///
/// Requires both the `nomicon` and `yara` features.
#[cfg(feature = "yara")]
pub fn build_catalog_scanner() -> anyhow::Result<crate::yara_scan::YaraScanner> {
    let templates = forensicnomicon::yara::all_yara_templates();
    let combined: String = templates
        .iter()
        .map(|(_, rule)| rule.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    crate::yara_scan::YaraScanner::from_source(&combined)
}

// ── Feature 4: YARA match enrichment ─────────────────────────────────────────

/// Attempt to look up enrichment for a YARA rule name generated by forensicnomicon.
///
/// The catalog sanitizes artifact IDs by replacing hyphens with underscores when
/// building YARA rule names.  This function reverses that by trying both the
/// rule name as-is and with underscores converted back to hyphens.
///
/// Returns `None` if no matching catalog artifact is found.
pub fn enrich_yara_match(rule_name: &str) -> Option<YaraEnrichment> {
    use forensicnomicon::playbooks::playbooks_for_artifact;
    use forensicnomicon::sigma::sigma_refs_for;
    use forensicnomicon::toolchain::KAPE_MAPPINGS;

    // Try the rule name directly, then with underscores replaced by hyphens.
    let desc = CATALOG
        .by_id(rule_name)
        .or_else(|| CATALOG.by_id(&rule_name.replace('_', "-")))?;

    let sigma_refs = sigma_refs_for(desc.id);
    let sigma_rule_id = sigma_refs.first().map(|s| s.rule_id);
    let sigma_title = sigma_refs.first().map(|s| s.title);

    let kape_mapping = KAPE_MAPPINGS
        .iter()
        .find(|m| m.artifact_id == desc.id);

    let velociraptor_artifacts: Vec<&'static str> = kape_mapping
        .map(|m| m.velociraptor_artifacts.to_vec())
        .unwrap_or_default();

    let kape_targets: Vec<&'static str> = kape_mapping
        .map(|m| m.kape_targets.to_vec())
        .unwrap_or_default();

    let playbooks = playbooks_for_artifact(desc.id);
    let playbook_id = playbooks.first().map(|p| p.id);
    let playbook_name = playbooks.first().map(|p| p.name);

    Some(YaraEnrichment {
        artifact_id: desc.id,
        triage_priority: priority_str(desc.triage_priority),
        mitre_techniques: desc.mitre_techniques.to_vec(),
        sigma_rule_id,
        sigma_title,
        velociraptor_artifacts,
        kape_targets,
        playbook_id,
        playbook_name,
    })
}
