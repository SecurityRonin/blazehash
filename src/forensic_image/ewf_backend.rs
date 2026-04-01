use anyhow::Result;
use ewf::EwfReader;
use std::path::Path;

use super::{ImageFormat, ImageMetadata, ImageVerification};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn verify_ewf(path: &Path) -> Result<ImageVerification> {
    let mut reader = EwfReader::open(path)?;

    let media_size = reader.total_size();
    let stored = reader.stored_hashes();
    let meta = reader.metadata().clone();

    let result = reader.verify()?;

    let metadata = {
        let has_any = meta.case_number.is_some()
            || meta.examiner.is_some()
            || meta.description.is_some()
            || meta.acquiry_software.is_some();

        if has_any {
            Some(ImageMetadata {
                case_number: meta.case_number,
                examiner: meta.examiner,
                description: meta.description,
                acquiry_software: meta.acquiry_software,
            })
        } else {
            None
        }
    };

    Ok(ImageVerification {
        format: ImageFormat::Ewf,
        path: path.display().to_string(),
        media_size,
        stored_md5: stored.md5.as_ref().map(|h| hex(h)),
        stored_sha1: stored.sha1.as_ref().map(|h| hex(h)),
        computed_md5: Some(hex(&result.computed_md5)),
        computed_sha1: result.computed_sha1.as_ref().map(|h| hex(h)),
        md5_match: result.md5_match,
        sha1_match: result.sha1_match,
        metadata,
    })
}
