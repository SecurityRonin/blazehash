use anyhow::Result;
use std::io::Write;
use std::path::PathBuf;

pub struct ReportArgs {
    pub manifest: PathBuf,
    pub output: PathBuf,
    pub examiner: String,
    pub case_id: String,
}

/// Convert Unix epoch seconds to (year, month, day, hour, min, sec) UTC.
fn epoch_to_parts(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    // Gregorian calendar calculation (valid for dates >= 1970)
    let mut y = 1970u32;
    let mut d = days as u32;
    loop {
        let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
        let days_in_year = if leap { 366 } else { 365 };
        if d < days_in_year {
            break;
        }
        d -= days_in_year;
        y += 1;
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let months = [
        31u32,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut mo = 1u32;
    for days_in_month in &months {
        if d < *days_in_month {
            break;
        }
        d -= days_in_month;
        mo += 1;
    }
    (y, mo, d + 1, h as u32, m as u32, s as u32)
}

pub fn run_report(args: ReportArgs) -> Result<()> {
    use blazehash::manifest_loader::load_manifest;
    use minijinja::{context, Environment};
    use sha2::{Digest, Sha256};

    // Compute SHA-256 of manifest file
    let manifest_bytes = std::fs::read(&args.manifest)?;
    let manifest_sha256 = hex::encode(Sha256::digest(&manifest_bytes));

    // Load records
    let records = load_manifest(&args.manifest)?;

    // Build rows for template
    let rows: Vec<_> = records
        .iter()
        .map(|r| {
            let hash = r
                .hashes
                .values()
                .next()
                .map(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            std::collections::HashMap::from([
                ("path".to_string(), r.path.display().to_string()),
                ("size".to_string(), r.size.to_string()),
                ("hash".to_string(), hash),
            ])
        })
        .collect();

    let template_src = include_str!("../report_template.html");
    let mut env = Environment::new();
    env.add_template("report", template_src)?;
    let tmpl = env.get_template("report")?;

    let now = {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let (y, mo, d, h, mi, s) = epoch_to_parts(secs);
        format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}")
    };
    let html = tmpl.render(context! {
        case => args.case_id,
        examiner => args.examiner,
        generated => now,
        manifest_sha256 => manifest_sha256,
        rows => rows,
    })?;

    let mut f = std::fs::File::create(&args.output)?;
    f.write_all(html.as_bytes())?;
    Ok(())
}
