use crate::algorithm::Algorithm;
use crate::hash::FileHashResult;
use anyhow::Result;
use std::io::Write;

pub fn write_csv<W: Write>(
    w: &mut W,
    results: &[FileHashResult],
    algorithms: &[Algorithm],
) -> Result<()> {
    let has_entropy = results.iter().any(|r| r.entropy.is_some());

    // Header
    write!(w, "size")?;
    for algo in algorithms {
        write!(w, ",{}", algo.hashdeep_name())?;
    }
    if has_entropy {
        write!(w, ",entropy")?;
    }
    writeln!(w, ",filename")?;

    // Data
    for result in results {
        write!(w, "{}", result.size)?;
        for algo in algorithms {
            let hash = result
                .hashes
                .get(algo)
                .ok_or_else(|| anyhow::anyhow!("missing hash for algorithm {algo}"))?;
            write!(w, ",{hash}")?;
        }
        if has_entropy {
            match result.entropy {
                Some(e) => write!(w, ",{e}")?,
                None => write!(w, ",")?,
            }
        }
        writeln!(w, ",{}", result.path.display())?;
    }

    Ok(())
}
