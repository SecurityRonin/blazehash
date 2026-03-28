use crate::algorithm::Algorithm;
use crate::hash::FileHashResult;
use anyhow::Result;
use std::io::Write;

pub fn write_csv<W: Write>(
    w: &mut W,
    results: &[FileHashResult],
    algorithms: &[Algorithm],
) -> Result<()> {
    // Header
    write!(w, "size")?;
    for algo in algorithms {
        write!(w, ",{}", algo.hashdeep_name())?;
    }
    writeln!(w, ",filename")?;

    // Data
    for result in results {
        write!(w, "{}", result.size)?;
        for algo in algorithms {
            write!(w, ",{}", result.hashes[algo])?;
        }
        writeln!(w, ",{}", result.path.display())?;
    }

    Ok(())
}
