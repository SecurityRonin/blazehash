use crate::algorithm::Algorithm;
use crate::hash::FileHashResult;
use anyhow::Result;
use std::io::Write;

pub fn write_dfxml<W: Write>(
    w: &mut W,
    results: &[FileHashResult],
    algorithms: &[Algorithm],
) -> Result<()> {
    writeln!(w, "<?xml version='1.0' encoding='UTF-8'?>")?;
    writeln!(w, "<dfxml version='1.0' xmlns='http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML'>")?;
    writeln!(w, "  <metadata>")?;
    writeln!(w, "    <program>blazehash</program>")?;
    writeln!(w, "    <version>{}</version>", env!("CARGO_PKG_VERSION"))?;
    writeln!(w, "  </metadata>")?;

    for result in results {
        writeln!(w, "  <fileobject>")?;
        writeln!(
            w,
            "    <filename>{}</filename>",
            xml_escape(&result.path.display().to_string())
        )?;
        writeln!(w, "    <filesize>{}</filesize>", result.size)?;
        for algo in algorithms {
            if let Some(hash) = result.hashes.get(algo) {
                writeln!(
                    w,
                    "    <hashdigest type='{}'>{hash}</hashdigest>",
                    algo.hashdeep_name()
                )?;
            }
        }
        writeln!(w, "  </fileobject>")?;
    }

    writeln!(w, "</dfxml>")?;
    Ok(())
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
