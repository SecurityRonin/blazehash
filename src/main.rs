mod cli;

use anyhow::Result;
use blazehash::hash::hash_file;
use blazehash::manifest::{write_header, write_record};
use blazehash::walk::walk_and_hash;
use clap::Parser;
use cli::Cli;
use std::fs::File;
use std::io::{self, BufWriter, Write};

fn main() -> Result<()> {
    let cli = Cli::parse();

    let algorithms = cli.flat_algorithms();

    let mut writer: Box<dyn Write> = match &cli.output {
        Some(path) => Box::new(BufWriter::new(File::create(path)?)),
        None => Box::new(BufWriter::new(io::stdout().lock())),
    };

    if cli.size_only {
        for path in &cli.paths {
            if path.is_file() {
                let meta = std::fs::metadata(path)?;
                writeln!(writer, "{}\t{}", meta.len(), path.display())?;
            } else if path.is_dir() {
                let results = walk_and_hash(path, &algorithms, cli.recursive)?;
                for r in &results {
                    writeln!(writer, "{}\t{}", r.size, r.path.display())?;
                }
            }
        }
        return Ok(());
    }

    if !cli.bare {
        write_header(&mut writer, &algorithms)?;
    }

    for path in &cli.paths {
        if path.is_file() {
            let result = hash_file(path, &algorithms)?;
            write_record(&mut writer, &result, &algorithms)?;
        } else if path.is_dir() {
            let results = walk_and_hash(path, &algorithms, cli.recursive)?;
            for result in &results {
                write_record(&mut writer, result, &algorithms)?;
            }
        }
    }

    writer.flush()?;
    Ok(())
}
