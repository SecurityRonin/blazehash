use anyhow::Result;
use std::collections::HashSet;
use std::path::PathBuf;

#[derive(Debug)]
pub struct ResumeState {
    completed: HashSet<PathBuf>,
}

impl ResumeState {
    pub fn new() -> Self {
        Self {
            completed: HashSet::new(),
        }
    }

    pub fn from_manifest(content: &str) -> Result<Self> {
        let mut completed = HashSet::new();

        for line in content.lines() {
            if line.starts_with("%%%%") || line.starts_with('#') || line.is_empty() {
                continue;
            }
            // The filename is everything after the last expected comma-separated field.
            // For simplicity in resume, we use rfind to get the last comma and take the rest.
            if let Some(last_comma) = line.rfind(',') {
                let path = &line[last_comma + 1..];
                completed.insert(PathBuf::from(path));
            }
        }

        Ok(Self { completed })
    }

    pub fn is_done(&self, path: &PathBuf) -> bool {
        self.completed.contains(path)
    }

    pub fn mark_done(&mut self, path: PathBuf) {
        self.completed.insert(path);
    }

    pub fn completed_count(&self) -> usize {
        self.completed.len()
    }
}
