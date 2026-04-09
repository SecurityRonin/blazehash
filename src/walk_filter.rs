use globset::{Glob, GlobSet, GlobSetBuilder};

/// Filter applied during directory walking.
#[derive(Debug, Default, Clone)]
pub struct WalkFilter {
    include: Option<GlobSet>,
    exclude: Option<GlobSet>,
    pub min_size: Option<u64>,
    pub max_size: Option<u64>,
    pub newer_than: Option<std::time::SystemTime>,
}

impl WalkFilter {
    pub fn builder() -> WalkFilterBuilder {
        WalkFilterBuilder::default()
    }

    /// Returns true if this file should be hashed.
    pub fn passes(&self, filename: &str, size: u64, mtime: Option<std::time::SystemTime>) -> bool {
        if let Some(inc) = &self.include {
            if !inc.is_match(filename) {
                return false;
            }
        }
        if let Some(exc) = &self.exclude {
            if exc.is_match(filename) {
                return false;
            }
        }
        if let Some(min) = self.min_size {
            if size < min {
                return false;
            }
        }
        if let Some(max) = self.max_size {
            if size > max {
                return false;
            }
        }
        if let Some(newer) = self.newer_than {
            if let Some(mt) = mtime {
                if mt <= newer {
                    return false;
                }
            }
        }
        true
    }
}

#[derive(Default)]
pub struct WalkFilterBuilder {
    include_patterns: Vec<String>,
    exclude_patterns: Vec<String>,
    min_size: Option<u64>,
    max_size: Option<u64>,
    newer_than: Option<std::time::SystemTime>,
}

impl WalkFilterBuilder {
    pub fn include(mut self, pattern: &str) -> Self {
        self.include_patterns.push(pattern.to_string());
        self
    }
    pub fn exclude(mut self, pattern: &str) -> Self {
        self.exclude_patterns.push(pattern.to_string());
        self
    }
    pub fn min_size(mut self, size: u64) -> Self {
        self.min_size = Some(size);
        self
    }
    pub fn max_size(mut self, size: u64) -> Self {
        self.max_size = Some(size);
        self
    }
    pub fn newer_than(mut self, t: std::time::SystemTime) -> Self {
        self.newer_than = Some(t);
        self
    }

    pub fn build(self) -> anyhow::Result<WalkFilter> {
        let include = if self.include_patterns.is_empty() {
            None
        } else {
            let mut b = GlobSetBuilder::new();
            for p in &self.include_patterns {
                b.add(Glob::new(p).map_err(|e| anyhow::anyhow!("invalid glob {p:?}: {e}"))?);
            }
            Some(b.build()?)
        };
        let exclude = if self.exclude_patterns.is_empty() {
            None
        } else {
            let mut b = GlobSetBuilder::new();
            for p in &self.exclude_patterns {
                b.add(Glob::new(p).map_err(|e| anyhow::anyhow!("invalid glob {p:?}: {e}"))?);
            }
            Some(b.build()?)
        };
        Ok(WalkFilter {
            include,
            exclude,
            min_size: self.min_size,
            max_size: self.max_size,
            newer_than: self.newer_than,
        })
    }
}
