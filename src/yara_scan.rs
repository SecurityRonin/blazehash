use anyhow::Result;
use std::path::Path;

/// A single YARA rule match, carrying the rule name and all its tags.
#[derive(Debug, Clone)]
pub struct YaraMatch {
    pub rule_name: String,
    pub tags: Vec<String>,
}

pub struct YaraScanner {
    rules: yara_x::Rules,
}

impl YaraScanner {
    pub fn new(rules_file: &Path) -> Result<Self> {
        let source = std::fs::read_to_string(rules_file)?;
        let mut compiler = yara_x::Compiler::new();
        compiler
            .add_source(source.as_str())
            .map_err(|e| anyhow::anyhow!("YARA compile error: {e}"))?;
        let rules = compiler.build();
        Ok(Self { rules })
    }

    pub fn scan(&self, data: &[u8]) -> Result<Vec<YaraMatch>> {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        let results = scanner
            .scan(data)
            .map_err(|e| anyhow::anyhow!("YARA scan error: {e}"))?;
        Ok(results
            .matching_rules()
            .map(|r| YaraMatch {
                rule_name: r.identifier().to_string(),
                tags: r.tags().map(|t| t.identifier().to_string()).collect(),
            })
            .collect())
    }
}
