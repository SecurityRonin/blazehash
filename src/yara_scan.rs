use anyhow::Result;
use std::path::Path;

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

    pub fn scan(&self, data: &[u8]) -> Result<Vec<String>> {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        let results = scanner
            .scan(data)
            .map_err(|e| anyhow::anyhow!("YARA scan error: {e}"))?;
        Ok(results
            .matching_rules()
            .map(|r| r.identifier().to_string())
            .collect())
    }
}
