use crate::algorithm::Algorithm;
use crate::hash::FileHashResult;
use anyhow::Result;
use arrow::array::{Float64Array, Int64Array, StringArray};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use parquet::arrow::arrow_writer::ArrowWriter;
use std::path::Path;
use std::sync::Arc;

pub fn write_parquet(path: &Path, results: &[FileHashResult], algos: &[Algorithm]) -> Result<()> {
    let mut fields = vec![
        Field::new("path", DataType::Utf8, false),
        Field::new("size", DataType::Int64, false),
        Field::new("entropy", DataType::Float64, true),
    ];
    for algo in algos {
        fields.push(Field::new(algo.hashdeep_name(), DataType::Utf8, true));
    }
    let schema = Arc::new(Schema::new(fields));

    let paths: StringArray = results
        .iter()
        .map(|r| Some(r.path.to_string_lossy().into_owned()))
        .collect();
    let sizes: Int64Array = results.iter().map(|r| Some(r.size as i64)).collect();
    let entropies: Float64Array = results.iter().map(|r| r.entropy).collect();

    let mut columns: Vec<Arc<dyn arrow::array::Array>> =
        vec![Arc::new(paths), Arc::new(sizes), Arc::new(entropies)];

    for algo in algos {
        let col: StringArray = results.iter().map(|r| r.hashes.get(algo).cloned()).collect();
        columns.push(Arc::new(col));
    }

    let batch = RecordBatch::try_new(schema.clone(), columns)?;
    let file = std::fs::File::create(path)?;
    let mut writer = ArrowWriter::try_new(file, schema, None)?;
    writer.write(&batch)?;
    writer.close()?;
    Ok(())
}
