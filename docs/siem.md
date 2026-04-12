# SIEM & Analytics Integration

Export blazehash output directly into Elastic, Splunk, threat intel platforms, or your data warehouse.

---

## ECS NDJSON for Elastic / Splunk

```bash
blazehash -r /mnt/evidence -c sha256 --format ecs -o evidence.ndjson
```

Produces one [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html) record per file as newline-delimited JSON. Compatible with Filebeat, Logstash, and Splunk HEC.

**Filebeat config to ingest:**

```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /path/to/evidence.ndjson
    json.keys_under_root: true
    json.add_error_key: true

output.elasticsearch:
  hosts: ["https://your-es-cluster:9200"]
  index: "blazehash-%{+yyyy.MM.dd}"
```

**Splunk HEC ingestion:**

```bash
curl -k https://splunk:8088/services/collector/raw \
  -H "Authorization: Splunk YOUR_HEC_TOKEN" \
  -d @evidence.ndjson
```

---

## STIX 2.1 for Threat Intel Platforms

```bash
blazehash -r /mnt/evidence -c sha256 --format stix -o evidence.stix.json
```

Produces a STIX 2.1 JSON Bundle with `file` and `observed-data` objects. Ready for ingestion into:

- **MISP** -- import as STIX 2.1 bundle
- **OpenCTI** -- import via STIX connector
- **ThreatConnect**, **Recorded Future**, and any OASIS STIX-compatible platform

Each file becomes a STIX `file` object with hash indicators, making it immediately searchable across your threat intel ecosystem.

---

## Parquet for Data Lakes and Analytics

```bash
blazehash -r /mnt/evidence -c sha256 --format parquet -o evidence.parquet
```

Apache Parquet columnar format. Efficient for large-scale analytics.

**Query with DuckDB:**

```sql
SELECT filename, sha256, size
FROM read_parquet('evidence.parquet')
WHERE size > 1000000
ORDER BY size DESC;
```

**Query with pandas:**

```python
import pandas as pd
df = pd.read_parquet('evidence.parquet')
df[df['size'] > 1_000_000].sort_values('size', ascending=False)
```

**Query with polars:**

```python
import polars as pl
pl.scan_parquet('evidence.parquet').filter(pl.col('size') > 1_000_000).collect()
```

---

## DuckDB Output

```bash
blazehash -r /mnt/evidence -c sha256 --format duckdb -o evidence.duckdb
```

Writes directly to a DuckDB database file. Query immediately:

```bash
duckdb evidence.duckdb "SELECT filename, sha256 FROM hashes WHERE size > 1000000"
```

---

## SQLite Output

```bash
blazehash -r /mnt/evidence -c sha256 --format sqlite -o evidence.db
```

Query with any SQLite client:

```bash
sqlite3 evidence.db "SELECT filename, sha256, size FROM hashes ORDER BY size DESC LIMIT 20"
```

Join against your own tables, build custom reports, or use as input for other tools.

---

## JSON and JSONL

```bash
# JSON array (entire result set)
blazehash -r /mnt/evidence --format json -o evidence.json

# JSONL (one JSON object per line, streamable)
blazehash -r /mnt/evidence --format jsonl -o evidence.jsonl
```

JSONL is preferred for streaming ingestion (each line is independently parseable). JSON is convenient for smaller result sets or tools that expect an array.

---

## CSV

```bash
blazehash -r /mnt/evidence --format csv -o evidence.csv
```

Opens in Excel, Google Sheets, or any spreadsheet tool.

---

## DFXML

```bash
blazehash -r /mnt/evidence -c sha256 --format dfxml -o evidence.xml
```

Digital Forensics XML. Compatible with Autopsy, The Sleuth Kit, and other forensic platforms that support the Garfinkel DFXML standard.

---

## sha256sum / md5sum compatible

```bash
blazehash -r /mnt/evidence -c sha256 --format sha256sum -o hashes.sha256
blazehash -r /mnt/evidence -c md5 --format md5sum -o hashes.md5
```

Verifiable with standard coreutils:

```bash
sha256sum -c hashes.sha256
```

---

## Combine with chain of custody

All output formats work with case metadata:

```bash
blazehash -r /mnt/evidence -c sha256 \
  --case "CASE-2026-001" --examiner "Jane Smith" \
  --format ecs -o evidence.ndjson
```

Case ID and examiner name are embedded in each record, making them searchable in your SIEM.
