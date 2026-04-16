use anyhow::{bail, Result};
use opendal::{services, Operator};

/// Build an [`Operator`] and return `(Operator, relative_path)` from a remote URI.
///
/// Supported schemes: `mem`, `s3`, `gcs`, `azblob`, `webdav`, `http`, `https`, `file`
pub fn operator_for_uri(uri: &str) -> Result<(Operator, String)> {
    let (scheme, rest) = uri
        .split_once("://")
        .ok_or_else(|| anyhow::anyhow!("not a URI: {uri}"))?;

    match scheme {
        "mem" => {
            // mem://bucket/key  →  write at "bucket/key" within a fresh Memory service
            let op = Operator::new(services::Memory::default())?.finish();
            Ok((op, rest.to_string()))
        }
        "s3" => {
            let (bucket, key) = rest.split_once('/').unwrap_or((rest, ""));
            let region = std::env::var("AWS_DEFAULT_REGION")
                .unwrap_or_else(|_| "us-east-1".into());
            let builder = services::S3::default().bucket(bucket).region(&region);
            let op = Operator::new(builder)?.finish();
            Ok((op, key.to_string()))
        }
        "gcs" => {
            let (bucket, key) = rest.split_once('/').unwrap_or((rest, ""));
            let builder = services::Gcs::default().bucket(bucket);
            let op = Operator::new(builder)?.finish();
            Ok((op, key.to_string()))
        }
        "azblob" => {
            let (container, blob) = rest.split_once('/').unwrap_or((rest, ""));
            let account = std::env::var("AZURE_STORAGE_ACCOUNT")
                .unwrap_or_else(|_| "devstoreaccount1".into());
            let builder = services::Azblob::default()
                .container(container)
                .account_name(&account);
            let op = Operator::new(builder)?.finish();
            Ok((op, blob.to_string()))
        }
        "webdav" => {
            let host = rest.split('/').next().unwrap_or("");
            let endpoint = format!("https://{host}");
            let path = rest.split_once('/').map(|(_, p)| p).unwrap_or("");
            let builder = services::Webdav::default().endpoint(&endpoint);
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }
        "http" | "https" => {
            let host = rest.split('/').next().unwrap_or("");
            let endpoint = format!("{scheme}://{host}");
            let path = rest.split_once('/').map(|(_, p)| p).unwrap_or("");
            let builder = services::Http::default().endpoint(&endpoint);
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }
        "file" => {
            let (dir, file) = rest.rsplit_once('/').unwrap_or(("/", rest));
            let builder = services::Fs::default().root(dir);
            let op = Operator::new(builder)?.finish();
            Ok((op, file.to_string()))
        }
        other => bail!("unsupported URI scheme: {other}://"),
    }
}
