use blazehash::algorithm::{hash_bytes, Algorithm};
use blazehash::hash::FileHashResult;
use anyhow::Result;
use oci_distribution::{
    client::{Client, ClientConfig},
    manifest::{IMAGE_LAYER_GZIP_MEDIA_TYPE, IMAGE_LAYER_MEDIA_TYPE},
    secrets::RegistryAuth,
    Reference,
};
use std::collections::HashMap;

use blazehash::image::{layer_path, parse_image_ref, strip_oci_prefix};

pub fn oci_results(uri: &str, algorithms: &[Algorithm]) -> Result<Vec<FileHashResult>> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(oci_results_async(uri, algorithms))
}

async fn oci_results_async(uri: &str, algorithms: &[Algorithm]) -> Result<Vec<FileHashResult>> {
    let ref_str = strip_oci_prefix(uri);
    let image_ref = parse_image_ref(ref_str)?;

    let reference = Reference::with_tag(
        image_ref.registry.clone(),
        image_ref.name.clone(),
        image_ref.tag.clone(),
    );

    let client = Client::new(ClientConfig::default());
    let image_data = client
        .pull(
            &reference,
            &RegistryAuth::Anonymous,
            vec![IMAGE_LAYER_MEDIA_TYPE, IMAGE_LAYER_GZIP_MEDIA_TYPE],
        )
        .await
        .map_err(|e| anyhow::anyhow!("OCI pull failed for {uri}: {e}"))?;

    let mut results = Vec::new();
    for (i, layer) in image_data.layers.iter().enumerate() {
        let digest = layer.sha256_digest();
        let path = layer_path(ref_str, i, &digest);
        let size = layer.data.len() as u64;
        let mut hashes = HashMap::new();
        for algo in algorithms {
            hashes.insert(*algo, hash_bytes(*algo, &layer.data));
        }
        results.push(FileHashResult { path, size, hashes, entropy: None });
    }
    Ok(results)
}
