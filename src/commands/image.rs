use blazehash::image::parse_image_ref;
use blazehash::algorithm::{hash_bytes, Algorithm};
use anyhow::Result;
use oci_distribution::{
    client::{Client, ClientConfig},
    manifest::{IMAGE_LAYER_GZIP_MEDIA_TYPE, IMAGE_LAYER_MEDIA_TYPE},
    secrets::RegistryAuth,
    Reference,
};

pub struct ImageArgs {
    pub image_ref: String,
    pub algorithms: Vec<Algorithm>,
}

pub fn run_image(args: ImageArgs) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_image_async(args))
}

async fn run_image_async(args: ImageArgs) -> Result<()> {
    let image_ref = parse_image_ref(&args.image_ref)?;

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
        .map_err(|e| anyhow::anyhow!("failed to pull image {}: {e}", args.image_ref))?;

    println!(
        "# blazehash image -- {}",
        args.image_ref
    );
    println!("# registry: {}", image_ref.registry);
    println!("# repository: {}", image_ref.name);
    if let Some(digest) = &image_data.digest {
        println!("# manifest digest: {digest}");
    }
    println!(
        "# algorithms: {}",
        args.algorithms
            .iter()
            .map(|a| a.hashdeep_name())
            .collect::<Vec<_>>()
            .join(",")
    );
    println!("# layer count: {}", image_data.layers.len());
    println!();

    for (i, layer) in image_data.layers.iter().enumerate() {
        let layer_digest = layer.sha256_digest();
        let label = format!("layer[{i}]:{layer_digest}");

        let hashes: Vec<String> = args
            .algorithms
            .iter()
            .map(|algo| hash_bytes(*algo, &layer.data))
            .collect();

        println!(
            "{}\t{}\t{}",
            hashes.join(","),
            layer.data.len(),
            label
        );
    }

    Ok(())
}
