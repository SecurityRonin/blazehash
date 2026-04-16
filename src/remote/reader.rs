use anyhow::Result;

use super::operator::operator_for_uri;

/// Fetch the full UTF-8 text content of a remote URI.
///
/// Works in both async (Tokio) and pure blocking contexts.  In a blocking
/// context a single-threaded Tokio runtime is spun up temporarily so that
/// the async operator's read call has a live executor.
pub fn fetch_remote_text(uri: &str) -> Result<String> {
    let (op, path) = operator_for_uri(uri)?;

    // `opendal`'s blocking wrapper requires an active Tokio runtime handle.
    // If we are already inside one, use the async operator directly via
    // block_on on the handle; otherwise spin up a temporary runtime.
    let buf = match tokio::runtime::Handle::try_current() {
        Ok(handle) => handle.block_on(op.read(&path))?,
        Err(_) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(op.read(&path))?
        }
    };

    Ok(String::from_utf8(buf.to_vec())?)
}
