/// Enumerate NTFS Alternate Data Streams for a file. Windows-only; returns empty on other platforms.
#[cfg(target_os = "windows")]
pub fn enumerate_ads(_path: &std::path::Path) -> Vec<std::path::PathBuf> {
    // TODO: implement using FindFirstStreamW / FindNextStreamW from windows-sys
    // Each stream "filename:streamname:$DATA" → synthetic path "filename:streamname"
    vec![]
}

#[cfg(not(target_os = "windows"))]
pub fn enumerate_ads(_path: &std::path::Path) -> Vec<std::path::PathBuf> {
    vec![]
}
