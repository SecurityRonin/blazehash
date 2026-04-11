/// Enumerate NTFS Alternate Data Streams for a file.
///
/// Returns a `Vec` of synthetic paths of the form `original_path:stream_name`
/// for each named ADS. The default unnamed stream (`::$DATA`) is excluded.
/// Returns empty on non-Windows or on any API failure (e.g. non-NTFS volume).
#[cfg(target_os = "windows")]
pub fn enumerate_ads(path: &std::path::Path) -> Vec<std::path::PathBuf> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        FindFirstStreamW, FindNextStreamW, FindStreamInfoStandard, WIN32_FIND_STREAM_DATA,
    };

    // Null-terminated wide string of the path
    let wide: Vec<u16> = std::ffi::OsStr::new(path)
        .encode_wide()
        .chain(Some(0))
        .collect();

    let mut data: WIN32_FIND_STREAM_DATA = unsafe { std::mem::zeroed() };
    let handle = unsafe {
        FindFirstStreamW(
            wide.as_ptr(),
            FindStreamInfoStandard,
            &mut data as *mut WIN32_FIND_STREAM_DATA as *mut _,
            0,
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        return vec![];
    }

    let mut results = Vec::new();

    loop {
        // Stream names have the form "::$DATA" (default) or ":name:$DATA" (named ADS).
        let name_len = data
            .cStreamName
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(data.cStreamName.len());
        let stream_name = String::from_utf16_lossy(&data.cStreamName[..name_len]);

        // Skip the default unnamed data stream; include only named ADS.
        if stream_name != "::$DATA" && stream_name.ends_with(":$DATA") {
            // ":name:$DATA" → strip trailing ":$DATA" to get ":name"
            let short = &stream_name[..stream_name.len() - ":$DATA".len()];
            // Synthetic path: "C:\path\to\file.txt:name"
            let ads_path = format!("{}{}", path.display(), short);
            results.push(std::path::PathBuf::from(ads_path));
        }

        let found =
            unsafe { FindNextStreamW(handle, &mut data as *mut WIN32_FIND_STREAM_DATA as *mut _) };
        if found == 0 {
            break;
        }
    }

    unsafe { CloseHandle(handle) };

    results
}

#[cfg(not(target_os = "windows"))]
pub fn enumerate_ads(_path: &std::path::Path) -> Vec<std::path::PathBuf> {
    vec![]
}
