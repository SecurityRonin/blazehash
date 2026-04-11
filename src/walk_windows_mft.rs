#![cfg(target_os = "windows")]
//! Windows NTFS MFT direct enumeration for fast size-only mode.
//!
//! Reading `C:\$MFT` directly:
//! - Single sequential read of the entire file table — no per-file syscalls
//! - `$FILE_NAME` attribute gives parent reference + name
//! - `$DATA` attribute gives the actual file size (resident: value_length, non-resident: data_size)
//! - Requires Administrator (OS restricts `$MFT` to SYSTEM/Admin)
//!
//! UAC elevation flow when not already elevated:
//!   ShellExecuteEx(runas) → elevated child writes TSV to temp file → parent reads after wait

use std::collections::HashMap;
use std::io::Read;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_SEQUENTIAL_SCAN, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcessToken, WaitForSingleObject, INFINITE,
};
use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};

// ─── Public types ─────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct MftEntry {
    pub path: PathBuf,
    pub size: u64,
}

// ─── Volume path helpers ──────────────────────────────────────────────────────

/// Extract the volume device path (e.g. `\\.\C:`) from an absolute path.
/// Returns `None` for UNC paths (`\\server\share\...`) which can't use MFT directly.
pub fn volume_path_opt(path: &Path) -> Option<String> {
    let s = path.to_string_lossy();
    if s.starts_with("\\\\") || s.starts_with("//") {
        return None;
    }
    let mut chars = s.chars();
    let letter = chars.next()?;
    if chars.next()? != ':' {
        return None;
    }
    Some(format!("\\\\.\\{}:", letter.to_ascii_uppercase()))
}

/// Like [`volume_path_opt`] but returns `\\.\C:` as a fallback.
pub fn volume_path_for(path: &Path) -> String {
    volume_path_opt(path).unwrap_or_else(|| "\\\\.\\C:".to_string())
}

/// Returns the drive root for a path (e.g. `C:\Users\foo` → `C:\`).
fn drive_root_for(path: &Path) -> Option<PathBuf> {
    let s = path.to_string_lossy();
    if s.starts_with("\\\\") || s.starts_with("//") {
        return None;
    }
    let mut chars = s.chars();
    let letter = chars.next()?;
    if chars.next()? != ':' {
        return None;
    }
    Some(PathBuf::from(format!("{}:\\", letter.to_ascii_uppercase())))
}

// ─── Elevation check ─────────────────────────────────────────────────────────

/// Returns `true` if the current process has administrator privileges.
pub fn is_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut ret_len: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            std::ptr::addr_of_mut!(elev).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        CloseHandle(token);
        ok != 0 && elev.TokenIsElevated != 0
    }
}

// ─── MFT record constants ─────────────────────────────────────────────────────

const MFT_RECORD_SIZE: usize = 1024;
const MFT_RECORD_MAGIC: &[u8; 4] = b"FILE";
const MFT_ATTR_FILE_NAME: u32 = 0x30;
const MFT_ATTR_DATA: u32 = 0x80;
const MFT_ATTR_END: u32 = 0xFFFF_FFFF;
const MFT_FLAG_IN_USE: u16 = 0x01;
const MFT_FLAG_IS_DIR: u16 = 0x02;
// Namespace preferences: Win32 > Win32&DOS > DOS > POSIX
const NS_POSIX: u8 = 0;
const NS_WIN32: u8 = 1;
const NS_DOS: u8 = 2;
const NS_WIN32DOS: u8 = 3;

// ─── Byte-level helpers (all little-endian) ───────────────────────────────────

fn u16le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}
fn u32le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}
fn u64le(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
}

// ─── Update-sequence fixup ────────────────────────────────────────────────────

/// Apply the NTFS update-sequence fixup to a 1024-byte MFT record in place.
///
/// NTFS writes a "fixup" signature at the last two bytes of each 512-byte
/// sector within the record and stashes the original bytes in the Update
/// Sequence Array (USA). This detects torn writes. We restore the originals
/// before parsing.
///
/// Returns `false` if the record is structurally invalid (truncated, bad USA).
fn apply_fixup(buf: &mut [u8]) -> bool {
    if buf.len() < MFT_RECORD_SIZE {
        return false;
    }
    let usa_off = u16le(buf, 4) as usize;
    let usa_cnt = u16le(buf, 6) as usize; // includes the signature word itself
    if usa_cnt < 2 || usa_off + usa_cnt * 2 > buf.len() {
        return false;
    }
    let sig = u16le(buf, usa_off);
    // Sectors: bytes 0-511, 512-1023 → fixup positions at 510 and 1022
    for i in 1..usa_cnt {
        let sector_end = i * 512 - 2;
        if sector_end + 1 >= buf.len() {
            break;
        }
        if u16le(buf, sector_end) != sig {
            return false; // fixup mismatch = disk error on this sector
        }
        let orig = u16le(buf, usa_off + i * 2);
        buf[sector_end] = orig as u8;
        buf[sector_end + 1] = (orig >> 8) as u8;
    }
    true
}

// ─── Attribute parsers ────────────────────────────────────────────────────────

struct FileNameInfo {
    parent_ref: u64, // low 48 bits = MFT record number of parent directory
    name: std::ffi::OsString,
    namespace: u8,
}

fn parse_filename_attr(buf: &[u8], attr_off: usize, attr_len: usize) -> Option<FileNameInfo> {
    // $FILE_NAME is always resident (non_resident byte is 0)
    if buf[attr_off + 8] != 0 {
        return None;
    }
    // Resident header: value_offset at attr+20 (u16), value_length at attr+16 (u32)
    let val_off = attr_off + u16le(buf, attr_off + 20) as usize;
    // $FILE_NAME value layout: parent_ref(8) + timestamps(32) + alloc_size(8) + real_size(8)
    //                          + flags(4) + reparse_tag(4) + name_len(1) + namespace(1) + name(*)
    if val_off + 66 > buf.len() || val_off + 66 > attr_off + attr_len {
        return None;
    }
    let parent_ref = u64le(buf, val_off) & 0x0000_FFFF_FFFF_FFFF;
    let name_len = buf[val_off + 64] as usize; // UTF-16 code units
    let namespace = buf[val_off + 65];
    let name_start = val_off + 66;
    let name_end = name_start + name_len * 2;
    if name_end > buf.len() || name_end > attr_off + attr_len {
        return None;
    }
    let utf16: Vec<u16> = (0..name_len)
        .map(|i| u16le(buf, name_start + i * 2))
        .collect();
    Some(FileNameInfo {
        parent_ref,
        name: std::ffi::OsString::from_wide(&utf16),
        namespace,
    })
}

fn parse_data_size(buf: &[u8], attr_off: usize) -> Option<u64> {
    let non_resident = buf[attr_off + 8];
    Some(if non_resident == 0 {
        // Resident: value_length at offset +16 from attr header
        u32le(buf, attr_off + 16) as u64
    } else {
        // Non-resident header: data_size at offset +48 from attr header
        if attr_off + 56 > buf.len() {
            return None;
        }
        u64le(buf, attr_off + 48)
    })
}

// ─── Single-record parser ─────────────────────────────────────────────────────

struct RawRecord {
    parent_ref: u64,
    name: std::ffi::OsString,
    size: u64,
    is_dir: bool,
}

fn parse_record(buf: &[u8]) -> Option<RawRecord> {
    if buf.len() < MFT_RECORD_SIZE || &buf[0..4] != MFT_RECORD_MAGIC {
        return None;
    }
    let flags = u16le(buf, 22);
    if flags & MFT_FLAG_IN_USE == 0 {
        return None; // deleted / unused slot
    }
    // Extension records (base_file_reference != 0) extend another record's attribute list;
    // they don't contain independent $FILE_NAME/$DATA — skip them.
    if u64le(buf, 32) != 0 {
        return None;
    }
    let is_dir = flags & MFT_FLAG_IS_DIR != 0;
    let first_attr = u16le(buf, 20) as usize;
    if first_attr >= buf.len() {
        return None;
    }

    let mut best_fn: Option<FileNameInfo> = None;
    let mut data_size: Option<u64> = None;

    let mut off = first_attr;
    loop {
        if off + 8 > buf.len() {
            break;
        }
        let attr_type = u32le(buf, off);
        if attr_type == MFT_ATTR_END {
            break;
        }
        let attr_len = u32le(buf, off + 4) as usize;
        if attr_len < 8 || off + attr_len > buf.len() {
            break;
        }

        match attr_type {
            MFT_ATTR_FILE_NAME => {
                if let Some(fi) = parse_filename_attr(buf, off, attr_len) {
                    let better = match &best_fn {
                        None => true,
                        Some(prev) => {
                            namespace_priority(fi.namespace) > namespace_priority(prev.namespace)
                        }
                    };
                    if better {
                        best_fn = Some(fi);
                    }
                }
            }
            MFT_ATTR_DATA => {
                // Only the first unnamed $DATA stream holds the file content size
                if data_size.is_none() && buf[off + 9] == 0 {
                    data_size = parse_data_size(buf, off);
                }
            }
            _ => {}
        }

        off += attr_len;
    }

    let fi = best_fn?;
    Some(RawRecord {
        parent_ref: fi.parent_ref,
        name: fi.name,
        size: data_size.unwrap_or(0),
        is_dir,
    })
}

/// Higher = preferred namespace for display names.
fn namespace_priority(ns: u8) -> u8 {
    match ns {
        NS_WIN32 | NS_WIN32DOS => 3,
        NS_DOS => 1,
        NS_POSIX => 2,
        _ => 0,
    }
}

// ─── Path resolution ──────────────────────────────────────────────────────────

/// Iteratively resolve a full path for MFT record `start` by walking parent refs.
/// MFT record 5 is the volume root ("." in NTFS parlance).
fn resolve_path(
    records: &HashMap<u64, RawRecord>,
    start: u64,
    drive_root: &Path,
) -> Option<PathBuf> {
    const NTFS_ROOT: u64 = 5;
    let mut components: Vec<std::ffi::OsString> = Vec::new();
    let mut current = start;
    let mut seen = std::collections::HashSet::new();

    loop {
        if current == NTFS_ROOT {
            break;
        }
        if !seen.insert(current) {
            return None; // cycle → corrupt MFT
        }
        let rec = records.get(&current)?;
        components.push(rec.name.clone());
        current = rec.parent_ref;
    }

    components.reverse();
    let mut path = drive_root.to_path_buf();
    for c in components {
        path.push(c);
    }
    Some(path)
}

// ─── Main enumeration function ────────────────────────────────────────────────

/// Enumerate file sizes for all files under `root` by reading the NTFS `$MFT` directly.
///
/// **Requires Administrator** — returns `Err` if the `$MFT` cannot be opened.
///
/// Algorithm:
/// 1. Open `DRIVE:\$MFT` with sequential-scan hint (no extra buffering overhead).
/// 2. Parse every 1024-byte record: apply fixup, extract `$FILE_NAME` + `$DATA`.
/// 3. Resolve full paths via parent-reference chain (iterative, cycle-safe).
/// 4. Filter to `root` (recursive = entire subtree; non-recursive = direct children only).
pub fn enumerate_mft_sizes(root: &Path, recursive: bool) -> Result<Vec<MftEntry>> {
    let drive_root =
        drive_root_for(root).context("path must be on a local NTFS drive (not UNC)")?;

    // $MFT lives at the drive root, e.g. C:\$MFT
    let mft_path = format!("{}$MFT", drive_root.to_string_lossy());
    let mft_path_w: Vec<u16> = mft_path.encode_utf16().chain(std::iter::once(0)).collect();

    let handle = unsafe {
        CreateFileW(
            mft_path_w.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_SEQUENTIAL_SCAN,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        bail!(
            "Cannot open {} — run as Administrator for MFT direct access",
            mft_path
        );
    }

    // Wrap in std::fs::File for convenient read_exact / iteration
    use std::os::windows::io::FromRawHandle;
    let mut file = unsafe { std::fs::File::from_raw_handle(handle as *mut _) };

    // ── Pass 1: scan all MFT records ─────────────────────────────────────────
    // Keyed by MFT record number (sequential position in the file).
    let mut records: HashMap<u64, RawRecord> = HashMap::with_capacity(500_000);
    let mut buf = vec![0u8; MFT_RECORD_SIZE];
    let mut record_num = 0u64;

    loop {
        match file.read_exact(&mut buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        let mut fbuf = buf.clone();
        if apply_fixup(&mut fbuf) {
            if let Some(rec) = parse_record(&fbuf) {
                records.insert(record_num, rec);
            }
        }
        record_num += 1;
    }

    // ── Pass 2: resolve paths and filter ──────────────────────────────────────
    let root_canonical = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());

    let mut results = Vec::new();
    for (&rec_num, rec) in &records {
        if rec.is_dir {
            continue; // size-only output is files only
        }
        let Some(path) = resolve_path(&records, rec_num, &drive_root) else {
            continue;
        };
        let in_scope = if recursive {
            path.starts_with(&root_canonical)
        } else {
            // Non-recursive: file's parent must equal root
            path.parent()
                .is_some_and(|p| p == root_canonical || p == root)
        };
        if in_scope {
            results.push(MftEntry {
                path,
                size: rec.size,
            });
        }
    }

    Ok(results)
}

// ─── UAC elevation ────────────────────────────────────────────────────────────

/// Re-launch the current executable with administrator privileges via UAC.
///
/// The elevated subprocess receives `--_mft-worker <output_file> [--recursive] <root>`.
/// It writes results as TSV (`size\tpath`) to `output_file`, one line per file.
/// This function blocks until the subprocess exits, then returns.
///
/// Returns `Err` if the user cancels the UAC dialog or the spawn fails.
pub fn spawn_elevated_mft_worker(root: &Path, recursive: bool, output_file: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;

    let exe = std::env::current_exe().context("cannot determine current executable path")?;

    let mut args = format!(
        "--_mft-worker \"{}\" \"{}\"",
        output_file.to_string_lossy().replace('"', "\"\""),
        root.to_string_lossy().replace('"', "\"\""),
    );
    if recursive {
        args.push_str(" --recursive");
    }

    let verb_w: Vec<u16> = "runas\0".encode_utf16().collect();
    let exe_w: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let args_w: Vec<u16> = args.encode_utf16().chain(std::iter::once(0)).collect();

    let mut sei: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    sei.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = verb_w.as_ptr();
    sei.lpFile = exe_w.as_ptr();
    sei.lpParameters = args_w.as_ptr();
    sei.nShow = 2; // SW_SHOWMINIMIZED — start minimized so console doesn't intrude

    let ok = unsafe { ShellExecuteExW(&mut sei) };
    if ok == 0 || sei.hProcess.is_null() {
        bail!("UAC elevation was cancelled or failed");
    }

    eprintln!("[*] Elevated MFT worker running — waiting for results...");
    unsafe {
        WaitForSingleObject(sei.hProcess, INFINITE);
        CloseHandle(sei.hProcess);
    }

    Ok(())
}

// ─── Worker entry point ───────────────────────────────────────────────────────

/// Called inside the elevated subprocess (`blazehash --_mft-worker <outfile> <root>`).
/// Enumerates MFT and writes TSV results to `output_file`, then returns.
pub fn run_mft_worker(root: &Path, recursive: bool, output_file: &Path) -> Result<()> {
    let entries = enumerate_mft_sizes(root, recursive)?;
    let mut out = std::fs::File::create(output_file)
        .with_context(|| format!("cannot create worker output: {}", output_file.display()))?;
    use std::io::Write;
    for e in &entries {
        writeln!(out, "{}\t{}", e.size, e.path.display())?;
    }
    Ok(())
}

// ─── TSV reader (parent process) ─────────────────────────────────────────────

/// Parse TSV results written by the elevated MFT worker.
/// Format: `size\tpath` one per line. Malformed lines are silently skipped.
pub fn read_mft_results(output_file: &Path) -> Result<Vec<MftEntry>> {
    let content = std::fs::read_to_string(output_file).with_context(|| {
        format!(
            "failed to read MFT worker output from {}",
            output_file.display()
        )
    })?;
    let mut entries = Vec::new();
    for line in content.lines() {
        let mut parts = line.splitn(2, '\t');
        let Some(size_str) = parts.next() else {
            continue;
        };
        let Some(path_str) = parts.next() else {
            continue;
        };
        let size: u64 = size_str.parse().unwrap_or(0);
        entries.push(MftEntry {
            path: PathBuf::from(path_str),
            size,
        });
    }
    Ok(entries)
}
