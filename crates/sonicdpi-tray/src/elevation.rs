//! Self-elevation: if launched without administrator privileges,
//! restart the same exe via `ShellExecuteExW` with the `runas` verb,
//! which prompts UAC. The current process exits cleanly so the user
//! sees only the UAC dialog → elevated tray icon.

#![cfg(windows)]

use std::os::windows::ffi::OsStrExt;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

pub fn ensure_elevated_or_relaunch() {
    if is_elevated() {
        return;
    }
    if relaunch_elevated().is_err() {
        // If UAC was cancelled, just continue without admin and let
        // the engine's own elevation check produce a clear error
        // visible in the log file.
        eprintln!("UAC declined — engine will fail to open WinDivert");
        return;
    }
    // The elevated child takes over; we exit so only one tray icon
    // appears.
    std::process::exit(0);
}

fn is_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut ret_len: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        let elevated = ok != 0 && elevation.TokenIsElevated != 0;
        CloseHandle(token);
        elevated
    }
}

fn relaunch_elevated() -> std::io::Result<()> {
    let exe = std::env::current_exe()?;
    let exe_w: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // Pass through any args (none expected for a tray launch).
    let args: String = std::env::args().skip(1).collect::<Vec<_>>().join(" ");
    let args_w: Vec<u16> = std::ffi::OsStr::new(&args)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let verb_w: [u16; 6] = [
        b'r' as u16,
        b'u' as u16,
        b'n' as u16,
        b'a' as u16,
        b's' as u16,
        0,
    ];

    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = verb_w.as_ptr();
    info.lpFile = exe_w.as_ptr();
    info.lpParameters = if args_w.len() > 1 {
        args_w.as_ptr()
    } else {
        std::ptr::null()
    };
    info.nShow = SW_SHOWNORMAL;

    let ok = unsafe { ShellExecuteExW(&mut info) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
