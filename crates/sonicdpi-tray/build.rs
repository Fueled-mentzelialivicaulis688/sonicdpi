//! Copy WinDivert.dll + WinDivert64.sys (from `vendor/windivert/x64/`)
//! next to the tray exe so it works when the user double-clicks it.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(target_os = "windows")]
    {
        if let Err(e) = copy_windivert_files() {
            println!("cargo:warning=could not copy WinDivert files: {e}");
        }
    }
}

#[cfg(target_os = "windows")]
fn copy_windivert_files() -> std::io::Result<()> {
    use std::path::PathBuf;

    let out_dir =
        std::env::var_os("OUT_DIR").ok_or_else(|| std::io::Error::other("OUT_DIR not set"))?;
    let out_dir = PathBuf::from(out_dir);
    let profile_dir = out_dir
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .ok_or_else(|| std::io::Error::other("walk OUT_DIR parents"))?
        .to_path_buf();
    let workspace_root = profile_dir
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| std::io::Error::other("walk to workspace root"))?
        .to_path_buf();
    let vendor = workspace_root.join("vendor").join("windivert").join("x64");

    for name in ["WinDivert.dll", "WinDivert64.sys"] {
        let src = vendor.join(name);
        let dst = profile_dir.join(name);
        if src.exists() {
            std::fs::copy(&src, &dst)?;
            println!("cargo:warning=copied {} to {}", name, dst.display());
        }
    }
    Ok(())
}
