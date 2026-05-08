//! System service install/uninstall.
//!
//! Each platform writes a service definition file pointing at the
//! current binary, then asks the OS to enable + start it.

use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

pub fn install(profile: &str) -> Result<()> {
    let bin = std::env::current_exe().context("current_exe")?;
    #[cfg(target_os = "linux")]
    return install_systemd(&bin, profile);
    #[cfg(target_os = "macos")]
    return install_launchd(&bin, profile);
    #[cfg(target_os = "windows")]
    return install_winsvc(&bin, profile);
    #[allow(unreachable_code)]
    {
        anyhow::bail!("install not supported on this OS");
    }
}

pub fn uninstall() -> Result<()> {
    #[cfg(target_os = "linux")]
    return uninstall_systemd();
    #[cfg(target_os = "macos")]
    return uninstall_launchd();
    #[cfg(target_os = "windows")]
    return uninstall_winsvc();
    #[allow(unreachable_code)]
    {
        anyhow::bail!("uninstall not supported on this OS");
    }
}

// ----------------- Linux: systemd -----------------
#[cfg(target_os = "linux")]
fn install_systemd(bin: &Path, profile: &str) -> Result<()> {
    let unit = format!(
        "[Unit]\n\
         Description=SonicDPI — DPI bypass for YouTube and Discord\n\
         After=network-online.target\n\
         Wants=network-online.target\n\n\
         [Service]\n\
         ExecStart={bin} run --profile {profile}\n\
         Restart=on-failure\n\
         AmbientCapabilities=CAP_NET_ADMIN\n\
         CapabilityBoundingSet=CAP_NET_ADMIN\n\
         NoNewPrivileges=true\n\
         ProtectSystem=strict\n\
         ProtectHome=true\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        bin = bin.display(),
        profile = profile,
    );
    let path = "/etc/systemd/system/sonicdpi.service";
    std::fs::write(path, unit).context("write systemd unit (need root)")?;
    let _ = Command::new("systemctl").args(["daemon-reload"]).status();
    let _ = Command::new("systemctl")
        .args(["enable", "--now", "sonicdpi.service"])
        .status();
    eprintln!("installed; tail logs: journalctl -u sonicdpi -f");
    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_systemd() -> Result<()> {
    let _ = Command::new("systemctl")
        .args(["disable", "--now", "sonicdpi.service"])
        .status();
    let _ = std::fs::remove_file("/etc/systemd/system/sonicdpi.service");
    let _ = Command::new("systemctl").args(["daemon-reload"]).status();
    Ok(())
}

// ----------------- macOS: launchd -----------------
#[cfg(target_os = "macos")]
fn install_launchd(bin: &Path, profile: &str) -> Result<()> {
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>Label</key>          <string>org.sonicdpi.daemon</string>
  <key>ProgramArguments</key>
  <array>
    <string>{bin}</string>
    <string>run</string>
    <string>--profile</string>
    <string>{profile}</string>
  </array>
  <key>RunAtLoad</key>      <true/>
  <key>KeepAlive</key>      <true/>
  <key>StandardOutPath</key><string>/var/log/sonicdpi.log</string>
  <key>StandardErrorPath</key><string>/var/log/sonicdpi.err.log</string>
</dict>
</plist>
"#,
        bin = bin.display(),
        profile = profile,
    );
    let path = "/Library/LaunchDaemons/org.sonicdpi.daemon.plist";
    std::fs::write(path, plist).context("write launchd plist (need sudo)")?;
    let _ = Command::new("launchctl")
        .args(["bootstrap", "system", path])
        .status();
    eprintln!("installed; tail logs: tail -f /var/log/sonicdpi.log");
    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_launchd() -> Result<()> {
    let path = "/Library/LaunchDaemons/org.sonicdpi.daemon.plist";
    let _ = Command::new("launchctl")
        .args(["bootout", "system", path])
        .status();
    let _ = std::fs::remove_file(path);
    Ok(())
}

// ----------------- Windows: SCM via sc.exe -----------------
#[cfg(target_os = "windows")]
fn install_winsvc(bin: &Path, profile: &str) -> Result<()> {
    let bin_str = bin.to_string_lossy();
    // sc create wants a single argv string for binPath; we wrap it in
    // double quotes so paths with spaces survive.
    let bin_path_arg = format!("\"{bin_str}\" run --profile {profile}");
    let st = Command::new("sc")
        .args([
            "create",
            "SonicDPI",
            "binPath=",
            &bin_path_arg,
            "start=",
            "auto",
            "DisplayName=",
            "SonicDPI DPI Bypass Service",
        ])
        .status()
        .context("sc create (run as Administrator)")?;
    if !st.success() {
        anyhow::bail!("sc create exited with {st}");
    }
    let _ = Command::new("sc").args(["start", "SonicDPI"]).status();
    eprintln!("installed; tail logs: Event Viewer → SonicDPI");
    Ok(())
}

#[cfg(target_os = "windows")]
fn uninstall_winsvc() -> Result<()> {
    let _ = Command::new("sc").args(["stop", "SonicDPI"]).status();
    let _ = Command::new("sc").args(["delete", "SonicDPI"]).status();
    Ok(())
}
