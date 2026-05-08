//! Engine lifecycle managed as a child process.
//!
//! `sonicdpi-tray.exe` does NOT load the engine in-process. It spawns
//! `sonicdpi.exe run --profile X --log-file %LOCALAPPDATA%\SonicDPI\sonicdpi.log`
//! as an elevated child (the tray itself is already elevated, so the
//! child inherits the token). On Stop / profile change / Quit we
//! `TerminateProcess` the child — the OS releases the WinDivert
//! handle cleanly, no chance of leaked handles racing each other on
//! the next start.
//!
//! The reason for this design: WinDivert's `recv()` is unconditionally
//! blocking and the windivert-rs handle isn't safe to shut down from
//! a different thread. Starting a new engine while the previous
//! handle is still alive results in two interceptors fighting over
//! the same packets. Using a child process is the OS-supported way
//! to guarantee teardown.

use anyhow::{Context, Result};
use sonicdpi_engine::Profile;
use std::path::PathBuf;
use std::process::{Child, Command};

pub struct EngineGuard {
    child: Option<Child>,
    /// Path to the sonicdpi.exe to run. Resolved once at construction.
    sonicdpi_exe: PathBuf,
}

impl EngineGuard {
    pub fn new() -> Self {
        Self {
            child: None,
            sonicdpi_exe: locate_sonicdpi_exe(),
        }
    }

    pub fn is_running(&mut self) -> bool {
        match self.child.as_mut() {
            Some(c) => match c.try_wait() {
                Ok(None) => true,
                Ok(Some(status)) => {
                    tracing::warn!(?status, "engine child exited unexpectedly");
                    self.child = None;
                    false
                }
                Err(e) => {
                    tracing::warn!(error = %e, "try_wait error");
                    false
                }
            },
            None => false,
        }
    }

    pub fn start(&mut self, profile: Profile) -> Result<()> {
        if self.is_running() {
            return Ok(());
        }
        if !self.sonicdpi_exe.exists() {
            anyhow::bail!(
                "sonicdpi.exe not found at {} — keep it next to sonicdpi-tray.exe",
                self.sonicdpi_exe.display()
            );
        }

        let log_file = log_file_path();

        let mut cmd = Command::new(&self.sonicdpi_exe);
        // -vv = debug. Surfaces "strategy fired" trace events and
        // per-flow target classifications, which are the only way to
        // diagnose why Discord/YouTube isn't being unblocked on a
        // specific user's network.
        cmd.args(["run", "--profile", &profile.name, "-vv"]);
        cmd.arg("--log-file").arg(&log_file);
        // Don't flash a console window; the child writes to log_file.
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        let child = cmd
            .spawn()
            .with_context(|| format!("spawn {}", self.sonicdpi_exe.display()))?;
        tracing::info!(pid = child.id(), profile = %profile.name, "engine child spawned");
        self.child = Some(child);
        Ok(())
    }

    pub fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let pid = c.id();
            // Best-effort: kill the child. On Windows this maps to
            // TerminateProcess, which the OS handles cleanly even
            // for elevated processes initiated by the same elevated
            // parent.
            if let Err(e) = c.kill() {
                tracing::warn!(pid, error = %e, "kill engine child");
            }
            // Reap so we don't leak a zombie/handle.
            let _ = c.wait();
            tracing::info!(pid, "engine child stopped");
        }
    }
}

impl Drop for EngineGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

/// `sonicdpi.exe` lives next to `sonicdpi-tray.exe` (we ship them in
/// the same release zip). Fall back to looking it up on PATH.
fn locate_sonicdpi_exe() -> PathBuf {
    let exe_name = if cfg!(windows) {
        "sonicdpi.exe"
    } else {
        "sonicdpi"
    };
    if let Ok(self_exe) = std::env::current_exe() {
        if let Some(dir) = self_exe.parent() {
            let candidate = dir.join(exe_name);
            if candidate.exists() {
                return candidate;
            }
        }
    }
    PathBuf::from(exe_name)
}

fn log_file_path() -> PathBuf {
    let dir = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(|v| PathBuf::from(v).join("SonicDPI"))
    } else if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library/Logs/SonicDPI"))
    } else {
        std::env::var_os("XDG_STATE_HOME")
            .map(|v| PathBuf::from(v).join("sonicdpi"))
            .or_else(|| {
                std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state/sonicdpi"))
            })
    }
    .unwrap_or_else(|| std::env::temp_dir().join("sonicdpi"));
    let _ = std::fs::create_dir_all(&dir);
    dir.join("sonicdpi.log")
}
