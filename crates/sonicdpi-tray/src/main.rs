//! SonicDPI tray — minimal "double-click and forget" launcher.
//!
//! Double-click the .exe → UAC prompt (auto-elevation) → tray icon
//! appears. Right-click menu:
//!
//!   ● Status: ON / OFF (read-only label)
//!   ▸ Toggle (Включить / Выключить)
//!   ▸ Profile ▸ youtube-discord
//!              ▸ youtube-discord-seqovl
//!              ▸ youtube-discord-hostfakesplit
//!   ─────────
//!   ▸ Open logs folder
//!   ▸ Quit
//!
//! On stop or quit we tear down the OS hook (NFQUEUE rules / pf
//! anchor / WinDivert handle) before exiting so the user is never
//! left with a dangling firewall rule.

#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod elevation;
mod engine_guard;
mod icons;

use anyhow::Result;
use parking_lot::Mutex;
use sonicdpi_engine::Profile;
use std::sync::Arc;
use std::time::Duration;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu};
use tray_icon::{TrayIcon, TrayIconBuilder};
use winit::application::ApplicationHandler;
use winit::event::StartCause;
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop};

const PROFILES: &[(&str, &str)] = &[
    (
        "youtube-discord",
        "YouTube + Discord (default — gentle multisplit + RU pattern)",
    ),
    (
        "youtube-discord-aggressive",
        "Aggressive — ALT11 для Discord-direct (.gg/.media)",
    ),
    (
        "youtube-discord-multidisorder",
        "Multidisorder — out-of-order сегменты вместо seqovl",
    ),
    (
        "youtube-discord-seqovl",
        "ALT — только YouTube, без Discord-десинка",
    ),
    (
        "youtube-discord-hostfakesplit",
        "ALT — host-fake-split для YouTube",
    ),
];

fn main() -> Result<()> {
    init_tracing();
    install_panic_hook();
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "sonicdpi-tray launched"
    );

    // On Windows, re-launch ourselves elevated if we're not admin.
    // The current process exits if elevation kicks in; the elevated
    // child takes over.
    #[cfg(windows)]
    {
        tracing::info!("checking elevation");
        elevation::ensure_elevated_or_relaunch();
        tracing::info!("running elevated, building event loop");
    }

    let event_loop = EventLoop::new()?;
    event_loop.set_control_flow(ControlFlow::Wait);
    tracing::info!("event loop built, entering run_app");

    let mut app = TrayApp::new();
    let result = event_loop.run_app(&mut app);
    tracing::info!(?result, "event loop exited");
    result?;
    Ok(())
}

fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let location = info.location().map(|l| format!("{l}")).unwrap_or_default();
        let payload = info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(|s| s.as_str()))
            .unwrap_or("<non-string panic>");
        tracing::error!(location = %location, payload = %payload, "PANIC");
        eprintln!("[sonicdpi-tray PANIC] {location}: {payload}");
        prev(info);
    }));
}

struct TrayApp {
    tray: Option<TrayIcon>,
    menu_ids: MenuIds,
    state: AppState,
    guard: Arc<Mutex<engine_guard::EngineGuard>>,
}

struct MenuIds {
    status: tray_icon::menu::MenuId,
    toggle: tray_icon::menu::MenuId,
    profile_items: Vec<(tray_icon::menu::MenuId, &'static str)>,
    open_logs: tray_icon::menu::MenuId,
    bot_rosevpn: tray_icon::menu::MenuId,
    open_github: tray_icon::menu::MenuId,
    quit: tray_icon::menu::MenuId,
}

struct AppState {
    profile_name: String,
}

impl TrayApp {
    fn new() -> Self {
        Self {
            tray: None,
            menu_ids: MenuIds {
                status: Default::default(),
                toggle: Default::default(),
                profile_items: Vec::new(),
                open_logs: Default::default(),
                bot_rosevpn: Default::default(),
                open_github: Default::default(),
                quit: Default::default(),
            },
            state: AppState {
                profile_name: PROFILES[0].0.to_string(),
            },
            guard: Arc::new(Mutex::new(engine_guard::EngineGuard::new())),
        }
    }

    fn build_menu(&mut self) -> Menu {
        let menu = Menu::new();

        let running = self.guard.lock().is_running();
        let status_label = if running {
            "● ON  (защита включена)"
        } else {
            "○ OFF (выключено)"
        };
        let status = MenuItem::new(status_label, false, None);
        self.menu_ids.status = status.id().clone();
        let _ = menu.append(&status);
        let _ = menu.append(&PredefinedMenuItem::separator());

        let toggle_label = if running {
            "Выключить"
        } else {
            "Включить"
        };
        let toggle = MenuItem::new(toggle_label, true, None);
        self.menu_ids.toggle = toggle.id().clone();
        let _ = menu.append(&toggle);

        let profile_sub = Submenu::new("Профиль", true);
        self.menu_ids.profile_items.clear();
        for (id, label) in PROFILES {
            let mark = if *id == self.state.profile_name {
                "● "
            } else {
                "  "
            };
            let item = MenuItem::new(format!("{mark}{label}"), true, None);
            self.menu_ids.profile_items.push((item.id().clone(), id));
            let _ = profile_sub.append(&item);
        }
        let _ = menu.append(&profile_sub);

        let _ = menu.append(&PredefinedMenuItem::separator());
        let open_logs = MenuItem::new("Открыть папку с логами", true, None);
        self.menu_ids.open_logs = open_logs.id().clone();
        let _ = menu.append(&open_logs);

        let _ = menu.append(&PredefinedMenuItem::separator());
        // RoseVPN — fallback когда DPI-десинка не хватает
        let bot_rosevpn =
            MenuItem::new("🌹 RoseVPN — @rosevpnru_bot (если не работает)", true, None);
        self.menu_ids.bot_rosevpn = bot_rosevpn.id().clone();
        let _ = menu.append(&bot_rosevpn);

        let open_github = MenuItem::new("GitHub: by-sonic/sonicdpi", true, None);
        self.menu_ids.open_github = open_github.id().clone();
        let _ = menu.append(&open_github);

        let _ = menu.append(&PredefinedMenuItem::separator());
        let quit = MenuItem::new("Выйти", true, None);
        self.menu_ids.quit = quit.id().clone();
        let _ = menu.append(&quit);

        menu
    }

    fn rebuild_tray(&mut self) {
        tracing::info!("rebuild_tray: building menu");
        let menu = self.build_menu();
        tracing::info!("rebuild_tray: menu built");
        let running = self.guard.lock().is_running();
        tracing::info!("rebuild_tray: building icon");
        let icon = if running {
            icons::active_icon()
        } else {
            icons::idle_icon()
        };
        tracing::info!("rebuild_tray: icon built, dropping old tray");
        let tooltip = if running {
            format!("SonicDPI — {} — ON", self.state.profile_name)
        } else {
            "SonicDPI — OFF".to_string()
        };

        self.tray.take();
        tracing::info!("rebuild_tray: calling TrayIconBuilder::build()");

        match TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip(tooltip)
            .with_icon(icon)
            .build()
        {
            Ok(t) => {
                tracing::info!(running, "tray icon (re)built OK");
                self.tray = Some(t);
            }
            Err(e) => tracing::error!(error = %e, "tray build failed"),
        }
    }

    fn handle_menu(&mut self, event: MenuEvent) {
        let id = event.id();
        if id == &self.menu_ids.toggle {
            self.toggle();
        } else if id == &self.menu_ids.open_logs {
            open_logs_folder();
        } else if id == &self.menu_ids.bot_rosevpn {
            open_url("https://t.me/rosevpnru_bot");
        } else if id == &self.menu_ids.open_github {
            open_url("https://github.com/by-sonic/sonicdpi");
        } else if id == &self.menu_ids.quit {
            self.guard.lock().stop();
            std::process::exit(0);
        } else {
            for (mid, profile) in &self.menu_ids.profile_items {
                if id == mid {
                    let new_profile = (*profile).to_string();
                    if new_profile != self.state.profile_name {
                        self.state.profile_name = new_profile;
                        // Restart engine if running so the new profile takes effect.
                        if self.guard.lock().is_running() {
                            self.guard.lock().stop();
                            self.start_with_current_profile();
                        }
                    }
                    self.rebuild_tray();
                    return;
                }
            }
        }
    }

    fn toggle(&mut self) {
        let running = self.guard.lock().is_running();
        if running {
            self.guard.lock().stop();
        } else {
            self.start_with_current_profile();
        }
        self.rebuild_tray();
    }

    fn start_with_current_profile(&mut self) {
        let profile = match load_profile(&self.state.profile_name) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(error = %e, "failed to load profile");
                return;
            }
        };
        if let Err(e) = self.guard.lock().start(profile) {
            tracing::error!(error = %e, "engine start failed");
        }
    }
}

fn load_profile(name: &str) -> Result<Profile> {
    Ok(match name {
        "youtube-discord" => Profile::builtin_youtube_discord(),
        "youtube-discord-aggressive" => Profile::builtin_aggressive(),
        "youtube-discord-multidisorder" => Profile::builtin_multidisorder(),
        "youtube-discord-seqovl" => Profile::builtin_alt_seqovl(),
        "youtube-discord-hostfakesplit" => Profile::builtin_alt_hostfakesplit(),
        other => anyhow::bail!("unknown profile: {other}"),
    })
}

impl ApplicationHandler for TrayApp {
    fn new_events(&mut self, event_loop: &ActiveEventLoop, cause: StartCause) {
        match cause {
            StartCause::Init => {
                // Auto-start with the default profile so the user gets
                // "double-click and forget" UX. They can still toggle
                // off via the tray menu.
                self.start_with_current_profile();
                self.rebuild_tray();
                // Check menu events every 100ms — tray-icon delivers
                // them through its own thread-local channel.
                event_loop.set_control_flow(ControlFlow::WaitUntil(
                    std::time::Instant::now() + Duration::from_millis(100),
                ));
            }
            StartCause::ResumeTimeReached { .. } | StartCause::Poll => {
                while let Ok(event) = MenuEvent::receiver().try_recv() {
                    self.handle_menu(event);
                }
                event_loop.set_control_flow(ControlFlow::WaitUntil(
                    std::time::Instant::now() + Duration::from_millis(100),
                ));
            }
            _ => {}
        }
    }

    fn resumed(&mut self, _: &ActiveEventLoop) {}

    fn window_event(
        &mut self,
        _: &ActiveEventLoop,
        _: winit::window::WindowId,
        _: winit::event::WindowEvent,
    ) {
    }

    fn exiting(&mut self, _: &ActiveEventLoop) {
        self.guard.lock().stop();
    }
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let log_dir = log_dir();
    let _ = std::fs::create_dir_all(&log_dir);
    let log_path = log_dir.join("sonicdpi.log");
    if let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        // Wrap the file in a per-line flushing writer so we never lose
        // log lines if the process crashes mid-call (e.g. inside a C
        // dependency's stack overflow).
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                EnvFilter::new("sonicdpi=debug,sonicdpi_engine=debug,sonicdpi_platform=debug")
            }))
            .with_writer(std::sync::Mutex::new(FlushingWriter(file)))
            .with_ansi(false)
            .try_init();
    }
}

struct FlushingWriter(std::fs::File);

impl std::io::Write for FlushingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.0.write(buf)?;
        self.0.flush()?;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

fn log_dir() -> std::path::PathBuf {
    if let Some(p) = dirs() {
        return p;
    }
    std::env::temp_dir().join("sonicdpi")
}

fn dirs() -> Option<std::path::PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("LOCALAPPDATA").map(|v| std::path::PathBuf::from(v).join("SonicDPI"))
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join("Library/Logs/SonicDPI"))
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var_os("XDG_STATE_HOME")
            .map(|v| std::path::PathBuf::from(v).join("sonicdpi"))
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(|h| std::path::PathBuf::from(h).join(".local/state/sonicdpi"))
            })
    }
}

fn open_logs_folder() {
    let dir = log_dir();
    let _ = std::fs::create_dir_all(&dir);
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("explorer").arg(&dir).spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(&dir).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open").arg(&dir).spawn();
    }
}

fn open_url(url: &str) {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
}
