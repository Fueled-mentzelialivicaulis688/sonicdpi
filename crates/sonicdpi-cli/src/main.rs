//! SonicDPI — CLI entry point.
//!
//! Subcommands:
//!   run        Run the engine in the foreground.
//!   install    Install as a system service (winsvc / systemd / launchd).
//!   uninstall  Remove the system service.
//!   profiles   List built-in profiles.
//!   show       Print a profile as TOML for editing.

mod service;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sonicdpi_engine::{Engine, Profile};
use sonicdpi_platform::{DefaultInterceptor, Interceptor, InterceptorConfig, PortRange};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(
    name = "sonicdpi",
    version,
    about = "Open-source DPI bypass for YouTube and Discord"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,

    /// Increase log verbosity (-v info, -vv debug, -vvv trace).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Append all log output to this file (in addition to stderr).
    /// Used by the tray launcher to capture child-process logs.
    #[arg(long, global = true)]
    log_file: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Start the engine in the foreground.
    Run {
        /// Built-in profile name or path to a TOML file.
        #[arg(short, long, default_value = "youtube-discord")]
        profile: String,
    },
    /// Install the system service.
    Install {
        #[arg(short, long, default_value = "youtube-discord")]
        profile: String,
    },
    /// Uninstall the system service.
    Uninstall,
    /// List built-in profiles.
    Profiles,
    /// Print a built-in profile as TOML.
    Show {
        /// Built-in profile name.
        name: String,
        /// Write to this path instead of stdout.
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Probe several profiles against a target host and report which
    /// one currently delivers data the fastest. Does NOT install the
    /// engine — it just opens TCP/443 with each profile's strategy
    /// from userspace and times the TLS handshake.
    Probe {
        /// Hostname to probe (e.g. `rr1.googlevideo.com`).
        #[arg(short = 'H', long, default_value = "www.googlevideo.com")]
        host: String,
        /// Comma-separated profile names. Empty = all built-ins.
        #[arg(short, long)]
        profiles: Option<String>,
        /// Probe timeout per profile, seconds.
        #[arg(short, long, default_value = "8")]
        timeout_secs: u64,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose, cli.log_file.as_deref());

    match cli.cmd {
        Cmd::Run { profile } => run(&profile),
        Cmd::Install { profile } => service::install(&profile),
        Cmd::Uninstall => service::uninstall(),
        Cmd::Profiles => {
            for name in BUILTIN_PROFILES {
                println!("  {name}");
            }
            Ok(())
        }
        Cmd::Show { name, out } => {
            let p = load_builtin(&name)?;
            let s = toml::to_string_pretty(&p).context("serialize profile")?;
            if let Some(path) = out {
                std::fs::write(&path, s)?;
                eprintln!("wrote {}", path.display());
            } else {
                print!("{s}");
            }
            Ok(())
        }
        Cmd::Probe {
            host,
            profiles,
            timeout_secs,
        } => probe(&host, profiles.as_deref(), timeout_secs),
    }
}

fn probe(host: &str, profiles: Option<&str>, timeout_secs: u64) -> Result<()> {
    use sonicdpi_engine::probing::ProbingHarness;
    use std::io::Write;
    use std::time::{Duration, Instant};

    let names: Vec<String> = match profiles {
        Some(s) => s.split(',').map(|s| s.trim().to_string()).collect(),
        None => BUILTIN_PROFILES.iter().map(|s| (*s).to_string()).collect(),
    };
    let h = ProbingHarness::new(names.clone());

    println!("probing {host}:443 with {} profile(s)", names.len());
    for name in &names {
        let profile = load_profile(name)?;
        let start = Instant::now();
        let result = run_one_probe(host, &profile, Duration::from_secs(timeout_secs));
        let elapsed = start.elapsed();
        match result {
            Ok(bytes_in) => {
                println!(
                    "  {name:<40}  WIN  {} bytes in {:.2}s",
                    bytes_in,
                    elapsed.as_secs_f64()
                );
                h.record(name, true);
            }
            Err(e) => {
                println!("  {name:<40}  LOSS {e}");
                h.record(name, false);
            }
        }
        std::io::stdout().flush().ok();
    }
    println!("\nranking (Wilson lower-bound, higher is better):");
    let mut snap = h.snapshot();
    snap.sort_by(|a, b| b.3.partial_cmp(&a.3).unwrap_or(std::cmp::Ordering::Equal));
    for (name, w, l, r) in snap {
        println!("  {name:<40}  {w}W / {l}L  rank={r:.3}");
    }
    Ok(())
}

fn run_one_probe(host: &str, _profile: &Profile, timeout: std::time::Duration) -> Result<usize> {
    use sonicdpi_engine::fakes::build_fake_clienthello;
    use sonicdpi_engine::proxy::process_first_chunk;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    // Open a plain TCP connection and apply the profile's
    // proxy-mode strategies on the first write. This measures the
    // proxy-path effectiveness; packet-mode strategies are
    // verified by the in-engine tests + a real `run` session.
    let addr = format!("{host}:443");
    let conn =
        TcpStream::connect_timeout(&addr.to_socket_addrs()?.next().context("resolve")?, timeout)
            .context("tcp connect")?;
    conn.set_read_timeout(Some(timeout)).ok();
    conn.set_write_timeout(Some(timeout)).ok();

    let ch = build_fake_clienthello(host);
    let plan = process_first_chunk(&ch, _profile);

    let mut stream = conn;
    for w in plan.writes {
        stream.write_all(&w.bytes).context("write")?;
        if !w.delay_after.is_zero() {
            std::thread::sleep(w.delay_after);
        }
    }

    let mut buf = vec![0u8; 16 * 1024];
    let mut total = 0usize;
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                if total >= 256 {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e).context("read"),
        }
    }
    if total == 0 {
        anyhow::bail!("no inbound bytes within {}s", timeout.as_secs());
    }
    Ok(total)
}

use std::net::ToSocketAddrs;

const BUILTIN_PROFILES: &[&str] = &[
    "youtube-discord",
    "youtube-discord-aggressive",
    "youtube-discord-multidisorder",
    "youtube-discord-seqovl",
    "youtube-discord-hostfakesplit",
];

fn load_builtin(name: &str) -> Result<Profile> {
    Ok(match name {
        "youtube-discord" => Profile::builtin_youtube_discord(),
        "youtube-discord-aggressive" => Profile::builtin_aggressive(),
        "youtube-discord-multidisorder" => Profile::builtin_multidisorder(),
        "youtube-discord-seqovl" => Profile::builtin_alt_seqovl(),
        "youtube-discord-hostfakesplit" => Profile::builtin_alt_hostfakesplit(),
        other => anyhow::bail!("unknown built-in profile: {other}"),
    })
}

fn load_profile(arg: &str) -> Result<Profile> {
    if BUILTIN_PROFILES.contains(&arg) {
        return load_builtin(arg);
    }
    let path = PathBuf::from(arg);
    if path.exists() {
        let s = std::fs::read_to_string(&path).context("read profile file")?;
        return toml::from_str(&s).context("parse profile TOML");
    }
    anyhow::bail!("profile not found: '{arg}' (neither a built-in nor a readable file)")
}

fn run(profile_arg: &str) -> Result<()> {
    let profile = load_profile(profile_arg)?;
    tracing::info!(profile = %profile.name, "starting engine");

    let cfg = InterceptorConfig {
        // Discord alt-TCP ports (2053, 2083, 2087, 2096, 8443) carry
        // `*.discord.media` voice-server signalling on some networks
        // — Flowseal `general.bat` captures all of these. Without
        // them, voice setup TLS never reaches our hook.
        tcp_ports: vec![80, 443, 2053, 2083, 2087, 2096, 8443],
        udp_ports: vec![
            PortRange::single(443),
            PortRange::single(53), // DNS — for the passive IP→SNI cache
            PortRange {
                lo: 19_294,
                hi: 19_344,
            },
            PortRange {
                lo: 50_000,
                hi: 50_100,
            },
        ],
        include_inbound: true, // need inbound for DNS responses
    };
    let engine = Arc::new(Engine::new(profile));

    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    ctrlc::set_handler(move || {
        tracing::info!("ctrl-c received, shutting down");
        stop2.store(true, Ordering::Relaxed);
    })
    .ok();

    let mut interceptor = DefaultInterceptor::open(&cfg).context("interceptor open failed")?;
    let stop_check: Arc<dyn Fn() -> bool + Send + Sync> = {
        let stop = stop.clone();
        Arc::new(move || stop.load(Ordering::Relaxed))
    };
    let res = interceptor.run(engine, stop_check);
    let _ = interceptor.close();
    res
}

fn init_tracing(level: u8, log_file: Option<&std::path::Path>) {
    let filter = match level {
        0 => "sonicdpi=warn",
        1 => "sonicdpi=info,sonicdpi_engine=info,sonicdpi_platform=info",
        2 => "sonicdpi=debug,sonicdpi_engine=debug,sonicdpi_platform=debug",
        _ => "trace",
    };
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter));

    if let Some(path) = log_file {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(env_filter)
                .with_writer(std::sync::Mutex::new(file))
                .with_ansi(false)
                .try_init();
            return;
        }
    }

    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .compact()
        .try_init();
}
