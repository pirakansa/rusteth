use anyhow::Result;
use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use tracing::{info, Level};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List network interfaces discovered from /sys/class/net
    Interfaces {
        /// Emit JSON instead of a human-readable table
        #[arg(long)]
        json: bool,
    },
    /// Show configuration for a specific interface or all interfaces
    Config {
        /// Limit output to a single interface
        #[arg(short, long)]
        interface: Option<String>,
        /// Emit JSON instead of a human-readable table
        #[arg(long)]
        json: bool,
    },
    /// Apply a YAML or JSON netplan to the host
    Apply {
        /// Path to the netplan file to apply
        path: PathBuf,
        /// Explicitly specify the format (otherwise derived from extension)
        #[arg(long, value_enum)]
        format: Option<ConfigFormatArg>,
        /// Validate without changing system state
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ConfigFormatArg {
    Yaml,
    Json,
}

impl From<ConfigFormatArg> for cli_template::NetplanFormat {
    fn from(value: ConfigFormatArg) -> Self {
        match value {
            ConfigFormatArg::Yaml => cli_template::NetplanFormat::Yaml,
            ConfigFormatArg::Json => cli_template::NetplanFormat::Json,
        }
    }
}

fn init_tracing(verbosity: u8) {
    let level = match verbosity {
        0 => Level::WARN,
        1 => Level::INFO,
        _ => Level::DEBUG,
    };
    let filter = EnvFilter::from_default_env()
        .add_directive(format!("cli_template={}", level).parse().unwrap())
        .add_directive(Level::WARN.into());

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}

fn render_interfaces_table(interfaces: &[cli_template::InterfaceInfo]) {
    println!(
        "{:<16} {:<18} {:<10} {:<8} {:>12} {:>12}",
        "NAME", "MAC", "STATE", "MTU", "RX(bytes)", "TX(bytes)"
    );
    for iface in interfaces {
        println!(
            "{:<16} {:<18} {:<10} {:<8} {:>12} {:>12}",
            iface.name,
            iface.mac_address.clone().unwrap_or_else(|| "-".into()),
            iface.oper_state.clone().unwrap_or_else(|| "unknown".into()),
            iface
                .mtu
                .map(|mtu| mtu.to_string())
                .unwrap_or_else(|| "-".into()),
            iface
                .stats
                .rx_bytes
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into()),
            iface
                .stats
                .tx_bytes
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into()),
        );
    }
}

fn print_interface_config(info: &cli_template::InterfaceInfo) {
    println!("Interface: {}", info.name);
    println!(
        "  MAC: {}",
        info.mac_address.clone().unwrap_or_else(|| "-".into())
    );
    println!(
        "  State: {}",
        info.oper_state.clone().unwrap_or_else(|| "unknown".into())
    );
    println!(
        "  MTU: {}",
        info.mtu
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".into())
    );
    println!(
        "  Speed: {}",
        info.speed_mbps
            .map(|v| format!("{} Mb/s", v))
            .unwrap_or_else(|| "-".into())
    );
    println!(
        "  RX bytes: {}",
        info.stats
            .rx_bytes
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".into())
    );
    println!(
        "  TX bytes: {}",
        info.stats
            .tx_bytes
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".into())
    );
    println!();
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);
    info!(?cli, "starting CLI");

    match cli.command {
        Commands::Interfaces { json } => {
            let interfaces = cli_template::list_interfaces()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&interfaces)?);
            } else {
                render_interfaces_table(&interfaces);
            }
        }
        Commands::Config { interface, json } => {
            if let Some(name) = interface {
                let info = cli_template::get_interface(&name)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&info)?);
                } else {
                    print_interface_config(&info);
                }
            } else {
                let interfaces = cli_template::list_interfaces()?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&interfaces)?);
                } else {
                    for iface in interfaces {
                        print_interface_config(&iface);
                    }
                }
            }
        }
        Commands::Apply {
            path,
            format,
            dry_run,
        } => {
            let doc = cli_template::load_netplan_from_path(path, format.map(Into::into))?;
            let result = cli_template::apply_netplan(&doc, dry_run)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
    }

    Ok(())
}
