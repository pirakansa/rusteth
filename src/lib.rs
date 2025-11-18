use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    str::FromStr,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RustethError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse {path}: {message}")]
    Parse { path: PathBuf, message: String },
    #[error("interface `{0}` not found")]
    InterfaceNotFound(String),
    #[error("unsupported platform: {0}")]
    Unsupported(&'static str),
    #[error("netplan parse error: {0}")]
    ConfigParse(String),
    #[error("netplan validation error: {0}")]
    ConfigValidation(String),
}

impl RustethError {
    fn io<P: AsRef<Path>>(path: P, source: std::io::Error) -> Self {
        Self::Io {
            path: path.as_ref().to_path_buf(),
            source,
        }
    }

    fn parse<P: AsRef<Path>>(path: P, message: impl Into<String>) -> Self {
        Self::Parse {
            path: path.as_ref().to_path_buf(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct InterfaceStats {
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub mac_address: Option<String>,
    pub oper_state: Option<String>,
    pub mtu: Option<u32>,
    pub speed_mbps: Option<u32>,
    pub stats: InterfaceStats,
}

pub fn list_interfaces() -> Result<Vec<InterfaceInfo>, RustethError> {
    #[cfg(target_os = "linux")]
    {
        linux::list_interfaces()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(RustethError::Unsupported(
            "only Linux systems expose /sys/class/net",
        ))
    }
}

pub fn get_interface(name: &str) -> Result<InterfaceInfo, RustethError> {
    let interfaces = list_interfaces()?;
    interfaces
        .into_iter()
        .find(|iface| iface.name == name)
        .ok_or_else(|| RustethError::InterfaceNotFound(name.to_string()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetplanDocument {
    pub network: NetworkSection,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkSection {
    pub version: Option<u8>,
    pub renderer: Option<String>,
    #[serde(default)]
    pub ethernets: BTreeMap<String, EthernetConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EthernetConfig {
    #[serde(default)]
    pub dhcp4: Option<bool>,
    #[serde(default)]
    pub dhcp6: Option<bool>,
    #[serde(default)]
    pub addresses: Vec<String>,
    #[serde(default)]
    pub gateway4: Option<String>,
    #[serde(default)]
    pub gateway6: Option<String>,
    #[serde(default)]
    pub mtu: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetplanFormat {
    Yaml,
    Json,
}

impl NetplanFormat {
    pub fn detect_from_path(path: &Path) -> Option<Self> {
        path.extension()
            .and_then(|ext| ext.to_str())
            .and_then(|ext| Self::from_str(ext).ok())
    }
}

impl FromStr for NetplanFormat {
    type Err = RustethError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "yaml" | "yml" => Ok(NetplanFormat::Yaml),
            "json" => Ok(NetplanFormat::Json),
            other => Err(RustethError::ConfigParse(format!(
                "unsupported format `{}`",
                other
            ))),
        }
    }
}

pub fn load_netplan_from_path(
    path: impl AsRef<Path>,
    hint: Option<NetplanFormat>,
) -> Result<NetplanDocument, RustethError> {
    let path = path.as_ref();
    let contents = fs::read_to_string(path).map_err(|err| RustethError::io(path, err))?;
    let format = hint
        .or_else(|| NetplanFormat::detect_from_path(path))
        .ok_or_else(|| RustethError::ConfigParse("unable to determine config format".into()))?;

    match format {
        NetplanFormat::Yaml => serde_yaml::from_str(&contents)
            .map_err(|err| RustethError::ConfigParse(err.to_string())),
        NetplanFormat::Json => serde_json::from_str(&contents)
            .map_err(|err| RustethError::ConfigParse(err.to_string())),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ApplyResult {
    pub planned_interfaces: Vec<String>,
    pub dry_run: bool,
    pub message: String,
}

pub fn apply_netplan(config: &NetplanDocument, dry_run: bool) -> Result<ApplyResult, RustethError> {
    let interfaces = list_interfaces()?;
    let existing: std::collections::HashSet<_> =
        interfaces.iter().map(|iface| iface.name.clone()).collect();
    let planned: Vec<String> = config.network.ethernets.keys().cloned().collect();

    let missing: Vec<_> = planned
        .iter()
        .filter(|iface| !existing.contains(*iface))
        .cloned()
        .collect();

    if !missing.is_empty() {
        return Err(RustethError::ConfigValidation(format!(
            "interfaces {:?} are not present on this host",
            missing
        )));
    }

    let message = if dry_run {
        "validation succeeded (dry run)".to_string()
    } else {
        "configuration validated; apply logic not implemented for safety".to_string()
    };

    Ok(ApplyResult {
        planned_interfaces: planned,
        dry_run,
        message,
    })
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{InterfaceInfo, InterfaceStats, RustethError};
    use std::{
        collections::HashMap,
        fs,
        path::{Path, PathBuf},
    };

    const SYS_CLASS_NET: &str = "/sys/class/net";
    const PROC_NET_DEV: &str = "/proc/net/dev";

    pub(super) fn list_interfaces() -> Result<Vec<InterfaceInfo>, RustethError> {
        let mut interfaces = Vec::new();
        let stats = read_proc_net_dev()?;
        let sys_path = Path::new(SYS_CLASS_NET);

        for entry in fs::read_dir(sys_path).map_err(|err| RustethError::io(sys_path, err))? {
            let entry = entry.map_err(|err| RustethError::io(sys_path, err))?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();

            let stats_for_iface = stats.get(&name).cloned().unwrap_or_default();
            let info = InterfaceInfo {
                name: name.clone(),
                mac_address: read_trimmed(&path.join("address"))?,
                oper_state: read_trimmed(&path.join("operstate"))?,
                mtu: read_u32(&path.join("mtu"))?,
                speed_mbps: read_u32(&path.join("speed"))?,
                stats: stats_for_iface,
            };
            interfaces.push(info);
        }

        interfaces.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(interfaces)
    }

    fn read_trimmed(path: &PathBuf) -> Result<Option<String>, RustethError> {
        match fs::read_to_string(path) {
            Ok(value) => {
                let v = value.trim().to_string();
                if v.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(v))
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(RustethError::io(path, err)),
        }
    }

    fn read_u32(path: &PathBuf) -> Result<Option<u32>, RustethError> {
        match read_trimmed(path)? {
            Some(value) => value
                .parse::<u32>()
                .map(Some)
                .map_err(|err| RustethError::parse(path, err.to_string())),
            None => Ok(None),
        }
    }

    fn read_proc_net_dev() -> Result<HashMap<String, InterfaceStats>, RustethError> {
        let contents =
            fs::read_to_string(PROC_NET_DEV).map_err(|err| RustethError::io(PROC_NET_DEV, err))?;
        let mut stats = HashMap::new();
        for line in contents.lines().skip(2) {
            if let Some((name_part, data_part)) = line.split_once(':') {
                let name = name_part.trim().to_string();
                let values: Vec<&str> = data_part.split_whitespace().collect();
                if values.len() < 16 {
                    continue;
                }
                let rx_bytes = values[0].parse::<u64>().ok();
                let tx_bytes = values[8].parse::<u64>().ok();
                stats.insert(name, InterfaceStats { rx_bytes, tx_bytes });
            }
        }
        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn detects_format_from_extension() {
        let path = Path::new("config.yaml");
        assert_eq!(
            NetplanFormat::detect_from_path(path),
            Some(NetplanFormat::Yaml)
        );
        let path = Path::new("config.json");
        assert_eq!(
            NetplanFormat::detect_from_path(path),
            Some(NetplanFormat::Json)
        );
    }

    #[test]
    fn loads_yaml_netplan() {
        let yaml = r#"
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      dhcp4: true
"#;
        let temp_path = std::env::temp_dir().join(format!(
            "rusteth-netplan-test-{}-{}.yaml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&temp_path, yaml).unwrap();

        let doc = load_netplan_from_path(&temp_path, None).expect("load netplan");
        assert_eq!(doc.network.version, Some(2));
        assert!(doc.network.ethernets.contains_key("eth0"));
        std::fs::remove_file(temp_path).unwrap();
    }
}
