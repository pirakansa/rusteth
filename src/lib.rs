use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    net::IpAddr,
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
    #[error("failed to apply configuration: {0}")]
    Apply(String),
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
    pub actions: Vec<ApplyAction>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApplyAction {
    pub interface: String,
    pub operation: ApplyOperation,
    pub status: ApplyActionStatus,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyActionStatus {
    Planned,
    Applied,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ApplyOperation {
    SetMtu { mtu: u32 },
    AddAddress { cidr: String },
    SetDefaultGateway { gateway: String },
}

struct PlannedAction {
    interface: String,
    spec: ActionSpec,
}

enum ActionSpec {
    SetMtu { mtu: u32 },
    AddAddress { cidr: IpNet },
    SetDefaultGateway { gateway: IpAddr },
}

impl PlannedAction {
    fn describe(&self, status: ApplyActionStatus) -> ApplyAction {
        ApplyAction {
            interface: self.interface.clone(),
            operation: match &self.spec {
                ActionSpec::SetMtu { mtu } => ApplyOperation::SetMtu { mtu: *mtu },
                ActionSpec::AddAddress { cidr } => ApplyOperation::AddAddress {
                    cidr: cidr.to_string(),
                },
                ActionSpec::SetDefaultGateway { gateway } => ApplyOperation::SetDefaultGateway {
                    gateway: gateway.to_string(),
                },
            },
            status,
        }
    }
}

trait ApplyBackend {
    fn set_mtu(&mut self, iface: &str, mtu: u32) -> Result<(), RustethError>;
    fn add_address(&mut self, iface: &str, cidr: &IpNet) -> Result<(), RustethError>;
    fn set_default_gateway(&mut self, iface: &str, gateway: IpAddr) -> Result<(), RustethError>;
}

pub fn apply_netplan(config: &NetplanDocument, dry_run: bool) -> Result<ApplyResult, RustethError> {
    let interfaces = list_interfaces()?;
    apply_netplan_with_interfaces(config, dry_run, &interfaces)
}

pub fn apply_netplan_with_interfaces(
    config: &NetplanDocument,
    dry_run: bool,
    interfaces: &[InterfaceInfo],
) -> Result<ApplyResult, RustethError> {
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

    let planned_actions = build_plan(config)?;

    if dry_run {
        let actions = planned_actions
            .into_iter()
            .map(|action| action.describe(ApplyActionStatus::Planned))
            .collect();
        return Ok(ApplyResult {
            planned_interfaces: planned,
            dry_run,
            message: "validation succeeded (dry run)".to_string(),
            actions,
        });
    }

    #[cfg(target_os = "linux")]
    {
        let mut backend = linux::NetlinkApplyBackend::new()?;
        for action in &planned_actions {
            match &action.spec {
                ActionSpec::SetMtu { mtu } => {
                    backend.set_mtu(&action.interface, *mtu)?;
                }
                ActionSpec::AddAddress { cidr } => {
                    backend.add_address(&action.interface, cidr)?;
                }
                ActionSpec::SetDefaultGateway { gateway } => {
                    backend.set_default_gateway(&action.interface, *gateway)?;
                }
            }
        }
        let actions = planned_actions
            .into_iter()
            .map(|action| action.describe(ApplyActionStatus::Applied))
            .collect();

        Ok(ApplyResult {
            planned_interfaces: planned,
            dry_run,
            message: "configuration applied".to_string(),
            actions,
        })
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(RustethError::Unsupported(
            "applying netplan is only supported on Linux",
        ))
    }
}

fn build_plan(config: &NetplanDocument) -> Result<Vec<PlannedAction>, RustethError> {
    let mut actions = Vec::new();
    for (iface, settings) in &config.network.ethernets {
        if let Some(mtu) = settings.mtu {
            actions.push(PlannedAction {
                interface: iface.clone(),
                spec: ActionSpec::SetMtu { mtu },
            });
        }

        for addr in &settings.addresses {
            let cidr = addr.parse::<IpNet>().map_err(|err| {
                RustethError::ConfigParse(format!(
                    "invalid address `{}` for interface `{}`: {}",
                    addr, iface, err
                ))
            })?;
            actions.push(PlannedAction {
                interface: iface.clone(),
                spec: ActionSpec::AddAddress { cidr },
            });
        }

        if let Some(gateway) = &settings.gateway4 {
            let parsed = gateway.parse::<IpAddr>().map_err(|err| {
                RustethError::ConfigParse(format!(
                    "invalid IPv4 gateway `{}` for interface `{}`: {}",
                    gateway, iface, err
                ))
            })?;
            if !parsed.is_ipv4() {
                return Err(RustethError::ConfigParse(format!(
                    "gateway4 `{}` must be an IPv4 address",
                    gateway
                )));
            }
            actions.push(PlannedAction {
                interface: iface.clone(),
                spec: ActionSpec::SetDefaultGateway { gateway: parsed },
            });
        }

        if let Some(gateway) = &settings.gateway6 {
            let parsed = gateway.parse::<IpAddr>().map_err(|err| {
                RustethError::ConfigParse(format!(
                    "invalid IPv6 gateway `{}` for interface `{}`: {}",
                    gateway, iface, err
                ))
            })?;
            if !parsed.is_ipv6() {
                return Err(RustethError::ConfigParse(format!(
                    "gateway6 `{}` must be an IPv6 address",
                    gateway
                )));
            }
            actions.push(PlannedAction {
                interface: iface.clone(),
                spec: ActionSpec::SetDefaultGateway { gateway: parsed },
            });
        }

        if settings.dhcp4 == Some(true) || settings.dhcp6 == Some(true) {
            tracing::warn!(
                interface = iface,
                dhcp4 = ?settings.dhcp4,
                dhcp6 = ?settings.dhcp6,
                "DHCP is requested but not managed directly by rusteth"
            );
        }
    }

    Ok(actions)
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{ApplyBackend, InterfaceInfo, InterfaceStats, RustethError};
    use futures_util::TryStreamExt;
    use ipnet::IpNet;
    use netlink_packet_route::link::{LinkAttribute, LinkMessage};
    use rtnetlink::{new_connection, Handle, RouteMessageBuilder};
    use std::{
        collections::HashMap,
        fs,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        path::Path,
    };
    use tokio::runtime::Runtime;

    const SYS_CLASS_NET: &str = "/sys/class/net";
    const PROC_NET_DEV: &str = "/proc/net/dev";

    pub(super) fn list_interfaces() -> Result<Vec<InterfaceInfo>, RustethError> {
        list_interfaces_from_paths(Path::new(SYS_CLASS_NET), Path::new(PROC_NET_DEV))
    }

    pub(super) fn list_interfaces_from_paths(
        sys_path: &Path,
        proc_net_dev: &Path,
    ) -> Result<Vec<InterfaceInfo>, RustethError> {
        let mut interfaces = Vec::new();
        let stats = read_proc_net_dev(proc_net_dev)?;

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

    fn read_trimmed(path: &Path) -> Result<Option<String>, RustethError> {
        match fs::read_to_string(path) {
            Ok(value) => {
                let v = value.trim().to_string();
                if v.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(v))
                }
            }
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidInput
                ) =>
            {
                Ok(None)
            }
            Err(err) => Err(RustethError::io(path, err)),
        }
    }

    fn read_u32(path: &Path) -> Result<Option<u32>, RustethError> {
        match read_trimmed(path)? {
            Some(value) => {
                if value.eq_ignore_ascii_case("unknown") || value == "-1" {
                    Ok(None)
                } else {
                    value
                        .parse::<u32>()
                        .map(Some)
                        .map_err(|err| RustethError::parse(path, err.to_string()))
                }
            }
            None => Ok(None),
        }
    }

    fn read_proc_net_dev(path: &Path) -> Result<HashMap<String, InterfaceStats>, RustethError> {
        let contents = fs::read_to_string(path).map_err(|err| RustethError::io(path, err))?;
        Ok(parse_proc_net_dev(&contents))
    }

    pub(super) fn parse_proc_net_dev(contents: &str) -> HashMap<String, InterfaceStats> {
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
        stats
    }

    pub(super) struct NetlinkApplyBackend {
        rt: Runtime,
        handle: Handle,
        link_cache: HashMap<String, u32>,
    }

    impl NetlinkApplyBackend {
        pub(super) fn new() -> Result<Self, RustethError> {
            let rt = Runtime::new().map_err(|err| {
                RustethError::Apply(format!("failed to initialize tokio runtime: {err}"))
            })?;
            let guard = rt.enter();
            let (connection, handle, _) = new_connection().map_err(|err| {
                RustethError::Apply(format!("failed to connect to netlink: {err}"))
            })?;
            drop(guard);
            rt.spawn(connection);
            Ok(Self {
                rt,
                handle,
                link_cache: HashMap::new(),
            })
        }

        fn resolve_index(&mut self, iface: &str) -> Result<u32, RustethError> {
            if let Some(index) = self.link_cache.get(iface) {
                return Ok(*index);
            }
            let handle = self.handle.clone();
            let name = iface.to_string();
            let result = self.rt.block_on(async move {
                let mut links = handle.link().get().match_name(name).execute();
                links.try_next().await
            });

            match result {
                Ok(Some(link)) => {
                    let index = link.header.index;
                    self.link_cache.insert(iface.to_string(), index);
                    Ok(index)
                }
                Ok(None) => Err(RustethError::InterfaceNotFound(iface.to_string())),
                Err(err) => Err(RustethError::Apply(format!(
                    "failed to query link `{}`: {}",
                    iface, err
                ))),
            }
        }

        fn set_link_mtu(&mut self, iface: &str, mtu: u32) -> Result<(), RustethError> {
            let index = self.resolve_index(iface)?;
            let mut message = LinkMessage::default();
            message.header.index = index;
            message.attributes.push(LinkAttribute::Mtu(mtu));
            let handle = self.handle.clone();
            self.rt
                .block_on(async move { handle.link().set(message).execute().await })
                .map_err(|err| {
                    RustethError::Apply(format!("failed to set MTU on `{}`: {}", iface, err))
                })
        }

        fn add_ip_address(&mut self, iface: &str, cidr: &IpNet) -> Result<(), RustethError> {
            let index = self.resolve_index(iface)?;
            let prefix_len = cidr.prefix_len();
            let addr = match cidr {
                IpNet::V4(net) => IpAddr::V4(net.addr()),
                IpNet::V6(net) => IpAddr::V6(net.addr()),
            };
            let handle = self.handle.clone();
            self.rt
                .block_on(async move {
                    handle
                        .address()
                        .add(index, addr, prefix_len)
                        .execute()
                        .await
                })
                .map_err(|err| {
                    RustethError::Apply(format!(
                        "failed to add address {} to `{}`: {}",
                        cidr, iface, err
                    ))
                })
        }

        fn add_default_gateway(
            &mut self,
            iface: &str,
            gateway: IpAddr,
        ) -> Result<(), RustethError> {
            let index = self.resolve_index(iface)?;
            let handle = self.handle.clone();
            let fut = async move {
                match gateway {
                    IpAddr::V4(addr) => {
                        let route = RouteMessageBuilder::<Ipv4Addr>::new()
                            .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
                            .gateway(addr)
                            .output_interface(index)
                            .build();
                        handle.route().add(route).execute().await
                    }
                    IpAddr::V6(addr) => {
                        let route = RouteMessageBuilder::<Ipv6Addr>::new()
                            .destination_prefix(Ipv6Addr::UNSPECIFIED, 0)
                            .gateway(addr)
                            .output_interface(index)
                            .build();
                        handle.route().add(route).execute().await
                    }
                }
            };
            self.rt.block_on(fut).map_err(|err| {
                RustethError::Apply(format!(
                    "failed to add default gateway {} via `{}`: {}",
                    gateway, iface, err
                ))
            })
        }
    }

    impl ApplyBackend for NetlinkApplyBackend {
        fn set_mtu(&mut self, iface: &str, mtu: u32) -> Result<(), RustethError> {
            self.set_link_mtu(iface, mtu)
        }

        fn add_address(&mut self, iface: &str, cidr: &IpNet) -> Result<(), RustethError> {
            self.add_ip_address(iface, cidr)
        }

        fn set_default_gateway(
            &mut self,
            iface: &str,
            gateway: IpAddr,
        ) -> Result<(), RustethError> {
            self.add_default_gateway(iface, gateway)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    #[cfg(target_os = "linux")]
    use tempfile::tempdir;

    #[test]
    fn apply_netplan_with_interfaces_detects_missing_links() {
        let mut doc = NetplanDocument {
            network: NetworkSection {
                version: Some(2),
                renderer: Some("networkd".into()),
                ethernets: BTreeMap::new(),
            },
        };
        doc.network
            .ethernets
            .insert("eth42".into(), EthernetConfig::default());

        let interfaces = vec![InterfaceInfo {
            name: "eth0".into(),
            mac_address: None,
            oper_state: None,
            mtu: None,
            speed_mbps: None,
            stats: InterfaceStats::default(),
        }];

        let err = apply_netplan_with_interfaces(&doc, true, &interfaces).unwrap_err();
        match err {
            RustethError::ConfigValidation(message) => {
                assert!(message.contains("eth42"), "unexpected message: {message}");
            }
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    #[test]
    fn apply_netplan_with_interfaces_passes_when_all_present() {
        let mut doc = NetplanDocument {
            network: NetworkSection {
                version: Some(2),
                renderer: Some("networkd".into()),
                ethernets: BTreeMap::new(),
            },
        };
        doc.network
            .ethernets
            .insert("eth0".into(), EthernetConfig::default());

        let interfaces = vec![InterfaceInfo {
            name: "eth0".into(),
            mac_address: None,
            oper_state: None,
            mtu: None,
            speed_mbps: None,
            stats: InterfaceStats::default(),
        }];

        let result = apply_netplan_with_interfaces(&doc, true, &interfaces).unwrap();
        assert!(result.dry_run);
        assert_eq!(result.planned_interfaces, vec!["eth0".to_string()]);
        assert!(result.actions.is_empty());
    }

    #[test]
    fn dry_run_returns_planned_actions() {
        let mut doc = NetplanDocument {
            network: NetworkSection {
                version: Some(2),
                renderer: Some("networkd".into()),
                ethernets: BTreeMap::new(),
            },
        };
        let cfg = EthernetConfig {
            mtu: Some(9000),
            addresses: vec!["192.0.2.10/24".into()],
            gateway4: Some("192.0.2.1".into()),
            ..Default::default()
        };
        doc.network.ethernets.insert("eth0".into(), cfg);

        let interfaces = vec![InterfaceInfo {
            name: "eth0".into(),
            mac_address: None,
            oper_state: None,
            mtu: None,
            speed_mbps: None,
            stats: InterfaceStats::default(),
        }];

        let result = apply_netplan_with_interfaces(&doc, true, &interfaces).unwrap();
        assert_eq!(result.actions.len(), 3);
        for action in &result.actions {
            assert!(matches!(action.status, ApplyActionStatus::Planned));
        }
        assert!(result
            .actions
            .iter()
            .any(|action| matches!(action.operation, ApplyOperation::AddAddress { .. })));
    }

    #[test]
    fn rejects_invalid_gateway_format() {
        let mut doc = NetplanDocument {
            network: NetworkSection {
                version: Some(2),
                renderer: Some("networkd".into()),
                ethernets: BTreeMap::new(),
            },
        };
        let cfg = EthernetConfig {
            gateway4: Some("2001:db8::1".into()),
            ..Default::default()
        };
        doc.network.ethernets.insert("eth0".into(), cfg);

        let interfaces = vec![InterfaceInfo {
            name: "eth0".into(),
            mac_address: None,
            oper_state: None,
            mtu: None,
            speed_mbps: None,
            stats: InterfaceStats::default(),
        }];

        let err = apply_netplan_with_interfaces(&doc, true, &interfaces).unwrap_err();
        match err {
            RustethError::ConfigParse(message) => {
                assert!(message.contains("gateway4"));
            }
            other => panic!("expected config parse error, got {other:?}"),
        }
    }

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

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_proc_net_dev_snapshot() {
        let snapshot = "Inter-|   Receive                                                |  Transmit\n    face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n  lo: 12345      10    0    0    0     0          0         0  67890      12    0    0    0     0       0          0\neth0: 55555     200    0    0    0     0          0       100  44444     150    0    0    0     0       0          0";
        let stats = super::linux::parse_proc_net_dev(snapshot);
        let lo = stats.get("lo").expect("lo stats");
        assert_eq!(lo.rx_bytes, Some(12345));
        assert_eq!(lo.tx_bytes, Some(67890));

        let eth0 = stats.get("eth0").expect("eth0 stats");
        assert_eq!(eth0.rx_bytes, Some(55555));
        assert_eq!(eth0.tx_bytes, Some(44444));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn lists_interfaces_from_fixture_tree() {
        use std::fs;

        let temp = tempdir().unwrap();
        let sys_path = temp.path().join("sys/class/net");
        fs::create_dir_all(&sys_path).unwrap();
        let iface_dir = sys_path.join("eth0");
        fs::create_dir_all(&iface_dir).unwrap();
        fs::write(iface_dir.join("address"), "aa:bb:cc:dd:ee:ff\n").unwrap();
        fs::write(iface_dir.join("operstate"), "up\n").unwrap();
        fs::write(iface_dir.join("mtu"), "1500\n").unwrap();
        fs::write(iface_dir.join("speed"), "1000\n").unwrap();

        let proc_path = temp.path().join("proc/net/dev");
        fs::create_dir_all(proc_path.parent().unwrap()).unwrap();
        let proc_contents = "Inter-|   Receive                                                |  Transmit\n    face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\neth0: 100      1    0    0    0     0          0         0  200      2    0    0    0     0       0          0";
        fs::write(&proc_path, proc_contents).unwrap();

        let interfaces =
            super::linux::list_interfaces_from_paths(sys_path.as_path(), proc_path.as_path())
                .expect("list interfaces from fixtures");
        assert_eq!(interfaces.len(), 1);
        let iface = &interfaces[0];
        assert_eq!(iface.name, "eth0");
        assert_eq!(iface.mac_address.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(iface.oper_state.as_deref(), Some("up"));
        assert_eq!(iface.mtu, Some(1500));
        assert_eq!(iface.speed_mbps, Some(1000));
        assert_eq!(iface.stats.rx_bytes, Some(100));
        assert_eq!(iface.stats.tx_bytes, Some(200));
    }
}
