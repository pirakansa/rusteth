#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("rusteth-monitor is only available on Linux hosts");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
mod app {
    use std::{ffi::CStr, net::IpAddr, time::SystemTime};

    use anyhow::{Context, Result};
    use clap::{ArgAction, Parser, ValueEnum};
    use futures_util::StreamExt;
    use humantime::format_rfc3339;
    use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
    use netlink_packet_route::{
        address::{AddressAttribute, AddressMessage},
        link::{LinkAttribute, LinkFlags, LinkMessage},
        route::RouteMessage,
        RouteNetlinkMessage,
    };
    use netlink_sys::{AsyncSocket, SocketAddr};
    use rtnetlink::{
        constants::{
            RTMGRP_IPV4_IFADDR, RTMGRP_IPV4_ROUTE, RTMGRP_IPV6_IFADDR, RTMGRP_IPV6_ROUTE,
            RTMGRP_LINK,
        },
        new_connection,
    };
    use serde::Serialize;
    use tokio::signal;
    use tracing::{debug, error, info, warn, Level};
    use tracing_subscriber::EnvFilter;

    #[derive(Parser, Debug)]
    #[command(
        name = "rusteth-monitor",
        about = "Netlink monitor for rusteth",
        version
    )]
    struct MonitorCli {
        /// Increase verbosity (-v, -vv, -vvv)
        #[arg(short, long, action = ArgAction::Count)]
        verbose: u8,

        /// Emit NDJSON instead of human-readable log lines
        #[arg(long)]
        json: bool,

        /// Skip the initial /sys snapshot
        #[arg(long)]
        no_initial_snapshot: bool,

        /// Exit after printing the initial snapshot
        #[arg(long)]
        once: bool,

        /// Filter events (repeatable, accepts comma-separated values)
        #[arg(long, value_enum, num_args = 1.., value_delimiter = ',')]
        filter: Vec<EventFilter>,
    }

    #[derive(Clone, Debug, Eq, PartialEq, ValueEnum, Copy)]
    enum EventFilter {
        Link,
        Address,
        Route,
    }

    impl EventFilter {
        fn mask(&self) -> u32 {
            match self {
                EventFilter::Link => RTMGRP_LINK,
                EventFilter::Address => RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR,
                EventFilter::Route => RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE,
            }
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct FilterSet {
        link: bool,
        address: bool,
        route: bool,
    }

    impl FilterSet {
        fn new(filters: &[EventFilter]) -> Self {
            let mut set = Self {
                link: false,
                address: false,
                route: false,
            };
            if filters.is_empty() {
                return Self {
                    link: true,
                    address: true,
                    route: true,
                };
            }
            for filter in filters {
                match filter {
                    EventFilter::Link => set.link = true,
                    EventFilter::Address => set.address = true,
                    EventFilter::Route => set.route = true,
                }
            }
            set
        }

        fn mask(&self) -> u32 {
            let mut mask = 0;
            if self.link {
                mask |= EventFilter::Link.mask();
            }
            if self.address {
                mask |= EventFilter::Address.mask();
            }
            if self.route {
                mask |= EventFilter::Route.mask();
            }
            mask
        }
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    enum MonitorRecord {
        Snapshot {
            timestamp: String,
            interfaces: Vec<rusteth::InterfaceInfo>,
        },
        Event {
            timestamp: String,
            kind: MonitorEventKind,
            #[serde(skip_serializing_if = "Option::is_none")]
            interface: Option<rusteth::InterfaceInfo>,
            message: String,
        },
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "snake_case")]
    enum MonitorEventKind {
        LinkUp,
        LinkDown,
        LinkRemoved,
        AddressAdded,
        AddressRemoved,
        RouteUpdated,
        RouteRemoved,
    }

    impl MonitorRecord {
        fn timestamp() -> String {
            format_rfc3339(SystemTime::now()).to_string()
        }
    }

    pub async fn run() -> Result<()> {
        let cli = MonitorCli::parse();
        init_tracing(cli.verbose);
        info!(?cli, "starting monitor");

        let filters = FilterSet::new(&cli.filter);
        let subscription_mask = filters.mask();
        if subscription_mask == 0 {
            anyhow::bail!("at least one filter is required");
        }

        if !cli.no_initial_snapshot {
            let interfaces = rusteth::list_interfaces()?;
            let timestamp = MonitorRecord::timestamp();
            emit_record(
                MonitorRecord::Snapshot {
                    timestamp: timestamp.clone(),
                    interfaces: interfaces.clone(),
                },
                cli.json,
            );
            if !cli.json {
                println!(
                    "\nSnapshot captured at {} ({} interfaces)",
                    timestamp,
                    interfaces.len()
                );
                render_interfaces_table(&interfaces);
            }
            if cli.once {
                return Ok(());
            }
        }

        let (mut conn, _handle, messages) =
            new_connection().context("failed to open rtnetlink connection")?;
        let addr = SocketAddr::new(0, subscription_mask);
        conn.socket_mut()
            .socket_mut()
            .bind(&addr)
            .context("failed to subscribe to netlink groups")?;
        tokio::spawn(conn);

        let mut stream = messages.fuse();
        loop {
            tokio::select! {
                _ = signal::ctrl_c() => {
                    info!("Ctrl+C received, shutting down");
                    break;
                }
                maybe_msg = stream.next() => {
                    match maybe_msg {
                        Some((message, _)) => {
                            if let Err(err) = handle_message(message, &filters, cli.json).await {
                                error!(?err, "failed to process netlink event");
                            }
                        }
                        None => {
                            warn!("netlink channel closed");
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_message(
        message: NetlinkMessage<RouteNetlinkMessage>,
        filters: &FilterSet,
        json: bool,
    ) -> Result<()> {
        match message.payload {
            NetlinkPayload::InnerMessage(message) => match message {
                RouteNetlinkMessage::NewLink(link) if filters.link => {
                    emit_event(LinkEvent::from_link(link, false), json)
                }
                RouteNetlinkMessage::DelLink(link) if filters.link => {
                    emit_event(LinkEvent::from_link(link, true), json)
                }
                RouteNetlinkMessage::NewAddress(address) if filters.address => {
                    emit_event(AddressEvent::from_message(address, false), json)
                }
                RouteNetlinkMessage::DelAddress(address) if filters.address => {
                    emit_event(AddressEvent::from_message(address, true), json)
                }
                RouteNetlinkMessage::NewRoute(route) if filters.route => {
                    emit_event(RouteEvent::from_message(route, false), json)
                }
                RouteNetlinkMessage::DelRoute(route) if filters.route => {
                    emit_event(RouteEvent::from_message(route, true), json)
                }
                other => {
                    debug!(?other, "ignoring message");
                    Ok(())
                }
            },
            NetlinkPayload::Error(err) => {
                warn!(?err, "kernel reported netlink error");
                Ok(())
            }
            NetlinkPayload::Done(_) => Ok(()),
            NetlinkPayload::Overrun(_) => {
                warn!("netlink overrun detected");
                Ok(())
            }
            NetlinkPayload::Noop => Ok(()),
            _ => Ok(()),
        }
    }

    fn emit_event(event: OutputEvent, json: bool) -> Result<()> {
        if let Some(record) = event.record {
            emit_record(record, json);
        }
        if !json {
            println!("{}", event.message);
        }
        Ok(())
    }

    fn emit_record(record: MonitorRecord, json: bool) {
        if json {
            match serde_json::to_string(&record) {
                Ok(line) => println!("{line}"),
                Err(err) => error!(?err, "failed to serialize event"),
            }
        }
    }

    struct OutputEvent {
        record: Option<MonitorRecord>,
        message: String,
    }

    struct LinkEvent;
    struct AddressEvent;
    struct RouteEvent;

    impl LinkEvent {
        fn from_link(message: LinkMessage, deleted: bool) -> OutputEvent {
            let name = link_name(&message);
            let info = name
                .as_deref()
                .and_then(|iface| rusteth::get_interface(iface).ok());
            let flags = message.header.flags;
            let kind = if deleted {
                MonitorEventKind::LinkRemoved
            } else if flags.contains(LinkFlags::Up) {
                MonitorEventKind::LinkUp
            } else {
                MonitorEventKind::LinkDown
            };
            let msg = match (&name, &kind) {
                (Some(iface), MonitorEventKind::LinkRemoved) => {
                    format!("link {iface} removed")
                }
                (Some(iface), MonitorEventKind::LinkUp) => {
                    format!("link {iface} is up")
                }
                (Some(iface), MonitorEventKind::LinkDown) => {
                    format!("link {iface} is down")
                }
                _ => "link state changed".to_string(),
            };
            OutputEvent {
                record: Some(MonitorRecord::Event {
                    timestamp: MonitorRecord::timestamp(),
                    kind,
                    interface: info,
                    message: msg.clone(),
                }),
                message: msg,
            }
        }
    }

    impl AddressEvent {
        fn from_message(message: AddressMessage, deleted: bool) -> OutputEvent {
            let ip = extract_address(&message.attributes);
            let ifname = address_label(&message).or_else(|| ifindex_to_name(message.header.index));
            let info = ifname
                .as_deref()
                .and_then(|name| rusteth::get_interface(name).ok());
            let action = if deleted {
                MonitorEventKind::AddressRemoved
            } else {
                MonitorEventKind::AddressAdded
            };
            let message_text = match (&ifname, ip) {
                (Some(name), Some(addr)) => {
                    format!(
                        "address {} {addr} on {name}",
                        if deleted { "removed" } else { "added" }
                    )
                }
                (Some(name), None) => {
                    format!("address state changed on {name}")
                }
                _ => "address state changed".to_string(),
            };
            OutputEvent {
                record: Some(MonitorRecord::Event {
                    timestamp: MonitorRecord::timestamp(),
                    kind: action,
                    interface: info,
                    message: message_text.clone(),
                }),
                message: message_text,
            }
        }
    }

    impl RouteEvent {
        fn from_message(message: RouteMessage, deleted: bool) -> OutputEvent {
            let kind = if deleted {
                MonitorEventKind::RouteRemoved
            } else {
                MonitorEventKind::RouteUpdated
            };
            let description = format!("route {:?}", message);
            OutputEvent {
                record: Some(MonitorRecord::Event {
                    timestamp: MonitorRecord::timestamp(),
                    kind,
                    interface: None,
                    message: description.clone(),
                }),
                message: description,
            }
        }
    }

    fn link_name(message: &LinkMessage) -> Option<String> {
        message.attributes.iter().find_map(|attr| match attr {
            LinkAttribute::IfName(name) => Some(name.clone()),
            _ => None,
        })
    }

    fn extract_address(attributes: &[AddressAttribute]) -> Option<IpAddr> {
        attributes.iter().find_map(|attr| match attr {
            AddressAttribute::Address(addr) | AddressAttribute::Local(addr) => Some(*addr),
            _ => None,
        })
    }

    fn address_label(message: &AddressMessage) -> Option<String> {
        message.attributes.iter().find_map(|attr| match attr {
            AddressAttribute::Label(label) => Some(label.clone()),
            _ => None,
        })
    }

    fn ifindex_to_name(index: u32) -> Option<String> {
        unsafe {
            let mut name = [0 as libc::c_char; libc::IFNAMSIZ];
            let ptr = libc::if_indextoname(index, name.as_mut_ptr());
            if ptr.is_null() {
                return None;
            }
            let cstr = CStr::from_ptr(name.as_ptr());
            cstr.to_str().ok().map(|s| s.to_string())
        }
    }

    fn render_interfaces_table(interfaces: &[rusteth::InterfaceInfo]) {
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

    fn init_tracing(verbosity: u8) {
        let level = match verbosity {
            0 => Level::WARN,
            1 => Level::INFO,
            _ => Level::DEBUG,
        };
        let filter = EnvFilter::from_default_env()
            .add_directive(format!("rusteth={level}").parse().unwrap())
            .add_directive(Level::WARN.into());

        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .compact()
            .init();
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use netlink_packet_route::link::LinkMessage;

        #[test]
        fn filter_set_defaults_to_all() {
            let set = FilterSet::new(&[]);
            assert!(set.link && set.address && set.route);
            assert_ne!(set.mask(), 0);
        }

        #[test]
        fn link_name_is_extracted() {
            let mut msg = LinkMessage::default();
            msg.attributes.push(LinkAttribute::IfName("eth0".into()));
            assert_eq!(link_name(&msg).as_deref(), Some("eth0"));
        }
    }
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    app::run().await
}
