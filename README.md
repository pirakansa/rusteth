# rusteth

`rusteth` is a Rust-native network management CLI that unifies distribution-specific tooling under a single, dependency-free binary. It exposes common inspection and configuration flows that normally require mixing `ip`, `netplan`, `nmcli`, and custom scripts so that admins can automate fleet changes without memorizing distro quirks.

## Motivation

Linux distributions ship a patchwork of network configuration utilities: Ubuntu encourages Netplan YAML rendered to `systemd-networkd`, Red Hat systems focus on `nmcli`, and legacy scripts often require Python or shell glue. `rusteth` provides a small, consistent CLI that:

- Surfaces interface inventory and statistics directly from the kernel via `/sys/class/net` and `/proc/net/dev`.
- Validates Netplan documents before they touch `systemd-networkd` or NetworkManager backends.
- Ships as a single static-friendly binary so you can copy it into containers, initrds, or hosts without installing Python, Perl, or distro-specific daemons.

The goal is to keep operations predictable across clouds and distributions while staying close to native kernel APIs.

## Installation

### Using Cargo (from source)

```bash
# Install the latest checked-out tree
cargo install --path .
```

Once the crate is published to crates.io, you will also be able to run `cargo install rusteth` to fetch a released version.

### Using packaged binaries

For environments where Rust is not available, download the prebuilt archives from the Releases page, then copy the `rusteth` binary to a directory on your `$PATH` (e.g., `/usr/local/bin`). Every release is built with `musl` to avoid libc incompatibilities.

## Usage

The CLI is organized into subcommands, each of which supports `-v/--verbose` for logging. Run `rusteth --help` for the full reference.

### `interfaces`

List every interface discovered in `/sys/class/net`, along with MAC address, operational state, MTU, and byte counters.

```bash
rusteth interfaces
# NAME             MAC                STATE      MTU      RX(bytes)    TX(bytes)
# eth0             00:16:3e:aa:bb:cc  up         1500     24123456     12674532
```

Pass `--json` when you want machine-readable output for scripts.

### `config`

Show configuration details for one interface or for the full system inventory. Without arguments, all interfaces are printed sequentially; use `-i/--interface` to scope to a single device.

```bash
rusteth config --interface eth0
# Interface: eth0
#   MAC: 00:16:3e:aa:bb:cc
#   State: up
#   MTU: 1500
#   Speed: 1000 Mb/s
#   RX bytes: 24123456
#   TX bytes: 12674532
```

Add `--json` to emit structured records.

### `apply`

Validate (and, when run without `--dry-run`, apply) a Netplan YAML/JSON document against the interfaces that actually exist on the host.

```bash
rusteth apply ./netplan/servers.yaml --dry-run
# {
#   "planned_interfaces": ["eth0", "eth1"],
#   "dry_run": true,
#   "message": "validation succeeded (dry run)",
#   "actions": [
#     {
#       "interface": "eth0",
#       "status": "planned",
#       "operation": { "kind": "set_mtu", "mtu": 9000 }
#     }
#   ]
# }
```

Use `--format yaml|json` to override file-extension detection. During real applies, `rusteth` talks to Netlink directly and currently supports MTU changes, static address assignments, and default gateways; additional Netplan keys fall back to warnings. Root privileges are required to change kernel state, so prefer `--dry-run` while iterating on a plan.

### `rusteth-monitor`

`rusteth-monitor` is a companion binary that subscribes to Netlink multicast groups and streams interface/link/address changes in real time. It is useful when you want to be notified immediately whenever a link flaps or an IP address is assigned/removed.

Key flags:

- `--json` &mdash; emit newline-delimited JSON (NDJSON) records suitable for log aggregators.
- `--filter link,address,route` &mdash; restrict the subscribed Netlink groups (comma-separated or repeated).
- `--no-initial-snapshot` &mdash; skip the initial `/sys/class/net` inventory if you only care about future events.
- `--once` &mdash; exit after printing the snapshot, which is handy for scripts that just need the boot-time state.

Example:

```bash
cargo run --bin rusteth-monitor -- --filter link,address
# link eth0 is up
# address added 192.0.2.10 on eth0
```

## Supported platforms and distributions

- **Linux (x86_64/aarch64):** fully supported. Interface discovery relies on `/sys/class/net` and `/proc/net/dev`, so any modern kernel works. Netplan validation aligns with distributions such as Ubuntu Server, Pop!\_OS, and Debian derivatives that ship Netplan.
- **Other UNIX-like systems (macOS, *BSD):** currently unsupported. The program will fail with `unsupported platform` because their network stacks do not expose the Linux-specific sysfs files used by `rusteth`.

If you need additional backends (e.g., `nmstate`, `ifconfig`-based stacks, or `iproute2` compatibility layers), contributions are welcome.

## Dependency-free design

`rusteth` is written entirely in Rust and interacts directly with kernel and filesystem APIs. It does **not** bundle Python, shell scripts, or runtime interpreters, which keeps it safe to run inside minimal containers and high-security environments. All serialization (YAML/JSON) is handled with the embedded `serde` stack, and logging uses `tracing`, so the only runtime requirement is `glibc` (or `musl` if you use the static builds).

## Backend integration

- **`systemd-networkd` / NetworkManager:** Netplan documents validated by `rusteth` can be fed to these renderers. `rusteth` checks that every interface referenced by the plan exists on the host before you run `netplan apply`, reducing the chance of disruptive configuration pushes.
- **Netlink and sysfs:** Interface data is read straight from `/sys/class/net` and `/proc/net/dev`, which are backed by the kernel's Netlink providers. This mirrors what tools like `ip link` expose but keeps the output consistent across distributions.

Future work will expand the `apply` subcommand to cover VLANs, bonds, DHCP orchestration, and other renderer-specific features.

## Development

Prerequisites: a recent Rust toolchain (see `rust-toolchain.toml`) plus the usual build utilities (`make`, `pkg-config` when cross-compiling).

Common tasks:

```bash
# Format the codebase
cargo fmt

# Run fast checks (format + clippy + tests)
make lint

# Run the full test suite
make test

# Build release binaries
make build
```

Integration tests live under `tests/`, while the CLI entry point is in `src/main.rs` and shared logic in `src/lib.rs`. Please update documentation and add tests for any new behaviors before opening a pull request.

## Contributing

Issues and pull requests are welcome! Describe which distribution/backend you are targeting, include sample configs when possible, and make sure `make lint`, `make test`, and `make build` all succeed locally before submitting.
