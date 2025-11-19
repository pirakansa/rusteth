use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::Value;
use std::{fs::File, io::Write};
use tempfile::tempdir;

#[test]
fn interfaces_command_emits_json() {
    let output = cargo_bin_cmd!("rusteth")
        .args(["interfaces", "--json"])
        .output()
        .expect("command executes");
    assert!(output.status.success());

    let json: Value = serde_json::from_slice(&output.stdout).expect("valid json");
    assert!(json.is_array());
}

#[test]
fn apply_command_validates_sample_config() {
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("netplan.yaml");
    let mut file = File::create(&config_path).unwrap();
    writeln!(
        file,
        "network:\n  version: 2\n  ethernets:\n    lo:\n      mtu: 1400"
    )
    .unwrap();

    let output = cargo_bin_cmd!("rusteth")
        .args(["apply", "--dry-run", config_path.to_str().unwrap()])
        .output()
        .expect("command executes");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json: Value = serde_json::from_slice(&output.stdout).expect("valid json");
    assert_eq!(json["dry_run"], Value::Bool(true));
    assert!(json["planned_interfaces"]
        .as_array()
        .unwrap()
        .contains(&Value::String("lo".into())));
    let actions = json["actions"].as_array().expect("actions array");
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0]["interface"], Value::String("lo".into()));
    assert_eq!(actions[0]["status"], Value::String("planned".into()));
    assert_eq!(
        actions[0]["operation"]["kind"],
        Value::String("set_mtu".into())
    );
}
