use std::process::Command;

fn portal_hub() -> &'static str {
    env!("CARGO_BIN_EXE_portal-hub")
}

#[test]
fn version_json_reports_api_contract() {
    let output = Command::new(portal_hub())
        .args(["version", "--json"])
        .output()
        .expect("run portal-hub version");

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["api_version"], 1);
    assert_eq!(json["metadata_schema_version"], 1);
    assert!(json["version"].as_str().is_some());
}

#[test]
fn list_v1_returns_empty_sessions_for_empty_state() {
    let state_dir = std::env::temp_dir().join(format!("portal-hub-cli-{}", uuid::Uuid::new_v4()));
    let output = Command::new(portal_hub())
        .args([
            "--state-dir",
            state_dir.to_str().unwrap(),
            "list",
            "--format",
            "v1",
        ])
        .output()
        .expect("run portal-hub list");
    let _ = std::fs::remove_dir_all(&state_dir);

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["api_version"], 1);
    assert_eq!(json["sessions"].as_array().unwrap().len(), 0);
}

#[test]
fn prune_dry_run_returns_report() {
    let state_dir = std::env::temp_dir().join(format!("portal-hub-cli-{}", uuid::Uuid::new_v4()));
    let output = Command::new(portal_hub())
        .args([
            "--state-dir",
            state_dir.to_str().unwrap(),
            "prune",
            "--dry-run",
        ])
        .output()
        .expect("run portal-hub prune");
    let _ = std::fs::remove_dir_all(&state_dir);

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["api_version"], 1);
    assert_eq!(json["dry_run"], true);
}
