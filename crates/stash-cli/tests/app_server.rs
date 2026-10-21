//! End-to-end test of `stash app-server`, the Mac app's backend, driven over
//! stdio like the app does.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use tempfile::TempDir;

#[test]
fn the_app_backend_speaks_json_rpc_over_stdio() {
    let dir = TempDir::new().unwrap();
    let mut child = Command::new(assert_cmd::cargo::cargo_bin("stash"))
        .env("STASH_AI_AGENTS", "stash-test-agent")
        .arg("app-server")
        .env("STASH_VAULT", dir.path().join("vault.db"))
        .env("STASH_AGENT_SOCK", dir.path().join("agent.sock"))
        .env("STASH_TOUCHID_HELPER", dir.path().join("no-helper"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut id = 0;
    let mut call = |method: &str, params: Value| -> Value {
        id += 1;
        let line = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        writeln!(stdin, "{line}").unwrap();
        let mut response = String::new();
        stdout.read_line(&mut response).unwrap();
        let v: Value = serde_json::from_str(&response).expect("one JSON response per line");
        assert_eq!(v["id"], id);
        v
    };

    assert_eq!(call("status", json!({}))["result"]["vault_exists"], false);
    assert!(call("create_vault", json!({ "password": "correct horse" }))["error"].is_null());
    let saved = call(
        "save",
        json!({ "name": "github", "kind": "login", "fields": [
            { "label": "username", "kind": "text", "value": "octocat" },
            { "label": "password", "kind": "concealed", "value": "hunter2!" },
        ]}),
    );
    assert!(saved["error"].is_null(), "{saved}");
    let listed = call("list", json!({}));
    assert_eq!(listed["result"]["items"][0]["username"], "octocat");
    assert!(
        !listed.to_string().contains("hunter2!"),
        "list must not carry values"
    );
    let revealed = call("reveal", json!({ "name": "github", "field": "password" }));
    assert_eq!(revealed["result"]["value"], "hunter2!");

    call("lock", json!({}));
    assert_eq!(call("list", json!({}))["error"]["code"], -32001);

    drop(stdin);
    assert!(
        child.wait().unwrap().success(),
        "exits cleanly when the app closes the pipe"
    );
}

#[test]
fn the_app_backend_previews_and_imports_exports() {
    let dir = TempDir::new().unwrap();
    let mut child = Command::new(assert_cmd::cargo::cargo_bin("stash"))
        .env("STASH_AI_AGENTS", "stash-test-agent")
        .arg("app-server")
        .env("STASH_VAULT", dir.path().join("vault.db"))
        .env("STASH_AGENT_SOCK", dir.path().join("agent.sock"))
        .env("STASH_TOUCHID_HELPER", dir.path().join("no-helper"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut id = 0;
    let mut call = |method: &str, params: Value| -> Value {
        id += 1;
        let line = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        writeln!(stdin, "{line}").unwrap();
        let mut response = String::new();
        stdout.read_line(&mut response).unwrap();
        serde_json::from_str(&response).unwrap()
    };
    assert!(call("create_vault", json!({ "password": "correct horse" }))["error"].is_null());

    let export = dir.path().join("bitwarden.json");
    std::fs::write(
        &export,
        r#"{"encrypted": false, "folders": [], "items": [
          {"type": 1, "name": "GitHub", "login": {"username": "octocat", "password": "gh-secret-1",
           "uris": [{"uri": "https://github.com"}]}},
          {"type": 3, "name": "Visa", "card": {"number": "4242424242424242", "code": "123",
           "expMonth": "8", "expYear": "2027"}}]}"#,
    )
    .unwrap();
    let path = export.to_str().unwrap();

    // The preview describes items without carrying any secret.
    let preview = call("import_preview", json!({ "path": path }));
    assert_eq!(preview["result"]["format"], "Bitwarden");
    assert_eq!(preview["result"]["entries"][0]["name"], "github");
    assert_eq!(
        preview["result"]["entries"][1]["subtitle"],
        "Visa •••• 4242 · 08/27"
    );
    let text = preview.to_string();
    assert!(
        !text.contains("gh-secret-1")
            && !text.contains("4242424242424242")
            && !text.contains("\"123\"")
    );

    // Only the chosen entries are imported.
    let first = call("import", json!({ "path": path, "indices": [0] }));
    assert_eq!(first["result"]["added"], json!(["login"]), "{first}");
    let listed = call("list", json!({}));
    assert_eq!(listed["result"]["items"].as_array().unwrap().len(), 1);

    // A card needs the sensitive key: the master password here.
    let cards = call(
        "import",
        json!({ "path": path, "indices": [0, 1], "password": "correct horse" }),
    );
    assert_eq!(cards["result"]["added"], json!(["card"]), "{cards}");
    assert_eq!(cards["result"]["same"], 1, "the login was already there");

    drop(stdin);
    assert!(child.wait().unwrap().success());
}
