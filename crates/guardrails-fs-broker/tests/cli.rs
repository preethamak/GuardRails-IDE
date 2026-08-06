use std::{fs, process::Command};

#[test]
fn cli_reads_allowed_source_end_to_end() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("src")).unwrap();
    fs::write(root.path().join("src/lib.rs"), "pub fn safe() {}\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_guardrails-fs-broker"))
        .args([
            root.path().to_str().unwrap(),
            "agent:cli@1",
            "src/lib.rs",
            "workspace/src/**",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(output.stdout, b"pub fn safe() {}\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn cli_blocks_environment_files_even_with_broad_allow() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join(".env"), "TOKEN=do-not-print\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_guardrails-fs-broker"))
        .args([
            root.path().to_str().unwrap(),
            "agent:cli@1",
            ".env",
            "workspace/**",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("builtin-root-secret-deny"));
    assert!(stderr.contains("audit: deny ExplicitDeny"));
    assert!(!stderr.contains("do-not-print"));
}
