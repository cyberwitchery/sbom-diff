use std::path::PathBuf;
use std::process::Command;

fn sbom_diff() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sbom-diff"))
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

#[test]
fn fail_on_added_components_exits_3() {
    let out = sbom_diff()
        .arg(fixture("golden-old.json"))
        .arg(fixture("golden-new.json"))
        .arg("--fail-on")
        .arg("added-components")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--fail-on added-components"),
        "stderr should mention the violated condition"
    );
}

#[test]
fn fail_on_removed_components_exits_3() {
    let out = sbom_diff()
        .arg(fixture("golden-old.json"))
        .arg(fixture("golden-new.json"))
        .arg("--fail-on")
        .arg("removed-components")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--fail-on removed-components"));
}

#[test]
fn fail_on_changed_components_exits_3() {
    let out = sbom_diff()
        .arg(fixture("golden-old.json"))
        .arg(fixture("golden-new.json"))
        .arg("--fail-on")
        .arg("changed-components")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--fail-on changed-components"));
}

#[test]
fn fail_on_deps_exits_3() {
    let out = sbom_diff()
        .arg(fixture("golden-old.json"))
        .arg(fixture("golden-new.json"))
        .arg("--fail-on")
        .arg("deps")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--fail-on deps"));
}

#[test]
fn fail_on_deps_kind_changed_reports_error() {
    let out = sbom_diff()
        .arg(fixture("kind-change-old.spdx.json"))
        .arg(fixture("kind-change-new.spdx.json"))
        .arg("--fail-on")
        .arg("deps")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("changed kind"),
        "stderr should mention a kind change, got: {}",
        stderr
    );
    assert!(
        stderr.contains("dev -> runtime"),
        "stderr should report old and new kind, got: {}",
        stderr
    );
}

#[test]
fn fail_on_missing_hashes_exits_3() {
    let out = sbom_diff()
        .arg(fixture("missing-hashes-old.json"))
        .arg(fixture("missing-hashes-new.json"))
        .arg("--fail-on")
        .arg("missing-hashes")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--fail-on missing-hashes"));
}

#[test]
fn fail_on_no_violation_exits_0() {
    let out = sbom_diff()
        .arg(fixture("golden-old.json"))
        .arg(fixture("golden-old.json"))
        .arg("--fail-on")
        .arg("added-components")
        .arg("--fail-on")
        .arg("removed-components")
        .arg("--fail-on")
        .arg("changed-components")
        .arg("--fail-on")
        .arg("deps")
        .arg("--fail-on")
        .arg("license-changed")
        .arg("--fail-on")
        .arg("hash-algorithm-downgrade")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn fail_on_multiple_conditions_all_checked() {
    let out = sbom_diff()
        .arg(fixture("golden-old.json"))
        .arg(fixture("golden-new.json"))
        .arg("--fail-on")
        .arg("added-components")
        .arg("--fail-on")
        .arg("removed-components")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--fail-on added-components"),
        "should report added-components violation"
    );
    assert!(
        stderr.contains("--fail-on removed-components"),
        "should report removed-components violation"
    );
}

#[test]
fn fail_on_license_changed_exits_3() {
    let out = sbom_diff()
        .arg(fixture("license-changed-old.json"))
        .arg(fixture("license-changed-new.json"))
        .arg("--fail-on")
        .arg("license-changed")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--fail-on license-changed"),
        "stderr should mention the violated condition, got: {}",
        stderr
    );
    assert!(
        stderr.contains("license changed on component"),
        "stderr should report the changed component, got: {}",
        stderr
    );
    assert!(
        stderr.contains("introduces license(s)"),
        "stderr should report the added component's licenses, got: {}",
        stderr
    );
}

#[test]
fn fail_on_license_changed_no_change_exits_0() {
    // same file as both old and new — no license changes
    let out = sbom_diff()
        .arg(fixture("cli-license.json"))
        .arg(fixture("cli-license.json"))
        .arg("--fail-on")
        .arg("license-changed")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn fail_on_license_changed_no_violation_exits_0() {
    // golden fixtures have no licenses, so no license changes
    let out = sbom_diff()
        .arg(fixture("golden-old.json"))
        .arg(fixture("golden-old.json"))
        .arg("--fail-on")
        .arg("license-changed")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn deny_license_match_exits_2() {
    let out = sbom_diff()
        .arg(fixture("cli-license.json"))
        .arg(fixture("cli-license.json"))
        .arg("--deny-license")
        .arg("MIT")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("license MIT is denied"));
}

#[test]
fn deny_license_case_insensitive() {
    let out = sbom_diff()
        .arg(fixture("cli-license.json"))
        .arg(fixture("cli-license.json"))
        .arg("--deny-license")
        .arg("mit")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn deny_license_no_match_exits_0() {
    let out = sbom_diff()
        .arg(fixture("cli-license.json"))
        .arg(fixture("cli-license.json"))
        .arg("--deny-license")
        .arg("GPL-3.0-only")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn allow_license_violation_exits_2() {
    // only allow Apache-2.0 — the MIT component should trigger a violation.
    let out = sbom_diff()
        .arg(fixture("cli-license.json"))
        .arg(fixture("cli-license.json"))
        .arg("--allow-license")
        .arg("Apache-2.0")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not allowed"));
}

#[test]
fn allow_license_all_match_exits_0() {
    let out = sbom_diff()
        .arg(fixture("cli-license.json"))
        .arg(fixture("cli-license.json"))
        .arg("--allow-license")
        .arg("MIT")
        .arg("--allow-license")
        .arg("Apache-2.0")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn deny_license_catches_licenseref_in_mixed_expression() {
    let out = sbom_diff()
        .arg(fixture("cli-license-ref.json"))
        .arg(fixture("cli-license-ref.json"))
        .arg("--deny-license")
        .arg("LicenseRef-proprietary")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("LicenseRef-proprietary"));
}

#[test]
fn deny_license_catches_spdx_id_in_mixed_expression() {
    let out = sbom_diff()
        .arg(fixture("cli-license-ref.json"))
        .arg(fixture("cli-license-ref.json"))
        .arg("--deny-license")
        .arg("Apache-2.0")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Apache-2.0"));
}

#[test]
fn allow_license_requires_licenseref_in_mixed_expression() {
    // allow only MIT and Apache-2.0 — LicenseRef-proprietary should trigger a violation.
    let out = sbom_diff()
        .arg(fixture("cli-license-ref.json"))
        .arg(fixture("cli-license-ref.json"))
        .arg("--allow-license")
        .arg("MIT")
        .arg("--allow-license")
        .arg("Apache-2.0")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("LicenseRef-proprietary"));
}

#[test]
fn license_violation_takes_precedence_over_fail_on() {
    let fail_on_only = sbom_diff()
        .arg(fixture("dual-violation-old.json"))
        .arg(fixture("dual-violation-new.json"))
        .arg("--fail-on")
        .arg("added-components")
        .output()
        .unwrap();

    assert_eq!(
        fail_on_only.status.code(),
        Some(3),
        "fixture pair must trigger a fail-on violation on its own"
    );

    let both = sbom_diff()
        .arg(fixture("dual-violation-old.json"))
        .arg(fixture("dual-violation-new.json"))
        .arg("--deny-license")
        .arg("GPL-3.0-only")
        .arg("--fail-on")
        .arg("added-components")
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&both.stderr);
    assert!(
        stderr.contains("license GPL-3.0-only is denied"),
        "license violation should be reported, got: {}",
        stderr
    );
    assert!(
        stderr.contains("--fail-on added-components"),
        "fail-on violation should be reported too, got: {}",
        stderr
    );
    assert_eq!(both.status.code(), Some(2));
}

#[test]
fn quiet_suppresses_stdout() {
    let out = sbom_diff()
        .arg(fixture("golden-old.json"))
        .arg(fixture("golden-new.json"))
        .arg("--quiet")
        .output()
        .unwrap();

    assert!(
        out.stdout.is_empty(),
        "stdout should be empty with --quiet, got: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn quiet_still_emits_stderr_on_violation() {
    let out = sbom_diff()
        .arg(fixture("cli-license.json"))
        .arg(fixture("cli-license.json"))
        .arg("--quiet")
        .arg("--deny-license")
        .arg("MIT")
        .output()
        .unwrap();

    assert!(out.stdout.is_empty(), "stdout should be empty with --quiet");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("license MIT is denied"),
        "stderr should still contain error messages"
    );
}

#[test]
fn quiet_preserves_fail_on_exit_code() {
    let out = sbom_diff()
        .arg(fixture("golden-old.json"))
        .arg(fixture("golden-new.json"))
        .arg("--quiet")
        .arg("--fail-on")
        .arg("added-components")
        .output()
        .unwrap();

    assert!(out.stdout.is_empty());
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn auto_detects_cyclonedx_json() {
    let out = sbom_diff()
        .arg(fixture("golden-old.json"))
        .arg(fixture("golden-new.json"))
        .arg("--summary")
        .arg("--output")
        .arg("json")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("output should be valid JSON");
    assert_eq!(v["added"], 1);
    assert_eq!(v["removed"], 1);
}

#[test]
fn auto_detects_spdx_json() {
    let out = sbom_diff()
        .arg(fixture("golden-old.spdx.json"))
        .arg(fixture("golden-new.spdx.json"))
        .arg("--summary")
        .arg("--output")
        .arg("json")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("output should be valid JSON");
    assert_eq!(v["added"], 1);
    assert_eq!(v["removed"], 1);
}

#[test]
fn auto_detects_cyclonedx_xml() {
    let out = sbom_diff()
        .arg(fixture("golden-old.cdx.xml"))
        .arg(fixture("golden-new.cdx.xml"))
        .arg("--summary")
        .arg("--output")
        .arg("json")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("output should be valid JSON");
    assert_eq!(v["added"], 1);
    assert_eq!(v["removed"], 1);
}

#[test]
fn auto_detects_spdx_tag_value() {
    let out = sbom_diff()
        .arg(fixture("golden-old.spdx"))
        .arg(fixture("golden-new.spdx"))
        .arg("--summary")
        .arg("--output")
        .arg("json")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("output should be valid JSON");
    assert_eq!(v["added"], 1);
    assert_eq!(v["removed"], 1);
}

#[test]
fn auto_detects_spdx_xml() {
    let out = sbom_diff()
        .arg(fixture("old.spdx.xml"))
        .arg(fixture("new.spdx.xml"))
        .arg("--summary")
        .arg("--output")
        .arg("json")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("output should be valid JSON");
    assert_eq!(v["added"], 0);
    assert_eq!(v["removed"], 0);
    assert_eq!(v["changed"], 1);
}

#[test]
fn explicit_spdx_xml_format_matches_auto() {
    let run = |format: Option<&str>| {
        let mut cmd = sbom_diff();
        cmd.arg(fixture("old.spdx.xml"))
            .arg(fixture("new.spdx.xml"));
        if let Some(f) = format {
            cmd.arg("--format").arg(f);
        }
        let out = cmd.arg("--output").arg("json").output().unwrap();
        assert_eq!(out.status.code(), Some(0));
        String::from_utf8_lossy(&out.stdout).into_owned()
    };

    assert_eq!(run(Some("spdx-xml")), run(None));
}

#[test]
fn spdx_xml_diffs_identically_to_spdx_json() {
    let run = |old: &str, new: &str| {
        let out = sbom_diff()
            .arg(fixture(old))
            .arg(fixture(new))
            .arg("--output")
            .arg("json")
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0));
        String::from_utf8_lossy(&out.stdout).into_owned()
    };

    assert_eq!(
        run("old.spdx.xml", "new.spdx.xml"),
        run("old.spdx.json", "new.spdx.json")
    );
}

#[test]
fn spdx_xml_errors_name_the_detected_format() {
    let dir = std::env::temp_dir().join("sbom-diff-cli-test-spdx-xml");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("broken.spdx.xml");
    std::fs::write(&path, b"<Document><spdxVersion>SPDX-2.3</Document>").unwrap();

    let out = sbom_diff()
        .arg(&path)
        .arg(fixture("new.spdx.xml"))
        .output()
        .unwrap();

    assert_ne!(out.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("SPDX XML"), "got {stderr}");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn explicit_format_overrides_auto() {
    let out = sbom_diff()
        .arg(fixture("golden-old.json"))
        .arg(fixture("golden-new.json"))
        .arg("--format")
        .arg("cyclonedx")
        .arg("--summary")
        .arg("--output")
        .arg("json")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("output should be valid JSON");
    assert_eq!(v["added"], 1);
}

#[test]
fn wrong_explicit_format_fails() {
    let out = sbom_diff()
        .arg(fixture("golden-old.json"))
        .arg(fixture("golden-new.json"))
        .arg("--format")
        .arg("spdx")
        .output()
        .unwrap();

    assert_ne!(out.status.code(), Some(0));
}

#[test]
fn summary_text_is_compact() {
    let full = sbom_diff()
        .arg(fixture("golden-old.json"))
        .arg(fixture("golden-new.json"))
        .output()
        .unwrap();

    let summary = sbom_diff()
        .arg(fixture("golden-old.json"))
        .arg(fixture("golden-new.json"))
        .arg("--summary")
        .output()
        .unwrap();

    assert_eq!(summary.status.code(), Some(0));
    let full_out = String::from_utf8_lossy(&full.stdout);
    let summary_out = String::from_utf8_lossy(&summary.stdout);

    assert!(
        summary_out.len() < full_out.len(),
        "summary ({} bytes) should be shorter than full output ({} bytes)",
        summary_out.len(),
        full_out.len()
    );
    assert!(summary_out.contains("Added"));
    assert!(summary_out.contains("Removed"));
}

#[test]
fn summary_json_output() {
    let out = sbom_diff()
        .arg(fixture("golden-old.json"))
        .arg(fixture("golden-new.json"))
        .arg("--summary")
        .arg("--output")
        .arg("json")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("summary JSON should parse");

    assert_eq!(v["added"], 1);
    assert_eq!(v["removed"], 1);
    assert_eq!(v["changed"], 2);
    assert_eq!(v["unchanged"], 2);
    assert_eq!(v["edge_changes"], 1);
}

#[test]
fn summary_markdown_output() {
    let out = sbom_diff()
        .arg(fixture("golden-old.json"))
        .arg(fixture("golden-new.json"))
        .arg("--summary")
        .arg("--output")
        .arg("markdown")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    // markdown summary should contain a table or structured output
    assert!(!stdout.is_empty());
}

#[test]
fn summary_with_quiet_produces_no_output() {
    let out = sbom_diff()
        .arg(fixture("golden-old.json"))
        .arg(fixture("golden-new.json"))
        .arg("--summary")
        .arg("--quiet")
        .output()
        .unwrap();

    assert!(out.stdout.is_empty());
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn fail_on_version_downgrade_exits_3() {
    let out = sbom_diff()
        .arg(fixture("version-downgrade-old.json"))
        .arg(fixture("version-downgrade-new.json"))
        .arg("--fail-on")
        .arg("version-downgrade")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--fail-on version-downgrade"),
        "stderr should mention the violated condition, got: {}",
        stderr
    );
    assert!(
        stderr.contains("version downgrade on component"),
        "stderr should report the downgraded component, got: {}",
        stderr
    );
    assert!(
        stderr.contains("2.0.0 -> 1.5.0"),
        "stderr should show old and new versions, got: {}",
        stderr
    );
}

#[test]
fn fail_on_version_downgrade_deb_revision_upgrade_exits_0() {
    let out = sbom_diff()
        .arg(fixture("deb-upgrade-old.json"))
        .arg(fixture("deb-upgrade-new.json"))
        .arg("--fail-on")
        .arg("version-downgrade")
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(0),
        "1.2.3-1ubuntu2 -> 1.2.3-2 and 1.0~rc1 -> 1.0 are upgrades per dpkg, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn fail_on_version_downgrade_deb_revision_downgrade_exits_3() {
    let out = sbom_diff()
        .arg(fixture("deb-upgrade-old.json"))
        .arg(fixture("deb-downgrade-new.json"))
        .arg("--fail-on")
        .arg("version-downgrade")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("1.2.3-1ubuntu2 -> 1.2.3-1ubuntu1"),
        "stderr should report the real revision downgrade, got: {stderr}"
    );
}

#[test]
fn fail_on_version_downgrade_rpm_upgrade_exits_0() {
    let out = sbom_diff()
        .arg(fixture("rpm-upgrade-old.json"))
        .arg(fixture("rpm-upgrade-new.json"))
        .arg("--fail-on")
        .arg("version-downgrade")
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(0),
        "1.a -> 1.1 is an upgrade per rpm (a downgrade per dpkg), got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn fail_on_version_downgrade_rpm_release_downgrade_exits_3() {
    let out = sbom_diff()
        .arg(fixture("rpm-upgrade-old.json"))
        .arg(fixture("rpm-downgrade-new.json"))
        .arg("--fail-on")
        .arg("version-downgrade")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("4.4.2-2.el7_9 -> 4.4.2-1.el7_9"),
        "stderr should report the release downgrade, got: {stderr}"
    );
}

#[test]
fn fail_on_version_downgrade_maven_qualifier_upgrade_exits_0() {
    let out = sbom_diff()
        .arg(fixture("maven-upgrade-old.json"))
        .arg(fixture("maven-upgrade-new.json"))
        .arg("--fail-on")
        .arg("version-downgrade")
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(0),
        "1.0-SNAPSHOT -> 1.0-Final and 1.7.0_80 -> 1.7.0_81 are upgrades per Maven, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn fail_on_version_downgrade_maven_dotted_qualifier_upgrade_exits_0() {
    let out = sbom_diff()
        .arg(fixture("maven-dotted-qualifier-old.json"))
        .arg(fixture("maven-dotted-qualifier-new.json"))
        .arg("--fail-on")
        .arg("version-downgrade")
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(0),
        "1.0.0.CR1 -> 1.0.0-CR2 and 3.1.0.M1 -> 3.1.0.RELEASE are upgrades per Maven, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn fail_on_version_downgrade_maven_qualifier_downgrade_exits_3() {
    let out = sbom_diff()
        .arg(fixture("maven-upgrade-old.json"))
        .arg(fixture("maven-downgrade-new.json"))
        .arg("--fail-on")
        .arg("version-downgrade")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("1.0-SNAPSHOT -> 1.0-alpha1"),
        "stderr should report the qualifier downgrade, got: {stderr}"
    );
}

#[test]
fn fail_on_version_downgrade_pypi_pre_release_upgrade_exits_0() {
    let out = sbom_diff()
        .arg(fixture("pypi-upgrade-old.json"))
        .arg(fixture("pypi-upgrade-new.json"))
        .arg("--fail-on")
        .arg("version-downgrade")
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(0),
        "1.0.2a -> 1.0.2 and 1.0+0 -> 1.0r are upgrades per PEP 440, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn fail_on_version_downgrade_pypi_pre_release_downgrade_exits_3() {
    let out = sbom_diff()
        .arg(fixture("pypi-upgrade-new.json"))
        .arg(fixture("pypi-upgrade-old.json"))
        .arg("--fail-on")
        .arg("version-downgrade")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("1.0.2 -> 1.0.2a"),
        "stderr should report the pre-release downgrade, got: {stderr}"
    );
}

#[test]
fn fail_on_version_downgrade_upgrade_exits_0() {
    // golden fixtures only have upgrades (1.0.0 -> 1.1.0)
    let out = sbom_diff()
        .arg(fixture("golden-old.json"))
        .arg(fixture("golden-new.json"))
        .arg("--fail-on")
        .arg("version-downgrade")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn fail_on_version_downgrade_multi_version_upgrade_exits_0() {
    let out = sbom_diff()
        .arg(fixture("multi-version-old.json"))
        .arg(fixture("multi-version-new.json"))
        .arg("--fail-on")
        .arg("version-downgrade")
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(0),
        "9.0.0/10.0.0 -> 9.0.1/10.0.1 upgrades both lines, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Version: 9.0.0 -> 9.0.1"), "got: {stdout}");
    assert!(
        stdout.contains("Version: 10.0.0 -> 10.0.1"),
        "got: {stdout}"
    );
}

#[test]
fn fail_on_version_downgrade_no_change_exits_0() {
    let out = sbom_diff()
        .arg(fixture("golden-old.json"))
        .arg(fixture("golden-old.json"))
        .arg("--fail-on")
        .arg("version-downgrade")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn fail_on_version_downgrade_letter_suffix_exits_3() {
    let out = sbom_diff()
        .arg(fixture("os-letter-version-old.json"))
        .arg(fixture("os-letter-version-new.json"))
        .arg("--fail-on")
        .arg("version-downgrade")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("1.0.2d -> 1.0.2c"),
        "openssl letter rollback should be reported, got: {stderr}"
    );
    assert!(
        stderr.contains("2025a -> 2024h"),
        "tzdata year rollback should be reported, got: {stderr}"
    );
}

#[test]
fn fail_on_version_downgrade_letter_suffix_upgrade_exits_0() {
    let out = sbom_diff()
        .arg(fixture("os-letter-upgrade-old.json"))
        .arg(fixture("os-letter-upgrade-new.json"))
        .arg("--fail-on")
        .arg("version-downgrade")
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    for change in [
        "1.0.2 -> 1.0.2a",
        "1.0.2a -> 1.0.2b",
        "2024h -> 2025a",
        "1.1.1a-r0 -> 1.1.1d-r0",
    ] {
        assert!(
            stdout.contains(change),
            "{change} should be listed: {stdout}"
        );
    }
}

#[test]
fn fail_on_supplier_changed_exits_3() {
    let out = sbom_diff()
        .arg(fixture("supplier-changed-old.json"))
        .arg(fixture("supplier-changed-new.json"))
        .arg("--fail-on")
        .arg("supplier-changed")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--fail-on supplier-changed"),
        "stderr should mention the violated condition, got: {}",
        stderr
    );
    assert!(
        stderr.contains("supplier changed on component"),
        "stderr should report the changed component, got: {}",
        stderr
    );
    assert!(
        stderr.contains("Acme Corp -> Evil Corp"),
        "stderr should show old and new suppliers, got: {}",
        stderr
    );
    assert!(
        stderr.contains("added component") && stderr.contains("has supplier"),
        "stderr should report the added component's supplier, got: {}",
        stderr
    );
}

#[test]
fn fail_on_supplier_changed_no_change_exits_0() {
    let out = sbom_diff()
        .arg(fixture("supplier-changed-old.json"))
        .arg(fixture("supplier-changed-old.json"))
        .arg("--fail-on")
        .arg("supplier-changed")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn fail_on_supplier_changed_spdx_noassertion_exits_0() {
    let out = sbom_diff()
        .arg(fixture("supplier-noassertion-old.spdx.json"))
        .arg(fixture("supplier-noassertion-new.spdx.json"))
        .arg("--fail-on")
        .arg("supplier-changed")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "sentinel supplier must not trip the gate. stdout: {}\nstderr: {}",
        stdout,
        stderr
    );
    assert!(
        !stdout.contains("Supplier"),
        "no supplier change should be reported, got: {}",
        stdout
    );
    assert!(
        !stdout.contains("NOASSERTION"),
        "NOASSERTION should never reach the output, got: {}",
        stdout
    );
}

#[test]
fn fail_on_purl_changed_exits_3() {
    let out = sbom_diff()
        .arg(fixture("purl-changed-old.json"))
        .arg(fixture("purl-changed-new.json"))
        .arg("--fail-on")
        .arg("purl-changed")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--fail-on purl-changed"),
        "stderr should mention the violated condition, got: {}",
        stderr
    );
    assert!(
        stderr.contains("purl changed on component"),
        "stderr should report the changed component, got: {}",
        stderr
    );
    assert!(
        stderr.contains("pkg:npm/pkg-a@1.0.0 -> pkg:npm/pkg-a-fork@1.0.0"),
        "stderr should show old and new purls, got: {}",
        stderr
    );
}

#[test]
fn fail_on_purl_changed_no_change_exits_0() {
    let out = sbom_diff()
        .arg(fixture("purl-changed-old.json"))
        .arg(fixture("purl-changed-old.json"))
        .arg("--fail-on")
        .arg("purl-changed")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn fail_on_ecosystem_changed_exits_3() {
    let out = sbom_diff()
        .arg(fixture("ecosystem-changed-old.json"))
        .arg(fixture("ecosystem-changed-new.json"))
        .arg("--fail-on")
        .arg("ecosystem-changed")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--fail-on ecosystem-changed"),
        "stderr should mention the violated condition, got: {}",
        stderr
    );
    assert!(
        stderr.contains("ecosystem changed on component"),
        "stderr should report the changed component, got: {}",
        stderr
    );
    assert!(
        stderr.contains("<none> -> npm"),
        "stderr should show old and new ecosystems, got: {}",
        stderr
    );
}

#[test]
fn fail_on_ecosystem_changed_no_change_exits_0() {
    let out = sbom_diff()
        .arg(fixture("ecosystem-changed-old.json"))
        .arg(fixture("ecosystem-changed-old.json"))
        .arg("--fail-on")
        .arg("ecosystem-changed")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn identity_diff_exits_0_with_no_output_changes() {
    let out = sbom_diff()
        .arg(fixture("golden-old.json"))
        .arg(fixture("golden-old.json"))
        .arg("--summary")
        .arg("--output")
        .arg("json")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["added"], 0);
    assert_eq!(v["removed"], 0);
    assert_eq!(v["changed"], 0);
}

#[test]
fn include_ecosystem_filters_to_matching() {
    let out = sbom_diff()
        .arg(fixture("golden-old.json"))
        .arg(fixture("golden-new.json"))
        .arg("--summary")
        .arg("--include-ecosystem")
        .arg("npm")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    // golden fixtures are all npm — should see the same counts as unfiltered
    assert!(stdout.contains("Added:            1"));
    assert!(stdout.contains("Removed:          1"));
    assert!(stdout.contains("Changed:          2"));
}

#[test]
fn include_ecosystem_non_matching_shows_zero() {
    let out = sbom_diff()
        .arg(fixture("golden-old.json"))
        .arg(fixture("golden-new.json"))
        .arg("--summary")
        .arg("--include-ecosystem")
        .arg("cargo")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Added:            0"));
    assert!(stdout.contains("Removed:          0"));
    assert!(stdout.contains("Changed:          0"));
    assert!(stdout.contains("Old total:        0 components"));
}

#[test]
fn exclude_ecosystem_removes_matching() {
    let out = sbom_diff()
        .arg(fixture("golden-old.json"))
        .arg(fixture("golden-new.json"))
        .arg("--summary")
        .arg("--exclude-ecosystem")
        .arg("npm")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    // all components are npm, so excluding npm should yield zero
    assert!(stdout.contains("Added:            0"));
    assert!(stdout.contains("Removed:          0"));
    assert!(stdout.contains("Changed:          0"));
}

#[test]
fn include_ecosystem_case_insensitive() {
    let out = sbom_diff()
        .arg(fixture("golden-old.json"))
        .arg(fixture("golden-new.json"))
        .arg("--summary")
        .arg("--include-ecosystem")
        .arg("NPM")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Added:            1"));
}

#[test]
fn include_ecosystem_json_output() {
    let out = sbom_diff()
        .arg(fixture("golden-old.json"))
        .arg(fixture("golden-new.json"))
        .arg("--summary")
        .arg("--output")
        .arg("json")
        .arg("--include-ecosystem")
        .arg("cargo")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["added"], 0);
    assert_eq!(v["removed"], 0);
    assert_eq!(v["changed"], 0);
    assert_eq!(v["old_total"], 0);
}

#[test]
fn exclude_ecosystem_does_not_affect_non_matching() {
    // excluding cargo should leave npm data intact
    let out = sbom_diff()
        .arg(fixture("golden-old.json"))
        .arg(fixture("golden-new.json"))
        .arg("--summary")
        .arg("--exclude-ecosystem")
        .arg("cargo")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Added:            1"));
    assert!(stdout.contains("Removed:          1"));
    assert!(stdout.contains("Changed:          2"));
}

#[test]
fn include_and_exclude_ecosystem_combined() {
    // include npm then exclude npm → should be empty
    let out = sbom_diff()
        .arg(fixture("golden-old.json"))
        .arg(fixture("golden-new.json"))
        .arg("--summary")
        .arg("--include-ecosystem")
        .arg("npm")
        .arg("--exclude-ecosystem")
        .arg("npm")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Added:            0"));
}

#[test]
fn include_ecosystem_with_fail_on_respects_filter() {
    // fail-on added-components + include cargo → no npm adds visible → exit 0
    let out = sbom_diff()
        .arg(fixture("golden-old.json"))
        .arg(fixture("golden-new.json"))
        .arg("--fail-on")
        .arg("added-components")
        .arg("--include-ecosystem")
        .arg("cargo")
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(0),
        "filtering out all adds should prevent fail-on trigger"
    );
}

#[test]
fn fail_on_hash_algorithm_downgrade_exits_3() {
    let out = sbom_diff()
        .arg(fixture("hash-downgrade-old.json"))
        .arg(fixture("hash-downgrade-new.json"))
        .arg("--fail-on")
        .arg("hash-algorithm-downgrade")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--fail-on hash-algorithm-downgrade"),
        "stderr should mention the violated condition, got: {}",
        stderr
    );
    assert!(
        stderr.contains("hash algorithm downgrade on component"),
        "stderr should report the downgraded component, got: {}",
        stderr
    );
}

#[test]
fn fail_on_hash_algorithm_downgrade_no_change_exits_0() {
    let out = sbom_diff()
        .arg(fixture("hash-downgrade-old.json"))
        .arg(fixture("hash-downgrade-old.json"))
        .arg("--fail-on")
        .arg("hash-algorithm-downgrade")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn fail_on_hash_algorithm_downgrade_only_downgraded_component_reported() {
    // pkg-a: SHA-256 → MD5 (downgrade), pkg-b: SHA-512 → SHA-512 (no change)
    let out = sbom_diff()
        .arg(fixture("hash-downgrade-old.json"))
        .arg(fixture("hash-downgrade-new.json"))
        .arg("--fail-on")
        .arg("hash-algorithm-downgrade")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    // only pkg-a should be reported, not pkg-b
    assert!(
        stderr.contains("pkg-a"),
        "stderr should mention pkg-a, got: {}",
        stderr
    );
    assert!(
        !stderr.contains("pkg-b"),
        "stderr should NOT mention pkg-b (unchanged hash), got: {}",
        stderr
    );
}

#[test]
fn mixed_eco_include_npm_text() {
    let out = sbom_diff()
        .arg(fixture("mixed-eco-old.json"))
        .arg(fixture("mixed-eco-new.json"))
        .arg("--include-ecosystem")
        .arg("npm")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    // summary counts: 1 added (axios), 1 removed (express), 1 changed (lodash)
    assert!(stdout.contains("Old total:        2 components"));
    assert!(stdout.contains("New total:        2 components"));
    assert!(stdout.contains("Added:            1"));
    assert!(stdout.contains("Removed:          1"));
    assert!(stdout.contains("Changed:          1"));
    // npm components present
    assert!(stdout.contains("pkg:npm/axios@1.0.0"));
    assert!(stdout.contains("pkg:npm/express@4.18.0"));
    assert!(stdout.contains("pkg:npm/lodash@4.17.21"));
    // non-npm components absent
    assert!(!stdout.contains("pkg:cargo/"));
    assert!(!stdout.contains("pkg:pypi/"));
}

#[test]
fn mixed_eco_include_cargo_text() {
    let out = sbom_diff()
        .arg(fixture("mixed-eco-old.json"))
        .arg(fixture("mixed-eco-new.json"))
        .arg("--include-ecosystem")
        .arg("cargo")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Old total:        1 components"));
    assert!(stdout.contains("New total:        2 components"));
    assert!(stdout.contains("Added:            1"));
    assert!(stdout.contains("Removed:          0"));
    assert!(stdout.contains("Changed:          0"));
    assert!(stdout.contains("Unchanged:        1"));
    assert!(stdout.contains("pkg:cargo/tokio@1.0.0"));
    assert!(!stdout.contains("pkg:npm/"));
    assert!(!stdout.contains("pkg:pypi/"));
}

#[test]
fn mixed_eco_exclude_npm_text() {
    let out = sbom_diff()
        .arg(fixture("mixed-eco-old.json"))
        .arg(fixture("mixed-eco-new.json"))
        .arg("--exclude-ecosystem")
        .arg("npm")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Old total:        3 components"));
    assert!(stdout.contains("New total:        3 components"));
    assert!(stdout.contains("Added:            1"));
    assert!(stdout.contains("Removed:          1"));
    assert!(stdout.contains("Changed:          0"));
    assert!(stdout.contains("Unchanged:        2"));
    // cargo and pypi components present
    assert!(stdout.contains("pkg:cargo/tokio@1.0.0"));
    assert!(stdout.contains("pkg:pypi/requests@2.28.0"));
    // npm components absent
    assert!(!stdout.contains("pkg:npm/"));
}

#[test]
fn mixed_eco_include_npm_json() {
    let out = sbom_diff()
        .arg(fixture("mixed-eco-old.json"))
        .arg(fixture("mixed-eco-new.json"))
        .arg("--output")
        .arg("json")
        .arg("--include-ecosystem")
        .arg("npm")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["old_total"], 2);
    assert_eq!(v["new_total"], 2);
    assert_eq!(v["unchanged"], 0);

    let added = v["added"].as_array().unwrap();
    assert_eq!(added.len(), 1);
    assert_eq!(added[0]["ecosystem"], "npm");
    assert_eq!(added[0]["name"], "axios");

    let removed = v["removed"].as_array().unwrap();
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0]["ecosystem"], "npm");
    assert_eq!(removed[0]["name"], "express");

    let changed = v["changed"].as_array().unwrap();
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0]["new"]["name"], "lodash");
}

#[test]
fn mixed_eco_exclude_npm_json() {
    let out = sbom_diff()
        .arg(fixture("mixed-eco-old.json"))
        .arg(fixture("mixed-eco-new.json"))
        .arg("--output")
        .arg("json")
        .arg("--exclude-ecosystem")
        .arg("npm")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["old_total"], 3);
    assert_eq!(v["new_total"], 3);
    assert_eq!(v["unchanged"], 2);

    let added = v["added"].as_array().unwrap();
    assert_eq!(added.len(), 1);
    assert_eq!(added[0]["ecosystem"], "cargo");

    let removed = v["removed"].as_array().unwrap();
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0]["ecosystem"], "pypi");

    // no npm components in output
    let changed = v["changed"].as_array().unwrap();
    assert!(changed.is_empty());
}

#[test]
fn mixed_eco_include_cargo_markdown() {
    let out = sbom_diff()
        .arg(fixture("mixed-eco-old.json"))
        .arg(fixture("mixed-eco-new.json"))
        .arg("--output")
        .arg("markdown")
        .arg("--include-ecosystem")
        .arg("cargo")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("| Old total | 1 |"));
    assert!(stdout.contains("| New total | 2 |"));
    assert!(stdout.contains("| Added | 1 |"));
    assert!(stdout.contains("| Removed | 0 |"));
    assert!(stdout.contains("`pkg:cargo/tokio@1.0.0`"));
    assert!(!stdout.contains("npm"));
    assert!(!stdout.contains("pypi"));
}

#[test]
fn mixed_eco_exclude_npm_markdown() {
    let out = sbom_diff()
        .arg(fixture("mixed-eco-old.json"))
        .arg(fixture("mixed-eco-new.json"))
        .arg("--output")
        .arg("markdown")
        .arg("--exclude-ecosystem")
        .arg("npm")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("| Old total | 3 |"));
    assert!(stdout.contains("| Added | 1 |"));
    assert!(stdout.contains("| Removed | 1 |"));
    assert!(stdout.contains("`pkg:cargo/tokio@1.0.0`"));
    assert!(stdout.contains("`pkg:pypi/requests@2.28.0`"));
    assert!(!stdout.contains("npm"));
}

#[test]
fn mixed_eco_multi_include_text() {
    let out = sbom_diff()
        .arg(fixture("mixed-eco-old.json"))
        .arg(fixture("mixed-eco-new.json"))
        .arg("--include-ecosystem")
        .arg("npm")
        .arg("--include-ecosystem")
        .arg("cargo")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Old total:        3 components"));
    assert!(stdout.contains("New total:        4 components"));
    assert!(stdout.contains("Added:            2"));
    assert!(stdout.contains("Removed:          1"));
    assert!(stdout.contains("Changed:          1"));
    assert!(stdout.contains("Unchanged:        1"));
    // both npm and cargo present
    assert!(stdout.contains("pkg:npm/axios@1.0.0"));
    assert!(stdout.contains("pkg:cargo/tokio@1.0.0"));
    assert!(stdout.contains("pkg:npm/express@4.18.0"));
    assert!(stdout.contains("pkg:npm/lodash@4.17.21"));
    // pypi excluded
    assert!(!stdout.contains("pkg:pypi/"));
}

#[test]
fn mixed_eco_include_unknown_text() {
    // components without a purl default to "unknown" ecosystem
    let out = sbom_diff()
        .arg(fixture("mixed-eco-old.json"))
        .arg(fixture("mixed-eco-new.json"))
        .arg("--include-ecosystem")
        .arg("unknown")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    // only no-purl-lib (unchanged in both) should remain
    assert!(stdout.contains("Old total:        1 components"));
    assert!(stdout.contains("New total:        1 components"));
    assert!(stdout.contains("Unchanged:        1"));
    assert!(stdout.contains("Added:            0"));
    assert!(stdout.contains("Removed:          0"));
    assert!(stdout.contains("Changed:          0"));
}

#[test]
fn fail_on_cyclic_dependency_exits_3() {
    let out = sbom_diff()
        .arg(fixture("cyclic-dep-old.json"))
        .arg(fixture("cyclic-dep-new.json"))
        .arg("--fail-on")
        .arg("cyclic-dependency")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--fail-on cyclic-dependency"),
        "stderr should mention the violated condition"
    );
    assert!(
        stderr.contains("dependency cycle detected"),
        "stderr should describe the cycle"
    );
}

#[test]
fn fail_on_cyclic_dependency_no_cycle_exits_0() {
    // use the old fixture for both sides — no cycles in either
    let out = sbom_diff()
        .arg(fixture("cyclic-dep-old.json"))
        .arg(fixture("cyclic-dep-old.json"))
        .arg("--fail-on")
        .arg("cyclic-dependency")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn fail_on_cyclic_dependency_quiet_suppresses_output() {
    let out = sbom_diff()
        .arg(fixture("cyclic-dep-old.json"))
        .arg(fixture("cyclic-dep-new.json"))
        .arg("--fail-on")
        .arg("cyclic-dependency")
        .arg("--quiet")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.is_empty(), "stdout should be empty in quiet mode");
    // stderr should still show the error
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("dependency cycle detected"));
}

#[test]
fn fail_on_cyclic_dependency_combined_with_other_conditions() {
    let out = sbom_diff()
        .arg(fixture("cyclic-dep-old.json"))
        .arg(fixture("cyclic-dep-new.json"))
        .arg("--fail-on")
        .arg("cyclic-dependency")
        .arg("--fail-on")
        .arg("deps")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--fail-on cyclic-dependency"));
}

#[test]
fn cross_format_identity_no_changes() {
    // the same logical SBOM in CycloneDX and SPDX formats — should produce
    // zero diffs despite different serialisation and hash algorithm naming
    // (CycloneDX "SHA-256" vs SPDX "SHA256").
    let out = sbom_diff()
        .arg(fixture("cross-format-base.json"))
        .arg(fixture("cross-format-base.spdx.json"))
        .arg("--summary")
        .arg("--output")
        .arg("json")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("output should be valid JSON");
    assert_eq!(v["added"], 0, "no components should be added");
    assert_eq!(v["removed"], 0, "no components should be removed");
    assert_eq!(v["changed"], 0, "no components should be changed");
    assert_eq!(v["unchanged"], 4, "all four components should be unchanged");
}

#[test]
fn cross_format_identity_spdx_to_cdx() {
    // same test but with SPDX as old and CycloneDX as new
    let out = sbom_diff()
        .arg(fixture("cross-format-base.spdx.json"))
        .arg(fixture("cross-format-base.json"))
        .arg("--summary")
        .arg("--output")
        .arg("json")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("output should be valid JSON");
    assert_eq!(v["added"], 0);
    assert_eq!(v["removed"], 0);
    assert_eq!(v["changed"], 0);
    assert_eq!(v["unchanged"], 4);
}

#[test]
fn cross_format_identity_fail_on_gates_pass() {
    // all --fail-on gates should pass when diffing identical SBOMs
    // across formats — this is the strongest test that canonicalisation
    // (hashes, licenses, identity) works end-to-end.
    let out = sbom_diff()
        .arg(fixture("cross-format-base.json"))
        .arg(fixture("cross-format-base.spdx.json"))
        .arg("--fail-on")
        .arg("added-components")
        .arg("--fail-on")
        .arg("removed-components")
        .arg("--fail-on")
        .arg("changed-components")
        .arg("--fail-on")
        .arg("deps")
        .arg("--fail-on")
        .arg("license-changed")
        .arg("--fail-on")
        .arg("hash-algorithm-downgrade")
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(0),
        "identical cross-format SBOMs should pass all gates, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn cross_format_modification_detected() {
    // diff SPDX base (old) against modified CycloneDX (new):
    // alpha: version 2.0.0 → 2.1.0
    // beta: license Apache-2.0 → GPL-3.0-only, hash changed
    let out = sbom_diff()
        .arg(fixture("cross-format-base.spdx.json"))
        .arg(fixture("cross-format-modified.json"))
        .arg("--summary")
        .arg("--output")
        .arg("json")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("output should be valid JSON");
    assert_eq!(v["changed"], 2, "alpha and beta should be changed");
    assert_eq!(v["unchanged"], 2, "gamma and delta should be unchanged");
    assert_eq!(v["added"], 0);
    assert_eq!(v["removed"], 0);
}

#[test]
fn cross_format_modification_full_json() {
    // verify the exact field changes in the JSON detail output
    let out = sbom_diff()
        .arg(fixture("cross-format-base.spdx.json"))
        .arg(fixture("cross-format-modified.json"))
        .arg("--output")
        .arg("json")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("output should be valid JSON");

    let changed = v["changed"].as_array().expect("changed should be an array");
    assert_eq!(changed.len(), 2);

    // collect changed component names for flexible assertion order
    let names: Vec<&str> = changed
        .iter()
        .map(|c| c["new"]["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"alpha"), "alpha should appear in changed");
    assert!(names.contains(&"beta"), "beta should appear in changed");
}

#[test]
fn cross_format_fail_on_changed_components_exits_3() {
    // modifications across formats should trigger --fail-on changed-components
    let out = sbom_diff()
        .arg(fixture("cross-format-base.spdx.json"))
        .arg(fixture("cross-format-modified.json"))
        .arg("--fail-on")
        .arg("changed-components")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--fail-on changed-components"),
        "stderr should mention the violated condition, got: {}",
        stderr
    );
}

#[test]
fn cross_format_fail_on_license_changed_exits_3() {
    // beta's license change (Apache-2.0 → GPL-3.0-only) should trigger
    // --fail-on license-changed even across formats
    let out = sbom_diff()
        .arg(fixture("cross-format-base.spdx.json"))
        .arg(fixture("cross-format-modified.json"))
        .arg("--fail-on")
        .arg("license-changed")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--fail-on license-changed"),
        "stderr should mention the violated condition, got: {}",
        stderr
    );
}

#[test]
fn cross_format_hash_canonicalisation_no_false_diff() {
    // CycloneDX uses "SHA-256", SPDX uses "SHA256" — after canonicalisation
    // these must be identical. The identity diff must show zero hash changes.
    let out = sbom_diff()
        .arg(fixture("cross-format-base.json"))
        .arg(fixture("cross-format-base.spdx.json"))
        .arg("--output")
        .arg("json")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("output should be valid JSON");

    // no changed components at all — hashes must have been canonicalised
    let changed = v["changed"].as_array().expect("changed should be an array");
    assert!(
        changed.is_empty(),
        "hash algorithm naming differences (SHA-256 vs SHA256) should not \
         produce false diffs after canonicalisation, got {} changes",
        changed.len()
    );
}

#[test]
fn cross_format_ecosystem_filter_works() {
    // filter to cargo ecosystem only — should see 2 unchanged (gamma, delta)
    let out = sbom_diff()
        .arg(fixture("cross-format-base.spdx.json"))
        .arg(fixture("cross-format-modified.json"))
        .arg("--summary")
        .arg("--output")
        .arg("json")
        .arg("--include-ecosystem")
        .arg("cargo")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("output should be valid JSON");
    assert_eq!(v["changed"], 0, "cargo components are unchanged");
    assert_eq!(v["unchanged"], 2, "gamma and delta are cargo");
    assert_eq!(v["added"], 0);
    assert_eq!(v["removed"], 0);
}

#[test]
fn only_masking_fail_on_gate_warns_and_silently_passes() {
    // --only license excludes the version field that --fail-on version-downgrade
    // reads, so pkg-a's 2.0.0 -> 1.5.0 downgrade goes undetected and the gate
    // exits 0. that silent bypass must be surfaced as a warning.
    let out = sbom_diff()
        .arg(fixture("version-downgrade-old.json"))
        .arg(fixture("version-downgrade-new.json"))
        .arg("--only")
        .arg("license")
        .arg("--fail-on")
        .arg("version-downgrade")
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--fail-on version-downgrade")
            && stderr.contains("--only")
            && stderr.contains("silently pass"),
        "expected a masking warning, got: {stderr}"
    );
    // the gate is bypassed: no violation detected, exit 0 despite the downgrade
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn only_including_gate_field_emits_no_masking_warning() {
    // --only version keeps the field the gate needs; no warning, and the
    // downgrade is caught as usual.
    let out = sbom_diff()
        .arg(fixture("version-downgrade-old.json"))
        .arg(fixture("version-downgrade-new.json"))
        .arg("--only")
        .arg("version")
        .arg("--fail-on")
        .arg("version-downgrade")
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("silently pass"),
        "expected no masking warning, got: {stderr}"
    );
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn fail_on_without_only_emits_no_masking_warning() {
    let out = sbom_diff()
        .arg(fixture("version-downgrade-old.json"))
        .arg(fixture("version-downgrade-new.json"))
        .arg("--fail-on")
        .arg("version-downgrade")
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("silently pass"),
        "expected no masking warning, got: {stderr}"
    );
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn fail_on_copyleft_added_exits_3() {
    // pkg-a: MIT -> GPL-3.0-only (changed component), pkg-c: new AGPL-3.0-only
    // component (added component) — both paths must fire.
    let out = sbom_diff()
        .arg(fixture("license-changed-old.json"))
        .arg(fixture("license-changed-new.json"))
        .arg("--fail-on")
        .arg("copyleft-added")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--fail-on copyleft-added"),
        "stderr should mention the violated condition, got: {}",
        stderr
    );
    assert!(
        stderr.contains("GPL-3.0-only"),
        "stderr should name the copyleft license introduced on the changed component, got: {}",
        stderr
    );
    assert!(
        stderr.contains("AGPL-3.0-only"),
        "stderr should name the copyleft license introduced by the added component, got: {}",
        stderr
    );
}

#[test]
fn fail_on_copyleft_added_no_change_exits_0() {
    // same file on both sides: copyleft licenses are present but nothing is
    // introduced, so the gate must not fire.
    let out = sbom_diff()
        .arg(fixture("license-changed-new.json"))
        .arg(fixture("license-changed-new.json"))
        .arg("--fail-on")
        .arg("copyleft-added")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn fail_on_copyleft_added_permissive_change_exits_0() {
    // a genuine license change that stays permissive (MIT -> Apache-2.0) must
    // not fire the copyleft gate.
    let out = sbom_diff()
        .arg(fixture("copyleft-added-permissive-old.json"))
        .arg(fixture("copyleft-added-permissive-new.json"))
        .arg("--fail-on")
        .arg("copyleft-added")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));

    // the change is still a license change, just not a copyleft one
    let license_out = sbom_diff()
        .arg(fixture("copyleft-added-permissive-old.json"))
        .arg(fixture("copyleft-added-permissive-new.json"))
        .arg("--fail-on")
        .arg("license-changed")
        .output()
        .unwrap();
    assert_eq!(license_out.status.code(), Some(3));
}

#[test]
fn cross_format_fail_on_copyleft_added_exits_3() {
    // beta's license change (Apache-2.0 -> GPL-3.0-only) across formats
    // introduces copyleft and must trip the gate.
    let out = sbom_diff()
        .arg(fixture("cross-format-base.spdx.json"))
        .arg(fixture("cross-format-modified.json"))
        .arg("--fail-on")
        .arg("copyleft-added")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--fail-on copyleft-added"),
        "stderr should mention the violated condition, got: {}",
        stderr
    );
    assert!(
        stderr.contains("GPL-3.0-only"),
        "stderr should name beta's introduced copyleft license, got: {}",
        stderr
    );
}

#[test]
fn only_masking_deps_gate_warns_and_silently_passes() {
    // --only license excludes deps, so --fail-on deps computes no edge diffs and
    // silently passes even though the parent's dependency edge changed.
    let out = sbom_diff()
        .arg(fixture("edge-change-old.json"))
        .arg(fixture("edge-change-new.json"))
        .arg("--only")
        .arg("license")
        .arg("--fail-on")
        .arg("deps")
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--fail-on deps") && stderr.contains("silently pass"),
        "expected a deps masking warning, got: {stderr}"
    );
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn deny_license_ignores_an_avoidable_choice() {
    let out = sbom_diff()
        .arg(fixture("license-expression.json"))
        .arg(fixture("license-expression.json"))
        .arg("--deny-license")
        .arg("gpl-3.0-only")
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(0),
        "MIT OR GPL-3.0-only can be taken under MIT: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn deny_license_fires_on_an_unavoidable_conjunct() {
    let out = sbom_diff()
        .arg(fixture("license-expression-conjunction.json"))
        .arg(fixture("license-expression-conjunction.json"))
        .arg("--deny-license")
        .arg("gpl-3.0-only")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("license GPL-3.0-only is denied"),
        "expected the denied conjunct to be named, got: {stderr}"
    );
}

#[test]
fn allow_license_accepts_a_satisfiable_expression() {
    let out = sbom_diff()
        .arg(fixture("license-expression.json"))
        .arg(fixture("license-expression.json"))
        .arg("--allow-license")
        .arg("mit")
        .arg("--allow-license")
        .arg("bsd-3-clause")
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(0),
        "(MIT OR Apache-2.0) AND BSD-3-Clause is satisfiable inside the allow-list: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn allow_license_fires_when_no_choice_is_allowed() {
    let out = sbom_diff()
        .arg(fixture("license-expression.json"))
        .arg(fixture("license-expression.json"))
        .arg("--allow-license")
        .arg("mit")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("BSD-3-Clause is not allowed"),
        "expected the unsatisfiable conjunct to be named, got: {stderr}"
    );
}

#[test]
fn spdx_deny_license_ignores_an_avoidable_choice() {
    let out = sbom_diff()
        .arg(fixture("license-expression.spdx.json"))
        .arg(fixture("license-expression.spdx.json"))
        .arg("--deny-license")
        .arg("gpl-3.0-only")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("pkg:npm/both-lib@1.0.0"),
        "the conjunction must be denied, got: {stderr}"
    );
    assert!(
        !stderr.contains("pkg:npm/dual-lib@1.0.0"),
        "the choice must not be denied, got: {stderr}"
    );
}

#[test]
fn fail_on_copyleft_added_ignores_a_dual_license() {
    let out = sbom_diff()
        .arg(fixture("copyleft-added-permissive-old.json"))
        .arg(fixture("copyleft-choice-new.json"))
        .arg("--fail-on")
        .arg("copyleft-added")
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(0),
        "MIT -> MIT OR GPL-3.0-only imposes no copyleft obligation: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn fail_on_copyleft_added_fires_on_a_conjunction() {
    let out = sbom_diff()
        .arg(fixture("copyleft-added-permissive-old.json"))
        .arg(fixture("copyleft-conjunction-new.json"))
        .arg("--fail-on")
        .arg("copyleft-added")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("copyleft license introduced") && stderr.contains("GPL-3.0-only"));
}

#[test]
fn fail_on_copyleft_added_ignores_an_unchanged_copyleft_choice() {
    let out = sbom_diff()
        .arg(fixture("copyleft-unchanged-choice-old.json"))
        .arg(fixture("copyleft-unchanged-choice-new.json"))
        .arg("--fail-on")
        .arg("copyleft-added")
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(0),
        "only the permissive operand changed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = sbom_diff()
        .arg(fixture("copyleft-unchanged-choice-old.json"))
        .arg(fixture("copyleft-unchanged-choice-new.json"))
        .arg("--fail-on")
        .arg("license-changed")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn dropping_a_license_exception_is_a_license_change() {
    let out = sbom_diff()
        .arg(fixture("license-exception-old.spdx.json"))
        .arg(fixture("license-exception-new.spdx.json"))
        .arg("--fail-on")
        .arg("license-changed")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("license expression changed")
            && stderr.contains("GPL-2.0-only WITH Classpath-exception-2.0 -> GPL-2.0-only"),
        "expected the dropped exception to be named, got: {stderr}"
    );

    let text = sbom_diff()
        .arg(fixture("license-exception-old.spdx.json"))
        .arg(fixture("license-exception-new.spdx.json"))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&text.stdout);
    assert!(
        stdout.contains("License expression"),
        "expected the diff to render the change, got: {stdout}"
    );
}

#[test]
fn license_exception_is_nameable_in_a_deny_list() {
    let out = sbom_diff()
        .arg(fixture("license-exception-old.spdx.json"))
        .arg(fixture("license-exception-old.spdx.json"))
        .arg("--deny-license")
        .arg("GPL-2.0-only WITH Classpath-exception-2.0")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn losing_a_choice_to_a_flat_set_is_a_copyleft_addition() {
    let out = sbom_diff()
        .arg(fixture("copyleft-choice-new.json"))
        .arg(fixture("copyleft-choice-flattened.json"))
        .arg("--fail-on")
        .arg("copyleft-added")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("copyleft license introduced") && stderr.contains("GPL-3.0-only"),
        "expected the now-mandatory copyleft to be named, got: {stderr}"
    );
}

#[test]
fn losing_a_choice_to_a_flat_set_is_a_license_change() {
    let out = sbom_diff()
        .arg(fixture("copyleft-choice-new.json"))
        .arg(fixture("copyleft-choice-flattened.json"))
        .arg("--fail-on")
        .arg("license-changed")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("license expression changed")
            && stderr.contains("MIT OR GPL-3.0-only -> <none>"),
        "expected the dropped choice to be named, got: {stderr}"
    );
}

#[test]
fn flattening_a_conjunction_is_not_a_license_change() {
    let out = sbom_diff()
        .arg(fixture("license-expression-conjunction.json"))
        .arg(fixture("license-conjunction-flattened.json"))
        .arg("--fail-on")
        .arg("license-changed")
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(0),
        "MIT AND GPL-3.0-only already means every identifier applies: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn reordering_expression_operands_is_not_a_license_change() {
    let out = sbom_diff()
        .arg(fixture("copyleft-choice-new.json"))
        .arg(fixture("copyleft-choice-reordered.json"))
        .arg("--fail-on")
        .arg("license-changed")
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(0),
        "GPL-3.0-only OR MIT offers the same choice: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
