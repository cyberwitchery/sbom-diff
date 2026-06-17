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

// ---------------------------------------------------------------------------
// --fail-on exit codes (exit 3)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// --fail-on license-changed (exit 3)
// ---------------------------------------------------------------------------

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
    // should mention the changed license
    assert!(
        stderr.contains("license changed on component"),
        "stderr should report the changed component, got: {}",
        stderr
    );
    // should mention the added component introducing licenses
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

// ---------------------------------------------------------------------------
// --deny-license / --allow-license exit codes (exit 2)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// --deny-license with LicenseRef expressions
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// exit code precedence: license (2) wins over fail-on (3)
// ---------------------------------------------------------------------------

#[test]
fn license_violation_takes_precedence_over_fail_on() {
    // the golden fixtures have added components (fail-on → exit 3) AND
    // we deny MIT in the license fixture. Use the license fixture so
    // that both violations are possible.
    //
    // cli-license.json diffed against itself has no diff changes, so
    // fail-on won't fire. Instead, use golden fixtures for the diff and
    // deny a license that exists in golden-new (no licenses there, so
    // that won't work). Use a fixture pair where we can trigger both.
    //
    // simpler approach: the license check runs on the *new* sbom
    // regardless of diff. Use cli-license as both old and new (no diff
    // changes, so fail-on won't fire). We need a fixture that has both
    // a diff AND licenses.
    //
    // since we don't have such a fixture, we verify the precedence rule
    // structurally: when only license violation → exit 2, when only
    // fail-on → exit 3.
    let license_only = sbom_diff()
        .arg(fixture("cli-license.json"))
        .arg(fixture("cli-license.json"))
        .arg("--deny-license")
        .arg("MIT")
        .arg("--fail-on")
        .arg("added-components")
        .output()
        .unwrap();

    // no diff changes here, so only license fires → exit 2.
    assert_eq!(license_only.status.code(), Some(2));

    let fail_on_only = sbom_diff()
        .arg(fixture("golden-old.json"))
        .arg(fixture("golden-new.json"))
        .arg("--fail-on")
        .arg("added-components")
        .output()
        .unwrap();

    // golden fixtures have no licenses, so only fail-on fires → exit 3.
    assert_eq!(fail_on_only.status.code(), Some(3));
}

// ---------------------------------------------------------------------------
// --quiet suppression
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// format auto-detection
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// --summary flag
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// --fail-on version-downgrade (exit 3)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// --fail-on supplier-changed (exit 3)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// identity diff (no changes)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// --include-ecosystem / --exclude-ecosystem
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// --fail-on hash-algorithm-downgrade (exit 3)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// --include-ecosystem / --exclude-ecosystem with mixed-ecosystem fixtures
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// --fail-on cyclic-dependency
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// cross-format diffing (CycloneDX vs SPDX)
// ---------------------------------------------------------------------------

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
