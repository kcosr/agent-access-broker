use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const REQUIRED_COVERAGE: &[&str] = &[
    "space-eq",
    "space-in",
    "type-page",
    "title-contains",
    "text-contains",
    "label-eq",
    "label-neq",
    "label-in",
    "label-not-in",
    "creator-eq",
    "creator-neq",
    "creator-in",
    "creator-not-in",
    "contributor-eq",
    "contributor-neq",
    "contributor-in",
    "contributor-not-in",
    "mention-eq",
    "mention-in",
    "id-eq",
    "id-in",
    "content-id-eq",
    "content-id-in",
    "ancestor-eq",
    "ancestor-in",
    "parent-eq",
    "parent-in",
    "created-eq",
    "created-neq",
    "created-lt",
    "created-lte",
    "created-gt",
    "created-gte",
    "lastmodified-eq",
    "lastmodified-neq",
    "lastmodified-lt",
    "lastmodified-lte",
    "lastmodified-gt",
    "lastmodified-gte",
    "order-created",
    "order-lastmodified-desc",
    "order-title-default",
    "order-multi",
    "escaping-string-literals",
];

#[test]
#[ignore = "requires a live broker, real Confluence credentials, and an external conformance manifest"]
fn confluence_cql_conformance_smoke() {
    if std::env::var("AGENT_ACCESS_RUN_CONFORMANCE_SMOKE")
        .ok()
        .as_deref()
        != Some("1")
    {
        eprintln!(
            "skipping Confluence CQL conformance smoke; set AGENT_ACCESS_RUN_CONFORMANCE_SMOKE=1 to run it"
        );
        return;
    }

    let started_at = timestamp();
    let report_path = report_path();
    let broker_url = std::env::var("AGENT_ACCESS_REAL_BROKER_URL").ok();
    let manifest_path = std::env::var("AGENT_ACCESS_CONFLUENCE_CQL_CONFORMANCE_CASES").ok();

    let missing = missing_required_env(&broker_url, &manifest_path);
    if !missing.is_empty() {
        let report = setup_failure_report(
            started_at,
            None,
            broker_url.as_deref(),
            manifest_path.as_deref(),
            None,
            "environment",
            &format!(
                "missing required environment variables: {}",
                missing.join(", ")
            ),
        );
        write_report(&report_path, &report);
        panic!("Confluence CQL conformance setup failed: missing required environment variables");
    }

    let broker_url = broker_url.expect("broker URL checked above");
    let manifest_path = manifest_path.expect("manifest path checked above");
    let manifest_path_hash = sha256_hex(manifest_path.as_bytes());
    let manifest_bytes = match std::fs::read(&manifest_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            let report = setup_failure_report(
                started_at,
                None,
                Some(&broker_url),
                Some(&manifest_path),
                None,
                "manifest",
                &format!("manifest read failed: {:?}", error.kind()),
            );
            write_report(&report_path, &report);
            panic!("Confluence CQL conformance setup failed: manifest could not be read");
        }
    };
    let manifest_hash = sha256_hex(&manifest_bytes);
    let manifest: Manifest = match serde_json::from_slice(&manifest_bytes) {
        Ok(manifest) => manifest,
        Err(error) => {
            let report = setup_failure_report(
                started_at,
                None,
                Some(&broker_url),
                Some(&manifest_path),
                Some(&manifest_hash),
                "manifest",
                &format!("manifest JSON invalid: {error}"),
            );
            write_report(&report_path, &report);
            panic!("Confluence CQL conformance setup failed: manifest JSON invalid");
        }
    };

    if let Err(errors) = validate_manifest(&manifest) {
        let report = setup_failure_report(
            started_at,
            Some(&manifest.description),
            Some(&broker_url),
            Some(&manifest_path),
            Some(&manifest_hash),
            "manifest",
            &format!("manifest validation failed: {}", errors.join("; ")),
        );
        write_report(&report_path, &report);
        panic!("Confluence CQL conformance setup failed: manifest validation failed");
    }

    let mut cases = Vec::new();
    let mut covered = BTreeSet::new();
    let mut upstream_incompatibility_coverage = BTreeSet::new();
    for case in &manifest.cases {
        let report = run_case(&broker_url, &manifest.defaults, case);
        if report.status == "passed" {
            for tag in &report.covers {
                covered.insert(tag.clone());
            }
        } else if report.status == "expected-upstream-failure" {
            for tag in &report.covers {
                upstream_incompatibility_coverage.insert(tag.clone());
            }
        }
        cases.push(report);
    }

    let passed = cases
        .iter()
        .all(|case| case.status == "passed" || case.status == "expected-upstream-failure");
    let passed_declared_coverage = covered.into_iter().collect();
    let accepted_upstream_incompatibility_coverage = upstream_incompatibility_coverage
        .into_iter()
        .collect::<Vec<_>>();
    let status = if !passed {
        "failed"
    } else if accepted_upstream_incompatibility_coverage.is_empty() {
        "passed"
    } else {
        "passed-with-upstream-incompatibilities"
    };
    let report = Report {
        version: 1,
        suite_description: Some(manifest.description),
        started_at,
        finished_at: timestamp(),
        broker_url_sha256: Some(sha256_hex(broker_url.as_bytes())),
        manifest_path_sha256: Some(manifest_path_hash),
        manifest_sha256: Some(manifest_hash),
        failure_phase: (!passed).then_some("cases".to_string()),
        required_coverage: required_coverage(),
        declared_coverage: declared_coverage(&cases),
        passed_declared_coverage,
        accepted_upstream_incompatibility_coverage,
        status: status.to_string(),
        cases,
        error_summary: None,
    };
    write_report(&report_path, &report);

    assert!(
        passed,
        "Confluence CQL conformance failed; see the sanitized report"
    );
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    version: u32,
    description: String,
    defaults: ManifestDefaults,
    cases: Vec<ManifestCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ManifestDefaults {
    spaces: Vec<String>,
    max_results: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ManifestCase {
    id: String,
    description: String,
    cql: String,
    spaces: Option<Vec<String>>,
    max_results: Option<usize>,
    covers: Vec<String>,
    expect: Option<Expectations>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Expectations {
    #[serde(default)]
    min_pages: usize,
    #[serde(default)]
    contains_page_ids: Vec<String>,
    expected_upstream_failure: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Report {
    version: u32,
    suite_description: Option<String>,
    started_at: String,
    finished_at: String,
    broker_url_sha256: Option<String>,
    manifest_path_sha256: Option<String>,
    manifest_sha256: Option<String>,
    failure_phase: Option<String>,
    required_coverage: Vec<String>,
    declared_coverage: Vec<String>,
    passed_declared_coverage: Vec<String>,
    accepted_upstream_incompatibility_coverage: Vec<String>,
    status: String,
    cases: Vec<CaseReport>,
    error_summary: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CaseReport {
    id: String,
    description: String,
    cql_sha256: String,
    space_hashes: Vec<String>,
    max_results: usize,
    covers: Vec<String>,
    status: String,
    decision: Option<String>,
    reason_code: Option<String>,
    page_count: Option<usize>,
    page_id_hashes: Vec<String>,
    expected_page_id_hashes: Vec<String>,
    expected_upstream_failure: Option<String>,
    failure_summary: Option<String>,
}

fn run_case(broker_url: &str, defaults: &ManifestDefaults, case: &ManifestCase) -> CaseReport {
    let spaces = effective_spaces(defaults, case).to_vec();
    let max_results = case.max_results.unwrap_or(defaults.max_results);
    let expectations = case.expect.clone().unwrap_or_default();
    let expected_page_id_hashes = expectations
        .contains_page_ids
        .iter()
        .map(|id| sha256_hex(id.as_bytes()))
        .collect::<Vec<_>>();

    let mut report = CaseReport {
        id: case.id.clone(),
        description: case.description.clone(),
        cql_sha256: sha256_hex(case.cql.as_bytes()),
        space_hashes: spaces
            .iter()
            .map(|space| sha256_hex(space.as_bytes()))
            .collect(),
        max_results,
        covers: case.covers.clone(),
        status: "failed".to_string(),
        decision: None,
        reason_code: None,
        page_count: None,
        page_id_hashes: Vec::new(),
        expected_page_id_hashes,
        expected_upstream_failure: expectations.expected_upstream_failure.clone(),
        failure_summary: None,
    };

    let output = match run_search_command(broker_url, case, &spaces, max_results) {
        Ok(output) => output,
        Err(error) => {
            report.failure_summary =
                Some(format!("failed to spawn agent-access: {:?}", error.kind()));
            return report;
        }
    };

    if !output.status.success() {
        if mark_expected_upstream_failure(&mut report, &expectations, &output) {
            return report;
        }
        report.failure_summary = Some(process_failure_summary(
            "process exited unsuccessfully",
            &output,
        ));
        return report;
    }

    let value: serde_json::Value = match serde_json::from_slice(&output.stdout) {
        Ok(value) => value,
        Err(_) => {
            report.failure_summary = Some(process_failure_summary(
                "stdout was not valid JSON",
                &output,
            ));
            return report;
        }
    };

    report.decision = value["decision"].as_str().map(ToOwned::to_owned);
    report.reason_code = value["reasonCode"].as_str().map(ToOwned::to_owned);
    if report.decision.as_deref() != Some("allow") {
        if expectations.expected_upstream_failure.is_some()
            && report.decision.as_deref() == Some("error")
            && report.reason_code.as_deref() == Some("upstream_failed")
        {
            report.status = "expected-upstream-failure".to_string();
            report.failure_summary = Some("expected upstream failure".to_string());
            return report;
        }
        report.failure_summary = Some(format!(
            "broker decision was {}; stdoutBytes={} stderrBytes={}",
            report.decision.as_deref().unwrap_or("missing"),
            output.stdout.len(),
            output.stderr.len()
        ));
        return report;
    }

    let pages = match value["result"]["pages"].as_array() {
        Some(pages) => pages,
        None => {
            report.failure_summary = Some(format!(
                "result.pages missing or not an array; stdoutBytes={} stderrBytes={}",
                output.stdout.len(),
                output.stderr.len()
            ));
            return report;
        }
    };

    let mut page_ids = Vec::new();
    let allowed_spaces = spaces.iter().cloned().collect::<HashSet<_>>();
    for page in pages {
        let Some(page_id) = page["id"].as_str() else {
            report.failure_summary = Some("returned page missing id".to_string());
            return report;
        };
        if let Some(space) = page["space"].as_str()
            && !allowed_spaces.contains(space)
        {
            report.failure_summary =
                Some("returned page space was outside requested spaces".to_string());
            return report;
        }
        page_ids.push(page_id.to_string());
    }

    report.page_count = Some(page_ids.len());
    report.page_id_hashes = page_ids
        .iter()
        .map(|page_id| sha256_hex(page_id.as_bytes()))
        .collect();

    if page_ids.len() < expectations.min_pages {
        report.failure_summary = Some(format!(
            "page count {} was below expected minimum {}",
            page_ids.len(),
            expectations.min_pages
        ));
        return report;
    }

    let returned = page_ids.iter().collect::<HashSet<_>>();
    for expected in &expectations.contains_page_ids {
        if !returned.contains(expected) {
            report.failure_summary = Some(format!(
                "expected page id hash {} was not present in first result page",
                sha256_hex(expected.as_bytes())
            ));
            return report;
        }
    }

    report.status = "passed".to_string();
    report
}

fn run_search_command(
    broker_url: &str,
    case: &ManifestCase,
    spaces: &[String],
    max_results: usize,
) -> std::io::Result<Output> {
    let max_results = max_results.to_string();
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
    command.args(["--url", broker_url, "confluence", "page", "search"]);
    for space in spaces {
        command.args(["--space", space]);
    }
    command.args(["--cql", &case.cql, "--max-results", &max_results]);
    command.output()
}

fn mark_expected_upstream_failure(
    report: &mut CaseReport,
    expectations: &Expectations,
    output: &Output,
) -> bool {
    if expectations.expected_upstream_failure.is_none() {
        return false;
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&output.stdout) else {
        return false;
    };
    report.decision = value["decision"].as_str().map(ToOwned::to_owned);
    report.reason_code = value["reasonCode"].as_str().map(ToOwned::to_owned);
    if report.decision.as_deref() != Some("error")
        || report.reason_code.as_deref() != Some("upstream_failed")
    {
        return false;
    }
    report.status = "expected-upstream-failure".to_string();
    report.failure_summary = Some(process_failure_summary("expected upstream failure", output));
    true
}

fn validate_manifest(manifest: &Manifest) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    let required = REQUIRED_COVERAGE.iter().copied().collect::<HashSet<_>>();
    let mut ids = HashSet::new();
    let mut declared = BTreeSet::new();

    if manifest.version != 1 {
        errors.push("version must be exactly 1".to_string());
    }
    if manifest.description.trim().is_empty() {
        errors.push("suite description must not be empty".to_string());
    }
    if manifest.defaults.spaces.is_empty() {
        errors.push("defaults.spaces must not be empty".to_string());
    }
    validate_spaces("defaults", &manifest.defaults.spaces, &mut errors);
    if manifest.defaults.max_results == 0 {
        errors.push("defaults.maxResults must be greater than zero".to_string());
    }
    if manifest.cases.is_empty() {
        errors.push("cases must not be empty".to_string());
    }

    for case in &manifest.cases {
        if !valid_case_id(&case.id) {
            errors.push("case id must be unique lowercase kebab-case".to_string());
        }
        if !ids.insert(case.id.clone()) {
            errors.push(format!("duplicate case id {}", case.id));
        }
        if case.description.trim().is_empty() {
            errors.push(format!("case {} description must not be empty", case.id));
        }
        if case.cql.is_empty() {
            errors.push(format!("case {} cql must not be empty", case.id));
        }
        if case.cql.len() > 4096 {
            errors.push(format!("case {} cql exceeds 4096 bytes", case.id));
        }
        if let Some(spaces) = &case.spaces {
            if spaces.is_empty() {
                errors.push(format!("case {} spaces must not be empty", case.id));
            }
            validate_spaces(&case.id, spaces, &mut errors);
        }
        let max_results = case.max_results.unwrap_or(manifest.defaults.max_results);
        if max_results == 0 {
            errors.push(format!(
                "case {} maxResults must be greater than zero",
                case.id
            ));
        }
        let expectations = case.expect.clone().unwrap_or_default();
        if expectations.min_pages > max_results {
            errors.push(format!(
                "case {} minPages must be less than or equal to effective maxResults",
                case.id
            ));
        }
        for page_id in &expectations.contains_page_ids {
            if page_id.trim().is_empty() {
                errors.push(format!(
                    "case {} containsPageIds entries must not be empty",
                    case.id
                ));
            }
        }
        if let Some(reason) = &expectations.expected_upstream_failure {
            if reason.trim().is_empty() {
                errors.push(format!(
                    "case {} expectedUpstreamFailure must not be empty",
                    case.id
                ));
            }
            if expectations.min_pages != 0 || !expectations.contains_page_ids.is_empty() {
                errors.push(format!(
                    "case {} expectedUpstreamFailure cannot be combined with page expectations",
                    case.id
                ));
            }
        }
        if case.covers.is_empty() {
            errors.push(format!("case {} covers must not be empty", case.id));
        }
        for tag in &case.covers {
            if tag.trim().is_empty() {
                errors.push(format!("case {} covers entries must not be empty", case.id));
            } else if !required.contains(tag.as_str()) {
                errors.push(format!("case {} covers unknown tag {}", case.id, tag));
            } else {
                declared.insert(tag.clone());
            }
        }
    }

    for tag in REQUIRED_COVERAGE {
        if !declared.contains(*tag) {
            errors.push(format!(
                "required coverage tag {tag} is not declared by any case"
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn validate_spaces(context: &str, spaces: &[String], errors: &mut Vec<String>) {
    for space in spaces {
        if space.trim().is_empty() {
            errors.push(format!("{context} spaces entries must not be empty"));
        }
    }
}

fn valid_case_id(value: &str) -> bool {
    if value.is_empty() || value.starts_with('-') || value.ends_with('-') {
        return false;
    }
    let mut previous_hyphen = false;
    for ch in value.chars() {
        let valid = ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-';
        if !valid || (ch == '-' && previous_hyphen) {
            return false;
        }
        previous_hyphen = ch == '-';
    }
    true
}

fn effective_spaces<'a>(defaults: &'a ManifestDefaults, case: &'a ManifestCase) -> &'a [String] {
    case.spaces.as_deref().unwrap_or(&defaults.spaces)
}

fn missing_required_env(
    broker_url: &Option<String>,
    manifest_path: &Option<String>,
) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if broker_url.is_none() {
        missing.push("AGENT_ACCESS_REAL_BROKER_URL");
    }
    if manifest_path.is_none() {
        missing.push("AGENT_ACCESS_CONFLUENCE_CQL_CONFORMANCE_CASES");
    }
    missing
}

fn setup_failure_report(
    started_at: String,
    suite_description: Option<&str>,
    broker_url: Option<&str>,
    manifest_path: Option<&str>,
    manifest_sha256: Option<&str>,
    failure_phase: &str,
    error_summary: &str,
) -> Report {
    Report {
        version: 1,
        suite_description: suite_description.map(ToOwned::to_owned),
        started_at,
        finished_at: timestamp(),
        broker_url_sha256: broker_url.map(|value| sha256_hex(value.as_bytes())),
        manifest_path_sha256: manifest_path.map(|value| sha256_hex(value.as_bytes())),
        manifest_sha256: manifest_sha256.map(ToOwned::to_owned),
        failure_phase: Some(failure_phase.to_string()),
        required_coverage: required_coverage(),
        declared_coverage: Vec::new(),
        passed_declared_coverage: Vec::new(),
        accepted_upstream_incompatibility_coverage: Vec::new(),
        status: "failed".to_string(),
        cases: Vec::new(),
        error_summary: Some(error_summary.to_string()),
    }
}

fn write_report(path: &Path, report: &Report) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap_or_else(|error| {
            panic!(
                "failed to create conformance report directory: {:?}",
                error.kind()
            )
        });
    }
    let bytes = serde_json::to_vec_pretty(report).expect("report serialization should not fail");
    std::fs::write(path, bytes)
        .unwrap_or_else(|error| panic!("failed to write conformance report: {:?}", error.kind()));
}

fn report_path() -> PathBuf {
    std::env::var_os("AGENT_ACCESS_CONFLUENCE_CQL_CONFORMANCE_REPORT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
                .join("conformance")
                .join("confluence-cql-report.json")
        })
}

fn declared_coverage(cases: &[CaseReport]) -> Vec<String> {
    cases
        .iter()
        .flat_map(|case| case.covers.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn required_coverage() -> Vec<String> {
    REQUIRED_COVERAGE
        .iter()
        .map(|tag| (*tag).to_string())
        .collect()
}

fn timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn process_failure_summary(reason: &str, output: &Output) -> String {
    format!(
        "{reason}; exitStatus={}; stdoutBytes={} stderrBytes={}",
        output
            .status
            .code()
            .map(|code| code.to_string())
            .unwrap_or_else(|| "terminated-by-signal".to_string()),
        output.stdout.len(),
        output.stderr.len()
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
