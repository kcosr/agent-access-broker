//! A real process and persisted accepted declarations through the shipped CLI.
use super::*;
use std::os::unix::fs::PermissionsExt;

const INPUT_SECRET: &str = "AUDIT_INPUT_SECRET_CANARY";
const BODY: &str = "AUDIT_BODY_CANARY";
const OUTPUT: &str = "AUDIT_PROCESS_OUTPUT_CANARY";

fn declaration() -> Value {
    json!([
        {"key":"query","label":"Requested query","pointer":"/query","capture":"value",
         "shape":"scalar","kind":"query","maxBytes":4096,"overflow":"prefix","display":"primary","role":"fact"},
        {"key":"body","label":"Body supplied","pointer":"/body","capture":"presence",
         "kind":"boolean","display":"detail","role":"change"},
        {"key":"secret","pointer":"/secret","capture":"omit"}
    ])
}

fn manifest(rules: Option<Value>) -> Value {
    let mut action = json!({"name":"issue.search","description":"Search synthetic records.",
        "readOnly":true,"inputSchema":{"type":"object","required":["query"],"properties":{
            "query":{"type":"string"},"body":{"type":"string"},
            "secret":{"type":"string","x-agent-access-sensitive":true}},"additionalProperties":false}});
    if let Some(rules) = rules {
        action["auditInputs"] = rules;
    }
    json!({"format":"agent-access-command/1","version":"1.0.0",
        "credential":{"kind":"token","modes":["service"]},"actions":[action]})
}

fn discover(admin: &Path) -> Value {
    let current = run(admin, &["admin", "imports", "get", "ticketing"]);
    let (version, revision) = versions(&current);
    run(
        admin,
        &[
            "admin",
            "imports",
            "discover",
            "ticketing",
            "--expected-version",
            &version,
            "--expected-catalog-revision",
            &revision,
        ],
    )
}

fn acceptance(discovered: &Value) -> Value {
    let (version, revision) = versions(discovered);
    json!({"expectedVersion":version.parse::<u64>().unwrap(),
        "expectedCatalogRevision":revision.parse::<u64>().unwrap(),
        "manifestHash":discovered["result"]["preview"]["manifestHash"],
        "selections":[{"source":{"name":"issue.search"},"action":"issue.search","readOnly":true}],
        "confirmAffectedGrants":true})
}

fn accept(admin: &Path, files: &Path, request: Value) -> Value {
    run(
        admin,
        &[
            "admin",
            "imports",
            "accept",
            "ticketing",
            "--request-file",
            &write_file(files, "accept-audit.json", request.to_string()),
        ],
    )
}

fn snapshot(files: &Path, response: &Value) -> Value {
    let records = audited(files, response["brokerRequestId"].as_str().unwrap());
    assert_eq!(records.len(), 1, "{records:?}");
    records[0]["requestAudit"].clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reviewed_inputs_survive_command_failures_and_refresh_requires_new_acceptance() {
    let application = IsolatedBroker::new(
        agent_access_broker::composition().unwrap(),
        agent_access_broker::build_identity(),
    )
    .unwrap();
    let directory = application.directory().clone();
    let files = directory.path();
    let base = application.public_url();
    directory
        .secret_file("key", URL_SAFE_NO_PAD.encode([71u8; 32]))
        .unwrap();
    let hash = directory
        .secret_file("hash", URL_SAFE_NO_PAD.encode([72u8; 32]))
        .unwrap();
    let seeded = seed(&directory, &hash);
    let admin = client_config(files, "admin", &base, &seeded.admin);
    let agent = client_config(files, "agent", &base, &seeded.agent);
    let command = write_file(
        files,
        "audit-inputs.sh",
        include_str!("../fixtures/command-imports/audit-inputs.sh"),
    );
    std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o700)).unwrap();
    let original = manifest(Some(declaration()));
    write_file(files, "manifest.json", original.to_string());
    write_file(
        files,
        "response.json",
        json!({"ok":true,"result":{"requestAudit":OUTPUT}}).to_string(),
    );
    let config = broker_document(&directory, &format!("{base}/mcp"))
        .replace(
            &toml_string(reference_command().display()),
            &toml_string(&command),
        )
        .replace(
            &format!(
                "TICKETING_PROFILE_FILE = {}",
                toml_string(files.join("profile").display())
            ),
            &format!(
                "MANIFEST = {}\nRESPONSE = {}\nREQUEST = {}",
                toml_string(files.join("manifest.json").display()),
                toml_string(files.join("response.json").display()),
                toml_string(files.join("request.json").display())
            ),
        );
    let broker = application.config_document(config).start().await.unwrap();
    run(
        &admin,
        &[
            "admin",
            "imports",
            "create",
            "--request-file",
            &write_file(
                files,
                "create-audit.json",
                json!({"service":"ticketing","displayName":"Audit fixture","adapterKind":"command",
            "endpoint":"command:ticketing","executionBindings":[{"ownerMode":"service",
                "mechanism":"static_token","delivery":{"kind":"stdin"},"status":"configured"}],
            "discovery":{"kind":"anonymous"}})
                .to_string(),
            ),
        ],
    );
    let discovered = discover(&admin);
    let metadata = &discovered["result"]["preview"]["manifest"]["tools"][0];
    assert!(metadata["unsupportedReason"].is_null(), "{metadata}");
    assert_eq!(
        metadata["definition"]["annotations"]["command"]["auditInputs"],
        declaration()
    );
    let accepted = accept(&admin, files, acceptance(&discovered));
    let (version, revision) = versions(&accepted);
    let configured = run(
        &admin,
        &[
            "admin",
            "imports",
            "credentials",
            "put",
            "ticketing",
            "execution",
            "--expected-version",
            &version,
            "--expected-catalog-revision",
            &revision,
            "--secret-file",
            &write_file(files, "service.token", SERVICE_TOKEN),
        ],
    );
    let (version, revision) = versions(&configured);
    run(
        &admin,
        &[
            "admin",
            "imports",
            "status",
            "ticketing",
            "enabled",
            "--expected-version",
            &version,
            "--expected-catalog-revision",
            &revision,
        ],
    );
    run(
        &admin,
        &[
            "admin",
            "policy",
            "grants",
            "create",
            "--grant-id",
            "audit-command",
            "--subject",
            "user:avery",
            "--service",
            "ticketing",
            "--credential-mode",
            "service",
            "--execution-context",
            "default",
            "--action",
            "issue.search",
        ],
    );
    let inputs = json!({"query":"requested audit phrase","body":BODY,"secret":INPUT_SECRET});
    let result = invoke(&agent, "issue.search", inputs.clone());
    assert_eq!(result["result"]["upstreamCommand"]["requestAudit"], OUTPUT);
    let request_audit = snapshot(files, &result);
    assert_eq!(request_audit["version"], 1);
    assert_eq!(
        request_audit["fields"][0]["value"],
        "requested audit phrase"
    );
    assert_eq!(request_audit["fields"][1]["value"], true);
    assert_eq!(request_audit["fields"].as_array().unwrap().len(), 2);
    let stdin = std::fs::read_to_string(files.join("request.json")).unwrap();
    assert!(stdin.contains(SERVICE_TOKEN));
    assert!(stdin.contains(BODY));
    assert!(stdin.contains(INPUT_SECRET));
    for canary in [SERVICE_TOKEN, BODY, INPUT_SECRET, OUTPUT] {
        assert!(
            !request_audit.to_string().contains(canary),
            "{canary} leaked"
        );
        assert!(!metadata.to_string().contains(canary));
    }
    // The process cannot overwrite core-owned input audit, including a failure.
    write_file(
        files,
        "response.json",
        json!({"ok":false,"error":{"code":"upstream_failed","message":"Synthetic failure."}})
            .to_string(),
    );
    let failure = run_failing(
        &agent,
        &[
            "invoke",
            "ticketing.issue.search",
            "--input-json",
            &inputs.to_string(),
        ],
    );
    assert_eq!(snapshot(files, &failure), request_audit);
    write_file(files, "response.json.signal", "");
    let terminated = run_failing(
        &agent,
        &[
            "invoke",
            "ticketing.issue.search",
            "--input-json",
            &inputs.to_string(),
        ],
    );
    assert_eq!(snapshot(files, &terminated), request_audit);
    std::fs::remove_file(files.join("response.json.signal")).unwrap();
    write_file(
        files,
        "response.json",
        json!({"ok":true,"result":{}}).to_string(),
    );

    // A failed whole-manifest discovery must not quarantine or alter acceptance.
    let before = run(&admin, &["admin", "imports", "get", "ticketing"]);
    write_file(files, "manifest.json", "{invalid");
    // Reload builds from stored accepted metadata without rerunning describe.
    broker.reload().await.unwrap();
    assert_eq!(
        snapshot(files, &invoke(&agent, "issue.search", inputs.clone())),
        request_audit
    );
    let (version, revision) = versions(&before);
    run_failing(
        &admin,
        &[
            "admin",
            "imports",
            "discover",
            "ticketing",
            "--expected-version",
            &version,
            "--expected-catalog-revision",
            &revision,
        ],
    );
    let after = run(&admin, &["admin", "imports", "get", "ticketing"]);
    assert_eq!(
        after["result"]["service"]["actions"],
        before["result"]["service"]["actions"]
    );
    assert_eq!(
        snapshot(files, &invoke(&agent, "issue.search", inputs.clone())),
        request_audit
    );

    // Identical metadata preserves behavior; a label-only edit requires review.
    write_file(files, "manifest.json", original.to_string());
    let identical = discover(&admin);
    assert_eq!(
        identical["result"]["preview"]["manifestHash"],
        discovered["result"]["preview"]["manifestHash"]
    );
    assert_eq!(
        identical["result"]["service"]["actions"][0]["status"],
        "enabled"
    );
    let stale = acceptance(&identical);
    let mut revised = original.clone();
    revised["actions"][0]["auditInputs"][0]["label"] = json!("Requested search text");
    write_file(files, "manifest.json", revised.to_string());
    let changed = discover(&admin);
    assert_ne!(
        changed["result"]["preview"]["manifestHash"],
        identical["result"]["preview"]["manifestHash"]
    );
    assert_eq!(
        changed["result"]["service"]["actions"][0]["status"],
        "quarantined"
    );
    assert_eq!(
        changed["result"]["affectedGrantsByAction"]["issue.search"],
        json!(["audit-command"])
    );
    run_failing(
        &agent,
        &[
            "invoke",
            "ticketing.issue.search",
            "--input-json",
            &inputs.to_string(),
        ],
    );
    run_failing(
        &admin,
        &[
            "admin",
            "imports",
            "accept",
            "ticketing",
            "--request-file",
            &write_file(files, "stale-audit.json", stale.to_string()),
        ],
    );
    let mut replaced = acceptance(&changed);
    replaced["selections"][0]["auditInputs"] = declaration();
    run_failing(
        &admin,
        &[
            "admin",
            "imports",
            "accept",
            "ticketing",
            "--request-file",
            &write_file(files, "replacement-audit.json", replaced.to_string()),
        ],
    );
    let mut unconfirmed = acceptance(&changed);
    unconfirmed["confirmAffectedGrants"] = json!(false);
    let rejected = run_failing(
        &admin,
        &[
            "admin",
            "imports",
            "accept",
            "ticketing",
            "--request-file",
            &write_file(files, "unconfirmed-audit.json", unconfirmed.to_string()),
        ],
    );
    assert!(rejected.to_string().contains("confirmAffectedGrants"));
    accept(&admin, files, acceptance(&changed));
    let revised_audit = snapshot(files, &invoke(&agent, "issue.search", inputs.clone()));
    assert_eq!(revised_audit["fields"][0]["label"], "Requested search text");
    assert_ne!(
        revised_audit["declarationSha256"],
        request_audit["declarationSha256"]
    );

    // A malformed per-action declaration remains visible and quarantines it.
    revised["actions"][0]["auditInputs"][0]["pointer"] = json!("/secret");
    write_file(files, "manifest.json", revised.to_string());
    let unsupported = discover(&admin);
    assert!(
        unsupported["result"]["preview"]["manifest"]["tools"][0]["unsupportedReason"].is_string()
    );
    assert_eq!(
        unsupported["result"]["service"]["actions"][0]["status"],
        "quarantined"
    );
    run_failing(
        &admin,
        &[
            "admin",
            "imports",
            "accept",
            "ticketing",
            "--request-file",
            &write_file(
                files,
                "invalid-audit.json",
                acceptance(&unsupported).to_string(),
            ),
        ],
    );

    // Removing the declaration is another behavior change. Reaccepting it uses
    // the historical absent shape and emits no input snapshot.
    write_file(files, "manifest.json", manifest(None).to_string());
    let removed = discover(&admin);
    accept(&admin, files, acceptance(&removed));
    assert!(snapshot(files, &invoke(&agent, "issue.search", inputs)).is_null());
    stop(broker).await;
    let audit = std::fs::read_to_string(files.join("audit.jsonl")).unwrap();
    for canary in [SERVICE_TOKEN, BODY, INPUT_SECRET, OUTPUT] {
        assert!(
            !audit.contains(canary),
            "{canary} leaked into complete audit"
        );
    }
}
