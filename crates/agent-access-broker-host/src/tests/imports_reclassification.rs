//! Reclassifying imported actions through the real router, store, runtime
//! publication and a fixture command import. Acceptance reports how it
//! changes each selected action's classification against the accepted state
//! and asks for confirmation when retained grants name a changed action.
//! Read-only identity paths see a reclassification in requests admitted
//! after it is published; a request admitted before is judged on its pinned
//! snapshot, and the import fences still refuse it before dispatch.
#![cfg(unix)]
use super::imports_command::{
    CommandFixture, assert_published_accept_result, definition, request, versions,
};
use super::imports_foundation::import_broker;
use super::mcp::{rpc_body, structured};
use super::*;
use agent_access_core::{
    BrokerTokenClass, IdentityTokenSettingsUpdate, ManagedPolicyGrantCreateRequest,
    TrustedCallerConfig, TrustedCallerContextMode, TrustedCallerCredentialTransport,
};
use sha2::{Digest, Sha256};

/// Records each subcommand in `$MARKER`, answers `describe` with
/// `$MANIFEST` and every other call with a fixed result.
const COMMAND: &str = r#"#!/bin/sh
echo "$1" >> "$MARKER"
if [ "$1" = describe ]; then cat "$MANIFEST"; exit 0; fi
cat > /dev/null
printf '{"ok":true,"result":{"served":true}}\n'
"#;
const RELAY: &str = "synthetic-reclassification-relay-0123";
const IDENTITY_TOKEN: &str = "5f0c6a8e-2d4b-4c1e-9a7f-3b8d2e6c1a90";
const CALLER: &str = "x-agent-access-caller-authorization";
const USER: &str = "x-agent-access-user";
const FINGERPRINT: &str = "x-aw-identity-token-sha256";
const READ_ONLY_DENIAL: &str = "identity access is read-only";
const IMPORT_FENCE_DENIAL: &str = "imported service changed or is unavailable; repeat discovery";

/// A manifest action. `read_only_hint` is the command's own hint, which
/// acceptance never uses to classify the action.
fn action(name: &str, read_only_hint: bool, property: Option<&str>) -> Value {
    let mut schema = json!({"type": "object", "additionalProperties": false});
    if let Some(property) = property {
        schema["properties"] = json!({property: {"type": "string"}});
    }
    json!({"name": name, "description": format!("The {name} action."),
        "readOnly": read_only_hint, "inputSchema": schema})
}

fn manifest(actions: Vec<Value>) -> Value {
    json!({"format": "agent-access-command/1", "version": "1.0.0", "actions": actions})
}

fn change(action: &str, from: Option<&str>, to: &str) -> Value {
    json!({"action": action, "from": from, "to": to})
}

fn class(read_only: bool) -> &'static str {
    if read_only { "read" } else { "write" }
}

async fn create(app: &Router, token: &str, service: &str) {
    let (status, created) = request(
        app,
        token,
        Method::POST,
        "/v1/admin/imports",
        Some(definition(service, service, &[])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
}

/// Runs discovery on the current record and returns its preview result.
async fn discover(app: &Router, token: &str, service: &str) -> Value {
    let path = format!("/v1/admin/imports/{service}");
    let (status, current) = request(app, token, Method::GET, &path, None).await;
    assert_eq!(status, StatusCode::OK, "{current}");
    let (status, discovered) = request(
        app,
        token,
        Method::POST,
        &format!("{path}/discover"),
        Some(versions(&current["result"])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{discovered}");
    discovered["result"].clone()
}

/// Accepts the discovered tools named by `selections`: the tool's source
/// name, the accepted action name when it differs, and `readOnly`.
async fn accept(
    app: &Router,
    token: &str,
    service: &str,
    discovered: &Value,
    selections: &[(&str, Option<&str>, bool)],
    confirm: bool,
) -> (StatusCode, Value) {
    let tools = discovered["preview"]["manifest"]["tools"]
        .as_array()
        .unwrap();
    let mut body = versions(discovered);
    body["manifestHash"] = discovered["preview"]["manifestHash"].clone();
    body["selections"] = json!(
        selections
            .iter()
            .map(|(source, name, read_only)| {
                let tool = tools
                    .iter()
                    .find(|tool| tool["definition"]["source"]["name"] == *source)
                    .unwrap_or_else(|| panic!("{source} was not discovered"));
                json!({"source": tool["definition"]["source"],
                    "action": name.unwrap_or(source), "readOnly": read_only})
            })
            .collect::<Vec<_>>()
    );
    body["confirmAffectedGrants"] = json!(confirm);
    request(
        app,
        token,
        Method::POST,
        &format!("/v1/admin/imports/{service}/accept"),
        Some(body),
    )
    .await
}

/// Sets the status of `service`, or of its `action`, confirming it.
async fn set_status(app: &Router, token: &str, service: &str, action: Option<&str>, status: &str) {
    let path = format!("/v1/admin/imports/{service}");
    let (code, current) = request(app, token, Method::GET, &path, None).await;
    assert_eq!(code, StatusCode::OK, "{current}");
    let mut body = versions(&current["result"]);
    body["status"] = json!(status);
    body["confirm"] = json!(true);
    let path = match action {
        Some(action) => format!("{path}/actions/{action}/status"),
        None => format!("{path}/status"),
    };
    let (code, changed) = request(app, token, Method::POST, &path, Some(body)).await;
    assert_eq!(code, StatusCode::OK, "{changed}");
}

fn grant(service: &str, actions: &[&str]) -> ManagedPolicyGrantCreateRequest {
    ManagedPolicyGrantCreateRequest {
        grant_id: Some(format!("{service}-alice")),
        subjects: vec!["user:alice".into()],
        execution_contexts: vec!["default".into()],
        service: service.into(),
        actions: actions.iter().map(|action| (*action).into()).collect(),
        resources: ResourceSelection::default(),
        credential_mode: "service".into(),
        priority: None,
        status: None,
        description: None,
        created_by: "admin".into(),
    }
}

fn assert_confirmation_refused(status: StatusCode, refused: &Value, changes: Value) {
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert_eq!(refused["reasonCode"], "input_invalid", "{refused}");
    assert!(
        refused["error"]["message"]
            .as_str()
            .unwrap()
            .contains("confirmAffectedGrants is required"),
        "{refused}"
    );
    assert_eq!(refused["target"]["classificationChanges"], changes);
}

fn assert_accepted(status: StatusCode, accepted: &Value, changes: Value) {
    assert_eq!(status, StatusCode::OK, "{accepted}");
    assert_published_accept_result(&accepted["result"]);
    assert_eq!(accepted["result"]["classificationChanges"], changes);
}

/// Item: acceptance computes each selected action's classification change
/// from the selections and the current accepted definition, whatever its
/// status, and never from the command's hints: added actions come from
/// `null`, unchanged, unselected and retired actions are omitted, and a
/// confirmation refusal reports the same list.
#[tokio::test]
async fn acceptance_reports_classification_changes_against_the_accepted_state() {
    let command = "ledger";
    let fixture = CommandFixture::with_script(
        command,
        &manifest(vec![
            action("entry.view", true, None),
            action("entry.list", true, None),
            action("entry.note", true, None),
        ]),
        COMMAND,
    );
    let admin = fixture.admin_token();
    let broker = import_broker(&fixture.config).await;
    let app = broker.app();
    create(&app, &admin, command).await;
    // Each acceptance reviews a fresh discovery of the current record.
    let reviewed = |selections: &'static [(&'static str, Option<&'static str>, bool)],
                    confirm: bool| {
        let (app, admin) = (app.clone(), admin.clone());
        async move {
            let discovered = discover(&app, &admin, command).await;
            accept(&app, &admin, command, &discovered, selections, confirm).await
        }
    };

    // Every action is new. The note is a write although the command hints
    // that it is a read.
    let (status, accepted) = reviewed(
        &[
            ("entry.view", None, true),
            ("entry.list", None, true),
            ("entry.note", None, false),
        ],
        false,
    )
    .await;
    assert_accepted(
        status,
        &accepted,
        json!([
            change("entry.list", None, "read"),
            change("entry.note", None, "write"),
            change("entry.view", None, "read"),
        ]),
    );
    // The preview has no selections, so it reports no changes.
    let (status, preview) = request(
        &app,
        &admin,
        Method::GET,
        "/v1/admin/imports/ledger/preview",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert!(preview["result"].get("classificationChanges").is_none());
    set_status(&app, &admin, command, None, "enabled").await;
    broker
        .runtime()
        .create_managed_policy_grant(grant(command, &["entry.view", "entry.note"]))
        .unwrap();

    // A granted read becomes a write: the unchanged note and the unselected
    // list are omitted.
    let selections = &[("entry.view", None, false), ("entry.note", None, false)];
    let expected = json!([change("entry.view", Some("read"), "write")]);
    let (status, refused) = reviewed(selections, false).await;
    assert_confirmation_refused(status, &refused, expected.clone());
    let (status, accepted) = reviewed(selections, true).await;
    assert_accepted(status, &accepted, expected);
    // And back.
    let (status, accepted) = reviewed(&[("entry.view", None, true)], true).await;
    assert_accepted(
        status,
        &accepted,
        json!([change("entry.view", Some("write"), "read")]),
    );
    // Accepting the same classifications needs no confirmation.
    let (status, accepted) = reviewed(
        &[("entry.view", None, true), ("entry.list", None, true)],
        false,
    )
    .await;
    assert_accepted(status, &accepted, json!([]));

    // A disabled action changes from its accepted classification. Restoring
    // it unchanged needs confirmation for its grant and reports nothing.
    set_status(&app, &admin, command, Some("entry.note"), "disabled").await;
    let (status, refused) = reviewed(&[("entry.note", None, true)], false).await;
    assert_confirmation_refused(
        status,
        &refused,
        json!([change("entry.note", Some("write"), "read")]),
    );
    let (status, refused) = reviewed(&[("entry.note", None, false)], false).await;
    assert_confirmation_refused(status, &refused, json!([]));
    let (status, accepted) = reviewed(&[("entry.note", None, false)], true).await;
    assert_accepted(status, &accepted, json!([]));

    // So does a quarantined one: a refresh that changes its schema
    // quarantines it.
    fixture.write_manifest(&manifest(vec![
        action("entry.view", true, Some("filter")),
        action("entry.list", true, None),
        action("entry.note", true, None),
    ]));
    let discovered = discover(&app, &admin, command).await;
    let view = discovered["service"]["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|action| action["definition"]["action"] == "entry.view")
        .unwrap();
    assert_eq!(view["status"], "quarantined", "{discovered}");
    let (status, refused) = reviewed(&[("entry.view", None, false)], false).await;
    assert_confirmation_refused(
        status,
        &refused,
        json!([change("entry.view", Some("read"), "write")]),
    );
    let (status, accepted) = reviewed(&[("entry.view", None, false)], true).await;
    assert_accepted(
        status,
        &accepted,
        json!([change("entry.view", Some("read"), "write")]),
    );

    // A retired action is not reclassified: accepting its source again adds
    // a new action, which no grant names yet.
    set_status(&app, &admin, command, Some("entry.note"), "retired").await;
    let (status, accepted) =
        reviewed(&[("entry.note", Some("entry.note-next"), true)], false).await;
    assert_accepted(
        status,
        &accepted,
        json!([change("entry.note-next", None, "read")]),
    );
    drop(app);
    broker.stop().await;
}

/// Which of alice's paths a request uses: both are read-only, and her
/// issued agent token keeps full access.
#[derive(Clone, Copy, Debug)]
enum Via {
    Username,
    Fingerprint,
}

/// A credential-free command import `service` whose `entry.view` alice is
/// granted, accepted as a read and enabled.
struct Paths {
    fixture: CommandFixture,
    broker: TestBroker,
    app: Router,
    admin: String,
    agent: String,
    fingerprint: String,
    service: &'static str,
}

impl Paths {
    async fn new(service: &'static str) -> Self {
        let mut fixture = CommandFixture::with_script(
            service,
            &manifest(vec![action("entry.view", true, None)]),
            COMMAND,
        );
        let relay = fixture.path("relay");
        std::fs::write(&relay, RELAY).unwrap();
        fixture.config.identity.trusted_callers.insert(
            "relay".into(),
            TrustedCallerConfig {
                credential_ref: format!("file:{}", relay.display()),
                credential_transport: TrustedCallerCredentialTransport::CallerAuthorization,
                username_namespace: Some("linux".into()),
                context_mode: TrustedCallerContextMode::Fixed,
                execution_context: Some("default".into()),
                allowed_execution_contexts: None,
                allow_forwarded_identity: true,
            },
        );
        fixture.config.mcp.enabled = true;
        fixture.config.mcp.public_url = Some("https://broker.example.test/mcp".into());
        let store = fixture.imports.runtime.managed_store().unwrap();
        let ring = fixture.imports.runtime.credential_key_ring().unwrap();
        store
            .create_username_binding("alice", "linux", "alice", true, "fixture")
            .unwrap();
        let token = store
            .set_identity_token("alice", IDENTITY_TOKEN, ring)
            .unwrap();
        store
            .update_identity_token_settings(
                "alice",
                IdentityTokenSettingsUpdate {
                    enabled: None,
                    read_only: Some(true),
                },
                token.revision,
            )
            .unwrap();
        let fingerprint = format!("sha256:{:x}", Sha256::digest(IDENTITY_TOKEN.as_bytes()));
        let admin = fixture.admin_token();
        let agent = fixture.issue(
            "alice",
            BrokerTokenClass::AgentInvoke,
            json!({"allowedServices": [service], "allowedExecutionContexts": ["default"]}),
        );
        let broker = import_broker(&fixture.config).await;
        let app = broker.app();
        create(&app, &admin, service).await;
        let discovered = discover(&app, &admin, service).await;
        let (code, _) = accept(
            &app,
            &admin,
            service,
            &discovered,
            &[("entry.view", None, true)],
            false,
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        set_status(&app, &admin, service, None, "enabled").await;
        broker
            .runtime()
            .create_managed_policy_grant(grant(service, &["entry.view"]))
            .unwrap();
        Self {
            fixture,
            broker,
            app,
            admin,
            agent,
            fingerprint,
            service,
        }
    }

    fn tool(&self) -> String {
        agent_access_core::mcp::tool_name(self.service, "entry.view")
    }

    /// The import's current preview, for [`Self::publish`].
    async fn discover(&self) -> Value {
        discover(&self.app, &self.admin, self.service).await
    }

    /// Accepts `entry.view` from `discovered` as `read_only`, confirming its
    /// grant, which publishes the reclassification.
    async fn publish(&self, discovered: &Value, read_only: bool) {
        let (code, accepted) = accept(
            &self.app,
            &self.admin,
            self.service,
            discovered,
            &[("entry.view", None, read_only)],
            true,
        )
        .await;
        assert_accepted(
            code,
            &accepted,
            json!([change(
                "entry.view",
                Some(class(!read_only)),
                class(read_only)
            )]),
        );
    }

    async fn reclassify(&self, read_only: bool) {
        let discovered = self.discover().await;
        self.publish(&discovered, read_only).await;
    }

    fn mcp_request(&self, via: Via, session: Option<&str>, message: Value) -> Request<Body> {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .extension(ConnectInfo(
                "127.0.0.1:47200".parse::<SocketAddr>().unwrap(),
            ))
            .header("host", "broker.example.test")
            .header(ACCEPT, "application/json, text/event-stream")
            .header(CONTENT_TYPE, "application/json")
            .header(CALLER, format!("Bearer {RELAY}"));
        builder = match via {
            Via::Username => builder.header(USER, "alice"),
            Via::Fingerprint => builder.header(FINGERPRINT, &self.fingerprint),
        };
        if let Some(session) = session {
            builder = builder
                .header("mcp-session-id", session)
                .header("mcp-protocol-version", "2025-11-25");
        }
        builder.body(Body::from(message.to_string())).unwrap()
    }

    async fn send(&self, request: Request<Body>) -> axum::response::Response {
        tokio::time::timeout(Duration::from_secs(10), self.app.clone().oneshot(request))
            .await
            .expect("request timed out")
            .unwrap()
    }

    async fn initialize(&self, via: Via) -> String {
        let response = self
            .send(self.mcp_request(
                via,
                None,
                json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                    "protocolVersion":"2025-11-25","capabilities":{},
                    "clientInfo":{"name":"imports-reclassification","version":"1"}
                }}),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::OK, "{via:?}");
        let session = response.headers()["mcp-session-id"]
            .to_str()
            .unwrap()
            .to_owned();
        rpc_body(response).await;
        let initialized = self
            .send(self.mcp_request(
                via,
                Some(&session),
                json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            ))
            .await;
        assert_eq!(initialized.status(), StatusCode::ACCEPTED);
        session
    }

    async fn rpc(&self, via: Via, session: &str, method: &str, params: Value) -> Value {
        let response = self
            .send(self.mcp_request(
                via,
                Some(session),
                json!({"jsonrpc":"2.0","id":2,"method":method,"params":params}),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::OK, "{method}");
        rpc_body(response).await
    }

    fn call_message(&self) -> Value {
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
            "params":{"name": self.tool(), "arguments": {"inputs": {}}}})
    }

    async fn listed(&self, via: Via, session: &str) -> bool {
        let listing = self.rpc(via, session, "tools/list", json!({})).await;
        let tool = self.tool();
        listing["result"]["tools"]
            .as_array()
            .unwrap_or_else(|| panic!("{listing}"))
            .iter()
            .any(|entry| entry["name"] == tool.as_str())
    }

    async fn call(&self, via: Via, session: &str) -> Value {
        let tool = self.tool();
        self.rpc(
            via,
            session,
            "tools/call",
            json!({"name": tool, "arguments": {"inputs": {}}}),
        )
        .await
    }

    /// Starts a call of `entry.view` that a test barrier can hold; the
    /// handle yields its response.
    fn spawn_call(
        &self,
        via: Via,
        session: &str,
    ) -> tokio::task::JoinHandle<axum::response::Response> {
        let request = self.mcp_request(via, Some(session), self.call_message());
        let app = self.app.clone();
        tokio::spawn(async move { app.oneshot(request).await.unwrap() })
    }

    async fn invoke(&self, headers: &[(&str, String)]) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(format!("/v1/invoke/{}/entry.view", self.service))
            .extension(ConnectInfo(
                "127.0.0.1:47201".parse::<SocketAddr>().unwrap(),
            ))
            .header(REQUEST_ID_HEADER, "imports-reclassification")
            .header(CONTENT_TYPE, "application/json");
        for (name, value) in headers {
            builder = builder.header(*name, value);
        }
        let response = self
            .send(
                builder
                    .body(Body::from(json!({"inputs": {}}).to_string()))
                    .unwrap(),
            )
            .await;
        let status = response.status();
        (status, response_json(response).await)
    }

    fn fingerprint_headers(&self) -> Vec<(&'static str, String)> {
        vec![
            (CALLER, format!("Bearer {RELAY}")),
            (FINGERPRINT, self.fingerprint.clone()),
        ]
    }

    fn agent_headers(&self) -> Vec<(&'static str, String)> {
        vec![(AUTHORIZATION.as_str(), format!("Bearer {}", self.agent))]
    }

    /// How many times the command ran `invoke`.
    fn invocations(&self) -> usize {
        self.fixture
            .runs()
            .iter()
            .filter(|run| *run == "invoke")
            .count()
    }
}

fn assert_hidden(called: &Value) {
    assert_eq!(called["error"]["code"], -32602, "{called}");
    assert!(
        called["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("Unknown or unavailable HTTP MCP tool"),
        "{called}"
    );
}

/// Releases a held pre-protocol barrier if the test fails while holding it.
struct ReleaseOnDrop(Arc<crate::state::McpBlockingBarrier>);
impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

/// Item: a reclassification reaches read-only identity paths with the next
/// request admitted after it is published, in both directions. A read made
/// a write leaves their lists and is refused, by MCP registry resolution and
/// by the REST read-only check; a write made a read is listed and runs.
/// Existing sessions follow the publication, and full access is unchanged.
#[tokio::test]
async fn reclassification_reaches_read_only_paths_from_the_next_request() {
    let paths = Paths::new("reclassed").await;
    let sessions = [
        (Via::Username, paths.initialize(Via::Username).await),
        (Via::Fingerprint, paths.initialize(Via::Fingerprint).await),
    ];
    let mut runs = 0;
    // Accepted as a read, then made a write and a read again.
    for (step, read_only) in [true, false, true].into_iter().enumerate() {
        if step > 0 {
            paths.reclassify(read_only).await;
        }
        let case = format!("readOnly={read_only}");
        for (via, session) in &sessions {
            assert_eq!(
                paths.listed(*via, session).await,
                read_only,
                "{case} {via:?}"
            );
            let called = paths.call(*via, session).await;
            if read_only {
                assert_eq!(
                    structured(&called)["decision"],
                    "allow",
                    "{case} {via:?}: {called}"
                );
                runs += 1;
            } else {
                assert_hidden(&called);
            }
        }
        let (status, body) = paths.invoke(&paths.fingerprint_headers()).await;
        if read_only {
            assert_eq!(status, StatusCode::OK, "{case}: {body}");
            runs += 1;
        } else {
            assert_eq!(status, StatusCode::FORBIDDEN, "{case}: {body}");
            assert_eq!(body["reasonCode"], "service_action_denied", "{body}");
            assert_eq!(body["reason"], READ_ONLY_DENIAL, "{body}");
        }
        let (status, body) = paths.invoke(&paths.agent_headers()).await;
        assert_eq!(status, StatusCode::OK, "{case}: {body}");
        runs += 1;
        assert_eq!(paths.invocations(), runs, "{case}");
    }
    let records = read_audit_records(Path::new(
        &paths.fixture.config.audit.as_ref().unwrap().path,
    ));
    let denials = records
        .iter()
        .filter(|record| {
            record["service"] == "reclassed"
                && record["providerAudit"]["identityAccess"]["readOnly"] == true
        })
        .count();
    assert_eq!(denials, 1);
    drop(paths.app);
    paths.broker.stop().await;
}

/// Item: a request admitted before a reclassification is published is
/// judged on the snapshot it was admitted with. Registry resolution, the
/// read-only check and dispatch each use that snapshot, and the existing
/// import fences still refuse a call whose import changed after admission,
/// with their own denial rather than the read-only one.
#[tokio::test]
async fn requests_admitted_before_a_reclassification_keep_their_snapshot() {
    let paths = Paths::new("pinned").await;
    let state = paths.broker.state();
    let session = paths.initialize(Via::Username).await;

    // Registry resolution: admitted while the action is a write, a call is
    // held before its tool resolves, and a publication makes the action a
    // read. The call resolves on its snapshot, where the tool is hidden.
    paths.reclassify(false).await;
    let discovered = paths.discover().await;
    let barrier = Arc::new(crate::state::McpBlockingBarrier::default());
    let _release = ReleaseOnDrop(barrier.clone());
    *state.mcp_preprotocol_barrier.lock().unwrap() =
        Some((crate::mcp::PreProtocolPhase::Identity, barrier.clone()));
    let pending = paths.spawn_call(Via::Username, &session);
    tokio::time::timeout(Duration::from_secs(10), barrier.reached.notified())
        .await
        .unwrap();
    paths.publish(&discovered, true).await;
    barrier.release();
    let response = tokio::time::timeout(Duration::from_secs(10), pending)
        .await
        .unwrap()
        .unwrap();
    assert_hidden(&rpc_body(response).await);
    assert_eq!(paths.invocations(), 0);
    // The next call is admitted on the published snapshot and runs.
    let called = paths.call(Via::Username, &session).await;
    assert_eq!(structured(&called)["decision"], "allow", "{called}");
    assert_eq!(paths.invocations(), 1);

    // The read-only check: admitted while the action is a read, a call is
    // held after its tool resolved, and a publication makes the action a
    // write. The read-only check of its snapshot passes; that snapshot's
    // import is fenced, so no grant applies and nothing runs.
    let discovered = paths.discover().await;
    let barrier = Arc::new(crate::state::McpAdmissionBarrier {
        reached: tokio::sync::Notify::new(),
        release: tokio::sync::Semaphore::new(0),
    });
    *state.mcp_admission_barrier.lock().unwrap() = Some(barrier.clone());
    let pending = paths.spawn_call(Via::Username, &session);
    tokio::time::timeout(Duration::from_secs(10), barrier.reached.notified())
        .await
        .unwrap();
    paths.publish(&discovered, false).await;
    barrier.release.add_permits(1);
    let response = tokio::time::timeout(Duration::from_secs(10), pending)
        .await
        .unwrap()
        .unwrap();
    let called = rpc_body(response).await;
    let envelope = structured(&called);
    assert_eq!(envelope["decision"], "deny", "{called}");
    assert_eq!(envelope["reasonCode"], "service_action_denied", "{called}");
    assert_eq!(
        envelope["reason"], "policy denied command action",
        "{called}"
    );
    assert_eq!(paths.invocations(), 1);
    // The next call is admitted on the published snapshot, which hides it.
    assert_hidden(&paths.call(Via::Username, &session).await);

    // Dispatch: admitted while the action is a read, a call is held after
    // its request was built, and a publication makes the action a write.
    // The dispatch fence refuses it before the command starts.
    paths.reclassify(true).await;
    let discovered = paths.discover().await;
    let pause = agent_access_core::test_support::CommandDispatchPause::new("pinned");
    let pending = paths.spawn_call(Via::Username, &session);
    tokio::time::timeout(Duration::from_secs(10), pause.reached())
        .await
        .unwrap();
    paths.publish(&discovered, false).await;
    pause.release();
    let response = tokio::time::timeout(Duration::from_secs(10), pending)
        .await
        .unwrap()
        .unwrap();
    let called = rpc_body(response).await;
    let envelope = structured(&called);
    assert_eq!(envelope["decision"], "deny", "{called}");
    assert_eq!(envelope["reasonCode"], "service_action_denied", "{called}");
    assert_eq!(envelope["reason"], IMPORT_FENCE_DENIAL, "{called}");
    drop(pause);
    assert_eq!(paths.invocations(), 1);
    assert_hidden(&paths.call(Via::Username, &session).await);

    // None of the refused calls was judged read-only.
    let records = read_audit_records(Path::new(
        &paths.fixture.config.audit.as_ref().unwrap().path,
    ));
    assert!(
        records
            .iter()
            .filter(|record| record["service"] == "pinned")
            .all(|record| record["providerAudit"].get("identityAccess").is_none()),
        "{records:?}"
    );
    drop((state, paths.app));
    paths.broker.stop().await;
}
