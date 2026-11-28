//! `POST /v1/access-keys/resolve` through the production router: the shared wire
//! fixtures, caller authentication and capability, forbidden headers, the
//! route's own admission and its body bound.

use super::*;
use agent_access_core::{
    AccessKeyTypeConfig, AdministratorAccessKeyRequest, PortalAccessKeyRequest,
    TrustedCallerConfig, TrustedCallerContextMode,
};

const CALLER_HEADER: &str = "x-agent-access-caller-authorization";
const RESOLVER: &str = "Bearer resolver-caller-credential-0123456789";
const OTHER_CALLER: &str = "Bearer other-caller-credential-0123456789";
const UNKNOWN_TOKEN: &str = "aab_ak_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
/// The description of the configured type, which people read when they
/// create a key and which a resolution never returns.
const TYPE_DESCRIPTION: &str = "Point your tool at https://gateway.example.com/v1.";

/// The vendored copy of the fixtures shared with the resolving service.
fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/access-key-resolution")
}

fn fixture_bytes(name: &str) -> Vec<u8> {
    std::fs::read(fixture_dir().join(name)).unwrap()
}

fn fixture_json(name: &str) -> Value {
    serde_json::from_slice(&fixture_bytes(name)).unwrap()
}

struct Resolver {
    fixture: BrowserRateFixture,
    store: agent_access_core::ManagedStore,
    /// Alice's portal token and the service account's administrator token.
    alice: agent_access_core::IssuedAccessKey,
    robot: agent_access_core::IssuedAccessKey,
}

fn caller(path: &Path, allow_access_key_resolution: bool) -> TrustedCallerConfig {
    TrustedCallerConfig {
        credential_ref: format!("file:{}", path.display()),
        credential_transport: Default::default(),
        username_namespace: None,
        context_mode: TrustedCallerContextMode::Fixed,
        execution_context: Some("default".to_string()),
        allowed_execution_contexts: None,
        allow_forwarded_identity: false,
        allow_access_key_resolution,
    }
}

async fn resolver_with(limits: LimitsConfig) -> Resolver {
    resolver_configured(limits, |_| {}).await
}

/// [`resolver_with`], with a last change to the configuration the Broker
/// starts with.
async fn resolver_configured(
    mut limits: LimitsConfig,
    configure: impl FnOnce(&mut BrokerConfig),
) -> Resolver {
    // A test that shrinks the pool and names no share gives the one
    // resolving caller the whole pool, as a configuration must say.
    limits.max_concurrent_access_key_resolutions_per_caller = limits
        .max_concurrent_access_key_resolutions_per_caller
        .min(limits.max_concurrent_access_key_resolutions);
    let resolver_secret = temp_path("access-key-resolver-caller");
    let other_secret = temp_path("access-key-other-caller");
    std::fs::write(&resolver_secret, RESOLVER.strip_prefix("Bearer ").unwrap()).unwrap();
    std::fs::write(&other_secret, OTHER_CALLER.strip_prefix("Bearer ").unwrap()).unwrap();
    let fixture = browser_rate_fixture_with(limits, |config| {
        config
            .identity
            .trusted_callers
            .insert("proxy".to_string(), caller(&resolver_secret, true));
        config
            .identity
            .trusted_callers
            .insert("other".to_string(), caller(&other_secret, false));
        config.access_key_types.insert(
            "inference".to_string(),
            AccessKeyTypeConfig {
                display_name: "Model inference".to_string(),
                // A type with a description: no answer may carry it.
                description: Some(TYPE_DESCRIPTION.to_string()),
                lifetime_options: vec!["1s".into(), "1h".into(), "30d".into()],
                default_lifetime: "30d".into(),
                self_service: true,
            },
        );
        configure(config);
    })
    .await;
    let runtime = fixture.state.current().runtime.clone();
    let store = runtime.managed_store().unwrap().clone();
    let hasher = runtime.broker_token_hasher().unwrap().clone();
    let contexts = agent_access_core::ConfiguredExecutionContexts::from_config(None).unwrap();
    store
        .create_principal(
            agent_access_core::PrincipalWriteRequest {
                agent_token_issuance: Default::default(),
                role: agent_access_core::PrincipalRole::User,
                self_service_enabled: Some(false),
                principal_id: "robot".to_string(),
                kind: "service_account".to_string(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".to_string(),
            },
            &contexts,
        )
        .unwrap();
    store
        .create_group(
            agent_access_core::GroupWriteRequest {
                group_id: "platform".to_string(),
                display_name: None,
                description: None,
                auto_enroll_new_microsoft_users: false,
                agent_token_issuance: Default::default(),
                created_by: "admin".to_string(),
            },
            &contexts,
        )
        .unwrap();
    store.add_group("alice", "platform", "admin").unwrap();
    store
        .set_account_username("alice", "alice", "admin")
        .unwrap()
        .unwrap();
    // Both accounts may hold the one configured type, by their own setting.
    for principal in ["alice", "robot"] {
        allow_access_key_types(&store, &runtime, principal, &["inference"]);
    }
    let session = store
        .list_broker_tokens_for_principal("alice")
        .unwrap()
        .into_iter()
        .find(|token| {
            store
                .broker_token_is_browser_session(&token.token_id)
                .unwrap()
        })
        .unwrap()
        .token_id;
    let alice = store
        .mint_portal_access_key(
            &hasher,
            runtime.access_key_types(),
            &PortalAccessKeyRequest {
                principal_id: "alice".to_string(),
                session_token_id: session,
                name: "laptop".to_string(),
                access_key_types: vec!["inference".to_string()],
                lifetime: "3600s".into(),
            },
        )
        .unwrap()
        .unwrap();
    let robot = store
        .mint_administrator_access_key(
            &hasher,
            runtime.access_key_types(),
            &AdministratorAccessKeyRequest {
                principal_id: "robot".to_string(),
                name: "nightly job".to_string(),
                access_key_types: vec!["inference".to_string()],
                lifetime: "3600s".into(),
                created_by: "admin".to_string(),
            },
        )
        .unwrap()
        .unwrap();
    Resolver {
        fixture,
        store,
        alice,
        robot,
    }
}

async fn resolver() -> Resolver {
    resolver_with(test_limits()).await
}

/// Sets `principal`'s access key type setting to allow exactly `access_key_types`.
pub(super) fn allow_access_key_types(
    store: &agent_access_core::ManagedStore,
    runtime: &agent_access_core::BrokerRuntime,
    principal: &str,
    access_key_types: &[&str],
) {
    let setting = agent_access_core::PrincipalAccessKeyTypes::new(
        access_key_types
            .iter()
            .map(|id| (*id).to_string())
            .collect(),
        Vec::new(),
    )
    .unwrap();
    store
        .patch_principal_access_with_access_key_types(
            agent_access_core::PrincipalAccessPatchRequest {
                agent_token_issuance: None,
                principal_id: principal.to_string(),
                role: None,
                self_service_enabled: None,
                actor: "admin".to_string(),
            },
            Some(agent_access_core::AccessKeyTypesWrite {
                setting: &setting,
                configured: runtime.access_key_types(),
            }),
            &agent_access_core::ConfiguredExecutionContexts::from_config(None).unwrap(),
        )
        .unwrap();
}

fn resolve_request(
    request_id: &str,
    headers: &[(&str, &str)],
    body: impl Into<Body>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri("/v1/access-keys/resolve")
        .extension(ConnectInfo(
            "127.0.0.1:43120".parse::<SocketAddr>().unwrap(),
        ))
        .header(REQUEST_ID_HEADER, request_id)
        .header(CONTENT_TYPE, "application/json");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(body.into()).unwrap()
}

impl Resolver {
    /// A resolution by the caller that has the capability.
    async fn resolve_raw(&self, request_id: &str, body: impl Into<Body>) -> (StatusCode, Vec<u8>) {
        self.send(resolve_request(
            request_id,
            &[(CALLER_HEADER, RESOLVER)],
            body,
        ))
        .await
    }

    async fn send(&self, request: Request<Body>) -> (StatusCode, Vec<u8>) {
        let response = self.fixture.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        assert_eq!(
            response.headers().get(axum::http::header::CACHE_CONTROL),
            Some(&axum::http::HeaderValue::from_static("no-store"))
        );
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        (status, bytes.to_vec())
    }

    async fn resolve(&self, request_id: &str, token: &str) -> (StatusCode, Value) {
        let (status, bytes) = self
            .resolve_raw(request_id, json!({"key": token}).to_string())
            .await;
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    /// Every audit record of `request_id`, whatever its action.
    fn records(&self, request_id: &str) -> Vec<Value> {
        read_audit_records(&self.fixture.audit_path)
            .into_iter()
            .filter(|record| record["agentRequestId"] == request_id)
            .collect()
    }

    /// A resolution's status and reason code; `active` or `inactive` for an
    /// answer.
    async fn outcome(&self, request_id: &str, key: &str) -> (StatusCode, String) {
        let (status, answer) = self.resolve(request_id, key).await;
        let what = match answer.get("active") {
            Some(Value::Bool(true)) => "active".to_string(),
            Some(_) => "inactive".to_string(),
            None => answer["reasonCode"].as_str().unwrap().to_string(),
        };
        (status, what)
    }

    /// Ends every rate window of the route, as the passing of a minute does.
    fn next_rate_window(&self) {
        self.fixture
            .state
            .access_key_resolution_ingress
            .expire_rate_windows();
    }

    /// An administrator's key for `principal`, which may hold `inference`.
    fn mint_for(
        &self,
        principal: &str,
        lifetime_seconds: u64,
    ) -> agent_access_core::IssuedAccessKey {
        let runtime = self.fixture.state.current().runtime.clone();
        self.store
            .mint_administrator_access_key(
                runtime.broker_token_hasher().unwrap(),
                runtime.access_key_types(),
                &AdministratorAccessKeyRequest {
                    principal_id: principal.to_string(),
                    name: "another".to_string(),
                    access_key_types: vec!["inference".to_string()],
                    lifetime: format!("{lifetime_seconds}s"),
                    created_by: "admin".to_string(),
                },
            )
            .unwrap()
            .unwrap()
    }
}

/// A well-formed access key that no store holds.
fn unknown_key(index: usize) -> String {
    format!("aab_ak_{index:043}")
}

const TOO_MANY: (StatusCode, &str) = (StatusCode::TOO_MANY_REQUESTS, "rate_limited");

fn rate_limited() -> (StatusCode, String) {
    (TOO_MANY.0, TOO_MANY.1.to_string())
}

fn answered(what: &str) -> (StatusCode, String) {
    (StatusCode::OK, what.to_string())
}

fn is_subject_id(value: &Value, max: usize) -> bool {
    value.as_str().is_some_and(|id| {
        !id.is_empty()
            && id.len() <= max
            && id != "anonymous"
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._@+-".contains(&byte))
    })
}

/// An access key type ID: `[a-z][a-z0-9_-]{0,63}`.
fn is_type_name(value: &Value) -> bool {
    value.as_str().is_some_and(|name| {
        let bytes = name.as_bytes();
        (1..=64).contains(&bytes.len())
            && bytes[0].is_ascii_lowercase()
            && bytes.iter().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
            })
    })
}

fn utc_time(value: &Value) -> Option<chrono::DateTime<chrono::Utc>> {
    let text = value.as_str()?;
    text.ends_with('Z')
        .then(|| chrono::DateTime::parse_from_rfc3339(text).ok())
        .flatten()
        .map(|time| time.with_timezone(&chrono::Utc))
}

/// Whether `answer` satisfies the active answer of the contract, with the
/// limits the fixture index states. Any deviation is an answer a resolving
/// service treats as unavailable.
fn satisfies_active_schema(answer: &Value, limits: &Value) -> bool {
    let Some(object) = answer.as_object() else {
        return false;
    };
    let members = [
        "active",
        "subject",
        "usernameIncarnation",
        "groups",
        "types",
        "origin",
        "application",
        "keyId",
        "expiresAt",
    ];
    if object.len() != members.len() || members.iter().any(|member| !object.contains_key(*member)) {
        return false;
    }
    let limit = |name: &str| limits[name].as_u64().unwrap() as usize;
    let subject_ok = answer["subject"].as_object().is_some_and(|subject| {
        subject.len() == 2
            && matches!(subject["kind"].as_str(), Some("user" | "service_account"))
            && is_subject_id(&subject["id"], 256)
    });
    let incarnation_ok = answer["usernameIncarnation"].as_str().is_some_and(|value| {
        (1..=64).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    });
    let groups_ok = answer["groups"].as_array().is_some_and(|groups| {
        groups.len() <= limit("groups")
            && groups.iter().all(|group| {
                is_subject_id(group, 128) && !group.as_str().unwrap().contains(['@', '+'])
            })
    });
    let expires = utc_time(&answer["expiresAt"]);
    if expires.is_none() && !answer["expiresAt"].is_null() {
        return false;
    }
    // Each type is exactly `{name, validUntil}`, and no name repeats.
    let types_ok = answer["types"].as_array().is_some_and(|types| {
        let mut names = std::collections::BTreeSet::new();
        (1..=limit("types")).contains(&types.len())
            && types.iter().all(|access_key_type| {
                access_key_type.as_object().is_some_and(|object| {
                    object.len() == 2
                        && object.contains_key("name")
                        && object.contains_key("validUntil")
                }) && is_type_name(&access_key_type["name"])
                    && names.insert(access_key_type["name"].as_str().unwrap())
                    && (utc_time(&access_key_type["validUntil"]).is_some_and(|valid_until| {
                        expires.is_none_or(|expires| valid_until <= expires)
                    }) || (expires.is_none() && access_key_type["validUntil"].is_null()))
            })
    });
    let application_ok = match (answer["origin"].as_str(), &answer["application"]) {
        (Some("portal" | "administrator"), Value::Null) => true,
        (Some("application"), Value::String(id)) => {
            (1..=64).contains(&id.len())
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_-.".contains(&byte))
        }
        _ => false,
    };
    let key_id_ok = answer["keyId"]
        .as_str()
        .and_then(|id| id.strip_prefix("ak_"))
        .is_some_and(|id| {
            (1..=60).contains(&id.len())
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        });
    answer["active"] == json!(true)
        && subject_ok
        && incarnation_ok
        && groups_ok
        && types_ok
        && application_ok
        && key_id_ok
}

/// The stored-key inactive form is stricter than what the caller tolerates.
fn satisfies_stored_inactive_schema(answer: &Value, index: &Value) -> bool {
    let Some(object) = answer.as_object() else {
        return false;
    };
    let members = ["active", "keyId", "owner", "reason"];
    if object.len() != members.len() || members.iter().any(|member| !object.contains_key(*member)) {
        return false;
    }
    let key_id_ok = answer["keyId"]
        .as_str()
        .and_then(|id| id.strip_prefix("ak_"))
        .is_some_and(|id| {
            (1..=60).contains(&id.len())
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        });
    let owner_ok = answer["owner"].is_null()
        || answer["owner"].as_object().is_some_and(|owner| {
            owner.len() == 2
                && matches!(
                    owner.get("kind").and_then(Value::as_str),
                    Some("user" | "service_account")
                )
                && owner.get("id").is_some_and(|id| is_subject_id(id, 256))
        });
    answer["active"] == json!(false)
        && key_id_ok
        && owner_ok
        && answer["reason"].is_string()
        && index["inactiveReasons"]
            .as_array()
            .unwrap()
            .contains(&answer["reason"])
}

fn bare_inactive_fixture(index: &Value) -> Value {
    fixture_json(
        index["answers"]["endpointInactiveForms"]["unknownOrMalformedKey"]
            .as_str()
            .unwrap(),
    )
}

/// Only these three forms may leave the Broker with HTTP 200.
fn satisfies_endpoint_schema(answer: &Value, index: &Value) -> bool {
    answer == &bare_inactive_fixture(index)
        || satisfies_stored_inactive_schema(answer, index)
        || satisfies_active_schema(answer, &index["limits"])
}

fn assert_emitted_answer(bytes: &[u8], index: &Value) -> Value {
    assert!(bytes.len() <= index["limits"]["answerBytes"].as_u64().unwrap() as usize);
    let answer: Value = serde_json::from_slice(bytes).unwrap();
    assert!(satisfies_endpoint_schema(&answer, index), "{answer}");
    if answer == bare_inactive_fixture(index) {
        assert_eq!(bytes, br#"{"active":false}"#);
    }
    answer
}

#[tokio::test]
async fn shared_fixtures_requests_and_answers_hold_on_the_broker_side() {
    let index = fixture_json("index.json");
    assert_eq!(index["contract"], "POST /v1/access-keys/resolve");
    let limits = &index["limits"];
    // The schema check used below accepts and refuses what the index says.
    for name in index["answers"]["callerAcceptsAsSubject"]
        .as_array()
        .unwrap()
    {
        let name = name.as_str().unwrap();
        assert!(
            satisfies_active_schema(&fixture_json(name), limits),
            "{name}"
        );
    }
    // Every answer classified as unavailable is outside all three endpoint forms:
    // active, bare inactive and stored-key inactive.
    let unavailable = index["answers"]["callerTreatsAsUnavailable"]
        .as_array()
        .unwrap();
    for entry in unavailable {
        let name = entry["file"].as_str().unwrap();
        let fixture = fixture_json(name);
        assert!(
            !satisfies_active_schema(&fixture, limits),
            "{name}: {}",
            entry["why"]
        );
        assert!(!satisfies_endpoint_schema(&fixture, &index), "{name}");
    }
    // A repeated type name alone makes an answer one the Broker may not
    // emit: the fixture with the repeat is refused, and is accepted once
    // its second type has a name of its own.
    let repeated = fixture_json("answer.invalid.duplicate-type.json");
    assert_eq!(
        repeated["types"][0]["name"], repeated["types"][1]["name"],
        "{repeated}"
    );
    assert!(!satisfies_active_schema(&repeated, limits));
    let mut distinct = repeated.clone();
    distinct["types"][1]["name"] = json!("web-search");
    assert!(satisfies_active_schema(&distinct, limits));
    let mut doubled = fixture_json("answer.active.portal.json");
    let again = doubled["types"][0].clone();
    doubled["types"].as_array_mut().unwrap().push(again);
    assert!(!satisfies_active_schema(&doubled, limits));

    // The caller accepts more inactive objects than this endpoint emits.
    // The endpoint forms, not caller tolerance, define this side's contract.
    let forms = &index["answers"]["endpointInactiveForms"];
    let bare_name = forms["unknownOrMalformedKey"].as_str().unwrap();
    assert_eq!(bare_inactive_fixture(&index), json!({"active": false}));
    let stored_names = forms["storedKey"].as_array().unwrap();
    assert!(!stored_names.is_empty());
    for name in stored_names {
        let name = name.as_str().unwrap();
        assert!(
            satisfies_stored_inactive_schema(&fixture_json(name), &index),
            "{name}"
        );
    }
    for name in index["answers"]["callerTreatsAsInactive"]
        .as_array()
        .unwrap()
    {
        let fixture = fixture_json(name.as_str().unwrap());
        let endpoint_form = name.as_str() == Some(bare_name) || stored_names.contains(name);
        assert_eq!(
            satisfies_endpoint_schema(&fixture, &index),
            endpoint_form,
            "{name}"
        );
    }

    let resolver = resolver().await;
    // Every request the index says the Broker answers 400 is answered 400.
    let refused = index["requests"]["endpointMustAnswer400"]
        .as_array()
        .unwrap();
    assert!(!refused.is_empty());
    for (index_in_list, entry) in refused.iter().enumerate() {
        let name = entry["file"].as_str().unwrap();
        let (status, _) = resolver
            .resolve_raw(
                &format!("fixture-invalid-{index_in_list}"),
                fixture_bytes(name),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{name}: {}", entry["why"]);
    }
    // A valid request for a token the Broker does not know is inactive.
    for name in index["requests"]["valid"].as_array().unwrap() {
        let (status, bytes) = resolver
            .resolve_raw("fixture-valid", fixture_bytes(name.as_str().unwrap()))
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            assert_emitted_answer(&bytes, &index),
            json!({"active": false})
        );
    }
    assert_eq!(resolver.records("fixture-valid"), Vec::<Value>::new());

    // The Broker's own answers satisfy the active schema.
    let (status, bytes) = resolver
        .resolve_raw(
            "active-portal",
            json!({"key": resolver.alice.key}).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let portal = assert_emitted_answer(&bytes, &index);
    let expected = fixture_json("answer.active.portal.json");
    assert_eq!(portal["subject"], expected["subject"]);
    assert_eq!(portal["groups"], expected["groups"]);
    assert_eq!(portal["origin"], expected["origin"]);
    assert_eq!(portal["application"], Value::Null);
    assert_eq!(portal["keyId"], json!(resolver.alice.record.key_id));
    assert_eq!(portal["expiresAt"], json!(resolver.alice.record.expires_at));
    assert_eq!(
        portal["usernameIncarnation"],
        json!(resolver.alice.record.username_incarnation)
    );
    // The configured type has a description, and no part of an answer
    // carries it.
    assert!(!String::from_utf8_lossy(&bytes).contains(TYPE_DESCRIPTION));
    assert!(!String::from_utf8_lossy(&bytes).contains("description"));
    assert_eq!(
        portal["types"],
        json!([{
            "name": "inference",
            "validUntil": resolver.alice.record.expires_at,
        }])
    );
    let (status, bytes) = resolver
        .resolve_raw(
            "active-administrator",
            json!({"key": resolver.robot.key}).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let administrator = assert_emitted_answer(&bytes, &index);
    assert_eq!(
        administrator["subject"],
        json!({"kind": "service_account", "id": "robot"})
    );
    assert_eq!(administrator["origin"], "administrator");
    assert_eq!(administrator["groups"], json!([]));
    assert_eq!(
        administrator["usernameIncarnation"],
        json!(resolver.robot.record.username_incarnation)
    );
    assert_eq!(administrator["keyId"], json!(resolver.robot.record.key_id));
    // Active resolutions are not audited and record the token's use.
    assert_eq!(resolver.records("active-portal"), Vec::<Value>::new());
    assert_eq!(
        resolver.records("active-administrator"),
        Vec::<Value>::new()
    );
    assert!(
        resolver
            .store
            .access_key(&resolver.alice.record.key_id)
            .unwrap()
            .unwrap()
            .last_used_at
            .is_some()
    );
}

#[tokio::test]
async fn an_administrator_s_key_for_a_person_resolves_as_the_shared_administrator_user_answer() {
    let resolver = resolver().await;
    let index = fixture_json("index.json");
    let expected = fixture_json("answer.active.administrator-user.json");
    assert!(
        index["answers"]["callerAcceptsAsSubject"]
            .as_array()
            .unwrap()
            .contains(&json!("answer.active.administrator-user.json"))
    );
    // The person of the fixture: named `dana`, a member of `platform`, who
    // may hold `inference`.
    let subject = expected["subject"]["id"].as_str().unwrap();
    let principal = format!("usr-{subject}");
    let admin = async |method: Method, uri: String, request_id: &str, body: Option<Value>| {
        let response = authed_json_request(
            resolver.fixture.app.clone(),
            method,
            uri,
            request_id,
            "X-Agent-Token",
            format!("Bearer {}", resolver.fixture.admin_token),
            body.map(|body| body.to_string()).as_deref(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "{request_id}");
        response_json(response).await["result"].clone()
    };
    admin(
        Method::POST,
        "/v1/admin/principals".to_string(),
        "fixture-person",
        Some(json!({"principalId": principal, "kind": "user"})),
    )
    .await;
    admin(
        Method::PUT,
        format!("/v1/admin/principals/{principal}/account-username"),
        "fixture-name",
        Some(json!({"mode": "manual", "accountUsername": subject})),
    )
    .await;
    for group in expected["groups"].as_array().unwrap() {
        admin(
            Method::PUT,
            format!(
                "/v1/admin/principals/{principal}/groups/{}",
                group.as_str().unwrap()
            ),
            "fixture-group",
            None,
        )
        .await;
    }
    let types = expected["types"]
        .as_array()
        .unwrap()
        .iter()
        .map(|access_key_type| access_key_type["name"].clone())
        .collect::<Vec<_>>();
    admin(
        Method::PATCH,
        format!("/v1/admin/principals/{principal}/access"),
        "fixture-access",
        Some(json!({"accessKeyTypes": {"allow": types, "deny": []}})),
    )
    .await;

    // An administrator issues the key for the person, through the route.
    let issued = admin(
        Method::POST,
        format!("/v1/admin/principals/{principal}/access-keys"),
        "fixture-issue",
        Some(
            json!({"name": "from the administrator", "accessKeyTypes": types,
            "lifetime": "1h"}),
        ),
    )
    .await;
    assert_eq!(issued["record"]["origin"], "administrator");
    assert_eq!(issued["record"]["createdBy"], "admin");
    let (status, bytes) = resolver
        .resolve_raw(
            "fixture-administrator-user",
            json!({"key": issued["key"]}).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let answer = assert_emitted_answer(&bytes, &index);

    // The answer is the fixture's, member for member, with this key's own
    // incarnation, ID and times in place of the fixture's.
    let mut expected = expected;
    expected["usernameIncarnation"] = issued["record"]["usernameIncarnation"].clone();
    expected["keyId"] = issued["record"]["keyId"].clone();
    expected["expiresAt"] = issued["record"]["expiresAt"].clone();
    for access_key_type in expected["types"].as_array_mut().unwrap() {
        access_key_type["validUntil"] = issued["record"]["expiresAt"].clone();
    }
    assert_eq!(answer, expected);
    assert_eq!(
        resolver.records("fixture-administrator-user"),
        Vec::<Value>::new()
    );
    assert_eq!(
        answer.as_object().unwrap().keys().collect::<Vec<_>>(),
        fixture_json("answer.active.administrator-user.json")
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn every_token_state_outcome_is_inactive_without_an_audit_record() {
    let resolver = resolver_configured(test_limits(), |config| {
        config.usernames.existing_usernames = vec!["alice.listed".to_string()];
    })
    .await;
    let index = fixture_json("index.json");
    let token = resolver.alice.key.clone();
    let inactive = |request_id: &'static str,
                    expected: &'static str,
                    owner: Option<&'static str>| {
        let resolver = &resolver;
        let token = token.clone();
        let index = index.clone();
        async move {
            let (status, bytes) = resolver
                .resolve_raw(request_id, json!({"key": token}).to_string())
                .await;
            assert_eq!(status, StatusCode::OK, "{request_id}");
            assert_eq!(
                assert_emitted_answer(&bytes, &index),
                json!({"active": false, "keyId": resolver.alice.record.key_id,
                    "owner": owner.map(|id| json!({"kind": "user", "id": id})), "reason": expected}),
                "{request_id}"
            );
            assert_eq!(resolver.records(request_id), Vec::<Value>::new());
        }
    };
    let active = |request_id: &'static str| {
        let resolver = &resolver;
        let token = token.clone();
        async move {
            let (status, answer) = resolver.resolve(request_id, &token).await;
            assert_eq!((status, &answer["active"]), (StatusCode::OK, &json!(true)));
            assert_eq!(resolver.records(request_id), Vec::<Value>::new());
        }
    };
    active("state-active").await;

    let version = resolver.store.identity_access("alice").unwrap().version;
    resolver
        .store
        .set_identity_access_paused("alice", true, version, "admin")
        .unwrap();
    inactive("state-paused", "identity_access_paused", Some("alice")).await;
    let version = resolver.store.identity_access("alice").unwrap().version;
    resolver
        .store
        .set_identity_access_paused("alice", false, version, "admin")
        .unwrap();
    active("state-resumed").await;

    resolver
        .store
        .set_principal_enabled("alice", false)
        .unwrap();
    inactive("state-disabled", "principal_disabled", Some("alice")).await;
    resolver.store.set_principal_enabled("alice", true).unwrap();

    // A group change shows in the next answer: the groups it returns are
    // the ones she holds now.
    let (_, before) = resolver.resolve("state-groups-before", &token).await;
    assert_eq!(before["groups"], json!(["platform"]));
    resolver.store.remove_group("alice", "platform").unwrap();
    let (status, after) = resolver.resolve("state-group-changed", &token).await;
    assert_eq!((status, &after["active"]), (StatusCode::OK, &json!(true)));
    assert_eq!(after["groups"], json!([]));

    // More local groups than an answer returns: no group is dropped to
    // fit, the key is not active.
    let contexts = agent_access_core::ConfiguredExecutionContexts::from_config(None).unwrap();
    for index in 0..65 {
        let group_id = format!("crowd-{index:02}");
        resolver
            .store
            .create_group(
                agent_access_core::GroupWriteRequest {
                    group_id: group_id.clone(),
                    display_name: None,
                    description: None,
                    auto_enroll_new_microsoft_users: false,
                    agent_token_issuance: Default::default(),
                    created_by: "admin".to_string(),
                },
                &contexts,
            )
            .unwrap();
        resolver
            .store
            .add_group("alice", &group_id, "admin")
            .unwrap();
    }
    inactive(
        "state-too-many-groups",
        "group_limit_exceeded",
        Some("alice"),
    )
    .await;
    resolver.store.remove_group("alice", "crowd-64").unwrap();
    let (_, crowded) = resolver.resolve("state-64-groups", &token).await;
    assert_eq!(crowded["groups"].as_array().unwrap().len(), 64);

    // Her only type withdrawn, and restored.
    let runtime = resolver.fixture.state.current().runtime.clone();
    allow_access_key_types(&resolver.store, &runtime, "alice", &[]);
    inactive("state-type-withdrawn", "no_access_key_type", Some("alice")).await;
    allow_access_key_types(&resolver.store, &runtime, "alice", &["inference"]);
    active("state-type-restored").await;

    resolver
        .store
        .set_account_username("alice", "alice.renamed", "admin")
        .unwrap()
        .unwrap();
    inactive(
        "state-renamed",
        "username_incarnation_changed",
        Some("alice.renamed"),
    )
    .await;
    // A username on the operator's list of names already in use is not
    // usable until an administrator confirms it.
    resolver
        .store
        .set_account_username("alice", "alice.listed", "admin")
        .unwrap()
        .unwrap();
    inactive(
        "state-awaiting",
        "account_username_awaiting_confirmation",
        None,
    )
    .await;
    resolver
        .store
        .set_account_username_setting(
            "alice",
            &agent_access_core::AccountUsernameSetting::ManualNone,
            "admin",
        )
        .unwrap()
        .unwrap();
    inactive("state-released", "no_account_username", None).await;
    resolver
        .store
        .revoke_access_key(&resolver.alice.record.key_id, None, "admin")
        .unwrap()
        .unwrap();
    inactive("state-revoked", "revoked", None).await;
}

#[tokio::test]
async fn only_a_caller_with_the_capability_resolves_and_no_other_credential_is_accepted() {
    let resolver = resolver().await;
    let body = || json!({"key": resolver.alice.key}).to_string();
    for (request_id, headers, status, reason) in [
        (
            "caller-missing",
            vec![],
            StatusCode::UNAUTHORIZED,
            "caller_authentication_required",
        ),
        (
            "caller-wrong",
            vec![(CALLER_HEADER, "Bearer not-a-configured-caller-credential")],
            StatusCode::UNAUTHORIZED,
            "caller_authentication_invalid",
        ),
        (
            "caller-without-capability",
            vec![(CALLER_HEADER, OTHER_CALLER)],
            StatusCode::FORBIDDEN,
            "broker_caller_access_key_resolution_denied",
        ),
    ] {
        let (code, bytes) = resolver
            .send(resolve_request(request_id, &headers, body()))
            .await;
        let answer: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(code, status, "{request_id}: {answer}");
        assert_eq!(answer["reasonCode"], reason, "{request_id}");
        assert!(answer.get("active").is_none());
        assert_eq!(resolver.records(request_id), Vec::<Value>::new());
    }
    // Real stored Broker credentials remain unusable on the resolution endpoint.
    for (class, token) in [
        ("admin", &resolver.fixture.admin_token),
        ("agent", &resolver.fixture.agent_tokens[0]),
    ] {
        let bearer = format!("Bearer {token}");
        for header in [CALLER_HEADER, "authorization", "x-agent-token", "cookie"] {
            let id = format!("wrong-kind-{class}-{header}");
            let (status, bytes) = resolver
                .send(resolve_request(&id, &[(header, &bearer)], body()))
                .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            let answer: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                answer["reasonCode"],
                if header == CALLER_HEADER {
                    "caller_authentication_invalid"
                } else {
                    "caller_authentication_required"
                }
            );
        }
    }
    let (status, _) = resolver
        .send(resolve_request(
            "browser-cookie-is-not-caller",
            &[("cookie", &resolver.fixture.cookie)],
            body(),
        ))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Nothing was resolved or recorded as used by the refused callers.
    assert_eq!(
        resolver
            .store
            .access_key(&resolver.alice.record.key_id)
            .unwrap()
            .unwrap()
            .last_used_at,
        None
    );

    // The request names nobody but its caller: a principal credential, a
    // forwarded fingerprint, a username or a context is refused with 400.
    let admin = format!("Bearer {}", resolver.fixture.admin_token);
    for (request_id, name, value) in [
        ("forbidden-authorization", "authorization", admin.as_str()),
        (
            "forbidden-fingerprint",
            "x-aw-identity-token-sha256",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ),
        ("forbidden-username", "x-agent-access-user", "alice"),
        ("forbidden-context", "x-agent-access-context", "default"),
    ] {
        let (code, bytes) = resolver
            .send(resolve_request(
                request_id,
                &[(CALLER_HEADER, RESOLVER), (name, value)],
                body(),
            ))
            .await;
        let answer: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(code, StatusCode::BAD_REQUEST, "{request_id}: {answer}");
        assert_eq!(answer["reasonCode"], "input_invalid", "{request_id}");
        assert!(answer.get("active").is_none());
    }
    // An access key is refused on the Broker's own routes.
    let response = authed_json_request(
        resolver.fixture.app.clone(),
        Method::GET,
        "/v1/me",
        "access-key-on-broker-route",
        "X-Agent-Token",
        format!("Bearer {}", resolver.alice.key),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_json(response).await["reasonCode"],
        "broker_token_not_found"
    );
    let (status, answer) = resolver.resolve("still-active", &resolver.alice.key).await;
    assert_eq!((status, &answer["active"]), (StatusCode::OK, &json!(true)));
}

async fn sign_in_status(fixture: &BrowserRateFixture, request_id: &str) -> StatusCode {
    fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/auth/local/login")
                .extension(ConnectInfo(
                    "127.0.0.1:43120".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, request_id)
                .header("Host", "localhost")
                .header("Origin", "http://localhost")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"principalId": "alice", "password": "alice-password"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

async fn services_status(fixture: &BrowserRateFixture, request_id: &str) -> StatusCode {
    authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/services",
        request_id,
        "X-Agent-Token",
        format!("Bearer {}", fixture.agent_tokens[0]),
        None,
    )
    .await
    .status()
}

#[tokio::test]
async fn resolution_has_its_own_pool_and_rate_and_spends_no_other_budget() {
    let resolver = resolver_with(LimitsConfig {
        max_concurrent_access_key_resolutions: 2,
        access_key_resolutions_per_caller_per_minute: 6,
        auth_requests_per_source_per_minute: 3,
        ..test_limits()
    })
    .await;
    let state = &resolver.fixture.state;

    // With the resolution pool full, resolution answers 429 and sign-in and
    // ordinary requests are served.
    let held = [
        state
            .access_key_resolution_ingress
            .try_global_concurrency(2)
            .unwrap(),
        state
            .access_key_resolution_ingress
            .try_global_concurrency(2)
            .unwrap(),
    ];
    let (status, answer) = resolver.resolve("pool-full", UNKNOWN_TOKEN).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{answer}");
    assert_eq!(answer["reasonCode"], "concurrency_limited");
    assert_eq!(
        sign_in_status(&resolver.fixture, "pool-full-sign-in").await,
        StatusCode::OK
    );
    assert_eq!(
        services_status(&resolver.fixture, "pool-full-services").await,
        StatusCode::OK
    );
    drop(held);

    // With the shared pool full, resolution is still served.
    let limit = state.current().runtime.limits().max_concurrent_requests;
    let shared: Vec<_> = (0..limit)
        .map(|_| state.shared_ingress.try_global_concurrency(limit).unwrap())
        .collect();
    assert_eq!(
        services_status(&resolver.fixture, "shared-full-services").await,
        StatusCode::TOO_MANY_REQUESTS
    );
    let (status, answer) = resolver.resolve("shared-full", &resolver.alice.key).await;
    assert_eq!((status, &answer["active"]), (StatusCode::OK, &json!(true)));
    drop(shared);
    assert_eq!(
        state
            .access_key_resolution_ingress
            .global_in_flight_requests(),
        0
    );

    // Resolutions spend neither the per-source sign-in budget (3 a minute
    // here) nor a principal's concurrency. The caller's own rate counts the
    // requests no stored key answers for: six unknown keys reach its six a
    // minute, and none spends the source budget of three.
    for attempt in 0..6 {
        assert_eq!(
            resolver
                .outcome(&format!("rate-{attempt}"), &unknown_key(attempt))
                .await,
            answered("inactive"),
            "{attempt}"
        );
    }
    assert_eq!(
        sign_in_status(&resolver.fixture, "rate-sign-in").await,
        StatusCode::OK
    );
    let (status, answer) = resolver.resolve("rate-limited", &unknown_key(6)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{answer}");
    assert_eq!(answer["reasonCode"], "rate_limited");
    // The refusal is the Broker's own admission answer and names no key.
    assert_eq!(
        (&answer["service"], &answer["action"], &answer["decision"]),
        (&json!("broker"), &json!("request.admit"), &json!("error"))
    );
    assert!(answer.get("active").is_none());
    // A stored key is still answered: the rate never refuses one.
    assert_eq!(
        resolver.outcome("rate-stored", &resolver.alice.key).await,
        answered("active")
    );
    // The caller's rate does not limit anyone else.
    assert_eq!(
        services_status(&resolver.fixture, "rate-limited-services").await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_stored_key_is_answered_while_the_unknown_key_rate_is_spent_in_every_window() {
    let resolver = resolver_with(LimitsConfig {
        access_key_resolutions_per_caller_per_minute: 3,
        auth_requests_per_source_per_minute: 3,
        ..test_limits()
    })
    .await;
    // Stored keys in each state a recheck can find: active, revoked,
    // expired, and one whose owner is disabled.
    let revoked = resolver.mint_for("alice", 3600);
    resolver
        .store
        .revoke_access_key(&revoked.record.key_id, None, "admin")
        .unwrap()
        .unwrap();
    let expired = resolver.mint_for("alice", 1);
    let contexts = agent_access_core::ConfiguredExecutionContexts::from_config(None).unwrap();
    resolver
        .store
        .create_principal(
            agent_access_core::PrincipalWriteRequest {
                agent_token_issuance: Default::default(),
                role: agent_access_core::PrincipalRole::User,
                self_service_enabled: Some(false),
                principal_id: "retired".to_string(),
                kind: "service_account".to_string(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".to_string(),
            },
            &contexts,
        )
        .unwrap();
    allow_access_key_types(
        &resolver.store,
        &resolver.fixture.state.current().runtime,
        "retired",
        &["inference"],
    );
    let disabled = resolver.mint_for("retired", 3600);
    resolver
        .store
        .set_principal_enabled("retired", false)
        .unwrap();
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let stored = [
        ("active", &resolver.alice, None),
        ("robot", &resolver.robot, None),
        ("revoked", &revoked, Some(("user", "alice", "revoked"))),
        ("expired", &expired, Some(("user", "alice", "expired"))),
        (
            "disabled",
            &disabled,
            Some(("service_account", "retired", "principal_disabled")),
        ),
    ];

    let mut unknown = 0..;
    for window in 1..=3 {
        // The window's three requests for keys no store holds are answered.
        for _ in 0..3 {
            let index = unknown.next().unwrap();
            let request_id = format!("w{window}-unknown-{index}");
            assert_eq!(
                resolver.outcome(&request_id, &unknown_key(index)).await,
                answered("inactive"),
                "{request_id}"
            );
            assert_eq!(resolver.records(&request_id), Vec::<Value>::new());
        }
        // Beyond the rate an unknown key is refused, and nothing is
        // recorded: not as a resolution, not as an admission failure.
        for _ in 0..4 {
            let index = unknown.next().unwrap();
            let request_id = format!("w{window}-flood-{index}");
            assert_eq!(
                resolver.outcome(&request_id, &unknown_key(index)).await,
                rate_limited(),
                "{request_id}"
            );
            assert_eq!(resolver.records(&request_id), Vec::<Value>::new());
        }
        // While the rate is spent, every stored key is answered, as often
        // as it is asked for: many times the rate. No lookup is audited.
        for round in 0..4 {
            for (name, key, inactive) in &stored {
                let request_id = format!("w{window}-{name}-{round}");
                let (status, answer) = resolver.resolve(&request_id, &key.key).await;
                assert_eq!(status, StatusCode::OK, "{request_id}: {answer}");
                if let Some((kind, owner, reason)) = inactive {
                    assert_eq!(
                        answer,
                        json!({
                            "active": false,
                            "keyId": key.record.key_id,
                            "owner": {"kind": kind, "id": owner},
                            "reason": reason,
                        }),
                        "{request_id}"
                    );
                } else {
                    assert_eq!(answer["active"], true, "{request_id}");
                }
                assert_eq!(
                    resolver.records(&request_id),
                    Vec::<Value>::new(),
                    "{request_id}"
                );
            }
        }
        // The flood did not let up meanwhile.
        let index = unknown.next().unwrap();
        assert_eq!(
            resolver
                .outcome(&format!("w{window}-still-{index}"), &unknown_key(index))
                .await,
            rate_limited()
        );
        // No other class's budget was touched: a sign-in from the same
        // address and an ordinary request are served in every window.
        assert_eq!(
            services_status(&resolver.fixture, &format!("w{window}-services")).await,
            StatusCode::OK
        );
        resolver.next_rate_window();
    }
    // The fixture's own sign-in used one of the address's three a minute;
    // the two that remain are still there after three windows of flood.
    for request_id in ["after-flood-sign-in-1", "after-flood-sign-in-2"] {
        assert_eq!(
            sign_in_status(&resolver.fixture, request_id).await,
            StatusCode::OK,
            "{request_id}"
        );
    }
    let state = &resolver.fixture.state;
    assert_eq!(
        state
            .access_key_resolution_ingress
            .global_in_flight_requests(),
        0
    );
    assert_eq!(state.shared_ingress.global_in_flight_requests(), 0);
}

#[tokio::test]
async fn malformed_requests_and_unknown_keys_share_the_rate_and_a_refusal_by_it_is_not_audited() {
    let resolver = resolver_with(LimitsConfig {
        access_key_resolutions_per_caller_per_minute: 4,
        ..test_limits()
    })
    .await;
    let send =
        |request_id: &'static str, headers: Vec<(&'static str, &'static str)>, body: String| {
            let resolver = &resolver;
            let mut all = vec![(CALLER_HEADER, RESOLVER)];
            all.extend(headers);
            let request = resolve_request(request_id, &all, body);
            async move {
                let (status, bytes) = resolver.send(request).await;
                let answer: Value = serde_json::from_slice(&bytes).unwrap();
                (
                    status,
                    answer["reasonCode"]
                        .as_str()
                        .unwrap_or("answer")
                        .to_string(),
                )
            }
        };
    let key = |key: &str| json!({ "key": key }).to_string();
    let malformed = [
        (
            "malformed-header",
            vec![("x-agent-access-user", "alice")],
            key(&resolver.alice.key),
            (StatusCode::BAD_REQUEST, "input_invalid"),
        ),
        (
            "malformed-body",
            vec![],
            "[]".to_string(),
            (StatusCode::BAD_REQUEST, "body_malformed"),
        ),
        (
            "malformed-key",
            vec![],
            key("aab_ak_short"),
            (StatusCode::BAD_REQUEST, "input_invalid"),
        ),
    ];
    // Three malformed requests and one unknown key are the four a minute:
    // each is answered without an audit record.
    for (request_id, headers, body, expected) in malformed.clone() {
        assert_eq!(
            send(request_id, headers, body).await,
            (expected.0, expected.1.to_string()),
            "{request_id}"
        );
        assert_eq!(resolver.records(request_id), Vec::<Value>::new());
    }
    assert_eq!(
        resolver.outcome("unknown-in-rate", &unknown_key(1)).await,
        answered("inactive")
    );
    // The rate is spent: the same requests are now refused by it, whatever
    // is wrong with them, and none of the refusals is recorded.
    for (request_id, headers, body, _) in malformed {
        let request_id: &'static str = format!("{request_id}-beyond").leak();
        assert_eq!(
            send(request_id, headers, body).await,
            (TOO_MANY.0, TOO_MANY.1.to_string()),
            "{request_id}"
        );
        assert_eq!(
            resolver.records(request_id),
            Vec::<Value>::new(),
            "{request_id}"
        );
    }
    assert_eq!(
        resolver
            .outcome("unknown-beyond-rate", &unknown_key(2))
            .await,
        rate_limited()
    );
    assert_eq!(resolver.records("unknown-beyond-rate"), Vec::<Value>::new());
    // The record a rate refusal used to leave is not written under any
    // request ID either.
    let refusals = read_audit_records(&resolver.fixture.audit_path)
        .into_iter()
        .filter(|record| {
            record["reasonCode"] == "rate_limited" || record["reasonCode"] == "concurrency_limited"
        })
        .collect::<Vec<_>>();
    assert_eq!(refusals, Vec::<Value>::new());
    // Nothing a refused request named was looked up: the unknown key of the
    // refused request costs the store one read and nothing is written.
    assert_eq!(
        resolver
            .store
            .access_key(&resolver.alice.record.key_id)
            .unwrap()
            .unwrap()
            .last_used_at,
        None
    );
    // A stored key is answered all the while, and a new window starts the
    // count again.
    assert_eq!(
        resolver.outcome("stored", &resolver.alice.key).await,
        answered("active")
    );
    resolver.next_rate_window();
    assert_eq!(
        resolver
            .outcome("unknown-next-window", &unknown_key(3))
            .await,
        answered("inactive")
    );
}

#[tokio::test]
async fn a_request_the_pool_turns_away_is_not_audited() {
    // One unknown key and one refused caller a minute: a single charge made
    // by a request the pool turned away would show below.
    let resolver = resolver_with(LimitsConfig {
        max_concurrent_access_key_resolutions: 1,
        access_key_resolutions_per_caller_per_minute: 1,
        auth_requests_per_source_per_minute: 1,
        ..test_limits()
    })
    .await;
    let held = resolver
        .fixture
        .state
        .access_key_resolution_ingress
        .try_global_concurrency(1)
        .unwrap();
    for (request_id, key) in [
        ("pool-full-stored", resolver.alice.key.clone()),
        ("pool-full-unknown", unknown_key(1)),
    ] {
        let (status, answer) = resolver.resolve(request_id, &key).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{answer}");
        assert_eq!(answer["reasonCode"], "concurrency_limited");
        assert_eq!(
            (&answer["service"], &answer["action"]),
            (&json!("broker"), &json!("request.admit"))
        );
        assert_eq!(resolver.records(request_id), Vec::<Value>::new());
    }
    let (status, _) = resolver
        .send(resolve_request("pool-full-no-credential", &[], "{}"))
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        resolver.records("pool-full-no-credential"),
        Vec::<Value>::new()
    );
    drop(held);
    // The refused requests spent none of the caller's rate either: the one
    // unknown key the caller may ask about in this minute is still answered,
    // and only the next is refused.
    assert_eq!(
        resolver.outcome("after-pool", &unknown_key(2)).await,
        answered("inactive")
    );
    assert_eq!(
        resolver.outcome("after-pool-spent", &unknown_key(3)).await,
        rate_limited()
    );
    // Nor did the request without a credential spend its source's rate.
    let (status, _) = resolver
        .send(resolve_request("after-pool-no-credential", &[], "{}"))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, bytes) = resolver
        .send(resolve_request("after-pool-no-credential-spent", &[], "{}"))
        .await;
    let answer: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        (status, answer["reasonCode"].as_str()),
        (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited")),
        "{answer}"
    );
    assert_eq!(
        resolver
            .outcome("after-pool-stored", &resolver.alice.key)
            .await,
        answered("active")
    );
}

#[tokio::test]
async fn an_invalid_request_id_is_refused_inside_the_route_s_admission() {
    let resolver = resolver_with(LimitsConfig {
        max_concurrent_access_key_resolutions: 1,
        access_key_resolutions_per_caller_per_minute: 3,
        ..test_limits()
    })
    .await;
    let request = |ids: Vec<axum::http::HeaderValue>| {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri("/v1/access-keys/resolve")
            .extension(ConnectInfo(
                "127.0.0.1:43120".parse::<SocketAddr>().unwrap(),
            ))
            .header(CALLER_HEADER, RESOLVER)
            .header(CONTENT_TYPE, "application/json");
        for id in ids {
            builder = builder.header(REQUEST_ID_HEADER, id);
        }
        builder
            .body(Body::from(json!({"key": resolver.alice.key}).to_string()))
            .unwrap()
    };
    let value = |text: &'static str| axum::http::HeaderValue::from_static(text);
    let invalid = || {
        vec![
            ("malformed", vec![value("bad id!")]),
            ("duplicate", vec![value("first"), value("second")]),
            (
                "not-utf8",
                vec![axum::http::HeaderValue::from_bytes(b"caf\xe9").unwrap()],
            ),
        ]
    };

    // With the pool full the request is turned away before its ID is
    // judged, like any other request to the route.
    let held = resolver
        .fixture
        .state
        .access_key_resolution_ingress
        .try_global_concurrency(1)
        .unwrap();
    let (status, bytes) = resolver.send(request(vec![value("bad id!")])).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap()["reasonCode"],
        "concurrency_limited"
    );
    drop(held);

    // Each invalid ID is refused in the Broker's response envelope, under a
    // generated ID, and counted against the caller's rate without auditing.
    for (name, ids) in invalid() {
        let (status, bytes) = resolver.send(request(ids)).await;
        let answer: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(status, StatusCode::BAD_REQUEST, "{name}: {answer}");
        assert_eq!(answer["reasonCode"], "request_id_invalid", "{name}");
        assert_eq!(
            (&answer["service"], &answer["action"], &answer["decision"]),
            (
                &json!("broker"),
                &json!("access_keys.resolve"),
                &json!("deny")
            ),
            "{name}: {answer}"
        );
        assert!(answer.get("active").is_none(), "{name}");
        let generated = answer["agentRequestId"].as_str().unwrap();
        assert!(!generated.is_empty(), "{name}");
        assert_eq!(resolver.records(generated), Vec::<Value>::new());
    }
    // The three were the caller's three a minute: the next is refused by
    // the rate, and nothing was resolved for any of them.
    let (status, bytes) = resolver.send(request(vec![value("bad id!")])).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap()["reasonCode"],
        "rate_limited"
    );
    assert_eq!(
        resolver
            .store
            .access_key(&resolver.alice.record.key_id)
            .unwrap()
            .unwrap()
            .last_used_at,
        None
    );
    // No ID is a request like any other: one is generated for it.
    let (status, bytes) = resolver.send(request(vec![])).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap()["active"],
        true
    );
}

#[tokio::test]
async fn a_slow_or_oversized_body_is_refused_within_its_bound_and_frees_the_pool() {
    let resolver = resolver_with(LimitsConfig {
        request_body_timeout_ms: 200,
        max_concurrent_access_key_resolutions: 1,
        ..test_limits()
    })
    .await;
    // A body that never completes: the first bytes arrive, the rest never.
    let stalled = Body::from_stream(futures_util::stream::unfold(0_u8, |sent| async move {
        if sent == 0 {
            Some((Ok::<_, std::io::Error>(Bytes::from_static(b"{\"key\":")), 1))
        } else {
            std::future::pending::<()>().await;
            None
        }
    }));
    let started = std::time::Instant::now();
    let (status, bytes) = resolver.resolve_raw("slow-body", stalled).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(started.elapsed() < Duration::from_secs(5));
    let answer: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(answer["reasonCode"], "body_malformed");
    assert!(
        answer["error"]["message"]
            .as_str()
            .unwrap()
            .contains("deadline")
    );
    // The only slot of the pool is free again.
    assert_eq!(
        resolver
            .fixture
            .state
            .access_key_resolution_ingress
            .global_in_flight_requests(),
        0
    );

    // A body over 4 KiB is refused whatever it contains.
    let padded = format!("{{\"key\":\"{}\"{}}}", resolver.alice.key, " ".repeat(4096));
    let (status, bytes) = resolver.resolve_raw("large-body", padded).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let answer: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(answer["reasonCode"], "body_malformed");
    let exact = format!(
        "{{\"key\":\"{}\"{}}}",
        resolver.alice.key,
        " ".repeat(4096 - 60)
    );
    assert_eq!(exact.len(), 4096);
    let (status, bytes) = resolver.resolve_raw("largest-body", exact).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap()["active"],
        true
    );

    // A caller that is not authenticated has no body read at all.
    let polled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = polled.clone();
    let unread = Body::from_stream(futures_util::stream::poll_fn(move |_| {
        observed.store(true, std::sync::atomic::Ordering::SeqCst);
        std::task::Poll::<Option<Result<Bytes, std::io::Error>>>::Pending
    }));
    let (status, _) = resolver
        .send(resolve_request("unread-body", &[], unread))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(!polled.load(std::sync::atomic::Ordering::SeqCst));
}

const SECOND_RESOLVER: &str = "Bearer second-resolver-credential-0123456789";

/// A request body that never arrives: it reports each time it is polled.
fn stalled_body() -> (Body, Arc<std::sync::atomic::AtomicBool>) {
    let polled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = polled.clone();
    let body = Body::from_stream(futures_util::stream::poll_fn(move |_| {
        observed.store(true, std::sync::atomic::Ordering::SeqCst);
        std::task::Poll::<Option<Result<Bytes, std::io::Error>>>::Pending
    }));
    (body, polled)
}

/// Waits until the Broker is reading the body `polled` belongs to.
async fn body_is_being_read(polled: &std::sync::atomic::AtomicBool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !polled.load(std::sync::atomic::Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the Broker reads the body");
}

#[tokio::test]
async fn one_caller_with_stalled_bodies_cannot_take_the_pool_from_another_caller() {
    let second_secret = temp_path("access-key-second-resolver");
    std::fs::write(
        &second_secret,
        SECOND_RESOLVER.strip_prefix("Bearer ").unwrap(),
    )
    .unwrap();
    // A pool of three, of which one caller may hold two. The bodies below
    // stall for longer than the test runs.
    let resolver = resolver_configured(
        LimitsConfig {
            max_concurrent_access_key_resolutions: 3,
            max_concurrent_access_key_resolutions_per_caller: 2,
            ..test_limits()
        },
        |config| {
            config
                .identity
                .trusted_callers
                .insert("second".to_string(), caller(&second_secret, true));
        },
    )
    .await;
    let state = &resolver.fixture.state;
    let in_flight = || {
        state
            .access_key_resolution_ingress
            .global_in_flight_requests()
    };
    let mut stalled = Vec::new();
    for request_id in ["stalled-1", "stalled-2"] {
        let (body, polled) = stalled_body();
        let app = resolver.fixture.app.clone();
        let request = resolve_request(request_id, &[(CALLER_HEADER, RESOLVER)], body);
        stalled.push(tokio::spawn(async move { app.oneshot(request).await }));
        body_is_being_read(&polled).await;
    }
    assert_eq!(in_flight(), 2);

    // The caller's third request is turned away at once, its body unread:
    // the pool has a slot left, and it is not this caller's to take.
    let (body, polled) = stalled_body();
    let (status, bytes) = tokio::time::timeout(
        Duration::from_secs(2),
        resolver.send(resolve_request(
            "stalled-3",
            &[(CALLER_HEADER, RESOLVER)],
            body,
        )),
    )
    .await
    .expect("a request beyond its caller's share is answered without its body");
    let answer: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{answer}");
    assert_eq!(answer["reasonCode"], "concurrency_limited");
    assert_eq!(
        (&answer["service"], &answer["action"]),
        (&json!("broker"), &json!("request.admit"))
    );
    assert!(
        answer["error"]["message"]
            .as_str()
            .unwrap()
            .contains("the most one caller may have at once"),
        "{answer}"
    );
    assert!(!polled.load(std::sync::atomic::Ordering::SeqCst));
    // Like every 429 of the route it is not audited.
    assert_eq!(resolver.records("stalled-3"), Vec::<Value>::new());
    assert_eq!(in_flight(), 2);

    // The other resolving caller is served meanwhile, stored key or not.
    let other = |request_id: &'static str, key: String| {
        let resolver = &resolver;
        async move {
            let (status, bytes) = resolver
                .send(resolve_request(
                    request_id,
                    &[(CALLER_HEADER, SECOND_RESOLVER)],
                    json!({"key": key}).to_string(),
                ))
                .await;
            let answer: Value = serde_json::from_slice(&bytes).unwrap();
            (status, answer["active"].clone())
        }
    };
    assert_eq!(
        other("other-caller-stored", resolver.alice.key.clone()).await,
        (StatusCode::OK, json!(true))
    );
    assert_eq!(
        other("other-caller-unknown", unknown_key(1)).await,
        (StatusCode::OK, json!(false))
    );
    assert_eq!(in_flight(), 2);

    // A peer address that presents no credential has the same share: with
    // two of its requests in the pool, a third is turned away unaudited.
    let held = [
        state
            .access_key_resolution_ingress
            .try_source_concurrency("127.0.0.1", 2)
            .unwrap(),
        state
            .access_key_resolution_ingress
            .try_source_concurrency("127.0.0.1", 2)
            .unwrap(),
    ];
    let (status, bytes) = resolver
        .send(resolve_request("no-credential-share", &[], "{}"))
        .await;
    let answer: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{answer}");
    assert_eq!(answer["reasonCode"], "concurrency_limited");
    assert_eq!(resolver.records("no-credential-share"), Vec::<Value>::new());
    drop(held);
    let (status, _) = resolver
        .send(resolve_request("no-credential-within-share", &[], "{}"))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // When the stalled requests go away their slots return, and with them
    // the caller's share.
    for request in &stalled {
        request.abort();
    }
    for request in stalled {
        assert!(request.await.unwrap_err().is_cancelled());
    }
    assert_eq!(in_flight(), 0);
    let (status, answer) = resolver.resolve("after-stalled", &resolver.alice.key).await;
    assert_eq!((status, &answer["active"]), (StatusCode::OK, &json!(true)));
}

#[tokio::test]
async fn a_request_abandoned_while_its_body_is_read_is_counted_as_malformed() {
    let resolver = resolver_with(LimitsConfig {
        access_key_resolutions_per_caller_per_minute: 2,
        ..test_limits()
    })
    .await;
    let state = &resolver.fixture.state;
    let in_flight = || {
        state
            .access_key_resolution_ingress
            .global_in_flight_requests()
    };
    // A request with a body that never arrives, and that body's report.
    let stalled = |request_id: &'static str| {
        let (body, polled) = stalled_body();
        let app = resolver.fixture.app.clone();
        let request = resolve_request(request_id, &[(CALLER_HEADER, RESOLVER)], body);
        (
            tokio::spawn(async move { app.oneshot(request).await }),
            polled,
        )
    };

    // The caller goes away while the Broker waits for its body. Nobody is
    // answered and nothing is audited, and the request is still one of the
    // two a minute that no stored key answers for.
    let (waiter, polled) = stalled("abandoned-body");
    body_is_being_read(&polled).await;
    assert_eq!(in_flight(), 1);
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    assert_eq!(in_flight(), 0);
    assert_eq!(resolver.records("abandoned-body"), Vec::<Value>::new());
    assert_eq!(
        resolver.outcome("after-abandoned-1", &unknown_key(1)).await,
        answered("inactive")
    );
    assert_eq!(
        resolver.outcome("after-abandoned-2", &unknown_key(2)).await,
        rate_limited()
    );
    // A second abandoned request finds the rate spent and changes nothing;
    // a stored key is answered all the same.
    let (waiter, polled) = stalled("abandoned-body-2");
    body_is_being_read(&polled).await;
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    assert_eq!(in_flight(), 0);
    assert_eq!(
        resolver
            .outcome("after-abandoned-stored", &resolver.alice.key)
            .await,
        answered("active")
    );
}

#[tokio::test]
async fn a_body_that_is_read_to_its_end_or_its_deadline_is_counted_once() {
    let resolver = resolver_with(LimitsConfig {
        access_key_resolutions_per_caller_per_minute: 2,
        request_body_timeout_ms: 100,
        ..test_limits()
    })
    .await;
    // A malformed body is counted by the refusal that answers it, and not
    // again when the request ends.
    let (status, bytes) = resolver.resolve_raw("malformed-body", "{").await;
    let answer: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        (status, answer["reasonCode"].as_str()),
        (StatusCode::BAD_REQUEST, Some("body_malformed")),
        "{answer}"
    );
    assert_eq!(
        resolver.outcome("after-malformed-1", &unknown_key(1)).await,
        answered("inactive")
    );
    assert_eq!(
        resolver.outcome("after-malformed-2", &unknown_key(2)).await,
        rate_limited()
    );
    // So is one that did not arrive within its deadline.
    resolver.next_rate_window();
    let (body, _) = stalled_body();
    let (status, bytes) = resolver.resolve_raw("late-body", body).await;
    let answer: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        (status, answer["reasonCode"].as_str()),
        (StatusCode::BAD_REQUEST, Some("body_malformed")),
        "{answer}"
    );
    assert_eq!(resolver.records("late-body"), Vec::<Value>::new());
    assert_eq!(
        resolver.outcome("after-late-1", &unknown_key(3)).await,
        answered("inactive")
    );
    assert_eq!(
        resolver.outcome("after-late-2", &unknown_key(4)).await,
        rate_limited()
    );
    // And a well-formed request for a stored key is not counted at all.
    resolver.next_rate_window();
    for request_id in ["stored-1", "stored-2", "stored-3"] {
        assert_eq!(
            resolver.outcome(request_id, &resolver.alice.key).await,
            answered("active")
        );
    }
    assert_eq!(
        resolver.outcome("after-stored-1", &unknown_key(5)).await,
        answered("inactive")
    );
    assert_eq!(
        resolver.outcome("after-stored-2", &unknown_key(6)).await,
        answered("inactive")
    );
}

#[tokio::test]
async fn lookup_answers_and_refusals_do_not_depend_on_the_audit_store() {
    let resolver = resolver().await;
    resolver
        .store
        .revoke_access_key(&resolver.robot.record.key_id, None, "admin")
        .unwrap()
        .unwrap();
    let before = read_audit_records(&resolver.fixture.audit_path);
    assert!(
        !before.is_empty(),
        "the fixture has audited its state changes"
    );
    let db = rusqlite::Connection::open(&resolver.fixture.audit_path).unwrap();
    db.execute_batch(
        "CREATE TRIGGER fail_every_audit BEFORE INSERT ON audit_events
         BEGIN SELECT RAISE(ABORT, 'private-audit-failure'); END;",
    )
    .unwrap();
    let rejected = db
        .execute_batch("INSERT INTO audit_events SELECT * FROM audit_events LIMIT 1;")
        .unwrap_err();
    assert!(rejected.to_string().contains("private-audit-failure"));

    for round in 0..2 {
        let request_id = format!("stored-inactive-unaudited-{round}");
        let (status, answer) = resolver.resolve(&request_id, &resolver.robot.key).await;
        assert_eq!(status, StatusCode::OK, "{request_id}: {answer}");
        assert_eq!(
            answer,
            json!({
                "active": false,
                "keyId": resolver.robot.record.key_id,
                "owner": {"kind": "service_account", "id": "robot"},
                "reason": "revoked",
            }),
            "{request_id}"
        );
        let (status, answer) = resolver
            .resolve(&format!("unknown-unaudited-{round}"), UNKNOWN_TOKEN)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(answer, json!({"active": false}));
        let (status, answer) = resolver
            .resolve(&format!("active-unaudited-{round}"), &resolver.alice.key)
            .await;
        assert_eq!((status, &answer["active"]), (StatusCode::OK, &json!(true)));
    }
    let (status, bytes) = resolver.resolve_raw("malformed-unaudited", "[]").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap()["reasonCode"],
        "body_malformed"
    );
    let (status, bytes) = resolver
        .send(resolve_request("caller-unaudited", &[], "{}"))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap()["reasonCode"],
        "caller_authentication_required"
    );
    assert_eq!(read_audit_records(&resolver.fixture.audit_path), before);
    db.execute_batch("DROP TRIGGER fail_every_audit;").unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn resolution_failures_keep_error_and_refusal_log_levels() {
    let captured = install_trace_capture().start();
    let resolver = resolver().await;
    let (status, _) = captured
        .run(resolver.resolve_raw("refusal-log", "[]"))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    *resolver
        .fixture
        .state
        .access_key_resolution_answer_cap
        .lock()
        .unwrap() = Some(1);
    let (status, _) = captured
        .run(resolver.resolve("size-error-log", &resolver.alice.key))
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    let db = rusqlite::Connection::open(&resolver.fixture.store_path).unwrap();
    db.execute_batch("ALTER TABLE access_keys RENAME TO access_keys_moved;")
        .unwrap();
    let (status, _) = captured
        .run(resolver.resolve("store-error-log", &resolver.alice.key))
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    let events = captured.take_events();
    for (request_id, level, reason, status) in [
        ("refusal-log", "INFO", "body_malformed", 400),
        (
            "size-error-log",
            "ERROR",
            "broker_access_key_answer_too_large",
            503,
        ),
        ("store-error-log", "ERROR", "managed_store_unavailable", 503),
    ] {
        let event = event_by_name_and_agent(&events, "access_key_resolution_failed", request_id);
        assert_eq!(string_field(event, "level"), Some(level));
        assert_eq!(string_field(event, "reasonCode"), Some(reason));
        assert_eq!(number_field(event, "http.statusCode"), Some(status));
        assert_eq!(resolver.records(request_id), Vec::<Value>::new());
    }
}

#[tokio::test]
async fn a_cancelled_resolution_keeps_its_capacity_until_its_lookup_finishes() {
    let resolver = resolver_with(LimitsConfig {
        max_concurrent_access_key_resolutions: 1,
        ..test_limits()
    })
    .await;
    let state = &resolver.fixture.state;
    let in_flight = || {
        state
            .access_key_resolution_ingress
            .global_in_flight_requests()
    };
    let barrier = Arc::new(crate::state::McpBlockingBarrier::default());
    // A failed assertion must not leave the lookup, and so the runtime, held.
    struct Release(Arc<crate::state::McpBlockingBarrier>);
    impl Drop for Release {
        fn drop(&mut self) {
            self.0.release();
        }
    }
    let _release = Release(barrier.clone());
    *state.access_key_resolution_store_barrier.lock().unwrap() = Some(barrier.clone());
    let app = resolver.fixture.app.clone();
    let request = resolve_request(
        "cancelled-lookup",
        &[(CALLER_HEADER, RESOLVER)],
        json!({"key": resolver.alice.key}).to_string(),
    );
    let waiter = tokio::spawn(async move { app.oneshot(request).await });
    // The lookup is inside its blocking task; later requests are not held.
    tokio::time::timeout(Duration::from_secs(10), barrier.reached.notified())
        .await
        .expect("the lookup reaches the store");
    *state.access_key_resolution_store_barrier.lock().unwrap() = None;
    assert_eq!(in_flight(), 1);

    // The caller goes away. Its lookup still runs, and still occupies the
    // only slot of the pool.
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    assert_eq!(in_flight(), 1);
    let (status, answer) = resolver
        .resolve("while-cancelled-lookup-runs", &resolver.alice.key)
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{answer}");
    assert_eq!(answer["reasonCode"], "concurrency_limited");

    // The slot is free once the lookup has returned, and not before.
    barrier.release();
    tokio::time::timeout(Duration::from_secs(10), barrier.completed.notified())
        .await
        .expect("the lookup finishes without its request");
    assert_eq!(in_flight(), 0);
    let (status, answer) = resolver
        .resolve("after-cancelled-lookup", &resolver.alice.key)
        .await;
    assert_eq!((status, &answer["active"]), (StatusCode::OK, &json!(true)));
    assert_eq!(in_flight(), 0);
}

#[tokio::test]
async fn a_cancelled_lookup_of_an_unknown_key_is_still_counted() {
    let resolver = resolver_with(LimitsConfig {
        access_key_resolutions_per_caller_per_minute: 1,
        ..test_limits()
    })
    .await;
    let state = &resolver.fixture.state;
    let barrier = Arc::new(crate::state::McpBlockingBarrier::default());
    struct Release(Arc<crate::state::McpBlockingBarrier>);
    impl Drop for Release {
        fn drop(&mut self) {
            self.0.release();
        }
    }
    let _release = Release(barrier.clone());
    *state.access_key_resolution_store_barrier.lock().unwrap() = Some(barrier.clone());
    let app = resolver.fixture.app.clone();
    let request = resolve_request(
        "cancelled-unknown",
        &[(CALLER_HEADER, RESOLVER)],
        json!({"key": unknown_key(1)}).to_string(),
    );
    let waiter = tokio::spawn(async move { app.oneshot(request).await });
    tokio::time::timeout(Duration::from_secs(10), barrier.reached.notified())
        .await
        .expect("the lookup reaches the store");
    *state.access_key_resolution_store_barrier.lock().unwrap() = None;
    // The caller goes away before its lookup has found that no store holds
    // the key.
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    barrier.release();
    tokio::time::timeout(Duration::from_secs(10), barrier.completed.notified())
        .await
        .expect("the lookup finishes without its request");
    // The lookup counted the unknown key itself: it was the caller's one a
    // minute, although nobody was there to be answered or audited.
    assert_eq!(resolver.records("cancelled-unknown"), Vec::<Value>::new());
    assert_eq!(
        resolver.outcome("after-cancelled", &unknown_key(2)).await,
        rate_limited()
    );
    assert_eq!(
        resolver.outcome("stored", &resolver.alice.key).await,
        answered("active")
    );
    assert_eq!(
        state
            .access_key_resolution_ingress
            .global_in_flight_requests(),
        0
    );
}

#[tokio::test]
async fn a_lookup_that_fails_is_counted_like_a_key_no_store_holds() {
    let resolver = resolver_with(LimitsConfig {
        access_key_resolutions_per_caller_per_minute: 2,
        ..test_limits()
    })
    .await;
    // The store stops answering lookups: another connection moves the table.
    let db = rusqlite::Connection::open(&resolver.fixture.store_path).unwrap();
    db.execute_batch("ALTER TABLE access_keys RENAME TO access_keys_moved;")
        .unwrap();
    // While it cannot answer, no request can be tied to a stored key: each
    // is answered 503 while the caller's rate lasts, whichever key it names,
    // and beyond the rate it is refused. None of these outcomes is audited.
    for (request_id, key) in [
        ("failed-stored", resolver.alice.key.clone()),
        ("failed-unknown", unknown_key(1)),
    ] {
        let (status, answer) = resolver.resolve(request_id, &key).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{answer}");
        assert_eq!(answer["reasonCode"], "managed_store_unavailable");
        assert!(answer.get("active").is_none());
        assert_eq!(resolver.records(request_id), Vec::<Value>::new());
    }
    for (request_id, key) in [
        ("failed-stored-beyond", resolver.alice.key.clone()),
        ("failed-unknown-beyond", unknown_key(2)),
    ] {
        assert_eq!(resolver.outcome(request_id, &key).await, rate_limited());
        assert_eq!(resolver.records(request_id), Vec::<Value>::new());
    }
    // Once the store answers again a stored key is answered at once, in the
    // same window, and an unknown key is still refused by the spent rate.
    db.execute_batch("ALTER TABLE access_keys_moved RENAME TO access_keys;")
        .unwrap();
    assert_eq!(
        resolver
            .outcome("restored-stored", &resolver.alice.key)
            .await,
        answered("active")
    );
    assert_eq!(
        resolver.outcome("restored-unknown", &unknown_key(3)).await,
        rate_limited()
    );
}

#[tokio::test]
async fn refused_callers_are_bounded_by_the_route_and_spend_no_sign_in_capacity() {
    let resolver = resolver_with(LimitsConfig {
        max_concurrent_access_key_resolutions: 2,
        access_key_resolutions_per_caller_per_minute: 4,
        auth_requests_per_source_per_minute: 3,
        ..test_limits()
    })
    .await;
    let state = &resolver.fixture.state;
    let body = || json!({"key": resolver.alice.key}).to_string();
    let refused = |request_id: &'static str, credential: Option<&'static str>| {
        let resolver = &resolver;
        let headers: Vec<(&str, &str)> = credential
            .map(|credential| (CALLER_HEADER, credential))
            .into_iter()
            .collect();
        let request = resolve_request(request_id, &headers, body());
        async move {
            let (status, bytes) = resolver.send(request).await;
            let answer: Value = serde_json::from_slice(&bytes).unwrap();
            assert!(answer.get("active").is_none(), "{answer}");
            (status, answer["reasonCode"].as_str().unwrap().to_string())
        }
    };
    let unknown = Some("Bearer not-a-configured-caller-credential");

    // With the shared pool full, a refused caller is still refused by this
    // route, as itself: nothing of the shared pool is needed to say no.
    let limit = state.current().runtime.limits().max_concurrent_requests;
    let shared: Vec<_> = (0..limit)
        .map(|_| state.shared_ingress.try_global_concurrency(limit).unwrap())
        .collect();
    assert_eq!(
        refused("shared-full-no-credential", None).await,
        (
            StatusCode::UNAUTHORIZED,
            "caller_authentication_required".to_string()
        )
    );
    assert_eq!(
        refused("shared-full-wrong-credential", unknown).await,
        (
            StatusCode::UNAUTHORIZED,
            "caller_authentication_invalid".to_string()
        )
    );
    assert_eq!(
        refused("shared-full-no-capability", Some(OTHER_CALLER)).await,
        (
            StatusCode::FORBIDDEN,
            "broker_caller_access_key_resolution_denied".to_string()
        )
    );
    drop(shared);
    assert_eq!(
        resolver.records("shared-full-no-capability"),
        Vec::<Value>::new()
    );
    assert_eq!(
        resolver.records("shared-full-wrong-credential"),
        Vec::<Value>::new()
    );

    // Requests that present no configured caller's credential are counted
    // against their address in this route's own window. The window is not
    // the address's sign-in budget, and it is as small: three a minute
    // here, not the four a resolving caller has for unknown keys. The two
    // above were the first two.
    assert_eq!(refused("unknown-3", None).await.0, StatusCode::UNAUTHORIZED);
    for (request_id, credential) in [("unknown-4", unknown), ("unknown-5", None)] {
        assert_eq!(
            refused(request_id, credential).await,
            (StatusCode::TOO_MANY_REQUESTS, "rate_limited".to_string()),
            "{request_id}"
        );
        // Beyond the bound nothing is recorded for it.
        assert_eq!(
            resolver.records(request_id),
            Vec::<Value>::new(),
            "{request_id}"
        );
    }
    // A caller without the capability is counted in its own caller window,
    // at the same small number.
    for request_id in ["no-capability-2", "no-capability-3"] {
        assert_eq!(
            refused(request_id, Some(OTHER_CALLER)).await.0,
            StatusCode::FORBIDDEN,
            "{request_id}"
        );
    }
    assert_eq!(
        refused("no-capability-4", Some(OTHER_CALLER)).await,
        (StatusCode::TOO_MANY_REQUESTS, "rate_limited".to_string())
    );
    assert_eq!(resolver.records("no-capability-4"), Vec::<Value>::new());
    // None of the refusals spent the address's sign-in budget or the
    // capable caller's rate. The fixture's own sign-in used one of the
    // budget's three; the two that remain and a resolution are served.
    for request_id in ["sign-in-1", "sign-in-2"] {
        assert_eq!(
            sign_in_status(&resolver.fixture, request_id).await,
            StatusCode::OK,
            "{request_id}"
        );
    }
    let (status, answer) = resolver
        .resolve("capable-caller", &resolver.alice.key)
        .await;
    assert_eq!((status, &answer["active"]), (StatusCode::OK, &json!(true)));

    // With this route's pool full, a refused caller waits its turn like any
    // other request to the route.
    let held = [
        state
            .access_key_resolution_ingress
            .try_global_concurrency(2)
            .unwrap(),
        state
            .access_key_resolution_ingress
            .try_global_concurrency(2)
            .unwrap(),
    ];
    assert_eq!(
        refused("pool-full-no-capability", Some(OTHER_CALLER)).await,
        (
            StatusCode::TOO_MANY_REQUESTS,
            "concurrency_limited".to_string()
        )
    );
    assert_eq!(
        refused("pool-full-no-credential", None).await,
        (
            StatusCode::TOO_MANY_REQUESTS,
            "concurrency_limited".to_string()
        )
    );
    drop(held);
    assert_eq!(
        state
            .access_key_resolution_ingress
            .global_in_flight_requests(),
        0
    );
    assert_eq!(
        resolver.records("pool-full-no-capability"),
        Vec::<Value>::new()
    );
}

#[tokio::test]
async fn a_forbidden_header_is_refused_within_the_pool_and_the_caller_rate() {
    let resolver = resolver_with(LimitsConfig {
        max_concurrent_access_key_resolutions: 1,
        access_key_resolutions_per_caller_per_minute: 2,
        ..test_limits()
    })
    .await;
    let state = &resolver.fixture.state;
    let forbidden = |request_id: &'static str| {
        let resolver = &resolver;
        let request = resolve_request(
            request_id,
            &[(CALLER_HEADER, RESOLVER), ("x-agent-access-user", "alice")],
            json!({"key": resolver.alice.key}).to_string(),
        );
        async move {
            let (status, bytes) = resolver.send(request).await;
            let answer: Value = serde_json::from_slice(&bytes).unwrap();
            (status, answer["reasonCode"].as_str().unwrap().to_string())
        }
    };

    // With the pool full the request is turned away before its header is
    // judged: no refusal is audited outside the pool.
    let held = state
        .access_key_resolution_ingress
        .try_global_concurrency(1)
        .unwrap();
    assert_eq!(
        forbidden("header-pool-full").await,
        (
            StatusCode::TOO_MANY_REQUESTS,
            "concurrency_limited".to_string()
        )
    );
    drop(held);
    let refusals = |request_id: &str| resolver.records(request_id).len();
    assert_eq!(refusals("header-pool-full"), 0);

    // Each refusal spends one request of the caller's rate, and the rate
    // bounds them like any other request of that caller.
    for request_id in ["header-1", "header-2"] {
        assert_eq!(
            forbidden(request_id).await,
            (StatusCode::BAD_REQUEST, "input_invalid".to_string()),
            "{request_id}"
        );
        assert_eq!(refusals(request_id), 0, "{request_id}");
    }
    assert_eq!(
        forbidden("header-3").await,
        (StatusCode::TOO_MANY_REQUESTS, "rate_limited".to_string())
    );
    assert_eq!(resolver.records("header-3"), Vec::<Value>::new());
    assert_eq!(resolver.records("header-pool-full"), Vec::<Value>::new());
    assert_eq!(
        state
            .access_key_resolution_ingress
            .global_in_flight_requests(),
        0
    );
}

#[tokio::test]
async fn a_request_that_carries_any_configured_identity_assertion_is_refused() {
    // A second identity source under a header of the operator's choosing.
    let resolver = resolver_configured(test_limits(), |config| {
        config
            .identity
            .sources
            .push(agent_access_core::IdentitySourceConfig {
                name: "second".to_string(),
                kind: "broker_tokens".to_string(),
                header: "X-Example-Agent-Credential".to_string(),
                scheme: "Bearer".to_string(),
                principals: vec![],
            });
    })
    .await;
    // Every header under which this configuration accepts a principal
    // credential, read from the configuration, and the fixed carriers of an
    // identity: a browser session, a forwarded fingerprint, an asserted
    // username and a context.
    let configured = resolver
        .fixture
        .state
        .current()
        .runtime
        .config()
        .identity
        .sources
        .iter()
        .map(|source| source.header.to_ascii_lowercase())
        .collect::<Vec<_>>();
    assert_eq!(
        configured,
        ["x-agent-token", "x-example-agent-credential"],
        "the configured identity-source headers"
    );
    let admin = format!("Bearer {}", resolver.fixture.admin_token);
    let mut carriers = configured
        .iter()
        .map(|header| (header.clone(), admin.clone()))
        .collect::<Vec<_>>();
    carriers.extend(
        [
            ("authorization", admin.as_str()),
            ("cookie", resolver.fixture.cookie.as_str()),
            (
                "x-aw-identity-token-sha256",
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            ),
            ("x-agent-access-user", "alice"),
            ("x-agent-access-context", "default"),
        ]
        .map(|(name, value)| (name.to_string(), value.to_string())),
    );
    for (name, value) in &carriers {
        let request_id = format!("carrier-{name}");
        let (status, bytes) = resolver
            .send(resolve_request(
                &request_id,
                &[(CALLER_HEADER, RESOLVER), (name.as_str(), value.as_str())],
                json!({"key": resolver.alice.key}).to_string(),
            ))
            .await;
        let answer: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(status, StatusCode::BAD_REQUEST, "{name}: {answer}");
        assert_eq!(answer["reasonCode"], "input_invalid", "{name}");
        assert!(answer.get("active").is_none(), "{name}");
        // The refusal names the header and nothing the header carried.
        let text = String::from_utf8(bytes).unwrap().to_ascii_lowercase();
        assert!(text.contains(name.as_str()), "{name}: {text}");
        assert!(!text.contains(&value.to_ascii_lowercase()), "{name}");
        assert_eq!(resolver.records(&request_id), Vec::<Value>::new());
    }
    // Nothing was resolved for any of them.
    assert_eq!(
        resolver
            .store
            .access_key(&resolver.alice.record.key_id)
            .unwrap()
            .unwrap()
            .last_used_at,
        None
    );
    // A header that asserts nobody is no concern of the route.
    let (status, bytes) = resolver
        .send(resolve_request(
            "carrier-none",
            &[(CALLER_HEADER, RESOLVER), ("x-example-trace", "abc")],
            json!({"key": resolver.alice.key}).to_string(),
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap()["active"],
        true
    );
}

#[tokio::test]
async fn a_wrong_method_on_the_resolution_path_is_refused_at_once_and_reaches_nothing() {
    let resolver = resolver_with(LimitsConfig {
        auth_requests_per_source_per_minute: 2,
        ..test_limits()
    })
    .await;
    let state = &resolver.fixture.state;
    let key = json!({"key": resolver.alice.key}).to_string();
    // What a request may carry besides its method: nothing, a caller's
    // credential (valid, unknown, or without the capability), a header the
    // route forbids with a nomination to strip it, and a signed-in person's
    // session with its request-forgery header.
    let variants: Vec<(&str, Vec<(&str, &str)>)> = vec![
        ("bare", vec![]),
        ("caller", vec![(CALLER_HEADER, RESOLVER)]),
        (
            "unknown-caller",
            vec![(CALLER_HEADER, "Bearer not-a-configured-caller-credential")],
        ),
        ("other-caller", vec![(CALLER_HEADER, OTHER_CALLER)]),
        (
            "nominated",
            vec![
                (CALLER_HEADER, RESOLVER),
                ("x-agent-access-user", "alice"),
                ("connection", "x-agent-access-user"),
            ],
        ),
        (
            "session",
            vec![
                ("cookie", resolver.fixture.cookie.as_str()),
                ("host", "localhost"),
                ("origin", "http://localhost"),
                ("x-agent-access-csrf", resolver.fixture.csrf.as_str()),
            ],
        ),
    ];
    let mut answers = BTreeSet::new();
    for method in [
        Method::GET,
        Method::HEAD,
        Method::PUT,
        Method::PATCH,
        Method::DELETE,
        Method::OPTIONS,
    ] {
        for (variant, headers) in &variants {
            let request_id = format!("method-{method}-{variant}");
            let mut builder = Request::builder()
                .method(method.clone())
                .uri("/v1/access-keys/resolve")
                .extension(ConnectInfo(
                    "127.0.0.1:43120".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, &request_id)
                .header(CONTENT_TYPE, "application/json");
            for (name, value) in headers {
                builder = builder.header(*name, *value);
            }
            let response = resolver
                .fixture
                .app
                .clone()
                .oneshot(builder.body(Body::from(key.clone())).unwrap())
                .await
                .unwrap();
            // The same answer whatever the request carried: the method is
            // judged first, so the answer says nothing about a credential.
            let headers = response.headers();
            answers.insert((
                response.status(),
                headers
                    .get(axum::http::header::ALLOW)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string),
                headers
                    .get(axum::http::header::CACHE_CONTROL)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string),
                axum::body::to_bytes(response.into_body(), 1024)
                    .await
                    .unwrap()
                    .to_vec(),
            ));
            // Nothing is recorded for it, under any action.
            assert_eq!(
                resolver.records(&request_id),
                Vec::<Value>::new(),
                "{request_id}"
            );
        }
    }
    assert_eq!(
        answers,
        BTreeSet::from([(
            StatusCode::METHOD_NOT_ALLOWED,
            Some("POST".to_string()),
            Some("no-store".to_string()),
            Vec::new(),
        )])
    );
    // Nothing was spent: no pool slot is held, the address's window of
    // this route still has its two refusals a minute, its sign-in budget
    // its remaining one, and the caller's rate is untouched.
    assert_eq!(
        state
            .access_key_resolution_ingress
            .global_in_flight_requests(),
        0
    );
    assert_eq!(state.shared_ingress.global_in_flight_requests(), 0);
    for request_id in ["post-unauthenticated-1", "post-unauthenticated-2"] {
        let (status, _) = resolver
            .send(resolve_request(request_id, &[], key.clone()))
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{request_id}");
    }
    assert_eq!(
        sign_in_status(&resolver.fixture, "sign-in-after-methods").await,
        StatusCode::OK
    );
    // No key was revoked or used through the path: a DELETE under a
    // person's session reached no route of theirs.
    let record = resolver
        .store
        .access_key(&resolver.alice.record.key_id)
        .unwrap()
        .unwrap();
    assert_eq!((record.revoked_at, record.last_used_at), (None, None));
    assert_eq!(
        resolver
            .outcome("post-after-methods", &resolver.alice.key)
            .await,
        answered("active")
    );
}

#[tokio::test]
async fn only_an_object_with_one_key_member_is_a_request() {
    let resolver = resolver().await;
    let token = &resolver.alice.key;
    for (request_id, body) in [
        // An array is not the object, whatever it holds.
        ("body-array", json!([token]).to_string()),
        ("body-nested-array", json!([{"key": token}]).to_string()),
        ("body-string", json!(token).to_string()),
        ("body-null", "null".to_string()),
        // One member, once, and a string.
        (
            "body-duplicate-member",
            format!(r#"{{"key":"{token}","key":"{token}"}}"#),
        ),
        ("body-key-array", json!({"key": [token]}).to_string()),
        (
            "body-unknown-member",
            json!({"key": token, "hint": "x"}).to_string(),
        ),
        ("body-empty-object", "{}".to_string()),
    ] {
        let (status, bytes) = resolver.resolve_raw(request_id, body).await;
        let answer: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(status, StatusCode::BAD_REQUEST, "{request_id}: {answer}");
        assert_eq!(answer["reasonCode"], "body_malformed", "{request_id}");
        assert!(answer.get("active").is_none(), "{request_id}");
        // The refusal names the one member the body takes.
        assert_eq!(
            answer["error"]["message"],
            "request body must be a JSON object with exactly the member key",
            "{request_id}"
        );
        assert_eq!(resolver.records(request_id), Vec::<Value>::new());
    }
    assert_eq!(
        resolver
            .store
            .access_key(&resolver.alice.record.key_id)
            .unwrap()
            .unwrap()
            .last_used_at,
        None
    );
    // The same token in the object resolves.
    let (status, answer) = resolver.resolve("body-object", token).await;
    assert_eq!((status, &answer["active"]), (StatusCode::OK, &json!(true)));
}

#[tokio::test]
async fn an_answer_over_the_size_limit_is_unavailable_and_no_part_of_it_is_given() {
    let resolver = resolver().await;
    // Under an accepted configuration no answer exceeds the limit, so the
    // limit is lowered here: an active answer no longer fits, the inactive
    // answer still does.
    *resolver
        .fixture
        .state
        .access_key_resolution_answer_cap
        .lock()
        .unwrap() = Some(64);
    let (status, bytes) = resolver
        .resolve_raw(
            "answer-too-large",
            json!({"key": resolver.alice.key}).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let answer: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(answer["reasonCode"], "broker_access_key_answer_too_large");
    assert_eq!(answer["decision"], "error");
    let text = String::from_utf8(bytes).unwrap();
    for part in ["\"active\"", "\"subject\"", "\"types\"", "ak_"] {
        assert!(!text.contains(part), "{part}: {text}");
    }
    assert_eq!(resolver.records("answer-too-large"), Vec::<Value>::new());

    let (status, bytes) = resolver
        .resolve_raw(
            "inactive-still-fits",
            json!({"key": UNKNOWN_TOKEN}).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, br#"{"active":false}"#);
}

#[tokio::test]
async fn emitted_stored_inactive_answers_follow_the_fixture_index() {
    let resolver = resolver().await;
    let index = fixture_json("index.json");
    for (request_id, key, owner) in [
        (
            "inactive-portal",
            &resolver.alice,
            json!({"kind": "user", "id": "alice"}),
        ),
        (
            "inactive-service",
            &resolver.robot,
            json!({"kind": "service_account", "id": "robot"}),
        ),
    ] {
        resolver
            .store
            .revoke_access_key(&key.record.key_id, None, "admin")
            .unwrap()
            .unwrap();
        let (status, bytes) = resolver
            .resolve_raw(request_id, json!({"key": key.key}).to_string())
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            assert_emitted_answer(&bytes, &index),
            json!({
                "active": false, "keyId": key.record.key_id, "owner": owner, "reason": "revoked"
            })
        );
        assert_eq!(resolver.records(request_id), Vec::<Value>::new());
    }
    resolver
        .store
        .set_account_username_setting(
            "alice",
            &agent_access_core::AccountUsernameSetting::ManualNone,
            "admin",
        )
        .unwrap()
        .unwrap();
    let (status, bytes) = resolver
        .resolve_raw(
            "inactive-no-owner",
            json!({"key": resolver.alice.key}).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        assert_emitted_answer(&bytes, &index),
        json!({
            "active": false, "keyId": resolver.alice.record.key_id, "owner": null, "reason": "revoked"
        })
    );
    assert_eq!(resolver.records("inactive-no-owner"), Vec::<Value>::new());
}

#[tokio::test]
async fn access_keys_are_not_broker_credentials_on_http_surfaces() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    let application_secret = "synthetic-client-secret-0123456789";
    let secret_path = temp_path("access-key-application-secret");
    std::fs::write(&secret_path, application_secret).unwrap();
    let resolver = resolver_configured(test_limits(), |config| {
        config.identity.sources[0].header = "Authorization".into();
        config.mcp.enabled = true;
        config.mcp.public_url = Some("https://broker.example.test/mcp".into());
        config
            .gateways
            .insert("gitlab_git".into(), test_git_gateway_config());
        config.credentials.service.insert(
            "gitlab_git".into(),
            config.credentials.service["fake"].clone(),
        );
        config.applications.insert(
            "example-runner".into(),
            agent_access_core::ApplicationConfig {
                display_name: "Example Runner".into(),
                client_secret_ref: format!("file:{}", secret_path.display()),
                redirect_uris: vec!["https://runner.example.test/callback".into()],
                connect: agent_access_core::ApplicationConnectLevel::ReadOnly,
                allowed_execution_contexts: vec!["default".into()],
                allowed_services: None,
                access_token_ttl: "8h".into(),
                refresh_idle_ttl: "90d".into(),
            },
        );
    })
    .await;
    for (cookie, expected) in [
        (resolver.fixture.cookie.clone(), StatusCode::OK),
        (
            format!("aab_session={}", resolver.alice.key),
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        let response = resolver
            .fixture
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/me")
                    .extension(ConnectInfo(
                        "127.0.0.1:43120".parse::<SocketAddr>().unwrap(),
                    ))
                    .header(REQUEST_ID_HEADER, "access-key-cookie")
                    .header("Host", "localhost")
                    .header("Origin", "http://localhost")
                    .header("Cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    let initialize = || {
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"access-key-test","version":"1"}
        }})
    };
    for (token, expected) in [
        (&resolver.fixture.agent_tokens[0], StatusCode::OK),
        (&resolver.alice.key, StatusCode::UNAUTHORIZED),
    ] {
        let response = resolver
            .fixture
            .app
            .clone()
            .oneshot(super::mcp::request(
                Method::POST,
                Some(token),
                None,
                Some(initialize()),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    let gateway = crate::router::build_gateway_router(resolver.fixture.state.clone());
    let basic =
        |user: &str, token: &str| format!("Basic {}", STANDARD.encode(format!("{user}:{token}")));
    for (auth, expected) in [
        // A real agent token gets as far as policy; this fixture grants no Git access.
        (
            basic("agent-access", &resolver.fixture.agent_tokens[0]),
            StatusCode::FORBIDDEN,
        ),
        (
            basic("agent-access", &resolver.alice.key),
            StatusCode::UNAUTHORIZED,
        ),
        // Git's configured transport accepts Basic only; Bearer cannot grant access either.
        (
            format!("Bearer {}", resolver.alice.key),
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        let response = gateway_get(
            gateway.clone(),
            "/sip/service.git/info/refs?service=git-upload-pack",
            "git.example.test",
            "access-key-git",
            Some(&auth),
        )
        .await;
        assert_eq!(response.status(), expected);
    }
    for path in ["/v1/applications/token", "/v1/applications/revoke"] {
        let response = authed_json_request(
            resolver.fixture.app.clone(),
            Method::POST,
            path,
            "access-key-client",
            "Authorization",
            basic("example-runner", &resolver.alice.key),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response_json(response).await,
            json!({"error":"invalid_client"})
        );
    }
    // A real client can reach revocation, but cannot revoke an access key there.
    let response = resolver
        .fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/applications/revoke")
                .header(REQUEST_ID_HEADER, "access-key-application-revoke")
                .extension(ConnectInfo(
                    "127.0.0.1:43120".parse::<SocketAddr>().unwrap(),
                ))
                .header("Authorization", basic("example-runner", application_secret))
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("token={}", resolver.alice.key)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let (status, answer) = resolver
        .resolve("http-surfaces-still-active", &resolver.alice.key)
        .await;
    assert_eq!((status, &answer["active"]), (StatusCode::OK, &json!(true)));
}
