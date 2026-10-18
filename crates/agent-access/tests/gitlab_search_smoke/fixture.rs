//! Synthetic GitLab HTTP and managed identity setup for the search acceptance tests.
//! Every provider request goes through the production assembly and HTTP transport.
use agent_access_broker_host::test_support::{FixtureDir, IsolatedBroker, RunningBroker};
use agent_access_core::{
    BrokerTokenClass, BrokerTokenHasher, BrokerTokenIssueRequest, BrokerTokensConfig,
    LocalPasswordHasher, LocalPasswordWriteRequest, ManagedResourceCatalog, ManagedStore,
    ManagedStoreConfig, ManagedStoreOpenMode, PrincipalAccessPatchRequest, PrincipalRole,
    PrincipalWriteRequest,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    process::Command,
    sync::{Arc, Mutex},
};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

pub const ACTIONS: [&str; 7] = [
    "project.search",
    "search.issues",
    "search.merge_requests",
    "search.code",
    "search.commits",
    "search.wiki",
    "search.comments",
];
pub const CATEGORIES: [(&str, &str); 6] = [
    ("issues", "issues"),
    ("merge-requests", "merge_requests"),
    ("code", "blobs"),
    ("commits", "commits"),
    ("wiki", "wiki_blobs"),
    ("comments", "notes"),
];
pub const QUERY: &str = "synthetic-rotation-query";
pub const FIRST_PROJECT: &str = "engineering/api";
pub const SECOND_PROJECT: &str = "engineering/new/service";
pub const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
pub const FORBIDDEN: [&str; 5] = [
    "engineering/private/denied-repository",
    "engineering-sibling/denied-repository",
    "DENIED_CANDIDATE_TITLE",
    "DENIED_CANDIDATE_BODY",
    "UNPROJECTED_UPSTREAM_FIELD",
];

#[derive(Clone, Copy, Debug)]
pub enum Credentials {
    Service,
    Personal,
    OAuth,
}

impl Credentials {
    fn mode(self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Personal | Self::OAuth => "per_user",
        }
    }

    pub fn authorization(self) -> &'static str {
        match self {
            Self::Service => "Bearer search-service-token",
            Self::Personal => "Bearer search-personal-token",
            Self::OAuth => "Bearer search-oauth-access-1",
        }
    }
}

pub struct GitlabState {
    pub first_path: String,
    pub reject_first_access: bool,
    pub refreshes: usize,
    consent: usize,
}

impl Default for GitlabState {
    fn default() -> Self {
        Self {
            first_path: FIRST_PROJECT.into(),
            reject_first_access: false,
            refreshes: 0,
            consent: 0,
        }
    }
}

#[derive(Clone)]
struct GitlabHttp {
    state: Arc<Mutex<GitlabState>>,
    origin: String,
}

impl Respond for GitlabHttp {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let route = request.url.path();
        let mut state = self.state.lock().unwrap();
        if request.method.as_str() == "POST" && route == "/oauth/token" {
            let form: BTreeMap<_, _> = url::form_urlencoded::parse(&request.body)
                .into_owned()
                .collect();
            let number = match form.get("grant_type").map(String::as_str) {
                Some("authorization_code") => {
                    state.consent += 1;
                    1 + 2 * (state.consent - 1)
                }
                Some("refresh_token") => {
                    state.refreshes += 1;
                    2
                }
                _ => return ResponseTemplate::new(400),
            };
            return ResponseTemplate::new(200).set_body_json(json!({
                "access_token":format!("search-oauth-access-{number}"),
                "refresh_token":format!("search-oauth-refresh-{number}"),
                "token_type":"Bearer", "expires_in":3600, "scope":"api"
            }));
        }
        if request.method.as_str() == "POST" && route == "/oauth/revoke" {
            return ResponseTemplate::new(200).set_body_json(json!({}));
        }
        if request.method.as_str() != "GET" {
            return ResponseTemplate::new(405);
        }
        let authorization = request
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok());
        if !authorization.is_some_and(|value| {
            matches!(
                value,
                "Bearer search-service-token"
                    | "Bearer search-personal-token"
                    | "Bearer search-oauth-access-1"
                    | "Bearer search-oauth-access-2"
                    | "Bearer search-oauth-access-3"
            )
        }) {
            return ResponseTemplate::new(401);
        }
        if route == "/api/v4/user" {
            return ResponseTemplate::new(200)
                .set_body_json(json!({"id":77,"username":"alice","name":"Alice Example"}));
        }
        let query: BTreeMap<_, _> = request.url.query_pairs().into_owned().collect();
        if route.ends_with("/search") {
            if state.reject_first_access && authorization == Some("Bearer search-oauth-access-1") {
                return ResponseTemplate::new(401).set_body_json(json!({"message":"expired"}));
            }
            let page = query
                .get("page")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap();
            let scope = query.get("scope").unwrap().as_str();
            let search = query.get("search").unwrap().as_str();
            assert_eq!(
                query.get("search_type").map(String::as_str),
                Some("advanced")
            );
            assert_eq!(query.get("per_page").map(String::as_str), Some("4"));
            let explicit = route
                .strip_prefix("/api/v4/projects/")
                .and_then(|value| value.strip_suffix("/search"));
            if let Some(id) = explicit {
                assert_eq!(id, "101");
            }
            let (ids, next) = match search {
                "empty-page-query" => match page {
                    1 => (vec![9901, 9902], "2"),
                    2 => (vec![101, 102], "3"),
                    _ => (vec![], ""),
                },
                "move-query" => (
                    if explicit.is_some() {
                        vec![101]
                    } else {
                        vec![101, 102]
                    },
                    if page == 1 { "2" } else { "" },
                ),
                "unavailable-query" => (vec![9903, 9903, 9904, 101], ""),
                "wrong-owner-query" => (vec![102], ""),
                "comment-parents-query" => (vec![101, 102, 101, 102], ""),
                "wiki-kinds-query" => (vec![101], ""),
                _ => (
                    if explicit.is_some() {
                        vec![101]
                    } else {
                        vec![101, 102, 9901, 9902]
                    },
                    "",
                ),
            };
            let mut hits: Vec<_> = ids
                .iter()
                .enumerate()
                .map(|(index, id)| {
                    let mut hit = self.hit(scope, *id, index);
                    if search == "comment-parents-query" {
                        hit["noteable_type"] =
                            json!(["Issue", "MergeRequest", "Commit", "Snippet"][index]);
                        // A numeric database ID must never become a commit SHA or a fabricated URL.
                        if index == 2 {
                            hit.as_object_mut().unwrap().remove("noteable_iid");
                        }
                    }
                    if search == "unknown-parent-query" {
                        hit["noteable_type"] = json!("UnknownParent");
                    }
                    if search == "contradictory-mr-query" {
                        hit["target_project_id"] = json!(9902);
                    }
                    hit
                })
                .collect();
            if search == "wiki-kinds-query" {
                hits.push(
                    json!({"group_id":9905,"path":"private-wiki","data":"DENIED_CANDIDATE_BODY"}),
                );
            }
            let response = ResponseTemplate::new(200)
                .insert_header("X-Next-Page", next)
                .set_body_json(hits);
            return match search {
                "missing-header-query" => response,
                "wrong-header-query" => response.insert_header("X-Search-Type", "basic"),
                _ => response.insert_header("X-Search-Type", "advanced"),
            };
        }
        if route == "/api/v4/projects" {
            for (key, value) in [
                ("simple", "false"),
                ("pagination", "keyset"),
                ("order_by", "id"),
                ("sort", "asc"),
                ("per_page", "4"),
                ("search_namespaces", "true"),
            ] {
                assert_eq!(query.get(key).map(String::as_str), Some(value), "{key}");
            }
            let after = query
                .get("id_after")
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0);
            let projects: Vec<_> = [101, 102, 9901, 9902]
                .into_iter()
                .filter(|id| *id > after)
                .map(|id| self.project(id, &state.first_path))
                .collect();
            return ResponseTemplate::new(200).set_body_json(projects);
        }
        if let Some(locator) = route.strip_prefix("/api/v4/projects/") {
            let locator = percent_encoding::percent_decode_str(locator)
                .decode_utf8()
                .unwrap();
            let id = match locator.as_ref() {
                "101" | FIRST_PROJECT | "engineering/renamed" => 101,
                "102" | SECOND_PROJECT => 102,
                "9901" => 9901,
                "9902" => 9902,
                "9903" => return ResponseTemplate::new(404),
                "9904" => return ResponseTemplate::new(403),
                _ => return ResponseTemplate::new(404),
            };
            return ResponseTemplate::new(200).set_body_json(self.project(id, &state.first_path));
        }
        ResponseTemplate::new(404)
    }
}

impl GitlabHttp {
    fn project(&self, id: u64, first_path: &str) -> Value {
        let project = match id {
            101 => first_path,
            102 => SECOND_PROJECT,
            9901 => FORBIDDEN[0],
            _ => FORBIDDEN[1],
        };
        json!({"id":id,"path_with_namespace":project,"name":if id < 9000 {"Synthetic repository"} else {FORBIDDEN[2]},
            "description":if id < 9000 {"Synthetic description"} else {FORBIDDEN[3]},
            "web_url":format!("{}/{project}",self.origin),"default_branch":"main","visibility":"private","archived":false,
            "extra":"UNPROJECTED_UPSTREAM_FIELD"})
    }

    fn hit(&self, scope: &str, project_id: u64, index: usize) -> Value {
        let title = if project_id < 9000 {
            "Authorized rotation result"
        } else {
            FORBIDDEN[2]
        };
        let body = if project_id < 9000 {
            "Authorized synthetic preview"
        } else {
            FORBIDDEN[3]
        };
        let mut hit = json!({"project_id":project_id,"id":700 + index,"iid":7 + index,"title":title,
            "state":"opened","description":body,"extra":"UNPROJECTED_UPSTREAM_FIELD",
            // Even an authorized hit's indexed URL can belong to a different repository.
            "web_url":format!("{}/{}/-/issues/7",self.origin,FORBIDDEN[0])});
        match scope {
            "issues" => {}
            "merge_requests" => {
                hit["target_project_id"] = json!(project_id);
                hit["source_project_id"] = json!(9902);
                hit["source_project"] =
                    json!({"path_with_namespace":FORBIDDEN[1],"description":FORBIDDEN[3]});
            }
            "blobs" => {
                hit["path"] = json!("src/rotation.rs");
                hit["ref"] = json!("main");
                hit["startline"] = json!(12);
                hit["data"] = json!(body);
            }
            "commits" => {
                hit["id"] = json!(COMMIT);
                hit["message"] = json!(body);
            }
            "wiki_blobs" => {
                hit["path"] = json!("Operations/Rotation");
                hit["data"] = json!(body);
            }
            "notes" => {
                hit["body"] = json!(body);
                hit["noteable_type"] = json!("Issue");
                hit["noteable_id"] = json!(800 + index);
                hit["noteable_iid"] = json!(7 + index);
            }
            _ => panic!("unexpected fixture scope"),
        }
        hit
    }
}

pub struct Fixture {
    pub broker: RunningBroker,
    pub server: MockServer,
    pub state: Arc<Mutex<GitlabState>>,
    pub token: String,
    pub token_id: String,
    pub narrow_token: String,
    pub discovery_token: String,
    client_config: PathBuf,
    client: reqwest::Client,
    cookie: String,
    csrf: String,
}

impl Fixture {
    pub async fn start(mode: Credentials, actions: &[&str]) -> Self {
        let server = MockServer::start().await;
        let state = Arc::new(Mutex::new(GitlabState::default()));
        Mock::given(|_: &Request| true)
            .respond_with(GitlabHttp {
                state: state.clone(),
                origin: server.uri(),
            })
            .mount(&server)
            .await;
        let application = IsolatedBroker::new(
            agent_access_broker::composition().unwrap(),
            agent_access_broker::build_identity(),
        )
        .unwrap();
        let directory = application.directory().clone();
        let hash_key = secret(&directory, "hash-key", &URL_SAFE_NO_PAD.encode([21_u8; 32]));
        let pepper = secret(&directory, "pepper", &URL_SAFE_NO_PAD.encode([22_u8; 32]));
        secret(&directory, "csrf-key", &URL_SAFE_NO_PAD.encode([23_u8; 32]));
        secret(
            &directory,
            "encryption-key",
            &URL_SAFE_NO_PAD.encode([24_u8; 32]),
        );
        secret(&directory, "client-secret", "synthetic-oauth-client-secret");
        secret(&directory, "service-token", "search-service-token");
        let personal_token = secret(&directory, "personal-token", "search-personal-token");
        directory.secret_file("personal-store.json", json!({"credentials":[{"principal":"alice","type":"bearer_token","token_ref":personal_token}]}).to_string()).unwrap();
        let store = ManagedStore::open(
            &ManagedStoreConfig {
                kind: "sqlite".into(),
                path: directory.join("store.sqlite").display().to_string(),
                require_registered_principal_for_invocation: false,
                auto_migrate: true,
            },
            ManagedStoreOpenMode::Startup,
        )
        .unwrap();
        store
            .create_principal(PrincipalWriteRequest {
                role: PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "admin".into(),
                kind: "user".into(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "test".into(),
            })
            .unwrap();
        store
            .patch_principal_access(PrincipalAccessPatchRequest {
                principal_id: "admin".into(),
                role: Some(PrincipalRole::Admin),
                self_service_enabled: None,
                actor: "test".into(),
            })
            .unwrap();
        store
            .create_principal(PrincipalWriteRequest {
                role: PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "alice".into(),
                kind: "user".into(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "test".into(),
            })
            .unwrap();
        store
            .enable_local_password(
                &LocalPasswordHasher::load("browser_auth.local_password.pepper_ref", &pepper)
                    .unwrap(),
                LocalPasswordWriteRequest {
                    principal_id: "alice".into(),
                    password: "alice-password".into(),
                    min_password_length: 8,
                    password_change_required: false,
                    actor: "test".into(),
                },
            )
            .unwrap();
        let hasher = BrokerTokenHasher::load(&BrokerTokensConfig {
            hash_key_ref: hash_key,
            ..BrokerTokensConfig::default()
        })
        .unwrap();
        // This fixture's policy is TOML-owned, so token issuance must validate
        // its resource reference against that catalog rather than the empty
        // managed resource tables. The production Broker uses the same port.
        let catalog: ManagedResourceCatalog = serde_json::from_value(json!({
            "resources":[{"id":"api","resourceType":"git_repository",
                "selector":{"kind":"exact","value":FIRST_PROJECT},
                "allowedExecutionContexts":["default"],"enabled":true}],
            "resourceGroups":[]
        }))
        .unwrap();
        let issue = |name: &str, restrictions: Option<Value>| {
            let mut scopes = json!({"allowedExecutionContexts":["default"]});
            if let Some(restrictions) = restrictions {
                scopes["allowedServices"] = json!(["gitlab"]);
                scopes["serviceRestrictions"] = json!({"gitlab":restrictions});
            }
            store
                .issue_broker_token_with_catalog(
                    &hasher,
                    BrokerTokenIssueRequest {
                        principal_id: "alice".into(),
                        name: name.into(),
                        token_class: BrokerTokenClass::AgentInvoke,
                        scopes,
                        expires_at: None,
                        created_by: "test".into(),
                    },
                    Some(&catalog),
                )
                .unwrap()
        };
        let unrestricted = issue("search", None);
        let narrow_token = issue(
            "one repository",
            Some(json!({"actions":ACTIONS,"resources":{"resourceIds":["api"]}})),
        )
        .token;
        let discovery_token = issue(
            "discovery only",
            Some(json!({"actions":["project.search"]})),
        )
        .token;
        drop(store);
        let document = document(
            &directory,
            &server.uri(),
            &application.public_url(),
            mode,
            actions,
        );
        let broker = application.config_document(document).start().await.unwrap();
        let client_config = directory.join("client.toml");
        let token_path = directory
            .secret_file("agent-token", &unrestricted.token)
            .unwrap();
        std::fs::write(&client_config,format!("[service]\nurl = {:?}\n[identity]\nheader = \"Authorization\"\nscheme = \"Bearer\"\ntoken_file = {:?}\n",broker.public_url(),token_path.display().to_string())).unwrap();
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let login = client
            .post(format!("{}/v1/auth/local/login", broker.public_url()))
            .header("Host", "127.0.0.1")
            .header("Origin", "http://127.0.0.1")
            .json(&json!({"principalId":"alice","password":"alice-password"}))
            .send()
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::OK);
        let cookie = login.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let csrf = login.json::<Value>().await.unwrap()["result"]["csrfToken"]
            .as_str()
            .unwrap()
            .to_string();
        let fixture = Self {
            broker,
            server,
            state,
            token: unrestricted.token,
            token_id: unrestricted.record.token_id,
            narrow_token,
            discovery_token,
            client_config,
            client,
            cookie,
            csrf,
        };
        if matches!(mode, Credentials::OAuth) {
            fixture.connect("connect").await;
        }
        fixture
    }

    pub fn cli(&self, args: &[&str]) -> std::process::Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("AGENT_ACCESS_") {
                command.env_remove(key);
            }
        }
        command
            .arg("--config")
            .arg(&self.client_config)
            .args(args)
            .output()
            .unwrap()
    }

    pub async fn invoke(&self, token: &str, action: &str, inputs: Value) -> (StatusCode, Value) {
        let response = self
            .client
            .post(format!(
                "{}/v1/invoke/gitlab/{action}",
                self.broker.public_url()
            ))
            .header(
                agent_access_provider::REQUEST_ID_HEADER,
                uuid::Uuid::new_v4().to_string(),
            )
            .bearer_auth(token)
            .json(&json!({"inputs":inputs}))
            .send()
            .await
            .unwrap();
        let status = response.status();
        if status.is_success() {
            assert!(
                response.headers()["cache-control"]
                    .to_str()
                    .unwrap()
                    .contains("no-store")
            );
        }
        (status, response.json().await.unwrap())
    }

    pub async fn browser(
        &self,
        method: Method,
        route: &str,
        body: Option<Value>,
    ) -> reqwest::Response {
        let mut request = self
            .client
            .request(method, format!("{}{route}", self.broker.public_url()))
            .header("Host", "127.0.0.1")
            .header("Origin", "http://127.0.0.1")
            .header("Cookie", &self.cookie)
            .header("X-Agent-Access-CSRF", &self.csrf)
            .header(
                agent_access_provider::REQUEST_ID_HEADER,
                uuid::Uuid::new_v4().to_string(),
            );
        if let Some(body) = body {
            request = request.json(&body);
        }
        request.send().await.unwrap()
    }

    pub async fn connect(&self, intent: &str) {
        let connect = self
            .browser(
                Method::POST,
                "/v1/oauth/connect",
                Some(json!({"registration":"gitlab","intent":intent})),
            )
            .await;
        assert_eq!(connect.status(), StatusCode::OK);
        let connect: Value = connect.json().await.unwrap();
        let authorization =
            url::Url::parse(connect["result"]["authorizationUrl"].as_str().unwrap()).unwrap();
        let state = authorization
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1
            .into_owned();
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("state", &state)
            .append_pair("code", "synthetic-once-code")
            .finish();
        let callback = self
            .browser(
                Method::GET,
                &format!("/v1/oauth/callback/gitlab?{query}"),
                None,
            )
            .await;
        assert_eq!(callback.status(), StatusCode::OK);
        assert!(
            callback
                .text()
                .await
                .unwrap()
                .contains("<h1>Authorized</h1>")
        );
    }

    pub async fn requests(&self) -> Vec<Request> {
        self.server.received_requests().await.unwrap()
    }

    pub async fn resource_request_count(&self) -> usize {
        self.requests()
            .await
            .iter()
            .filter(|request| {
                request.url.path() == "/api/v4/search"
                    || request.url.path().starts_with("/api/v4/projects")
            })
            .count()
    }

    pub async fn stop(self) {
        self.broker.shutdown();
        assert!(self.broker.join().await.unwrap().is_clean());
    }

    pub async fn mcp_request(&self, session: Option<&str>, body: Value) -> reqwest::Response {
        let mut request = self
            .client
            .post(format!("{}/mcp", self.broker.public_url()))
            .bearer_auth(&self.token)
            .header("Accept", "application/json, text/event-stream")
            .json(&body);
        if let Some(session) = session {
            request = request
                .header("mcp-session-id", session)
                .header("mcp-protocol-version", "2025-11-25");
        }
        request.send().await.unwrap()
    }

    pub async fn close_mcp(&self, session: &str) {
        let response = self
            .client
            .delete(format!("{}/mcp", self.broker.public_url()))
            .bearer_auth(&self.token)
            .header("mcp-session-id", session)
            .header("mcp-protocol-version", "2025-11-25")
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success());
    }
}

fn secret(directory: &FixtureDir, name: &str, value: &str) -> String {
    format!(
        "file:{}",
        directory.secret_file(name, value).unwrap().display()
    )
}

fn document(
    directory: &FixtureDir,
    upstream: &str,
    public_url: &str,
    mode: Credentials,
    actions: &[&str],
) -> String {
    let reference = |name: &str| format!("file:{}", directory.join(name).display());
    let credentials = match mode {
        Credentials::Service => String::new(),
        Credentials::Personal => format!(
            "[credentials.per_user.gitlab]\ntype = \"secret_store\"\nprovider = \"local_file\"\npath = {:?}\n",
            directory.join("personal-store.json").display().to_string()
        ),
        Credentials::OAuth => format!(
            r#"
[oauth.registrations.gitlab]
adapter = "gitlab"
base_url = {upstream:?}
redirect_uri = "http://127.0.0.1/v1/oauth/callback/gitlab"
client_id = "synthetic-broker"
client_secret_ref = {client_secret:?}
client_auth = "client_secret_post"
encoding = "form"
rotation = "rotate_both"
allow_insecure_loopback = true

[oauth.registrations.gitlab.permission_profiles.read]
scope_mode = "explicit"
scopes = ["api"]
audience = "gitlab"
target = {upstream:?}

[credentials.connections.gitlab]
token_profile = "gitlab-access-token"
oauth = {{ registration = "gitlab", profile = "read" }}

[credentials.per_user.gitlab]
type = "connection"
connection = "gitlab"
"#,
            client_secret = reference("client-secret")
        ),
    };
    format!(
        r#"
[identity]
mode = "required"
authority = "managed"
[[identity.sources]]
name = "broker"
type = "broker_tokens"
header = "Authorization"
scheme = "Bearer"
[managed_store]
type = "sqlite"
path = {store:?}
require_registered_principal_for_invocation = false
auto_migrate = true
[management]
enabled = true
[broker_tokens]
hash_key_ref = {hash_key:?}
default_user_manage_ttl = "8h"
max_self_issued_agent_invoke_ttl = "30d"
[credential_encryption]
active_key = "k1"
[[credential_encryption.keys]]
id = "k1"
provider = "file"
path = {encryption_key:?}
[browser_auth]
enabled = true
public_origin = "http://127.0.0.1"
session_cookie_name = "aab_session"
csrf_header = "X-Agent-Access-CSRF"
csrf_key_ref = {csrf_key:?}
session_ttl = "8h"
allowed_return_paths = ["/ui"]
[browser_auth.local_password]
enabled = true
pepper_ref = {pepper:?}
min_password_length = 8
max_failed_attempts = 3
lockout_ttl = "15m"
[credentials.service.gitlab]
type = "bearer_token"
token_ref = {service_token:?}
{credentials}
[providers.gitlab]
api_base_url = "{upstream}/api/v4"
web_base_url = {upstream:?}
allowed_upstream_hosts = ["{upstream}/api/v4/**"]
[providers.gitlab.search]
max_results = 4
default_engine = "advanced"
max_candidate_pages = 1
max_upstream_requests = 8
max_scan_bytes = 1048576
[providers.gitlab.search.engines.advanced]
project_categories = ["issues", "merge_requests", "code", "commits", "wiki", "comments"]
instance_categories = ["issues", "merge_requests", "code", "commits", "wiki", "comments"]
[policy]
authority = "toml"
default_decision = "deny"
[[policy.resources]]
id = "engineering"
resource_type = "git_repository"
selector = {{ kind = "namespace", value = "engineering" }}
allowed_execution_contexts = ["default"]
[[policy.resources]]
id = "private"
resource_type = "git_repository"
selector = {{ kind = "namespace", value = "engineering/private" }}
allowed_execution_contexts = ["default"]
enabled = false
[[policy.resources]]
id = "api"
resource_type = "git_repository"
selector = {{ kind = "exact", value = "engineering/api" }}
allowed_execution_contexts = ["default"]
[[policy.resource_groups]]
id = "engineering"
name = "Engineering except private"
included_resource_ids = ["engineering"]
excluded_resource_ids = ["private"]
[[policy.grants]]
subjects = ["user:alice"]
service = "gitlab"
actions = {actions}
resources = {{ resource_group_ids = ["engineering"] }}
execution_contexts = ["default"]
credential_mode = {mode:?}
[mcp]
enabled = true
public_url = "http://127.0.0.1/mcp"
[limits]
upload_spool_dir = {spool:?}
[audit]
type = "jsonl"
path = {audit:?}
"#,
        store = directory.join("store.sqlite").display().to_string(),
        hash_key = reference("hash-key"),
        encryption_key = directory.join("encryption-key").display().to_string(),
        csrf_key = reference("csrf-key"),
        pepper = reference("pepper"),
        service_token = reference("service-token"),
        actions = serde_json::to_string(actions).unwrap(),
        mode = mode.mode(),
        spool = directory.join("spool").display().to_string(),
        audit = directory.join("audit.jsonl").display().to_string()
    )
    // The browser origin deliberately remains fixed; the MCP URL names its actual listener.
    .replace(
        "public_url = \"http://127.0.0.1/mcp\"",
        &format!("public_url = \"{public_url}/mcp\""),
    )
}
