//! Basic and form contracts use the same real Broker/CLI/MCP import journey for
//! both admitted document dialects. All credentials and API data are synthetic.
use super::*;
use axum::{
    body::Bytes,
    extract::OriginalUri,
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
};
use base64::engine::general_purpose::STANDARD;
use std::{io::Write, process::Stdio};

#[path = "openapi/uploaded.rs"]
mod uploaded;

const SERVICE_USER: &str = " service usér ";
const SERVICE_SECRET: &str = " päss:+ &= ";
const PERSONAL_USER: &str = " 個人 user ";
const PERSONAL_SECRET: &str = " 個人: token ";
const DEFINITION_USER: &str = " definition user ";
const DEFINITION_SECRET: &str = " document:秘密 ";
const FORM_BYTES: &[u8] = b"empty=&enabled=true&ids=123%2C456&page=2&q=caf%C3%A9+%2B%25%26%3D";

#[derive(Clone, Debug, PartialEq)]
struct WireRequest {
    method: String,
    path: String,
    authorization: Option<String>,
    content_type: Option<String>,
    body: Vec<u8>,
}
#[derive(Clone, Default)]
struct ApiRequests(Arc<Mutex<Vec<WireRequest>>>);
impl ApiRequests {
    fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }
    fn last(&self) -> WireRequest {
        self.0.lock().unwrap().last().unwrap().clone()
    }
}

fn basic(username: &str, token: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{username}:{token}")))
}

async fn api_call(
    State(state): State<ApiRequests>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let authorization = headers
        .get("authorization")
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned());
    // Record every arrival before validating it. Otherwise a handler panic or
    // rejected credential could hide a forbidden dispatch from the assertions.
    state.0.lock().unwrap().push(WireRequest {
        method: method.to_string(),
        path: uri.to_string(),
        authorization: authorization.clone(),
        content_type: headers
            .get("content-type")
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned()),
        body: body.to_vec(),
    });
    if !authorization.as_ref().is_some_and(|value| {
        [
            basic(SERVICE_USER, SERVICE_SECRET),
            basic(PERSONAL_USER, PERSONAL_SECRET),
        ]
        .contains(value)
    }) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if uri.path() == "/api/remove" {
        return StatusCode::OK.into_response();
    }
    // /remove-body deliberately violates its declared empty success contract.
    let mut response = Json(json!({"value":PAYLOAD})).into_response();
    response.headers_mut().insert(
        "content-type",
        "application/json; charset=utf-8".parse().unwrap(),
    );
    response
}

fn form_inputs() -> Value {
    json!({"body":{"q":"café +%&=","ids":"123,456","page":2,"empty":"","enabled":true}})
}

/// Paired source documents declare the same contracts, including inherited media
/// on the bodyless GET and an intentionally empty DELETE success response.
fn document(swagger: bool, endpoint: &str) -> Value {
    let output =
        json!({"type":"object","properties":{"value":{"type":"string"}},"required":["value"]});
    let response = if swagger {
        json!({"200":{"description":"success","schema":output}})
    } else {
        json!({"200":{"description":"success","content":{"application/json":{"schema":output}}}})
    };
    let fields = json!({
        "q":{"type":"string"},"ids":{"type":"string"},
        "page":{"type":"integer"},"empty":{"type":"string"},"enabled":{"type":"boolean"}
    });
    let form = |id: &str, empty: bool| {
        let responses = if empty {
            json!({"200":{"description":"declares no response content"}})
        } else {
            response.clone()
        };
        if swagger {
            let parameters: Vec<Value> = fields.as_object().unwrap().iter().map(|(name, schema)| {
                json!({"in":"formData","name":name,"required":name == "q","type":schema["type"]})
            }).collect();
            json!({"operationId":id,"consumes":["application/x-www-form-urlencoded"],"parameters":parameters,"responses":responses})
        } else {
            json!({"operationId":id,"requestBody":{"required":true,"content":{"application/x-www-form-urlencoded":{"schema":{"type":"object","properties":fields,"required":["q"],"additionalProperties":false}}}},"responses":responses})
        }
    };
    let array = |id: &str| {
        let schema = json!({"type":"array","items":{"type":"integer"}});
        if swagger {
            json!({"operationId":id,"consumes":["application/json"],"parameters":[{"in":"body","name":"items","required":true,"schema":schema}],"responses":response})
        } else {
            json!({"operationId":id,"requestBody":{"required":true,"content":{"application/json":{"schema":schema}}},"responses":response})
        }
    };
    let path_parameter = if swagger {
        json!({"in":"path","name":"id","required":true,"type":"string"})
    } else {
        json!({"in":"path","name":"id","required":true,"schema":{"type":"string"}})
    };
    let paths = json!({
        "/items/{id}":{"get":{"operationId":"readItem","parameters":[path_parameter],"responses":response}},
        "/search":{"post":form("searchItems",false)},
        "/batch":{"post":array("createItems"),"delete":array("deleteItems")},
        "/remove":{"delete":form("removeItems",true)},
        "/remove-body":{"delete":form("removeItemsWithUnexpectedBody",true)},
        "/transition":{"post":form("transitionItems",false)}
    });
    if swagger {
        let url = reqwest::Url::parse(endpoint).unwrap();
        json!({"swagger":"2.0","info":{"title":"Synthetic Basic API","version":"1"},
            "host":format!("{}:{}",url.host_str().unwrap(),url.port().unwrap()),"basePath":url.path(),"schemes":["http"],
            "consumes":["application/json","application/x-www-form-urlencoded"],"produces":["application/json"],
            "securityDefinitions":{"access":{"type":"basic"}},"security":[{"access":[]}],"paths":paths})
    } else {
        json!({"openapi":"3.1.1","info":{"title":"Synthetic Basic API","version":"1"},"servers":[{"url":endpoint}],
            "components":{"securitySchemes":{"access":{"type":"http","scheme":"basic"}}},"security":[{"access":[]}],"paths":paths})
    }
}

fn assert_input_contract(result: &Value, discovery: bool) {
    let input = &result["service"]["credentialInputs"];
    assert_eq!(input["execution"]["state"], "ready", "{result}");
    assert_eq!(input["execution"]["credentialKind"], "basic_api_token");
    assert_eq!(input["execution"]["inputPolicy"], "http_basic");
    assert_eq!(input["execution"]["fields"][0]["name"], "username");
    assert_eq!(input["execution"]["fields"][1]["name"], "token");
    if discovery {
        assert_eq!(input["discovery"]["inputPolicy"], "http_basic");
    } else {
        assert!(input.get("discovery").is_none());
    }
    assert!(result.get("credentialInputs").is_none());
    assert_secret_free(result);
}

fn assert_secret_free(result: &Value) {
    let public = result.to_string();
    for secret in [
        SERVICE_SECRET.to_owned(),
        PERSONAL_SECRET.to_owned(),
        DEFINITION_SECRET.to_owned(),
        basic(SERVICE_USER, SERVICE_SECRET),
        basic(PERSONAL_USER, PERSONAL_SECRET),
        basic(DEFINITION_USER, DEFINITION_SECRET),
    ] {
        assert!(!public.contains(&secret));
    }
}

fn create_service(
    directory: &FixtureDir,
    config: &Path,
    service: &str,
    endpoint: &str,
    definition_url: &str,
    private_definition: bool,
    writes: bool,
) -> Value {
    let request = write_request(
        directory.path(),
        &format!("{service}-create.json"),
        json!({
            "service":service,"displayName":"Synthetic Basic operations","adapterKind":"openapi_http","endpoint":endpoint,
            "connectionSettings":{"definitionUrl":definition_url,"securityScheme":"access","definitionAuthKind":if private_definition {"basic"} else {"none"}},
            "executionBindings":[
                {"ownerMode":"service","mechanism":"static_token","delivery":{"kind":"basic"},"status":"configured"},
                {"ownerMode":"per_user","mechanism":"static_token","delivery":{"kind":"basic"},"status":"configured"}
            ],"discovery":{"kind":if private_definition {"slot"} else {"anonymous"}}
        }),
    );
    let mut current = run(
        config,
        &["admin", "imports", "create", "--request-file", &request],
    );
    assert_input_contract(&current["result"], private_definition);
    for (purpose, username, secret) in [
        ("execution", SERVICE_USER, SERVICE_SECRET),
        ("discovery", DEFINITION_USER, DEFINITION_SECRET),
    ] {
        if purpose == "discovery" && !private_definition {
            continue;
        }
        let path = directory
            .secret_file(
                format!("{service}-{purpose}.secret"),
                format!("{secret}\r\n"),
            )
            .unwrap();
        let (version, revision) = versions(&current);
        current = run(
            config,
            &[
                "admin",
                "imports",
                "credentials",
                "put",
                service,
                purpose,
                "--expected-version",
                &version,
                "--expected-catalog-revision",
                &revision,
                "--username",
                username,
                "--secret-file",
                path.to_str().unwrap(),
            ],
        );
        assert_input_contract(&current["result"], private_definition);
    }
    let (version, revision) = versions(&current);
    current = run(
        config,
        &[
            "admin",
            "imports",
            "discover",
            service,
            "--expected-version",
            &version,
            "--expected-catalog-revision",
            &revision,
        ],
    );
    assert_input_contract(&current["result"], private_definition);
    let preview = &current["result"]["preview"];
    let tools = preview["manifest"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 7, "{preview}");
    for tool in tools {
        assert!(
            tool.get("unsupportedReason").is_none_or(Value::is_null),
            "{tool}"
        );
    }
    let actions: &[(&str, &str)] = if writes {
        &[
            ("createItems", "item.create"),
            ("deleteItems", "item.delete"),
            ("removeItems", "item.remove"),
            ("removeItemsWithUnexpectedBody", "item.remove_unexpected"),
            ("transitionItems", "item.transition"),
        ]
    } else {
        &[("readItem", "item.read"), ("searchItems", "item.search")]
    };
    let selections: Vec<Value> = actions
        .iter()
        .map(|(source, action)| {
            json!({
                "source":{"operationId":source},"action":action,"readOnly":!writes
            })
        })
        .collect();
    let (version, revision) = versions(&current);
    let request = write_request(
        directory.path(),
        &format!("{service}-accept.json"),
        json!({
            "expectedVersion":version.parse::<u64>().unwrap(),"expectedCatalogRevision":revision.parse::<u64>().unwrap(),
            "manifestHash":preview["manifestHash"],"selections":selections
        }),
    );
    current = run(
        config,
        &[
            "admin",
            "imports",
            "accept",
            service,
            "--request-file",
            &request,
        ],
    );
    assert_input_contract(&current["result"], private_definition);
    let (version, revision) = versions(&current);
    current = run(
        config,
        &[
            "admin",
            "imports",
            "status",
            service,
            "enabled",
            "--expected-version",
            &version,
            "--expected-catalog-revision",
            &revision,
        ],
    );
    assert_input_contract(&current["result"], private_definition);
    current
}

fn grant(config: &Path, principal: &str, service: &str, mode: &str, actions: &[&str]) {
    let subject = format!("user:{principal}");
    let mut args = vec![
        "admin",
        "policy",
        "grants",
        "create",
        "--subject",
        &subject,
        "--service",
        service,
        "--credential-mode",
        mode,
        "--execution-context",
        "default",
    ];
    for action in actions {
        args.extend(["--action", action]);
    }
    run(config, &args);
}

struct HttpMcp {
    client: reqwest::Client,
    url: String,
    token: String,
    session: String,
    id: u64,
}
impl HttpMcp {
    async fn start(base: &str, token: &str, scoped: bool) -> Self {
        let client = reqwest::Client::new();
        let url = format!("{base}/mcp{}", if scoped { "/readers" } else { "" });
        let response = client.post(&url).bearer_auth(token)
            .header("accept","application/json, text/event-stream")
            .json(&json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                "protocolVersion":DOWNSTREAM_MCP,"capabilities":{},"clientInfo":{"name":"basic-form-import","version":"1"}}}))
            .send().await.unwrap();
        let session = response.headers()["mcp-session-id"]
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            rpc_response(response).await["result"]["protocolVersion"],
            DOWNSTREAM_MCP
        );
        let initialized = client
            .post(&url)
            .bearer_auth(token)
            .header("accept", "application/json, text/event-stream")
            .header("mcp-session-id", &session)
            .header("mcp-protocol-version", DOWNSTREAM_MCP)
            .json(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .send()
            .await
            .unwrap();
        assert!(initialized.status().is_success());
        Self {
            client,
            url,
            token: token.into(),
            session,
            id: 2,
        }
    }
    async fn call(&mut self, method: &str, params: Value) -> Value {
        self.id += 1;
        let response = self
            .client
            .post(&self.url)
            .bearer_auth(&self.token)
            .header("accept", "application/json, text/event-stream")
            .header("mcp-session-id", &self.session)
            .header("mcp-protocol-version", DOWNSTREAM_MCP)
            .json(&json!({"jsonrpc":"2.0","id":self.id,"method":method,"params":params}))
            .send()
            .await
            .unwrap();
        rpc_response(response).await
    }
}

fn assert_form_request(requests: &ApiRequests, before: usize, personal: bool) {
    assert_eq!(
        requests.len(),
        before + 1,
        "one admitted call means one dispatch"
    );
    let request = requests.last();
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/api/search");
    assert_eq!(
        request.content_type.as_deref(),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(request.body, FORM_BYTES);
    assert_eq!(
        request.authorization,
        Some(if personal {
            basic(PERSONAL_USER, PERSONAL_SECRET)
        } else {
            basic(SERVICE_USER, SERVICE_SECRET)
        })
    );
}

fn assert_read_request(requests: &ApiRequests, before: usize, personal: bool) {
    assert_eq!(requests.len(), before + 1);
    let request = requests.last();
    assert_eq!(request.method, "GET");
    assert_eq!(request.path, "/api/items/ABC-12");
    assert_eq!(
        request.authorization,
        Some(if personal {
            basic(PERSONAL_USER, PERSONAL_SECRET)
        } else {
            basic(SERVICE_USER, SERVICE_SECRET)
        })
    );
    assert!(request.content_type.is_none());
    assert!(request.body.is_empty());
}

async fn assert_preflight_without_stdin(
    config: &Path,
    purpose: &str,
    version: &str,
    revision: &str,
    message: &str,
) {
    let mut child = command(config)
        .args([
            "admin",
            "imports",
            "credentials",
            "put",
            "readers",
            purpose,
            "--expected-version",
            version,
            "--expected-catalog-revision",
            revision,
            "--username",
            SERVICE_USER,
            "--secret-stdin",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Keep stdin open and supply no bytes. An attempted read would block, so
    // this tests ordering rather than merely the eventual error response.
    let exited = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    if exited.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        panic!("credential preflight must finish without consuming stdin");
    }
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.to_ascii_lowercase().contains(message), "{text}");
}

fn rotate_service_from_env_and_stdin(config: &Path, agent_config: &Path, requests: &ApiRequests) {
    for source in ["env", "stdin"] {
        let detail = run(config, &["admin", "imports", "get", "readers"]);
        let (version, revision) = versions(&detail);
        let mut cli = command(config);
        cli.args([
            "admin",
            "imports",
            "credentials",
            "put",
            "readers",
            "execution",
            "--expected-version",
            &version,
            "--expected-catalog-revision",
            &revision,
            "--username",
            SERVICE_USER,
        ]);
        let output = if source == "env" {
            cli.args(["--secret-env", "SYNTHETIC_IMPORT_PASSWORD"])
                .env("SYNTHETIC_IMPORT_PASSWORD", SERVICE_SECRET)
                .output()
                .unwrap()
        } else {
            let mut child = cli
                .arg("--secret-stdin")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(format!("{SERVICE_SECRET}\n").as_bytes())
                .unwrap();
            child.wait_with_output().unwrap()
        };
        assert!(
            output.status.success(),
            "{source}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["ok"], true);
        assert!(!result.to_string().contains(SERVICE_SECRET));
        let before = requests.len();
        run(
            agent_config,
            &[
                "invoke",
                "readers.item.search",
                "--input-json",
                &form_inputs().to_string(),
            ],
        );
        assert_form_request(requests, before, false);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn swagger_basic_forms_preserve_authority_and_wire_contract_across_cli_and_mcp() {
    exercise_basic_import(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn openapi_basic_forms_preserve_authority_and_wire_contract_across_cli_and_mcp() {
    exercise_basic_import(false).await;
}

async fn exercise_basic_import(swagger: bool) {
    let requests = ApiRequests::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/api", listener.local_addr().unwrap());
    let api = Router::new()
        .fallback(api_call)
        .with_state(requests.clone());
    let _api = ServerTask(tokio::spawn(async move {
        axum::serve(listener, api).await.unwrap()
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let definition_url = format!("http://{}/definition.json", listener.local_addr().unwrap());
    let definition_requests = Arc::new(Mutex::new(Vec::<Option<String>>::new()));
    let seen = definition_requests.clone();
    let source = document(swagger, &endpoint);
    let definitions = Router::new().route(
        "/definition.json",
        get(move |headers: HeaderMap| {
            let source = source.clone();
            let seen = seen.clone();
            async move {
                let authorization = headers
                    .get("authorization")
                    .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned());
                seen.lock().unwrap().push(authorization.clone());
                if authorization != swagger.then(|| basic(DEFINITION_USER, DEFINITION_SECRET)) {
                    return StatusCode::UNAUTHORIZED.into_response();
                }
                Json(source).into_response()
            }
        }),
    );
    let definitions = ServerTask(tokio::spawn(async move {
        axum::serve(listener, definitions).await.unwrap()
    }));
    let application = isolated_broker();
    let directory = application.directory().clone();
    let base = application.public_url();
    directory
        .secret_file("key", URL_SAFE_NO_PAD.encode([62u8; 32]))
        .unwrap();
    let hash = directory
        .secret_file("hash", URL_SAFE_NO_PAD.encode([63u8; 32]))
        .unwrap();
    let (admin, agent, personal, missing) = seed_import_identities(&directory, &hash);
    let admin_config = config_file(directory.path(), "admin", &base, &admin);
    let agent_config = config_file(directory.path(), "agent", &base, &agent);
    let personal_config = config_file(directory.path(), "personal", &base, &personal);
    let missing_config = config_file(directory.path(), "missing", &base, &missing);
    let permissions = ImportPermissions {
        allowed_kinds: vec!["openapi_http".into()],
        allowed_endpoints: vec![endpoint.clone(), definition_url.clone()],
    };
    let broker = application
        .config_document(import_document(
            &directory,
            &permissions,
            &format!("{base}/mcp"),
        ))
        .start()
        .await
        .unwrap();
    create_service(
        &directory,
        &admin_config,
        "readers",
        &endpoint,
        &definition_url,
        swagger,
        false,
    );
    let detail = run(&admin_config, &["admin", "imports", "get", "readers"]);
    assert_input_contract(&detail["result"], swagger);
    let list = run(&admin_config, &["admin", "imports", "list"]);
    assert_input_contract(&json!({"service":list["result"]["services"][0]}), swagger);
    assert_eq!(
        detail["result"]["service"]["actions"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(
        detail["result"]["service"]["actions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|action| action["definition"]["readOnly"] == true),
        "both accepted reader operations are explicitly read-only: {detail}"
    );
    let (version, revision) = versions(&detail);
    assert_preflight_without_stdin(
        &admin_config,
        "execution",
        &(version.parse::<u64>().unwrap() + 1).to_string(),
        &revision,
        "version conflict",
    )
    .await;
    assert_preflight_without_stdin(
        &admin_config,
        "transport",
        &version,
        &revision,
        "unavailable",
    )
    .await;
    assert_preflight_without_stdin(&agent_config, "execution", &version, &revision, "denied").await;
    grant(
        &admin_config,
        "agent",
        "readers",
        "service",
        &["item.read", "item.search"],
    );
    for principal in ["personal", "missing"] {
        grant(
            &admin_config,
            principal,
            "readers",
            "per_user",
            &["item.read", "item.search"],
        );
    }
    let personal_secret = directory
        .secret_file("personal.secret", format!("{PERSONAL_SECRET}\n"))
        .unwrap();
    let personal_username = directory
        .secret_file("personal.username", format!("{PERSONAL_USER}\n"))
        .unwrap();
    run(
        &admin_config,
        &[
            "admin",
            "credentials",
            "put",
            "personal",
            "readers",
            "--profile",
            "username-token",
            "--field-file",
            &format!("username={}", personal_username.display()),
            "--field-file",
            &format!("token={}", personal_secret.display()),
        ],
    );
    assert_eq!(
        requests.len(),
        0,
        "setup and availability never call the API"
    );

    for (config, is_personal) in [(&agent_config, false), (&personal_config, true)] {
        let before = requests.len();
        let read = run(
            config,
            &[
                "invoke",
                "readers.item.read",
                "--input-json",
                r#"{"path":{"id":"ABC-12"}}"#,
            ],
        );
        assert_eq!(read["result"]["upstreamHttp"]["body"]["value"], PAYLOAD);
        assert_read_request(&requests, before, is_personal);
        let before = requests.len();
        let search = run(
            config,
            &[
                "invoke",
                "readers.item.search",
                "--input-json",
                &form_inputs().to_string(),
            ],
        );
        assert_eq!(search["result"]["upstreamHttp"]["body"]["value"], PAYLOAD);
        assert_form_request(&requests, before, is_personal);
    }
    let request = write_request(
        directory.path(),
        "form-send.json",
        json!({
            "version":"agent-access.send.v1","kind":"invoke","service":"readers",
            "action":"item.search","inputs":form_inputs()
        }),
    );
    let before = requests.len();
    run(&agent_config, &["send", "--request-file", &request]);
    assert_form_request(&requests, before, false);
    let before = requests.len();
    run(
        &agent_config,
        &[
            "invoke",
            "readers.item.search",
            "--input-json",
            r#"{"body":{"q":""}}"#,
        ],
    );
    assert_eq!(requests.len(), before + 1);
    assert_eq!(
        requests.last().body,
        b"q=",
        "omitted fields stay absent while an empty string is encoded"
    );
    rotate_service_from_env_and_stdin(&admin_config, &agent_config, &requests);
    let before = requests.len();
    for (config, action, input) in [
        (&missing_config, "readers.item.search", form_inputs()),
        (&agent_config, "readers.item.create", json!({"body":[1,2]})),
        (
            &agent_config,
            "readers.item.search",
            json!({"body":{"q":null}}),
        ),
        (
            &agent_config,
            "readers.item.search",
            json!({"body":{"q":"ok","extra":"not declared"}}),
        ),
        (&agent_config, "readers.item.search", json!({"body":{}})),
    ] {
        let denied = command(config)
            .args(["invoke", action, "--input-json", &input.to_string()])
            .output()
            .unwrap();
        assert!(!denied.status.success());
    }
    assert_eq!(
        requests.len(),
        before,
        "invalid inputs, unaccepted writes and missing personal material never dispatch"
    );

    let mut expected_schema = None;
    for (token, is_personal) in [(&agent, false), (&personal, true)] {
        for scoped in [false, true] {
            let mut http = HttpMcp::start(&base, token, scoped).await;
            let before = requests.len();
            let tools = http.call("tools/list", json!({})).await;
            assert_secret_free(&tools);
            assert_eq!(requests.len(), before, "MCP availability is local");
            let name = if scoped {
                "searchItems".into()
            } else {
                agent_access_core::mcp::tool_name("readers", "item.search")
            };
            let tool = tools["result"]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .find(|tool| tool["name"] == name)
                .unwrap();
            let body_schema = &tool["inputSchema"]["properties"]["inputs"]["properties"]["body"];
            assert_eq!(body_schema["type"], "object");
            assert_eq!(body_schema["properties"]["q"]["type"], "string");
            assert_eq!(body_schema["properties"]["page"]["type"], "integer");
            assert_eq!(body_schema["properties"]["enabled"]["type"], "boolean");
            if let Some(schema) = &expected_schema {
                assert_eq!(&tool["inputSchema"], schema);
            } else {
                expected_schema = Some(tool["inputSchema"].clone());
            }
            assert!(!tools.to_string().contains("createItems"));
            let result = http
                .call(
                    "tools/call",
                    json!({"name":name,"arguments":{"inputs":form_inputs()}}),
                )
                .await;
            assert_eq!(result["result"]["isError"], false, "{result}");
            assert_eq!(
                result["result"]["structuredContent"]["result"]["upstreamHttp"]["body"]["value"],
                PAYLOAD
            );
            assert_form_request(&requests, before, is_personal);
            let before = requests.len();
            let read_name = if scoped {
                "readItem".into()
            } else {
                agent_access_core::mcp::tool_name("readers", "item.read")
            };
            let read_tool = tools["result"]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .find(|tool| tool["name"] == read_name)
                .unwrap();
            assert_eq!(
                read_tool["inputSchema"]["properties"]["inputs"]["properties"]["path"]["properties"]
                    ["id"]["type"],
                "string"
            );
            let read = http
                .call(
                    "tools/call",
                    json!({"name":read_name,"arguments":{"inputs":{"path":{"id":"ABC-12"}}}}),
                )
                .await;
            assert_eq!(read["result"]["isError"], false, "{read}");
            assert_read_request(&requests, before, is_personal);
            let before = requests.len();
            let invalid = http
                .call(
                    "tools/call",
                    json!({"name":name,"arguments":{"inputs":{"body":{"q":null}}}}),
                )
                .await;
            assert_eq!(invalid["result"]["isError"], true, "{invalid}");
            let unaccepted = if scoped {
                "createItems".into()
            } else {
                agent_access_core::mcp::tool_name("readers", "item.create")
            };
            let denied = http
                .call(
                    "tools/call",
                    json!({"name":unaccepted,"arguments":{"inputs":{"body":[1,2]}}}),
                )
                .await;
            assert!(denied.get("error").is_some() || denied["result"]["isError"] == true);
            assert_eq!(
                requests.len(),
                before,
                "invalid form and unaccepted write never dispatch from HTTP MCP"
            );
        }
    }
    let described = run(
        &agent_config,
        &["actions", "describe", "--service", "readers", "item.search"],
    );
    assert_eq!(
        described["mcpTool"]["inputSchema"]["properties"]["inputs"],
        expected_schema.as_ref().unwrap()["properties"]["inputs"]
    );
    for (config, is_personal) in [(&agent_config, false), (&personal_config, true)] {
        for scoped in [false, true] {
            let mut stdio = if scoped {
                McpProcess::start_scoped(config, "readers")
            } else {
                McpProcess::start(config)
            };
            stdio.initialize().await;
            let before = requests.len();
            let listed = stdio.request("tools/list", json!({})).await;
            assert_secret_free(&listed);
            assert_eq!(requests.len(), before);
            let name = if scoped {
                "searchItems".into()
            } else {
                agent_access_core::mcp::tool_name("readers", "item.search")
            };
            let tool = listed["result"]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .find(|tool| tool["name"] == name)
                .unwrap();
            // Stdio adds local output options to the tool envelope. Its accepted
            // `inputs` schema must still be identical to HTTP MCP's.
            assert_eq!(
                tool["inputSchema"]["properties"]["inputs"],
                expected_schema.as_ref().unwrap()["properties"]["inputs"]
            );
            assert!(!listed.to_string().contains("createItems"));
            let result = stdio
                .request(
                    "tools/call",
                    json!({"name":name,"arguments":{"inputs":form_inputs()}}),
                )
                .await;
            assert_eq!(result["result"]["isError"], false, "{result}");
            assert_form_request(&requests, before, is_personal);
            let before = requests.len();
            let read_name = if scoped {
                "readItem".into()
            } else {
                agent_access_core::mcp::tool_name("readers", "item.read")
            };
            let read_tool = listed["result"]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .find(|tool| tool["name"] == read_name)
                .unwrap();
            assert_eq!(
                read_tool["inputSchema"]["properties"]["inputs"]["properties"]["path"]["properties"]
                    ["id"]["type"],
                "string"
            );
            let read = stdio
                .request(
                    "tools/call",
                    json!({"name":read_name,"arguments":{"inputs":{"path":{"id":"ABC-12"}}}}),
                )
                .await;
            assert_eq!(read["result"]["isError"], false, "{read}");
            assert_read_request(&requests, before, is_personal);
            let before = requests.len();
            let invalid = stdio
                .request(
                    "tools/call",
                    json!({"name":name,"arguments":{"inputs":{"body":{"q":null}}}}),
                )
                .await;
            assert_eq!(invalid["result"]["isError"], true, "{invalid}");
            let unaccepted = if scoped {
                "createItems".into()
            } else {
                agent_access_core::mcp::tool_name("readers", "item.create")
            };
            let denied = stdio
                .request(
                    "tools/call",
                    json!({"name":unaccepted,"arguments":{"inputs":{"body":[1,2]}}}),
                )
                .await;
            assert!(denied.get("error").is_some() || denied["result"]["isError"] == true);
            assert_eq!(
                requests.len(),
                before,
                "invalid form and unaccepted write never dispatch from stdio MCP"
            );
            stdio.finish().await;
        }
    }
    let before = requests.len();
    let mut missing_http = HttpMcp::start(&base, &missing, false).await;
    let listed = missing_http.call("tools/list", json!({})).await;
    assert!(!listed.to_string().contains("item.search"));
    let name = agent_access_core::mcp::tool_name("readers", "item.search");
    let denied = missing_http
        .call(
            "tools/call",
            json!({"name":name,"arguments":{"inputs":form_inputs()}}),
        )
        .await;
    assert!(denied.get("error").is_some() || denied["result"]["isError"] == true);
    let mut missing_stdio = McpProcess::start_scoped(&missing_config, "readers");
    missing_stdio.initialize().await;
    let listed = missing_stdio.request("tools/list", json!({})).await;
    assert!(!listed.to_string().contains("searchItems"));
    let denied = missing_stdio
        .request(
            "tools/call",
            json!({"name":"searchItems","arguments":{"inputs":form_inputs()}}),
        )
        .await;
    assert!(denied.get("error").is_some() || denied["result"]["isError"] == true);
    missing_stdio.finish().await;
    assert_eq!(
        requests.len(),
        before,
        "missing personal mode never borrows the service credential"
    );

    let detail = run(&admin_config, &["admin", "imports", "get", "readers"]);
    let (version, revision) = versions(&detail);
    run(
        &admin_config,
        &[
            "admin",
            "imports",
            "credentials",
            "delete",
            "readers",
            "execution",
            "--expected-version",
            &version,
            "--expected-catalog-revision",
            &revision,
        ],
    );
    let before = requests.len();
    let denied = command(&agent_config)
        .args([
            "invoke",
            "readers.item.search",
            "--input-json",
            &form_inputs().to_string(),
        ])
        .output()
        .unwrap();
    assert!(!denied.status.success());
    let mut http = HttpMcp::start(&base, &agent, false).await;
    let listed = http.call("tools/list", json!({})).await;
    assert!(!listed.to_string().contains("item.search"));
    assert_eq!(
        requests.len(),
        before,
        "missing shared material never borrows personal or discovery credentials"
    );
    run(
        &personal_config,
        &[
            "invoke",
            "readers.item.search",
            "--input-json",
            &form_inputs().to_string(),
        ],
    );
    assert_form_request(&requests, before, true);
    rotate_service_from_env_and_stdin(&admin_config, &agent_config, &requests);

    create_service(
        &directory,
        &admin_config,
        "writers",
        &endpoint,
        &definition_url,
        swagger,
        true,
    );
    grant(
        &admin_config,
        "agent",
        "writers",
        "service",
        &[
            "item.create",
            "item.delete",
            "item.remove",
            "item.remove_unexpected",
            "item.transition",
        ],
    );
    for (action, method, path, inputs, content_type, body) in [
        (
            "item.create",
            "POST",
            "/api/batch",
            json!({"body":[1,2]}),
            "application/json",
            b"[1,2]".as_slice(),
        ),
        (
            "item.delete",
            "DELETE",
            "/api/batch",
            json!({"body":[1,2]}),
            "application/json",
            b"[1,2]".as_slice(),
        ),
        (
            "item.remove",
            "DELETE",
            "/api/remove",
            form_inputs(),
            "application/x-www-form-urlencoded",
            FORM_BYTES,
        ),
        (
            "item.transition",
            "POST",
            "/api/transition",
            form_inputs(),
            "application/x-www-form-urlencoded",
            FORM_BYTES,
        ),
    ] {
        let before = requests.len();
        let result = run(
            &agent_config,
            &[
                "invoke",
                &format!("writers.{action}"),
                "--input-json",
                &inputs.to_string(),
            ],
        );
        assert_eq!(requests.len(), before + 1, "{action} dispatches once");
        assert_eq!(
            result["result"]["mutationStatus"], "applied_unverified",
            "{result}"
        );
        if action == "item.remove" {
            assert_eq!(
                result.pointer("/result/upstreamHttp/body"),
                Some(&Value::Null),
                "an empty declared success has an explicit null body"
            );
        }
        let request = requests.last();
        assert_eq!(request.method, method);
        assert_eq!(request.path, path);
        assert_eq!(
            request.authorization,
            Some(basic(SERVICE_USER, SERVICE_SECRET))
        );
        assert_eq!(request.content_type.as_deref(), Some(content_type));
        assert_eq!(request.body, body);
    }
    let before = requests.len();
    let failed = command(&agent_config)
        .args([
            "invoke",
            "writers.item.remove_unexpected",
            "--input-json",
            &form_inputs().to_string(),
        ])
        .output()
        .unwrap();
    assert!(!failed.status.success());
    let failed: Value = serde_json::from_slice(&failed.stdout).unwrap();
    assert_eq!(failed["reasonCode"], "upstream_protocol_failed", "{failed}");
    assert_eq!(failed["result"]["mutationStatus"], "unknown", "{failed}");
    assert_eq!(failed["result"]["retrySafe"], false, "{failed}");
    assert!(!failed.to_string().contains(PAYLOAD));
    assert_eq!(
        requests.len(),
        before + 1,
        "a malformed success must never replay a DELETE"
    );
    let request = requests.last();
    assert_eq!(request.method, "DELETE");
    assert_eq!(request.path, "/api/remove-body");
    assert_eq!(
        request.authorization,
        Some(basic(SERVICE_USER, SERVICE_SECRET))
    );
    assert_eq!(request.body, FORM_BYTES);

    assert_eq!(
        definition_requests.lock().unwrap().len(),
        2,
        "only explicit discovery fetches the definition"
    );
    assert!(
        definition_requests
            .lock()
            .unwrap()
            .iter()
            .all(|authorization| authorization
                == &swagger.then(|| basic(DEFINITION_USER, DEFINITION_SECRET)))
    );
    drop(definitions);
    stop(broker).await;
    let restarted = isolated_broker().in_directory(directory.clone());
    let restarted_base = restarted.public_url();
    let broker = restarted
        .config_document(import_document(
            &directory,
            &permissions,
            &format!("{restarted_base}/mcp"),
        ))
        .start()
        .await
        .unwrap();
    assert_eq!(
        requests.len(),
        before + 1,
        "startup loads accepted plans without API I/O"
    );
    for (principal, token, is_personal) in [("agent", &agent, false), ("personal", &personal, true)]
    {
        let config = config_file(
            directory.path(),
            &format!("restarted-{principal}"),
            &restarted_base,
            token,
        );
        let before = requests.len();
        run(
            &config,
            &[
                "invoke",
                "readers.item.search",
                "--input-json",
                &form_inputs().to_string(),
            ],
        );
        assert_form_request(&requests, before, is_personal);
    }
    assert_eq!(definition_requests.lock().unwrap().len(), 2);
    stop(broker).await;
}
