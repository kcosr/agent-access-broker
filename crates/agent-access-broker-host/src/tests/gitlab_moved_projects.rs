//! GitLab REST through the real provider and policy when a project was
//! renamed, moved or transferred: old paths and web URLs are authorized as
//! the project's current path, and a path another project took over names
//! that project.
use super::*;
use axum::extract::State;
use axum::response::IntoResponse;
use std::sync::Mutex;

/// The upstream's project 42, `sip/service`, formerly `old/service` and
/// before that `sip/old-name`, which project 99 has since taken over;
/// project 77, `secret/vault`, formerly `old/secret`. A moved project's old
/// path answers as GitLab 16.7 and later do: a `301` naming the project ID
/// on GitLab's external URL, another origin than the API base. Every request
/// is recorded.
async fn moved_projects_stub(
    State(seen): State<Arc<Mutex<Vec<String>>>>,
    method: Method,
    uri: Uri,
) -> axum::response::Response {
    let path = uri.path().to_string();
    seen.lock().unwrap().push(format!("{method} {path}"));
    let moved = |id: u64| {
        let location = format!("https://gitlab-external.example.test/api/v4/projects/{id}");
        axum::response::Response::builder()
            .status(StatusCode::MOVED_PERMANENTLY)
            .header("location", &location)
            .body(Body::from(format!(
                "This resource has been moved permanently to {location}"
            )))
            .unwrap()
    };
    let ok = |status: StatusCode, body: Value| (status, axum::Json(body)).into_response();
    let project = |id: u64, path: &str| json!({ "id": id, "path_with_namespace": path });
    match (method.as_str(), path.as_str()) {
        ("GET", "/api/v4/projects/old%2Fservice") => moved(42),
        ("GET", "/api/v4/projects/old%2Fsecret") => moved(77),
        ("GET", "/api/v4/projects/42" | "/api/v4/projects/sip%2Fservice") => {
            ok(StatusCode::OK, project(42, "sip/service"))
        }
        ("GET", "/api/v4/projects/77") => ok(StatusCode::OK, project(77, "secret/vault")),
        ("GET", "/api/v4/projects/sip%2Fold-name") => {
            ok(StatusCode::OK, project(99, "sip/old-name"))
        }
        ("GET", "/api/v4/projects/42/issues/5") => ok(
            StatusCode::OK,
            json!({ "id": 500, "iid": 5, "project_id": 42, "title": "Moved issue" }),
        ),
        ("POST", "/api/v4/projects/42/issues/5/notes") => ok(
            StatusCode::CREATED,
            json!({
                "id": 701, "body": "noted", "noteable_type": "Issue",
                "noteable_iid": 5, "project_id": 42,
                "author": { "id": 314, "username": "service-user" }
            }),
        ),
        // GitLab refuses other methods on a moved project's old path.
        (_, path) if path.starts_with("/api/v4/projects/old%2F") => ok(
            StatusCode::METHOD_NOT_ALLOWED,
            json!({ "message": "Non GET methods are not allowed for moved projects" }),
        ),
        _ => ok(StatusCode::NOT_FOUND, json!({ "message": "404 Not Found" })),
    }
}

fn write_moved_projects_config(
    config_path: &Path,
    audit_path: &Path,
    spool_dir: &Path,
    service_token: &Path,
    lookup_token: &Path,
    upstream_addr: SocketAddr,
) {
    let config = format!(
        r#"[deployment]
environment = "test"

[secret_outputs]
mode = "raw"

[identity]
mode = "anonymous"
authority = "toml"

[credentials.service.gitlab]
type = "bearer_token"
token_ref = "file:{service_token}"

[credentials.lookup.gitlab]
type = "bearer_token"
token_ref = "file:{lookup_token}"
read_only = true

[policy]
authority = "toml"
default_decision = "deny"

[[policy.resources]]
id = "repository-sip-service"
resource_type = "git_repository"
selector = {{ kind = "exact", value = "sip/service" }}
allowed_execution_contexts = ["default"]

[[policy.grants]]
subjects = ["group:anonymous"]
service = "gitlab"
actions = ["project.view", "issue.view", "issue.note.add"]
resources = {{ resource_ids = ["repository-sip-service"] }}
credential_mode = "service"

[limits]
upload_spool_dir = "{spool_dir}"

[audit]
type = "jsonl"
path = "{audit_path}"

[providers.gitlab]
api_base_url = "http://{upstream_addr}/api/v4"
web_base_url = "https://gitlab.example.com"
allowed_upstream_hosts = ["http://{upstream_addr}/api/v4/**"]
"#,
        service_token = service_token.display(),
        lookup_token = lookup_token.display(),
        spool_dir = spool_dir.display(),
        audit_path = audit_path.display(),
    );
    std::fs::write(config_path, config).unwrap();
}

async fn invoke(app: Router, action: &str, request_id: &str, inputs: Value) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/v1/invoke/gitlab/{action}"))
                .extension(ConnectInfo(
                    "127.0.0.1:43221".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, request_id)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "inputs": inputs }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    (status, response_json(response).await)
}

#[tokio::test]
async fn moved_gitlab_projects_are_authorized_by_their_current_identity() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let upstream_app = Router::new()
        .fallback(moved_projects_stub)
        .with_state(seen.clone());
    let upstream = tokio::spawn(async move {
        axum::serve(listener, upstream_app).await.unwrap();
    });
    let config_path = temp_path("gitlab-moved-projects.toml");
    let audit_path = temp_path("gitlab-moved-projects.audit.jsonl");
    let spool_dir = temp_path("gitlab-moved-projects-spool");
    let service_token = temp_path("gitlab-moved-projects-service-token");
    let lookup_token = temp_path("gitlab-moved-projects-lookup-token");
    std::fs::write(&service_token, "service-token").unwrap();
    std::fs::write(&lookup_token, "lookup-token").unwrap();
    write_moved_projects_config(
        &config_path,
        &audit_path,
        &spool_dir,
        &service_token,
        &lookup_token,
        upstream_addr,
    );
    let broker = TestBroker::start_with(TestBroker::builder_at(config_path)).await;
    let app = broker.app();
    let seen_since = |start: usize| seen.lock().unwrap()[start..].to_vec();

    // The old path and an old web URL of the granted project are authorized
    // as its current path and read by its numeric ID.
    for (action, inputs) in [
        ("project.view", json!({ "project": "old/service" })),
        (
            "project.view",
            json!({ "url": "https://gitlab.example.com/old/service" }),
        ),
        (
            "issue.view",
            json!({ "url": "https://gitlab.example.com/old/service/-/issues/5" }),
        ),
    ] {
        let (status, body) =
            invoke(app.clone(), action, "gitlab-moved-allow", inputs.clone()).await;
        assert_eq!(status, StatusCode::OK, "{action} {inputs}: {body}");
        assert_eq!(body["decision"], "allow");
        assert_eq!(
            body["resourceScopes"],
            json!({ "repository": ["sip/service"] })
        );
    }

    // A write through the old path reaches GitLab by project ID; nothing
    // but a GET is ever sent to a path-addressed project.
    let start = seen.lock().unwrap().len();
    let (status, body) = invoke(
        app.clone(),
        "issue.note.add",
        "gitlab-moved-write",
        json!({ "project": "old/service", "iid": 5, "contentFormat": "markdown", "content": "noted" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["resourceScopes"],
        json!({ "repository": ["sip/service"] })
    );
    let requests = seen_since(start);
    assert!(requests.contains(&"POST /api/v4/projects/42/issues/5/notes".to_string()));
    assert!(
        requests
            .iter()
            .filter(|request| !request.starts_with("GET "))
            .all(|request| request == "POST /api/v4/projects/42/issues/5/notes"),
        "{requests:?}"
    );

    // An old path whose project now lives under an ungranted path, and an
    // old path another project took over, are denied as their current
    // owners, concealed like every lookup-backed denial, and never executed.
    for (project, owner_lookup) in [
        ("old/secret", "GET /api/v4/projects/77"),
        ("sip/old-name", "GET /api/v4/projects/sip%2Fold-name"),
    ] {
        let start = seen.lock().unwrap().len();
        let (status, body) = invoke(
            app.clone(),
            "project.view",
            "gitlab-moved-deny",
            json!({ "project": project }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{project}: {body}");
        assert_eq!(body["decision"], "deny");
        assert_eq!(body["reasonCode"], "scope_unresolved");
        assert_eq!(body["resourceScopes"], json!({}));
        let requests = seen_since(start);
        assert_eq!(
            requests.last().map(String::as_str),
            Some(owner_lookup),
            "{requests:?}"
        );
        assert!(
            !requests
                .iter()
                .any(|request| request.contains("/projects/42"))
        );
    }

    // The current path keeps working unchanged.
    let (status, body) = invoke(
        app,
        "project.view",
        "gitlab-current-path",
        json!({ "project": "sip/service" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["resourceScopes"],
        json!({ "repository": ["sip/service"] })
    );
    drop(broker);
    upstream.abort();
}
