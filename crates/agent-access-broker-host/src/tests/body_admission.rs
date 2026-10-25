use super::*;
use std::task::Poll;

fn body_request(path: &str, body: Body) -> Request<Body> {
    Request::builder()
        .method(if path.ends_with("/document") {
            Method::PUT
        } else {
            Method::POST
        })
        .uri(path)
        .extension(ConnectInfo(
            "127.0.0.1:41320".parse::<SocketAddr>().unwrap(),
        ))
        .header(REQUEST_ID_HEADER, "body-admission-test")
        .header(CONTENT_TYPE, "application/json")
        .body(body)
        .unwrap()
}

#[tokio::test]
async fn body_admission_limits_login_json_and_management_bytes_before_polling() {
    for path in [
        "/v1/auth/local/login",
        "/v1/admin/principals",
        "/v1/admin/config/reload",
        "/v1/admin/imports/documents/document",
    ] {
        let mut config = fake_config("");
        config.limits.max_concurrent_requests = 1;
        let broker = TestBroker::start_config(&config).await;
        let app = broker.app();
        let polled = Arc::new(tokio::sync::Notify::new());
        let signal = polled.clone();
        let first = app.clone().oneshot(body_request(
            path,
            Body::from_stream(stream::poll_fn(move |_| {
                signal.notify_one();
                Poll::<Option<Result<Bytes, std::io::Error>>>::Pending
            })),
        ));
        let first = tokio::spawn(first);
        tokio::time::timeout(Duration::from_secs(2), polled.notified())
            .await
            .unwrap();
        let second_polls = Arc::new(AtomicUsize::new(0));
        let counter = second_polls.clone();
        let response = app
            .oneshot(body_request(
                path,
                Body::from_stream(stream::poll_fn(move |_| {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Poll::<Option<Result<Bytes, std::io::Error>>>::Pending
                })),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS, "{path}");
        assert_eq!(second_polls.load(Ordering::SeqCst), 0, "{path}");
        let rejected = response_json(response).await;
        assert_eq!(rejected["agentRequestId"], "body-admission-test");
        assert_eq!(rejected["service"], "broker");
        assert_eq!(rejected["action"], "request.admit");
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
    }
}

#[tokio::test]
async fn body_admission_uses_small_route_caps() {
    for (path, size) in [
        ("/v1/auth/local/login", 16 * 1024 + 1),
        ("/v1/admin/principals", 1024 * 1024 + 1),
        ("/v1/admin/config/reload", 1024 * 1024 + 1),
        // The upload route's larger allowance requires an admitted identity.
        ("/v1/admin/imports/documents/document", 1024 * 1024 + 1),
    ] {
        let broker = TestBroker::start_config(&fake_config("")).await;
        let app = broker.app();
        let response = app
            .oneshot(body_request(path, Body::from(vec![b' '; size])))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE, "{path}");
    }
}

#[tokio::test]
async fn body_admission_idle_and_total_deadlines_release_requests() {
    for path in [
        "/v1/auth/local/login",
        "/v1/admin/imports/documents/document",
    ] {
        for progress in [false, true] {
            let mut config = fake_config("");
            config.limits.request_body_timeout_ms = 100;
            config.limits.streaming_idle_timeout_ms = 40;
            let broker = TestBroker::start_config(&config).await;
            let app = broker.app();
            let body = Body::from_stream(stream::unfold((), move |()| async move {
                if progress {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                } else {
                    std::future::pending::<()>().await;
                }
                Some((Ok::<Bytes, std::io::Error>(Bytes::from_static(b" ")), ()))
            }));
            let started = Instant::now();
            let response = tokio::time::timeout(
                Duration::from_secs(2),
                app.oneshot(body_request(path, body)),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
            let bytes = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            assert!(
                std::str::from_utf8(&bytes)
                    .unwrap()
                    .contains("receive deadline exceeded")
            );
            if progress {
                assert!(started.elapsed() >= Duration::from_millis(90));
            }
        }
    }
}

#[tokio::test]
async fn body_admission_charges_sources_before_json_and_bytes_extraction() {
    for path in [
        "/v1/auth/local/login",
        "/v1/admin/principals",
        "/v1/admin/config/reload",
        "/v1/admin/imports/documents/document",
    ] {
        let mut config = fake_config("");
        config.limits.auth_requests_per_source_per_minute = 1;
        let broker = TestBroker::start_config(&config).await;
        let app = broker.app();
        let first = app
            .clone()
            .oneshot(body_request(path, Body::from("{")))
            .await
            .unwrap();
        assert_ne!(first.status(), StatusCode::TOO_MANY_REQUESTS, "{path}");
        drop(first);
        let polls = Arc::new(AtomicUsize::new(0));
        let counter = polls.clone();
        let second = app
            .oneshot(body_request(
                path,
                Body::from_stream(stream::poll_fn(move |_| {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Poll::<Option<Result<Bytes, std::io::Error>>>::Pending
                })),
            ))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS, "{path}");
        assert_eq!(polls.load(Ordering::SeqCst), 0, "{path}");
    }
}

/// A test broker serving `config` on both listeners, for routes built over
/// its state.
async fn body_test_broker(config: BrokerConfig) -> TestBroker {
    TestBroker::start_with(
        TestBroker::config_builder(&config)
            .gateway_listener()
            .expect("loopback gateway listener"),
    )
    .await
}

#[tokio::test]
async fn body_admission_source_concurrency_is_released_after_body_consumption() {
    let mut config = fake_config("");
    config.limits.max_concurrent_requests = 4;
    config.limits.max_concurrent_requests_per_principal = 1;
    let broker = body_test_broker(config).await;
    let state = broker.state();
    let consumed = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let app = Router::new()
        .route(
            "/v1/admin/probe",
            axum::routing::post({
                let consumed = consumed.clone();
                let release = release.clone();
                move |_: Bytes| {
                    let consumed = consumed.clone();
                    let release = release.clone();
                    async move {
                        consumed.notify_one();
                        release.notified().await;
                        "ok"
                    }
                }
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            state,
            crate::ingress::body::admit_public_body,
        ));
    let first = tokio::spawn(
        app.clone()
            .oneshot(body_request("/v1/admin/probe", Body::from("{}"))),
    );
    tokio::time::timeout(Duration::from_secs(2), consumed.notified())
        .await
        .unwrap();
    let second = tokio::spawn(app.oneshot(body_request("/v1/admin/probe", Body::from("{}"))));
    tokio::time::timeout(Duration::from_secs(2), consumed.notified())
        .await
        .unwrap();
    release.notify_waiters();
    assert_eq!(first.await.unwrap().unwrap().status(), StatusCode::OK);
    assert_eq!(second.await.unwrap().unwrap().status(), StatusCode::OK);
}

#[tokio::test]
async fn body_admission_source_concurrency_rejects_without_polling_and_isolates_sources() {
    let mut config = fake_config("");
    config.limits.max_concurrent_requests = 8;
    config.limits.max_concurrent_requests_per_principal = 1;
    let broker = TestBroker::start_config(&config).await;
    let app = broker.app();
    let polled = Arc::new(tokio::sync::Notify::new());
    let signal = polled.clone();
    let first = tokio::spawn(app.clone().oneshot(body_request(
        "/v1/auth/local/login",
        Body::from_stream(stream::poll_fn(move |_| {
            signal.notify_one();
            Poll::<Option<Result<Bytes, std::io::Error>>>::Pending
        })),
    )));
    tokio::time::timeout(Duration::from_secs(2), polled.notified())
        .await
        .unwrap();
    let polls = Arc::new(AtomicUsize::new(0));
    let counter = polls.clone();
    let denied = app
        .clone()
        .oneshot(body_request(
            "/v1/admin/principals",
            Body::from_stream(stream::poll_fn(move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
                Poll::<Option<Result<Bytes, std::io::Error>>>::Pending
            })),
        ))
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    drop(denied);
    let mut other_source = body_request("/v1/auth/local/login", Body::from("{"));
    other_source.extensions_mut().insert(ConnectInfo(
        "127.0.0.2:41320".parse::<SocketAddr>().unwrap(),
    ));
    let allowed = app.clone().oneshot(other_source).await.unwrap();
    assert_eq!(allowed.status(), StatusCode::BAD_REQUEST);
    drop(allowed);
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    let released = app
        .oneshot(body_request("/v1/auth/local/login", Body::from("{")))
        .await
        .unwrap();
    assert_eq!(released.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn body_admission_charges_source_once_when_handler_also_checks_authentication() {
    let mut config = fake_config("");
    config.limits.auth_requests_per_source_per_minute = 1;
    let broker = body_test_broker(config).await;
    let state = broker.state();
    let handler_state = state.clone();
    let app = Router::new()
        .route(
            "/v1/admin/probe",
            axum::routing::post(move |_: Bytes| {
                let state = handler_state.clone();
                async move {
                    let source = SourceContext {
                        remote: "127.0.0.1:41320".into(),
                        ..SourceContext::unknown()
                    };
                    state
                        .shared_ingress
                        .check_auth_source_rate(
                            &crate::ingress::source::auth_source_key(&source),
                            1,
                        )
                        .unwrap();
                    "ok"
                }
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            state,
            crate::ingress::body::admit_public_body,
        ));
    let first = app
        .clone()
        .oneshot(body_request("/v1/admin/probe", Body::from("{}")))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    drop(first);
    let second = app
        .oneshot(body_request("/v1/admin/probe", Body::from("{}")))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn body_admission_total_deadline_applies_to_multipart_and_gateway_mcp_paths() {
    for gateway in [false, true] {
        let mut config = fake_config("");
        config.limits.request_body_timeout_ms = 80;
        config.limits.streaming_idle_timeout_ms = 40;
        let broker = body_test_broker(config).await;
        let state = broker.state();
        let called = Arc::new(AtomicUsize::new(0));
        let calls = called.clone();
        let path = if gateway {
            "/mcp/team.git/git-upload-pack"
        } else {
            "/v1/invoke/fake/echo"
        };
        let app = Router::new().route(
            path,
            axum::routing::post(move |_: Bytes| {
                calls.fetch_add(1, Ordering::SeqCst);
                async { "must not finish" }
            }),
        );
        let app = if gateway {
            app.layer(axum::middleware::from_fn_with_state(
                state,
                crate::ingress::body::admit_gateway_body,
            ))
        } else {
            app.layer(axum::middleware::from_fn_with_state(
                state,
                crate::ingress::body::admit_public_body,
            ))
        };
        let body = Body::from_stream(stream::unfold((), |_| async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            Some((Ok::<Bytes, std::io::Error>(Bytes::from_static(b"data")), ()))
        }));
        let mut request = body_request(path, body);
        request.headers_mut().insert(
            CONTENT_TYPE,
            "multipart/form-data; boundary=test".parse().unwrap(),
        );
        let started = Instant::now();
        let response = tokio::time::timeout(Duration::from_secs(2), app.oneshot(request))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(started.elapsed() >= Duration::from_millis(70));
        assert_eq!(called.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn body_admission_default_hard_cap_matches_startup_limit() {
    let config_path = temp_path("body-startup-cap.toml");
    let audit_path = temp_path("body-startup-cap.audit.jsonl");
    let spool = temp_path("body-startup-cap-spool");
    let service_token = temp_path("body-startup-cap-token");
    std::fs::write(&service_token, "service-token").unwrap();
    write_reload_config(
        &config_path,
        "TEST",
        &audit_path,
        &service_token,
        &spool,
        2048,
    );
    let broker = TestBroker::start_with(TestBroker::builder_at(config_path)).await;
    assert_eq!(broker.state().body_hard_cap, 2048);
}

// Run the RSS assertion alone in a constrained subprocess: unrelated parallel
// tests must not affect the memory measurement or inherit this address-space cap.
#[cfg(target_os = "linux")]
#[test]
fn body_admission_concurrency_has_bounded_resident_memory() {
    const CHILD_ENV: &str = "AGENT_ACCESS_TEST_BODY_MEMORY_CHILD";
    if std::env::var_os(CHILD_ENV).is_some() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(body_admission_memory_child());
        return;
    }
    use std::os::unix::process::CommandExt;
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "tests::body_admission::body_admission_concurrency_has_bounded_resident_memory",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1");
    // SAFETY: the child hook makes only the async-signal-safe setrlimit syscall
    // and constructs an OS error on failure, before exec initializes the runtime.
    unsafe {
        command.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: 512 * 1024 * 1024,
                rlim_max: 512 * 1024 * 1024,
            };
            if libc::setrlimit(libc::RLIMIT_AS, &limit) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "memory-constrained child failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "linux")]
async fn body_admission_memory_child() {
    fn resident_kib() -> usize {
        std::fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|line| {
                line.strip_prefix("VmRSS:")
                    .map(|value| value.split_whitespace().next().unwrap().parse().unwrap())
            })
            .unwrap()
    }
    let mut config = fake_config("");
    config.limits.max_concurrent_requests = 16;
    config.limits.max_concurrent_requests_per_principal = 4;
    config.limits.request_body_timeout_ms = 30_000;
    let broker = TestBroker::start_config(&config).await;
    let app = broker.app();
    // Measure incremental attack memory after broker initialization and one
    // ordinary extraction, not lazy executable pages or TLS/store startup.
    let warmup = app
        .clone()
        .oneshot(body_request("/v1/admin/principals", Body::from("{")))
        .await
        .unwrap();
    assert_eq!(warmup.status(), StatusCode::BAD_REQUEST);
    axum::body::to_bytes(warmup.into_body(), 4096)
        .await
        .unwrap();
    let baseline = resident_kib();
    let mut held = Vec::new();
    // Each admitted extractor buffers nearly its 1 MiB cap before stalling.
    for _ in 0..4 {
        let filled = Arc::new(tokio::sync::Notify::new());
        let signal = filled.clone();
        let body = Body::from_stream(stream::unfold(0_usize, move |total| {
            let signal = signal.clone();
            async move {
                if total < 1024 * 1024 - 4096 {
                    Some((
                        Ok::<Bytes, std::io::Error>(Bytes::from(vec![b' '; 4096])),
                        total + 4096,
                    ))
                } else {
                    signal.notify_one();
                    std::future::pending().await
                }
            }
        }));
        held.push(tokio::spawn(
            app.clone()
                .oneshot(body_request("/v1/admin/principals", body)),
        ));
        tokio::time::timeout(Duration::from_secs(5), filled.notified())
            .await
            .unwrap();
    }
    let rejected_polls = Arc::new(AtomicUsize::new(0));
    for _ in 0..64 {
        let counter = rejected_polls.clone();
        let body = Body::from_stream(stream::poll_fn(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Some(Ok::<Bytes, std::io::Error>(Bytes::from(
                vec![b' '; 1024 * 1024],
            ))))
        }));
        let response = app
            .clone()
            .oneshot(body_request("/v1/admin/principals", body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }
    assert_eq!(rejected_polls.load(Ordering::SeqCst), 0);
    let resident = resident_kib();
    assert!(
        resident.saturating_sub(baseline) < 32 * 1024,
        "body flood RSS grew from {baseline} KiB to {resident} KiB"
    );
    println!(
        "body flood: baseline RSS={baseline} KiB, loaded RSS={resident} KiB; 4 bounded buffers, 64 unpolled rejections, 512 MiB address-space cap"
    );
    for task in held {
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }
}

#[tokio::test]
async fn body_admission_invoke_json_uses_configured_transfer_cap() {
    let mut config = fake_config("");
    config.limits.max_http_body_bytes = 2 * 1024 * 1024;
    let broker = body_test_broker(config).await;
    let state = broker.state();
    let app = Router::new()
        .route(
            "/v1/invoke/fake/echo",
            axum::routing::post(|_: Bytes| async { "ok" }),
        )
        .layer(axum::middleware::from_fn_with_state(
            state,
            crate::ingress::body::admit_public_body,
        ));
    for (size, expected) in [
        (1024 * 1024 + 1, StatusCode::OK),
        (2 * 1024 * 1024 + 1, StatusCode::PAYLOAD_TOO_LARGE),
    ] {
        let response = app
            .clone()
            .oneshot(body_request(
                "/v1/invoke/fake/echo",
                Body::from(vec![b' '; size]),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
}

#[tokio::test]
async fn body_admission_caps_unfinished_multipart_metadata_incrementally() {
    let broker = test_multipart_broker().await;
    let app = broker.app();
    let chunks_read = Arc::new(AtomicUsize::new(0));
    let counter = chunks_read.clone();
    let body = Body::from_stream(stream::unfold(0_usize, move |index| {
        let counter = counter.clone();
        async move {
            // Each ready chunk must be processed before more metadata arrives.
            // The stream never terminates or supplies a file part or boundary.
            tokio::time::sleep(Duration::from_millis(1)).await;
            counter.fetch_add(1, Ordering::SeqCst);
            let chunk = if index == 0 {
                Bytes::from_static(b"--metadata-limit\r\nContent-Disposition: form-data; name=\"request\"\r\nContent-Type: application/json\r\n\r\n")
            } else {
                Bytes::from(vec![b' '; 64 * 1024])
            };
            Some((Ok::<Bytes, std::io::Error>(chunk), index + 1))
        }
    }));
    let mut request = body_request("/v1/invoke/jira/attachment.add", body);
    request.headers_mut().insert(
        CONTENT_TYPE,
        "multipart/form-data; boundary=metadata-limit"
            .parse()
            .unwrap(),
    );
    let response = tokio::time::timeout(Duration::from_secs(2), app.oneshot(request))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        response_json(response).await["reasonCode"],
        "attachment_size_denied"
    );
    assert!(
        chunks_read.load(Ordering::SeqCst) <= 19,
        "metadata must stop near 1 MiB without buffering the full upload allowance"
    );
}

#[tokio::test]
async fn body_admission_metadata_cap_still_allows_large_spooled_files() {
    use sha2::{Digest, Sha256};
    let broker = test_multipart_broker().await;
    let app = broker.app();
    let payload = "x".repeat(1024 * 1024 + 8);
    let mut metadata = json!({"inputs": {"project":"TEST", "attachments": [{
        "field":"file", "filename":"large.txt", "contentType":"text/plain",
        "size":payload.len(), "sha256":format!("{:x}", Sha256::digest(payload.as_bytes()))
    }]}})
    .to_string();
    // Exactly 1 MiB remains admissible; only metadata above the cap is denied.
    metadata.push_str(&" ".repeat(1024 * 1024 - metadata.len()));
    let boundary = "large-file-after-metadata";
    let body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"request\"\r\nContent-Type: application/json\r\n\r\n{metadata}\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"large.txt\"\r\nContent-Type: text/plain\r\n\r\n{payload}\r\n--{boundary}--\r\n"
    );
    let response = multipart_upload_request(
        app,
        "large-file-metadata-cap",
        "127.0.0.1:41320",
        boundary,
        body,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let value = response_json(response).await;
    assert_eq!(value["result"]["bytesInMemory"], 0);
    assert_eq!(value["result"]["tempFileBacked"], true);
    assert_eq!(value["result"]["readBack"], payload);
    assert!(!Path::new(value["result"]["tempPath"].as_str().unwrap()).exists());
}

#[tokio::test]
async fn gateway_body_admission_preserves_git_error_headers_and_cache_policy() {
    let mut config = fake_config("");
    config.limits.max_concurrent_requests = 1;
    let broker = body_test_broker(config).await;
    let state = broker.state();
    let _occupied = state.shared_ingress.try_global_concurrency(1).unwrap();
    let app = broker.gateway_app();
    let response = app
        .oneshot(body_request("/repo.git/git-upload-pack", Body::empty()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response.headers()[REASON_CODE_HEADER],
        "concurrency_limited"
    );
    assert!(response.headers().contains_key(BROKER_REQUEST_ID_HEADER));
    assert_eq!(response.headers()[CACHE_CONTROL], "private, no-store");
    assert!(response.headers().get(RETRY_AFTER).is_none());
    let bytes = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    let body = std::str::from_utf8(&bytes).unwrap();
    assert!(body.starts_with("This request was not queued or executed."));
    assert!(body.contains("shared request concurrency limit of 1"));
    assert!(body.contains("waiting for rate admission"));
    assert!(body.contains("do not resend pending requests"));
    assert!(!body.contains("agentRequestId"));
}

#[tokio::test]
async fn body_admission_invalid_explicit_token_cannot_use_cookie_to_bypass_source_budget() {
    let fixture = browser_rate_fixture(LimitsConfig {
        auth_requests_per_source_per_minute: 1,
        ..test_limits()
    })
    .await;
    // Fixture login consumed this IPv4 source's one authentication attempt.
    // Its valid session remains usable without spending that budget again.
    let authenticated = fixture
        .browser_request(Method::GET, "/v1/services", None)
        .await;
    assert_eq!(authenticated.status(), StatusCode::OK);
    drop(authenticated);
    assert!(
        fixture
            .ingress
            .check_auth_source_rate("127.0.0.1", 1)
            .is_err()
    );

    let polls = Arc::new(AtomicUsize::new(0));
    let counter = polls.clone();
    let mut request = body_request(
        "/v1/admin/principals",
        Body::from_stream(stream::poll_fn(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            Poll::<Option<Result<Bytes, std::io::Error>>>::Pending
        })),
    );
    request
        .headers_mut()
        .insert("Cookie", fixture.cookie.parse().unwrap());
    request
        .headers_mut()
        .insert("X-Agent-Token", "Bearer invalid-token".parse().unwrap());
    let response = tokio::time::timeout(Duration::from_secs(2), fixture.app.oneshot(request))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response_json(response).await["reasonCode"], "rate_limited");
    assert_eq!(polls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn body_admission_probes_bypass_saturated_global_capacity_without_reading_bodies() {
    let mut config = fake_config("");
    config.limits.max_concurrent_requests = 1;
    let broker = body_test_broker(config).await;
    let state = broker.state();
    let _occupied = state.shared_ingress.try_global_concurrency(1).unwrap();
    let app = broker.app();
    for path in ["/v1/healthz", "/v1/readyz"] {
        let polls = Arc::new(AtomicUsize::new(0));
        let counter = polls.clone();
        let mut request = body_request(
            path,
            Body::from_stream(stream::poll_fn(move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
                Poll::<Option<Result<Bytes, std::io::Error>>>::Pending
            })),
        );
        *request.method_mut() = Method::GET;
        let response = app.clone().oneshot(request).await.unwrap();
        // The fixture's fake credential is unresolved, so readiness remains
        // unavailable; saturation must not replace its status with 429.
        let expected = if path == "/v1/healthz" {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        assert_eq!(response.status(), expected, "{path}");
        assert_eq!(polls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn body_admission_anonymous_pool_preserves_authenticated_capacity_and_same_source_writes() {
    let fixture = browser_rate_fixture(LimitsConfig {
        max_concurrent_requests: 8,
        max_concurrent_requests_per_principal: 1,
        ..test_limits()
    })
    .await;
    let mut held = Vec::new();
    for ip in ["127.0.0.1:41320", "127.0.0.2:41320"] {
        let polled = Arc::new(tokio::sync::Notify::new());
        let signal = polled.clone();
        let mut request = body_request(
            "/v1/auth/local/login",
            Body::from_stream(stream::poll_fn(move |_| {
                signal.notify_one();
                Poll::<Option<Result<Bytes, std::io::Error>>>::Pending
            })),
        );
        request
            .extensions_mut()
            .insert(ConnectInfo(ip.parse::<SocketAddr>().unwrap()));
        held.push(tokio::spawn(fixture.app.clone().oneshot(request)));
        tokio::time::timeout(Duration::from_secs(2), polled.notified())
            .await
            .unwrap();
    }
    let mut excess = body_request("/v1/auth/local/login", Body::from("{}"));
    excess.extensions_mut().insert(ConnectInfo(
        "127.0.0.3:41320".parse::<SocketAddr>().unwrap(),
    ));
    assert_eq!(
        fixture.app.clone().oneshot(excess).await.unwrap().status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    // An empty login cannot occupy body capacity; extraction rejects it normally.
    let empty = fixture
        .app
        .clone()
        .oneshot(body_request("/v1/auth/local/login", Body::empty()))
        .await
        .unwrap();
    assert_eq!(empty.status(), StatusCode::BAD_REQUEST);
    let response = fixture
        .token_invoke("authenticated-during-body-flood", &fixture.agent_tokens[0])
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    drop(response);
    // A valid admin token behind the same source reaches input validation.
    let response = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/principals",
        "admin-during-body-flood",
        "X-Agent-Token",
        format!("Bearer {}", fixture.admin_token),
        Some("{}"),
    )
    .await;
    assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    // Invalid explicit credentials cannot borrow a valid cookie's exemption.
    let mut invalid = body_request("/v1/admin/principals", Body::from("{}"));
    invalid
        .headers_mut()
        .insert("Cookie", fixture.cookie.parse().unwrap());
    invalid
        .headers_mut()
        .insert("X-Agent-Token", "Bearer invalid".parse().unwrap());
    assert_eq!(
        fixture.app.clone().oneshot(invalid).await.unwrap().status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    for task in held {
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }
}

#[tokio::test]
async fn body_admission_login_deadline_is_short_even_with_long_upload_deadline() {
    let mut config = fake_config("");
    config.limits.request_body_timeout_ms = 300_000;
    let broker = TestBroker::start_config(&config).await;
    let app = broker.app();
    let body = Body::from_stream(stream::unfold((), |_| async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        Some((Ok::<Bytes, std::io::Error>(Bytes::from_static(b" ")), ()))
    }));
    let start = Instant::now();
    let response = tokio::time::timeout(
        Duration::from_secs(8),
        app.oneshot(body_request("/v1/auth/local/login", body)),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    assert!(start.elapsed() >= Duration::from_millis(4900));
}

#[tokio::test]
async fn body_admission_invoke_deadline_errors_remain_distinct_through_json_and_multipart() {
    for multipart in [false, true] {
        let mut config = fake_config("");
        config.limits.request_body_timeout_ms = 80;
        let broker = TestBroker::start_config(&config).await;
        let app = broker.app();
        let body = Body::from_stream(stream::pending::<Result<Bytes, std::io::Error>>());
        let mut request = body_request("/v1/invoke/fake/echo", body);
        if multipart {
            request.headers_mut().insert(
                CONTENT_TYPE,
                "multipart/form-data; boundary=test".parse().unwrap(),
            );
        }
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let value = response_json(response).await;
        assert_eq!(value["reasonCode"], "body_malformed");
        assert_eq!(
            value["error"]["message"],
            "request body receive deadline exceeded"
        );
    }
}

#[tokio::test]
async fn body_admission_verified_principals_cannot_fill_global_capacity_with_control_bodies() {
    let fixture = browser_rate_fixture_with(
        LimitsConfig {
            max_concurrent_requests: 8,
            max_concurrent_requests_per_principal: 1,
            ..test_limits()
        },
        |config| config.policy.grants[0].subjects.push("user:admin".into()),
    )
    .await;
    let snapshot = fixture.state.current();
    let admin_invoke = snapshot
        .runtime
        .managed_store()
        .unwrap()
        .issue_broker_token(
            snapshot.runtime.broker_token_hasher().unwrap(),
            agent_access_core::BrokerTokenIssueRequest {
                principal_id: "admin".into(),
                name: "other principal invoke".into(),
                token_class: agent_access_core::BrokerTokenClass::AgentInvoke,
                scopes: json!({"allowedExecutionContexts": ["default"]}),
                expires_at: None,
                created_by: "test".into(),
            },
        )
        .unwrap();
    let polled = Arc::new(tokio::sync::Notify::new());
    let signal = polled.clone();
    let mut first = body_request(
        "/v1/admin/principals",
        Body::from_stream(stream::poll_fn(move |_| {
            signal.notify_one();
            Poll::<Option<Result<Bytes, std::io::Error>>>::Pending
        })),
    );
    first.headers_mut().insert(
        "X-Agent-Token",
        format!("Bearer {}", fixture.agent_tokens[0])
            .parse()
            .unwrap(),
    );
    let held = tokio::spawn(fixture.app.clone().oneshot(first));
    tokio::time::timeout(Duration::from_secs(2), polled.notified())
        .await
        .unwrap();
    let polls = Arc::new(AtomicUsize::new(0));
    let counter = polls.clone();
    let mut second = body_request(
        "/v1/admin/principals",
        Body::from_stream(stream::poll_fn(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            Poll::<Option<Result<Bytes, std::io::Error>>>::Pending
        })),
    );
    // A different token for the same principal shares the body ceiling.
    second.headers_mut().insert(
        "X-Agent-Token",
        format!("Bearer {}", fixture.agent_tokens[1])
            .parse()
            .unwrap(),
    );
    let denied = fixture.app.clone().oneshot(second).await.unwrap();
    assert_eq!(denied.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert_eq!(
        response_json(denied).await["reasonCode"],
        "concurrency_limited"
    );
    let invoked = fixture
        .token_invoke("other-principal-during-control-flood", &admin_invoke.token)
        .await;
    assert_eq!(invoked.status(), StatusCode::OK);
    drop(invoked);
    let admin_write = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/principals",
        "admin-write-during-control-flood",
        "X-Agent-Token",
        format!("Bearer {}", fixture.admin_token),
        Some(r#"{"principalId":"new-user","kind":"user","role":"user"}"#),
    )
    .await;
    assert_eq!(admin_write.status(), StatusCode::OK);
    drop(admin_write);
    held.abort();
    assert!(held.await.unwrap_err().is_cancelled());
    // Cancellation returns the principal's body slot; class authorization then
    // rejects this low-privilege token after a complete valid JSON extraction.
    let after = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/admin/principals",
        "after-control-body-cancel",
        "X-Agent-Token",
        format!("Bearer {}", fixture.agent_tokens[0]),
        Some(r#"{"principalId":"never-created","kind":"user","role":"user"}"#),
    )
    .await;
    assert_eq!(after.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn body_admission_owner_can_pause_and_revoke_while_compromised_token_holds_body_slots() {
    let fixture = browser_rate_fixture(LimitsConfig {
        max_concurrent_requests: 8,
        max_concurrent_requests_per_principal: 1,
        ..test_limits()
    })
    .await;
    let snapshot = fixture.state.current();
    let issued = snapshot
        .runtime
        .managed_store()
        .unwrap()
        .issue_broker_token(
            snapshot.runtime.broker_token_hasher().unwrap(),
            agent_access_core::BrokerTokenIssueRequest {
                principal_id: "alice".into(),
                name: "compromised token".into(),
                token_class: agent_access_core::BrokerTokenClass::AgentInvoke,
                scopes: json!({"allowedExecutionContexts": ["default"]}),
                expires_at: None,
                created_by: "alice".into(),
            },
        )
        .unwrap();
    let polled = Arc::new(tokio::sync::Notify::new());
    let signal = polled.clone();
    let mut request = body_request(
        "/v1/admin/principals",
        Body::from_stream(stream::poll_fn(move |_| {
            signal.notify_one();
            Poll::<Option<Result<Bytes, std::io::Error>>>::Pending
        })),
    );
    request.headers_mut().insert(
        "X-Agent-Token",
        format!("Bearer {}", issued.token).parse().unwrap(),
    );
    let held = tokio::spawn(fixture.app.clone().oneshot(request));
    tokio::time::timeout(Duration::from_secs(2), polled.notified())
        .await
        .unwrap();
    assert!(
        fixture
            .ingress
            .try_principal_body_concurrency("alice", 1)
            .is_err()
    );
    for (method, suffix, expected_reason) in [
        (Method::POST, "/pause", "broker_token_paused"),
        (Method::DELETE, "", "broker_token_revoked"),
    ] {
        let response = fixture
            .browser_request(
                method,
                &format!("/v1/tokens/{}{suffix}", issued.record.token_id),
                None,
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        drop(response);
        // The attacker still holds the body's slot while the cookie owner acts.
        assert!(
            fixture
                .ingress
                .try_principal_body_concurrency("alice", 1)
                .is_err()
        );
        let denied = fixture
            .token_invoke("compromised-token-after-offboarding", &issued.token)
            .await;
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response_json(denied).await["reasonCode"], expected_reason);
    }
    held.abort();
    assert!(held.await.unwrap_err().is_cancelled());
}
