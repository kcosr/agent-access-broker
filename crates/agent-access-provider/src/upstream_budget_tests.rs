use super::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn client(base: &str, profile: ClientProfile) -> UpstreamClient {
    UpstreamClient::build(
        UpstreamClientSpec::new(
            "test",
            "example",
            &Url::parse(base).unwrap(),
            EgressDeclaration::Ordinary(None),
            &[format!("{base}/**")],
            profile,
        ),
        &crate::test_support::TestHost::default(),
    )
    .unwrap()
}

#[tokio::test]
async fn actual_sends_error_bodies_and_explicit_replays_share_counters() {
    let server = MockServer::start().await;
    Mock::given(path("/unauthorized"))
        .respond_with(ResponseTemplate::new(401).set_body_string("denied"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(path("/retry"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&server)
        .await;
    let client = client(&server.uri(), ClientProfile::SingleAttempt);
    let requests = UpstreamRequestBudget::new(2);
    let bytes = SharedBodyBudget::new(8);
    for (route, expected) in [("unauthorized", "denied"), ("retry", "ok")] {
        let response = client
            .send(
                client.request(
                    Method::GET,
                    Url::parse(&format!("{}/{route}", server.uri())).unwrap(),
                ),
                UpstreamCall::new("search").with_request_budget(&requests),
            )
            .await
            .unwrap();
        assert_eq!(
            read_bounded_body_with_budget(response, 100, None, Some(&bytes))
                .await
                .unwrap(),
            expected.as_bytes()
        );
    }
    assert_eq!(requests.remaining_requests(), 0);
    assert_eq!(bytes.remaining_bytes(), 0);
    let result = client
        .send(
            client.request(
                Method::GET,
                Url::parse(&format!("{}/extra", server.uri())).unwrap(),
            ),
            UpstreamCall::new("search").with_request_budget(&requests),
        )
        .await;
    assert!(matches!(result, Err(UpstreamError::RequestBudgetExceeded)));
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn concurrent_sends_cannot_overdraw_and_rejected_requests_do_not_charge() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .expect(3)
        .mount(&server)
        .await;
    let client = client(&server.uri(), ClientProfile::SingleAttempt);
    let requests = UpstreamRequestBudget::new(3);
    let rejected = client
        .send(
            client.request(
                Method::GET,
                Url::parse("https://elsewhere.example/request").unwrap(),
            ),
            UpstreamCall::new("search").with_request_budget(&requests),
        )
        .await;
    assert!(matches!(rejected, Err(UpstreamError::NotAllowed)));
    assert_eq!(requests.remaining_requests(), 3);
    let calls = (0..16).map(|_| {
        client.send(
            client.request(Method::GET, Url::parse(&server.uri()).unwrap()),
            UpstreamCall::new("search").with_request_budget(&requests),
        )
    });
    let results = futures_util::future::join_all(calls).await;
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 3);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(UpstreamError::RequestBudgetExceeded)))
            .count(),
        13
    );
    assert_eq!(requests.remaining_requests(), 0);
}

#[tokio::test]
async fn budgeted_calls_require_a_retry_disabled_profile() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let requests = UpstreamRequestBudget::new(1);
    for profile in [
        ClientProfile::Request,
        ClientProfile::Stream,
        ClientProfile::Upload,
    ] {
        let client = client(&server.uri(), profile);
        let result = client
            .send(
                client.request(Method::GET, Url::parse(&server.uri()).unwrap()),
                UpstreamCall::new("search").with_request_budget(&requests),
            )
            .await;
        assert!(matches!(result, Err(UpstreamError::NotSent { .. })));
        assert_eq!(requests.remaining_requests(), 1);
    }
    let client = client(
        &server.uri(),
        ClientProfile::Bounded {
            total: Duration::from_secs(2),
            connect: Duration::from_secs(1),
        },
    );
    client
        .send(
            client.request(Method::GET, Url::parse(&server.uri()).unwrap()),
            UpstreamCall::new("search").with_request_budget(&requests),
        )
        .await
        .unwrap();
    assert_eq!(requests.remaining_requests(), 0);
}

#[tokio::test]
async fn concurrent_streams_atomically_charge_before_retaining_chunks() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![42; 64]))
        .mount(&server)
        .await;
    let client = client(&server.uri(), ClientProfile::SingleAttempt);
    let budget = SharedBodyBudget::new(128);
    let barrier = Arc::new(tokio::sync::Barrier::new(8));
    let calls = (0..8).map(|_| {
        let barrier = barrier.clone();
        let budget = budget.clone();
        let client = client.clone();
        let url = Url::parse(&server.uri()).unwrap();
        async move {
            let response = client
                .send(client.request(Method::GET, url), UpstreamCall::new("body"))
                .await
                .unwrap();
            barrier.wait().await;
            read_bounded_body_with_budget(response, 64, None, Some(&budget)).await
        }
    });
    let results = futures_util::future::join_all(calls).await;
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 2);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(BodyReadError::BudgetExceeded)))
            .count(),
        6
    );
    assert_eq!(
        results
            .into_iter()
            .filter_map(Result::ok)
            .map(|body| body.len())
            .sum::<usize>(),
        128
    );
    assert_eq!(budget.remaining_bytes(), 0);
}

#[tokio::test]
async fn per_response_and_shared_caps_each_apply_and_error_body_bytes_stay_charged() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500).set_body_string("12345678"))
        .mount(&server)
        .await;
    let client = client(&server.uri(), ClientProfile::SingleAttempt);
    let fetch = || {
        client.send(
            client.request(Method::GET, Url::parse(&server.uri()).unwrap()),
            UpstreamCall::new("body"),
        )
    };
    let budget = SharedBodyBudget::new(12);
    assert_eq!(
        read_bounded_body_with_budget(fetch().await.unwrap(), 8, None, Some(&budget))
            .await
            .unwrap(),
        b"12345678"
    );
    assert_eq!(budget.remaining_bytes(), 4);
    assert!(matches!(
        read_bounded_body_with_budget(fetch().await.unwrap(), 8, None, Some(&budget)).await,
        Err(BodyReadError::BudgetExceeded)
    ));
    assert_eq!(budget.remaining_bytes(), 4);
    assert!(matches!(
        read_bounded_body_with_budget(fetch().await.unwrap(), 4, None, Some(&budget)).await,
        Err(BodyReadError::TooLarge)
    ));
    assert_eq!(budget.remaining_bytes(), 4); // rejected from Content-Length, without consuming a chunk
    assert_eq!(
        read_bounded_body_with_budget(fetch().await.unwrap(), 8, None, None)
            .await
            .unwrap()
            .len(),
        8
    );
}

#[tokio::test]
async fn failed_transports_consume_their_attempt() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let client = client(&url, ClientProfile::SingleAttempt);
    let budget = UpstreamRequestBudget::new(1);
    assert!(
        client
            .send(
                client.request(Method::GET, Url::parse(&url).unwrap()),
                UpstreamCall::new("search").with_request_budget(&budget)
            )
            .await
            .is_err()
    );
    assert_eq!(budget.remaining_requests(), 0);
}

#[tokio::test]
async fn protocol_negative_acknowledgments_cannot_hide_a_retry() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let observed = Arc::new(AtomicU32::new(0));
    let observed_server = observed.clone();
    let server = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let observed = observed_server.clone();
            connections.spawn(async move {
                let mut connection = h2::server::handshake(socket).await.unwrap();
                while let Some(Ok((_, mut response))) = connection.accept().await {
                    observed.fetch_add(1, Ordering::Relaxed);
                    // reqwest's default policy can replay this HTTP/2 NACK.
                    response.send_reset(h2::Reason::REFUSED_STREAM);
                }
            });
        }
    });
    for profile in [
        ClientProfile::SingleAttempt,
        ClientProfile::Bounded {
            total: Duration::from_secs(2),
            connect: Duration::from_secs(1),
        },
    ] {
        let mut client = client(&base, profile);
        client.client = crate::host::configure_client_profile(
            reqwest::Client::builder().http2_prior_knowledge(),
            profile,
            &crate::ProviderLimits::default(),
        )
        .build()
        .unwrap();
        let budget = UpstreamRequestBudget::new(1);
        let before = observed.load(Ordering::Relaxed);
        let result = client
            .send(
                client.request(Method::GET, Url::parse(&base).unwrap()),
                UpstreamCall::new("search").with_request_budget(&budget),
            )
            .await;
        assert!(matches!(result, Err(UpstreamError::Transport(_))));
        assert_eq!(observed.load(Ordering::Relaxed) - before, 1);
        assert_eq!(budget.remaining_requests(), 0);
    }
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn chunked_bodies_charge_the_decoded_chunk_before_a_local_cap_rejection() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(socket.read_u8().await.unwrap());
        }
        socket.write_all(b"HTTP/1.1 500 Error\r\ntransfer-encoding: chunked\r\n\r\n8\r\n12345678\r\n0\r\n\r\n").await.unwrap();
    });
    let client = client(&base, ClientProfile::SingleAttempt);
    let response = client
        .send(
            client.request(Method::GET, Url::parse(&base).unwrap()),
            UpstreamCall::new("body"),
        )
        .await
        .unwrap();
    assert_eq!(response.content_length(), None);
    let budget = SharedBodyBudget::new(12);
    assert!(matches!(
        read_bounded_body_with_budget(response, 4, None, Some(&budget)).await,
        Err(BodyReadError::TooLarge)
    ));
    assert_eq!(budget.remaining_bytes(), 4);
    server.await.unwrap();
}
