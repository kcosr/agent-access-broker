use super::*;
use agent_access_provider::test_support::InvocationBuilder;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const ORIGIN: &str = "https://synthetic.environment.api.powerplatform.com";
const ENDPOINT: &str = "https://synthetic.environment.api.powerplatform.com/powerautomate/automations/direct/cu/08/workflows/fixture/triggers/manual/paths/invoke?api-version=1&sp=fixture&sig=SYNTHETIC_SECRET";

fn config() -> TeamsConfig {
    TeamsConfig {
        allowed_upstream_hosts: vec![format!("{ORIGIN}/**")],
        egress_proxy: None,
    }
}
fn simple() -> Value {
    json!({"destination":"release-alerts","contentFormat":"simple","content":{"title":"Release","text":"Version 2.3"}})
}
fn message_card() -> Value {
    json!({"@type":"MessageCard","@context":"http://schema.org/extensions","summary":"Release","sections":[{"facts":[{"name":"Version","value":"2.3"}]}],"potentialAction":[{"@type":"OpenUri","name":"Details","targets":[{"os":"default","uri":"https://example.com/build"}]}]})
}

struct AcceptTransport(std::sync::atomic::AtomicUsize);
#[async_trait]
impl NotificationTransport for AcceptTransport {
    async fn send(&self, endpoint: Url, _body: Vec<u8>) -> Result<TransportReceipt, ProviderError> {
        assert_eq!(endpoint.as_str(), ENDPOINT);
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(TransportReceipt::status(202))
    }
}

struct ThrottledTransport(Option<UpstreamRetryAfter>);
#[async_trait]
impl NotificationTransport for ThrottledTransport {
    async fn send(
        &self,
        _endpoint: Url,
        _body: Vec<u8>,
    ) -> Result<TransportReceipt, ProviderError> {
        Ok(TransportReceipt {
            status: 429,
            retry_after: self.0,
        })
    }
}

fn admitted_invocation() -> ProviderInvocation {
    InvocationBuilder::new("teams", ACTION)
        .inputs(simple())
        .identity(InvocationIdentity {
            principal: "alice".into(),
            authenticated: true,
        })
        .correlation(Default::default())
        .resources(BTreeMap::from([(
            "destination".into(),
            vec!["release-alerts".into()],
        )]))
        .resource_attributes(ResourceAttributes::from(BTreeMap::from([(
            "webhookUrl".into(),
            ENDPOINT.into(),
        )])))
        .build()
}

#[tokio::test]
async fn workflow_throttling_is_an_upstream_rate_limit_without_retry_claims() {
    let wait = UpstreamRetryAfter::after_seconds(30);
    for (retry_after, message) in [
        (
            Some(wait),
            format!(
                "teams is rate limiting requests. Retry after 30s (at {}).",
                wait.retry_at()
            ),
        ),
        (
            None,
            "teams is rate limiting requests. Retry later.".to_string(),
        ),
    ] {
        let provider = TeamsProvider {
            transport: Arc::new(ThrottledTransport(retry_after)),
            allowed_upstream_hosts: vec![format!("{ORIGIN}/**")],
            max_bytes: MAX_BODY_BYTES,
        };
        let error = provider.invoke(admitted_invocation()).await.unwrap_err();
        assert_eq!(error.decision(), Decision::Error);
        assert_eq!(error.reason_code(), ReasonCode::UpstreamRateLimited);
        assert_eq!(error.upstream_status, Some(429));
        assert_eq!(error.message, message);
        let mut expected = json!({"limitScope": "upstream", "service": "teams"});
        if let Some(wait) = retry_after {
            expected["retryAfterSeconds"] = json!(30);
            expected["retryAt"] = json!(wait.retry_at());
        }
        assert_eq!(error.result.as_deref(), Some(&expected));
        assert!(!format!("{error:?}").contains("SYNTHETIC_SECRET"));
    }
}

#[tokio::test]
async fn invocation_requires_private_admitted_endpoint_and_returns_only_receipt_metadata() {
    let transport = Arc::new(AcceptTransport(std::sync::atomic::AtomicUsize::new(0)));
    let provider = TeamsProvider {
        transport: transport.clone(),
        allowed_upstream_hosts: vec![format!("{ORIGIN}/**")],
        max_bytes: MAX_BODY_BYTES,
    };
    let mut invocation = InvocationBuilder::new("teams", ACTION)
        .inputs(simple())
        .identity(InvocationIdentity {
            principal: "alice".into(),
            authenticated: true,
        })
        .correlation(Default::default())
        .resources(BTreeMap::from([(
            "destination".into(),
            vec!["release-alerts".into()],
        )]))
        .build();
    assert!(provider.invoke(invocation.clone()).await.is_err());
    invocation = InvocationBuilder::from(invocation)
        .resource_attributes(ResourceAttributes::from(BTreeMap::from([(
            "webhookUrl".into(),
            ENDPOINT.into(),
        )])))
        .build();
    let receipt = provider.invoke(invocation.clone()).await.unwrap();
    assert_eq!(
        receipt.result,
        json!({"destination":"release-alerts","accepted":true})
    );
    assert_eq!(receipt.upstream_status, Some(202));
    let serialized = serde_json::to_string(&receipt).unwrap();
    assert!(!serialized.contains("SYNTHETIC_SECRET"));
    assert!(!serialized.contains("Version 2.3"));
    assert!(!serialized.contains("/powerautomate/"));
    invocation = InvocationBuilder::from(invocation)
        .credential_mode(CredentialMode::PerUser)
        .build();
    assert!(provider.invoke(invocation).await.is_err());
    assert_eq!(transport.0.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn descriptor_and_schema_preserve_mutation_authority_and_content_union() {
    let descriptor = descriptor();
    assert!(!descriptor.credentials.execution_required);
    let action = &descriptor.actions[0];
    assert!(!action.read_only);
    assert!(action.requires_resource_attributes);
    assert_eq!(action.credential_modes, vec!["service"]);
    assert!(action.attribution.is_none());
    let schema = jsonschema::validator_for(&action.input_schema).unwrap();
    let (_, expanded) = payload::prepare(&simple(), MAX_BODY_BYTES).unwrap();
    let adaptive: Value = serde_json::from_slice(&expanded).unwrap();
    assert_eq!(
        adaptive["attachments"][0]["content"]["body"][0]["text"],
        "Release"
    );
    assert_eq!(
        adaptive["attachments"][0]["content"]["body"][1]["wrap"],
        true
    );
    for value in [
        simple(),
        json!({"destination":"release-alerts","contentFormat":"microsoft","content":adaptive}),
        json!({"destination":"release-alerts","contentFormat":"microsoft","content":message_card()}),
    ] {
        assert!(schema.is_valid(&value));
        let (_, bytes) = payload::prepare(&value, MAX_BODY_BYTES).unwrap();
        if value["contentFormat"] == "microsoft" {
            assert_eq!(
                serde_json::from_slice::<Value>(&bytes).unwrap(),
                value["content"]
            );
        }
    }
    for value in [
        json!({"destination":"https://example.com","contentFormat":"simple","content":{"text":"hi"}}),
        json!({"destination":"release-alerts","contentFormat":"simple","content":{"text":" "}}),
        json!({"destination":"release-alerts","contentFormat":"simple","content":{"text":"hi","payload":{}}}),
        json!({"destination":"release-alerts","contentFormat":"simple","content":{"text":"hi"},"webhookUrl":ENDPOINT}),
        json!({"destination":"release-alerts","contentFormat":"microsoft","content":{"text":"hi"}}),
    ] {
        assert!(!schema.is_valid(&value));
        assert!(payload::prepare(&value, MAX_BODY_BYTES).is_err());
    }
}

#[test]
fn payload_bounds_cover_source_expansion_and_depth() {
    let mut value = simple();
    value["content"]["text"] = json!("x".repeat(24 * 1024));
    assert!(payload::prepare(&value, MAX_BODY_BYTES).is_err());
    let source_len = serde_json::to_vec(&simple()).unwrap().len() as u64;
    assert!(
        payload::prepare(&simple(), source_len + 1).is_err(),
        "simple expansion is bounded too"
    );
    let mut nested = json!(null);
    for _ in 0..33 {
        nested = json!({"nested":nested});
    }
    let mut card = message_card();
    card["extra"] = nested;
    assert!(
        payload::prepare(
            &json!({"destination":"release-alerts","contentFormat":"microsoft","content":card}),
            MAX_BODY_BYTES
        )
        .is_err()
    );
}

#[test]
fn only_current_signed_workflow_urls_and_nonsecret_exact_origins_are_accepted() {
    assert!(valid_webhook_url(ENDPOINT));
    assert!(valid_webhook_url(
        "https://synthetic.86.environment.api.powerplatform.com/opaque/route?sig=fixture"
    ));
    assert!(
        TeamsConfig {
            allowed_upstream_hosts: vec![
                "https://synthetic.86.environment.api.powerplatform.com/**".into()
            ],
            egress_proxy: None,
        }
        .origins()
        .is_ok()
    );
    for prefix in [
        "",
        ".synthetic",
        "synthetic.",
        "synthetic..86",
        "-synthetic.86",
        "synthetic-.86",
        "synthetic._86",
        "*.86",
    ] {
        assert!(!valid_webhook_url(&format!(
            "https://{prefix}.environment.api.powerplatform.com/route?sig=fixture"
        )));
    }
    assert!(!valid_webhook_url(&format!(
        "https://{}.86.environment.api.powerplatform.com/route?sig=fixture",
        "x".repeat(64)
    )));
    assert!(valid_webhook_url(&format!(
        "{ORIGIN}:443/opaque/route?sig={}",
        "x".repeat(500)
    )));
    for endpoint in [
        "https://tenant.webhook.office.com/webhookb2/secret",
        "https://prod.logic.azure.com/workflows/fixture?sig=x",
        "http://synthetic.environment.api.powerplatform.com/path?sig=x",
        "https://synthetic.environment.api.powerplatform.com:444/path?sig=x",
        "https://user:pass@synthetic.environment.api.powerplatform.com/path?sig=x",
        "https://synthetic.environment.api.powerplatform.com/path?sig=x#fragment",
        "https://synthetic.environment.api.powerplatform.com.evil.example/path?sig=x",
        "https://127.0.0.1/path?sig=x",
        "https://synthetic.environment.api.powerplatform.com/path",
        "https://synthetic.environment.api.powerplatform.com/path?sig=",
        "https://synthetic.environment.api.powerplatform.com/path?sig=x\n",
        "https://synthetic.environment.api.powerplatform.com\\path?sig=x",
    ] {
        assert!(!valid_webhook_url(endpoint));
    }
    assert!(config().origins().is_ok());
    let attributes =
        ResourceAttributes::from(BTreeMap::from([("webhookUrl".into(), ENDPOINT.into())]));
    assert!(
        config()
            .validate_resource_attributes(TEAMS_DESTINATION_RESOURCE.id(), &attributes)
            .is_ok()
    );
    let other = TeamsConfig {
        allowed_upstream_hosts: vec!["https://other.environment.api.powerplatform.com/**".into()],
        egress_proxy: None,
    };
    assert!(
        other
            .validate_resource_attributes(TEAMS_DESTINATION_RESOURCE.id(), &attributes)
            .is_err()
    );
    let unsafe_config = TeamsConfig {
        allowed_upstream_hosts: vec![ENDPOINT.into()],
        egress_proxy: None,
    };
    assert!(!format!("{unsafe_config:?}").contains("SYNTHETIC_SECRET"));
    assert!(
        !unsafe_config
            .origins()
            .unwrap_err()
            .contains("SYNTHETIC_SECRET")
    );
    let mut errors = vec![];
    config().validate(
        &ValidationContext {
            environment: "production",
            policy_authority: "toml",
            limits: &ProviderLimits::default(),
            credentials: ServiceCredentialKinds {
                service: Some("bearer"),
                per_user: None,
            },
        },
        &mut errors,
    );
    assert_eq!(errors.len(), 2);
}

#[test]
fn build_creates_one_single_attempt_client_per_configured_origin() {
    let second = "https://second.environment.api.powerplatform.com";
    let host = agent_access_provider::test_support::TestHost::default();
    TeamsConfig {
        allowed_upstream_hosts: vec![format!("{ORIGIN}/**"), format!("{second}/**")],
        egress_proxy: None,
    }
    .build(&host.context())
    .unwrap();
    let built = host
        .built_clients()
        .into_iter()
        .map(|client| {
            (
                client.base.to_string(),
                client.profile,
                client.literal_loopback,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        built,
        [
            (format!("{ORIGIN}/"), ClientProfile::SingleAttempt, false),
            (format!("{second}/"), ClientProfile::SingleAttempt, false),
        ]
    );
}

async fn transport(server: &MockServer) -> HttpTransport {
    let base = Url::parse(&format!("{}/", server.uri())).unwrap();
    let limits = ProviderLimits {
        request_timeout_ms: 200,
        ..ProviderLimits::default()
    };
    let client = UpstreamClient::build(
        UpstreamClientSpec {
            label: "teams.test",
            provider: "teams",
            base: &base,
            egress: EgressDeclaration::Ordinary(None),
            allowed_upstream_hosts: &[format!("{}/**", server.uri())],
            profile: ClientProfile::SingleAttempt,
            status_reasons: &[],
        },
        &agent_access_provider::test_support::TestHost::with_limits(limits),
    )
    .unwrap();
    HttpTransport {
        clients: BTreeMap::from([(base.origin().ascii_serialization(), client)]),
    }
}

#[tokio::test]
async fn http_posts_once_without_auth_and_discards_response_secrets() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/signed"))
        .respond_with(ResponseTemplate::new(202).set_body_string("SYNTHETIC_RESPONSE_SECRET"))
        .expect(1)
        .mount(&server)
        .await;
    let http = transport(&server).await;
    let endpoint = Url::parse(&format!("{}/signed?sig=SYNTHETIC_SECRET", server.uri())).unwrap();
    let receipt = http
        .send(endpoint, b"{\"text\":\"hello\"}".to_vec())
        .await
        .unwrap();
    assert_eq!(receipt, TransportReceipt::status(202));
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].headers["content-type"], "application/json");
    assert!(!requests[0].headers.contains_key("authorization"));
    assert_eq!(requests[0].url.query(), Some("sig=SYNTHETIC_SECRET"));
}

#[tokio::test]
async fn http_redirects_errors_and_timeouts_never_retry_or_leak_urls() {
    for status in [302, 401, 403, 429, 500] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header(
                        "Location",
                        format!("{}/redirect?sig=OTHER_SECRET", server.uri()),
                    )
                    .set_body_string("SYNTHETIC_RESPONSE_SECRET"),
            )
            .expect(1)
            .mount(&server)
            .await;
        let http = transport(&server).await;
        let receipt = http
            .send(
                Url::parse(&format!("{}/signed?sig=SYNTHETIC_SECRET", server.uri())).unwrap(),
                vec![],
            )
            .await
            .unwrap();
        assert_eq!(receipt.status, status);
        assert!(status_reason(status).is_some());
        assert_eq!(receipt.retry_after, None);
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
    for (retry_after, seconds) in [("45", Some(45)), ("172800", Some(86_400)), ("later", None)] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", retry_after))
            .expect(1)
            .mount(&server)
            .await;
        let receipt = transport(&server)
            .await
            .send(
                Url::parse(&format!("{}/signed?sig=SYNTHETIC_SECRET", server.uri())).unwrap(),
                vec![],
            )
            .await
            .unwrap();
        assert_eq!(
            status_reason(receipt.status),
            Some(ReasonCode::UpstreamRateLimited)
        );
        assert_eq!(receipt.retry_after.map(|wait| wait.seconds()), seconds);
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(202).set_delay(std::time::Duration::from_secs(1)))
        .expect(1)
        .mount(&server)
        .await;
    let error = transport(&server)
        .await
        .send(
            Url::parse(&format!("{}/signed?sig=SYNTHETIC_SECRET", server.uri())).unwrap(),
            vec![],
        )
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamTimeout);
    assert!(error.message.contains("outcome may be unknown"));
    assert!(!format!("{error:?}").contains("SYNTHETIC_SECRET"));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}
