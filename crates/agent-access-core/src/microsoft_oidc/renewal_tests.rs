//! The renewal side of the Microsoft protocol: `Retry-After`, the bounded
//! token-endpoint body, the classification precedence of design §8.6, the
//! backoff and the OIDC Core §12.2 reference comparison.
use super::*;
use chrono::TimeZone;
use serde_json::json;

const DESCRIPTION_SENTINEL: &str = "SENTINEL-error-description-never-kept";

fn at(seconds: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(seconds, 0).single().unwrap()
}

fn response(
    status: u16,
    retry_after: Option<&str>,
    body: TokenEndpointBody,
) -> TokenEndpointResponse {
    let retry_after = retry_after.map(|value| HeaderValue::from_str(value).unwrap());
    TokenEndpointResponse::new(status, retry_after.as_ref(), body)
}

fn json_body(value: Value) -> TokenEndpointBody {
    TokenEndpointBody::Complete(serde_json::to_vec(&value).unwrap())
}

fn class_name(class: &TokenEndpointClass) -> &'static str {
    match class {
        TokenEndpointClass::Unavailable => "unavailable",
        TokenEndpointClass::Throttled => "throttled",
        TokenEndpointClass::Issued(_) => "issued",
        TokenEndpointClass::InvalidResponse => "invalid_response",
        TokenEndpointClass::SignInRequired => "sign_in_required",
        TokenEndpointClass::ClientRejected => "client_rejected",
        TokenEndpointClass::RequestRejected => "request_rejected",
    }
}

#[test]
fn retry_after_accepts_seconds_and_every_http_date_format_and_is_a_floor() {
    let now = at(1_800_000_000);
    let seconds = RetryAfter::parse(&HeaderValue::from_static("120")).unwrap();
    assert_eq!(seconds, RetryAfter::Seconds(120));
    assert_eq!(seconds.not_before(now), at(1_800_000_120));
    let expected = Utc
        .with_ymd_and_hms(2027, 1, 15, 8, 0, 30)
        .single()
        .unwrap();
    // IMF-fixdate, RFC 850 and asctime (RFC 9110 §5.6.7).
    for date in [
        "Fri, 15 Jan 2027 08:00:30 GMT",
        "Friday, 15-Jan-27 08:00:30 GMT",
        "Fri Jan 15 08:00:30 2027",
    ] {
        assert_eq!(
            RetryAfter::parse(&HeaderValue::from_static(date)),
            Some(RetryAfter::At(expected)),
            "{date}"
        );
    }
    // A date in the past allows a retry now, never earlier.
    assert_eq!(
        RetryAfter::At(at(1_700_000_000)).not_before(now),
        now,
        "a past date is not before now"
    );
    // A weekday that does not match its date, a zone other than GMT and
    // other text are unusable.
    for unusable in [
        "",
        "-5",
        "1.5",
        "soon",
        "Sunday, 15-Jan-27 08:00:30 GMT",
        "Sun, 15 Jan 2027 08:00:30 GMT",
        "Fri, 15 Jan 2027 08:00:30 UTC",
    ] {
        assert_eq!(
            RetryAfter::parse(&HeaderValue::from_str(unusable).unwrap()),
            None,
            "{unusable:?}"
        );
    }
    // An absurd value, as seconds or a date, is clamped to ten years
    // instead of overflowing.
    let ten_years = now + ChronoDuration::seconds(10 * 365 * 24 * 60 * 60);
    let huge = RetryAfter::parse(&HeaderValue::from_static("99999999999999999999")).unwrap();
    assert_eq!(huge.not_before(now), ten_years);
    let far =
        RetryAfter::parse(&HeaderValue::from_static("Fri, 31 Dec 9999 23:59:59 GMT")).unwrap();
    assert_eq!(far.not_before(now), ten_years);
}

#[tokio::test]
async fn token_body_reader_keeps_bounds_and_reports_failure_or_overflow() {
    let chunks = |parts: Vec<Result<&'static [u8], ()>>| {
        futures_util::stream::iter(parts.into_iter().map(|part| part.map(Bytes::from_static)))
    };
    match read_token_endpoint_body(None, chunks(vec![Ok(b"{\"a\""), Ok(b":1}")]), 16).await {
        TokenEndpointBody::Complete(body) => assert_eq!(body, b"{\"a\":1}"),
        _ => panic!("complete body"),
    }
    assert!(matches!(
        read_token_endpoint_body(Some(17), chunks(vec![Ok(b"x")]), 16).await,
        TokenEndpointBody::Oversized
    ));
    assert!(matches!(
        read_token_endpoint_body(None, chunks(vec![Ok(b"0123456789"), Ok(b"0123456789")]), 16)
            .await,
        TokenEndpointBody::Oversized
    ));
    assert!(matches!(
        read_token_endpoint_body(None, chunks(vec![Ok(b"{\"err"), Err(())]), 16).await,
        TokenEndpointBody::Failed
    ));
}

/// Every rule of the precedence, first match wins: no status, 429 whatever
/// the body, 5xx whatever the body, 200 (a usable JSON object only), 4xx by
/// `error`, then any other status.
#[test]
fn classification_follows_the_design_precedence() {
    let error = |error: &str| {
        json_body(json!({
            "error": error,
            "error_description": DESCRIPTION_SENTINEL,
            "error_codes": [70008],
        }))
    };
    let cases: Vec<(&str, TokenEndpointResponse, &str)> = vec![
        (
            "no response",
            TokenEndpointResponse::no_response(),
            "unavailable",
        ),
        (
            "429 json",
            response(429, Some("30"), error("invalid_grant")),
            "throttled",
        ),
        (
            "429 oversized",
            response(429, None, TokenEndpointBody::Oversized),
            "throttled",
        ),
        (
            "429 truncated",
            response(429, None, TokenEndpointBody::Failed),
            "throttled",
        ),
        (
            "500 invalid_grant",
            response(500, None, error("invalid_grant")),
            "unavailable",
        ),
        (
            "503 empty",
            response(503, None, TokenEndpointBody::Complete(vec![])),
            "unavailable",
        ),
        (
            "502 non-json",
            response(502, None, TokenEndpointBody::Complete(b"<html>".to_vec())),
            "unavailable",
        ),
        (
            "200 tokens",
            response(200, None, json_body(json!({"id_token": "a.b.c"}))),
            "issued",
        ),
        (
            "200 without id token",
            response(200, None, json_body(json!({"access_token": "x"}))),
            "issued",
        ),
        (
            "200 truncated",
            response(200, None, TokenEndpointBody::Failed),
            "invalid_response",
        ),
        (
            "200 oversized",
            response(200, None, TokenEndpointBody::Oversized),
            "invalid_response",
        ),
        (
            "200 non-json",
            response(200, None, TokenEndpointBody::Complete(b"not json".to_vec())),
            "invalid_response",
        ),
        (
            "200 array",
            response(200, None, json_body(json!(["id_token"]))),
            "invalid_response",
        ),
        (
            "200 wrong token type",
            response(200, None, json_body(json!({"id_token": 5}))),
            "invalid_response",
        ),
        (
            "400 server_error",
            response(400, None, error("server_error")),
            "unavailable",
        ),
        (
            "400 temporarily_unavailable",
            response(400, None, error("temporarily_unavailable")),
            "unavailable",
        ),
        (
            "400 invalid_grant",
            response(400, None, error("invalid_grant")),
            "sign_in_required",
        ),
        (
            "400 interaction_required",
            response(400, None, error("interaction_required")),
            "sign_in_required",
        ),
        (
            "400 consent_required",
            response(400, None, error("consent_required")),
            "sign_in_required",
        ),
        (
            "400 login_required",
            response(400, None, error("login_required")),
            "sign_in_required",
        ),
        (
            "401 invalid_client",
            response(401, None, error("invalid_client")),
            "client_rejected",
        ),
        (
            "400 unauthorized_client",
            response(400, None, error("unauthorized_client")),
            "client_rejected",
        ),
        (
            "400 invalid_scope",
            response(400, None, error("invalid_scope")),
            "request_rejected",
        ),
        (
            "400 other",
            response(400, None, error("strange_error")),
            "request_rejected",
        ),
        (
            "400 empty",
            response(400, None, TokenEndpointBody::Complete(vec![])),
            "request_rejected",
        ),
        (
            "400 truncated",
            response(400, None, TokenEndpointBody::Failed),
            "request_rejected",
        ),
        (
            "400 oversized",
            response(400, None, TokenEndpointBody::Oversized),
            "request_rejected",
        ),
        (
            "403 non-json",
            response(403, None, TokenEndpointBody::Complete(b"denied".to_vec())),
            "request_rejected",
        ),
        (
            "400 error not a string",
            response(400, None, json_body(json!({"error": ["invalid_grant"]}))),
            "request_rejected",
        ),
        (
            "302",
            response(302, None, TokenEndpointBody::Complete(vec![])),
            "invalid_response",
        ),
        (
            "201",
            response(201, None, json_body(json!({"id_token": "a.b.c"}))),
            "invalid_response",
        ),
        (
            "101",
            response(101, None, TokenEndpointBody::Complete(vec![])),
            "invalid_response",
        ),
    ];
    for (case, response, expected) in cases {
        let (class, diagnostics) = classify_token_endpoint_response(response);
        assert_eq!(class_name(&class), expected, "{case}");
        assert!(
            !format!("{diagnostics:?}").contains(DESCRIPTION_SENTINEL),
            "{case}"
        );
    }
}

#[test]
fn diagnostics_keep_an_allowlisted_error_and_eight_numeric_codes() {
    let (_, diagnostics) = classify_token_endpoint_response(response(
        400,
        Some("Fri, 15 Jan 2027 08:00:30 GMT"),
        json_body(json!({
            "error": "invalid_grant",
            "error_description": DESCRIPTION_SENTINEL,
            "error_codes": [1, 2, "3", 4, 5, 6, 7, 8, 9, 10, -1],
            "trace_id": "trace",
        })),
    ));
    assert_eq!(diagnostics.status, Some(400));
    assert_eq!(diagnostics.error, Some("invalid_grant"));
    assert_eq!(diagnostics.error_codes, [1, 2, 4, 5, 6, 7, 8, 9]);
    assert!(matches!(diagnostics.retry_after, Some(RetryAfter::At(_))));
    let (_, other) = classify_token_endpoint_response(response(
        400,
        None,
        json_body(json!({"error": DESCRIPTION_SENTINEL})),
    ));
    assert_eq!(other.error, Some("other"));
    for allowed in LOGGED_ERRORS {
        let (_, diagnostics) = classify_token_endpoint_response(response(
            400,
            None,
            json_body(json!({"error": allowed})),
        ));
        assert_eq!(diagnostics.error, Some(*allowed));
    }
    // A 200 never reports error fields.
    let (_, success) = classify_token_endpoint_response(response(
        200,
        None,
        json_body(json!({"id_token": "a.b.c", "error": "invalid_grant", "error_codes": [1]})),
    ));
    assert_eq!(success.error, None);
    assert!(success.error_codes.is_empty());
    // Tokens never appear in debug output.
    let (issued, _) = classify_token_endpoint_response(response(
        200,
        None,
        json_body(
            json!({"id_token": "id-SENTINEL", "refresh_token": "rt-SENTINEL", "access_token": "at-SENTINEL"}),
        ),
    ));
    let TokenEndpointClass::Issued(tokens) = &issued else {
        panic!("issued");
    };
    assert_eq!(tokens.refresh_token.as_deref(), Some("rt-SENTINEL"));
    assert!(!format!("{issued:?}").contains("SENTINEL"));
}

#[test]
fn stale_issued_at_is_judged_against_the_renewal_window() {
    let now = at(1_800_000_000);
    let ttl = 8 * 3600;
    assert!(!membership_renewal_issued_at_stale(
        now.timestamp(),
        now,
        ttl
    ));
    // A token from Microsoft's clock ahead is clamped to now, not later.
    assert!(!membership_renewal_issued_at_stale(
        now.timestamp() + 60,
        now,
        ttl
    ));
    // Evidence ending exactly `ahead` from now is stale; one second more is not.
    let boundary = now.timestamp() - (ttl as i64 - ttl as i64 / 4);
    assert!(membership_renewal_issued_at_stale(boundary, now, ttl));
    assert!(!membership_renewal_issued_at_stale(boundary + 1, now, ttl));
}

#[test]
fn backoff_doubles_to_a_cap_with_bounded_jitter() {
    let seconds = |failures, jitter| membership_renewal_backoff(failures, jitter).num_seconds();
    assert_eq!(seconds(1, 0.0), 30);
    assert_eq!(seconds(2, 0.0), 60);
    assert_eq!(seconds(3, 0.0), 120);
    assert_eq!(seconds(5, 0.0), 480);
    assert_eq!(seconds(6, 0.0), 900);
    assert_eq!(seconds(60, 0.0), 900);
    assert_eq!(seconds(0, 0.0), 30);
    assert_eq!(seconds(1, 0.2), 36);
    assert_eq!(seconds(1, -0.2), 24);
    assert_eq!(seconds(1, 5.0), 36, "jitter is bounded to ±20%");
    assert_eq!(seconds(60, 0.2), 1080);
}

#[test]
fn next_attempt_uses_backoff_or_an_hour_and_never_shortens_retry_after() {
    use MembershipRenewalClassification as C;
    let now = at(1_800_000_000);
    let next = |class, failures, retry_after| {
        membership_renewal_next_attempt(class, failures, retry_after, now, 0.0)
            .map(|at| (at - now).num_seconds())
    };
    assert_eq!(next(C::Unavailable, 1, None), Some(30));
    assert_eq!(next(C::Throttled, 3, None), Some(120));
    assert_eq!(
        next(C::Throttled, 1, Some(RetryAfter::Seconds(600))),
        Some(600),
        "Retry-After is a minimum"
    );
    assert_eq!(
        next(C::Unavailable, 6, Some(RetryAfter::Seconds(3600))),
        Some(3600),
        "the local cap does not shorten Retry-After"
    );
    assert_eq!(
        next(C::Unavailable, 6, Some(RetryAfter::Seconds(5))),
        Some(900)
    );
    for blocked in [
        C::GroupsIncomplete,
        C::ClientRejected,
        C::RequestRejected,
        C::InvalidResponse,
    ] {
        assert_eq!(next(blocked, 1, None), Some(3600), "{blocked:?}");
        assert_eq!(
            next(blocked, 1, Some(RetryAfter::Seconds(7200))),
            Some(7200),
            "{blocked:?}"
        );
    }
    for ended in [C::Renewed, C::SignInRequired, C::IdentityMismatch] {
        assert_eq!(next(ended, 1, Some(RetryAfter::Seconds(10))), None);
    }
}

#[test]
fn throttle_uses_retry_after_or_sixty_seconds() {
    let now = at(1_800_000_000);
    assert_eq!(microsoft_oidc_throttle_until(None, now), at(1_800_000_060));
    assert_eq!(
        microsoft_oidc_throttle_until(Some(RetryAfter::Seconds(5)), now),
        at(1_800_000_005)
    );
    assert_eq!(
        microsoft_oidc_throttle_until(Some(RetryAfter::At(at(1_800_000_300))), now),
        at(1_800_000_300)
    );
}

#[test]
fn refresh_request_posts_the_sign_in_scopes_with_client_secret_post() {
    let endpoint = Url::parse(
        "https://login.microsoftonline.com/00000000-0000-4000-8000-000000000001/oauth2/v2.0/token",
    )
    .unwrap();
    let request =
        microsoft_refresh_token_request(&endpoint, "client", "secret", "refresh&=+").unwrap();
    assert_eq!(request.method(), http::Method::POST);
    assert_eq!(request.uri().to_string(), endpoint.as_str());
    assert_eq!(
        request.headers()[http::header::CONTENT_TYPE],
        "application/x-www-form-urlencoded"
    );
    let form = url::form_urlencoded::parse(request.body())
        .into_owned()
        .collect::<Vec<_>>();
    assert_eq!(
        form,
        [
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("refresh_token".to_string(), "refresh&=+".to_string()),
            ("client_id".to_string(), "client".to_string()),
            ("client_secret".to_string(), "secret".to_string()),
            (
                "scope".to_string(),
                "openid profile email offline_access".to_string()
            ),
        ]
    );
}

fn reference(audience: Value, azp: Option<&str>, auth_time: Option<i64>) -> OidcRenewalReference {
    OidcRenewalReference::new(
        "pairwise-subject".to_string(),
        audience,
        azp.map(str::to_string),
        microsoft_oidc_nonce_sha256("sign-in-nonce"),
        auth_time,
    )
    .unwrap()
}

#[test]
fn reference_comparison_separates_claim_and_identity_mismatches() {
    let client = "00000000-0000-4000-8000-000000000002";
    let method = "entra:v1:tenant:object";
    let stored = reference(
        json!([client, "api://other"]),
        Some(client),
        Some(1_700_000_000),
    );
    let audience = json!([client, "api://other"]);
    let valid = RenewalObservation {
        subject: "pairwise-subject",
        audience: &audience,
        authorized_party: Some(client),
        auth_time: Some(1_700_000_000),
        external_subject: method,
    };
    assert_eq!(compare_renewal_reference(&stored, &valid, method), Ok(()));
    let without_auth_time = RenewalObservation {
        auth_time: None,
        ..valid
    };
    assert_eq!(
        compare_renewal_reference(&stored, &without_auth_time, method),
        Ok(())
    );
    let string_audience = json!(client);
    let reordered = json!(["api://other", client]);
    for (case, observed) in [
        (
            "aud as a string",
            RenewalObservation {
                audience: &string_audience,
                ..valid
            },
        ),
        (
            "aud reordered",
            RenewalObservation {
                audience: &reordered,
                ..valid
            },
        ),
        (
            "azp disappears",
            RenewalObservation {
                authorized_party: None,
                ..valid
            },
        ),
        (
            "azp changes",
            RenewalObservation {
                authorized_party: Some("api://other"),
                ..valid
            },
        ),
        (
            "auth_time changes",
            RenewalObservation {
                auth_time: Some(1_700_000_001),
                ..valid
            },
        ),
    ] {
        assert_eq!(
            compare_renewal_reference(&stored, &observed, method),
            Err(RenewalReferenceMismatch::Claims),
            "{case}"
        );
    }
    let without_azp = reference(json!(client), None, None);
    let single = json!(client);
    let appears = RenewalObservation {
        audience: &single,
        authorized_party: Some(client),
        auth_time: None,
        ..valid
    };
    assert_eq!(
        compare_renewal_reference(&without_azp, &appears, method),
        Err(RenewalReferenceMismatch::Claims),
        "azp appears"
    );
    let auth_time_appears = RenewalObservation {
        audience: &single,
        authorized_party: None,
        auth_time: Some(1),
        ..valid
    };
    assert_eq!(
        compare_renewal_reference(&without_azp, &auth_time_appears, method),
        Err(RenewalReferenceMismatch::Claims),
        "auth_time appears"
    );
    for (case, observed) in [
        (
            "sub",
            RenewalObservation {
                subject: "other-subject",
                ..valid
            },
        ),
        (
            "oid",
            RenewalObservation {
                external_subject: "entra:v1:tenant:other",
                ..valid
            },
        ),
    ] {
        assert_eq!(
            compare_renewal_reference(&stored, &observed, method),
            Err(RenewalReferenceMismatch::Identity),
            "{case}"
        );
    }
    // A claim mismatch takes precedence over an identity mismatch.
    let both = RenewalObservation {
        subject: "other-subject",
        authorized_party: None,
        ..valid
    };
    assert_eq!(
        compare_renewal_reference(&stored, &both, method),
        Err(RenewalReferenceMismatch::Claims)
    );
}

#[test]
fn refreshed_nonce_may_be_absent_or_the_sign_in_nonce() {
    let stored = reference(json!("client"), None, None);
    assert!(renewal_nonce_matches(&stored, None));
    assert!(renewal_nonce_matches(&stored, Some("sign-in-nonce")));
    assert!(!renewal_nonce_matches(&stored, Some("other-nonce")));
    assert!(!renewal_nonce_matches(&stored, Some("")));
}
