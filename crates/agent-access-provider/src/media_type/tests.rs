use super::*;
use crate::{AttachmentLimitsConfig, validate_attachment_limits, validate_upload_limits};
use reqwest::header::HeaderValue;

fn policy(allow: &[&str], deny: &[&str]) -> MediaTypePolicyConfig {
    MediaTypePolicyConfig {
        allow: allow.iter().map(|value| (*value).to_string()).collect(),
        deny: deny.iter().map(|value| (*value).to_string()).collect(),
    }
}

fn permits(policy: &MediaTypePolicyConfig, metadata: &str, response: &str) -> bool {
    policy
        .check_download(
            &MediaTypeDeclaration::parse(metadata),
            &MediaTypeDeclaration::parse(response),
        )
        .is_ok()
}

#[test]
fn download_defaults_and_explicit_empty_policy_are_distinct_from_uploads() {
    let omitted: AttachmentLimitsConfig = toml::from_str("").unwrap();
    assert!(omitted.upload_media_types.is_empty());
    assert_eq!(
        omitted.download_media_types,
        MediaTypePolicyConfig::default()
    );
    assert!(permits(
        &omitted.download_media_types,
        "application/pdf",
        ""
    ));

    let empty: MediaTypePolicyConfig = toml::from_str("allow = []").unwrap();
    assert!(empty.allow.is_empty());
    assert!(!permits(&empty, "application/pdf", "application/pdf"));
    assert!(!permits(&empty, "", ""));

    let deny_only: MediaTypePolicyConfig = toml::from_str("deny = ['text/html']").unwrap();
    assert_eq!(deny_only.allow, ["*/*"]);
    assert!(permits(&deny_only, "application/pdf", ""));
    assert!(!permits(&deny_only, "text/html", ""));

    let upload_only: AttachmentLimitsConfig =
        toml::from_str("upload_media_types = ['text/plain']").unwrap();
    assert_eq!(upload_only.upload_media_types, ["text/plain"]);
    assert!(permits(
        &upload_only.download_media_types,
        "application/pdf",
        ""
    ));
    let download_only: AttachmentLimitsConfig =
        toml::from_str("download_media_types = { allow = ['text/*'] }").unwrap();
    assert!(download_only.upload_media_types.is_empty());
    assert!(!permits(
        &download_only.download_media_types,
        "application/pdf",
        ""
    ));

    let old_key = toml::from_str::<AttachmentLimitsConfig>("media_types = ['text/plain']")
        .unwrap_err()
        .to_string();
    assert!(old_key.contains("unknown field `media_types`"));
    assert!(toml::from_str::<MediaTypePolicyConfig>("allowed = ['text/plain']").is_err());
}

#[test]
fn exact_family_and_universal_patterns_use_deny_precedence() {
    for (allow, deny, value, expected) in [
        (vec!["*/*"], vec![], "application/pdf", true),
        (vec!["application/pdf"], vec![], "application/pdf", true),
        (vec!["application/pdf"], vec![], "application/json", false),
        (vec!["image/*"], vec![], "image/png", true),
        (vec!["image/*"], vec![], "image/svg+xml", true),
        (vec!["image/*"], vec![], "application/png", false),
        (vec!["*/*"], vec!["image/*"], "image/png", false),
        (vec!["image/png"], vec!["image/*"], "image/png", false),
        (vec!["*/*"], vec!["image/svg+xml"], "image/png", true),
        (vec!["*/*"], vec!["image/svg+xml"], "image/svg+xml", false),
        (
            vec!["application/pdf"],
            vec!["*/*"],
            "application/pdf",
            false,
        ),
        (vec!["IMAGE/*"], vec!["image/SVG+XML"], "Image/PNG", true),
        (
            vec!["IMAGE/*"],
            vec!["image/SVG+XML"],
            "Image/Svg+Xml",
            false,
        ),
    ] {
        assert_eq!(
            permits(&policy(&allow, &deny), value, value),
            expected,
            "allow={allow:?}, deny={deny:?}, value={value}"
        );
    }
}

#[test]
fn config_patterns_reject_parameters_whitespace_and_partial_wildcards() {
    for value in [
        "",
        "text",
        "/plain",
        "text/",
        "text/plain/extra",
        "*/plain",
        "text/p*",
        "im*ge/png",
        "image/*+xml",
        "text/plain;charset=utf-8",
        " text/plain",
        "text/plain ",
        "text /plain",
        "text/pläin",
        "text/plain\r\n",
        "text/plain,application/json",
        "*",
    ] {
        for field in ["allow", "deny"] {
            let config = if field == "allow" {
                policy(&[value], &[])
            } else {
                policy(&["*/*"], &[value])
            };
            let mut errors = Vec::new();
            config.validate(
                "providers.jira.attachments.download_media_types",
                &mut errors,
            );
            assert_eq!(errors.len(), 1, "{field}: {value:?}");
            assert!(errors[0].contains(&format!("download_media_types.{field}[0]")));
            assert!(!permits(&config, "text/plain", "text/plain"));
            assert!(
                config
                    .check_metadata(&MediaTypeDeclaration::unspecified())
                    .is_err()
            );
        }
    }
    for value in [
        "text/plain",
        "IMAGE/*",
        "*/*",
        "application/vnd.example+json",
    ] {
        let mut errors = Vec::new();
        policy(&[value], &[]).validate("policy", &mut errors);
        assert!(errors.is_empty(), "{value}: {errors:?}");
    }
}

#[test]
fn all_concrete_declarations_are_checked_without_requiring_equality() {
    assert!(permits(
        &MediaTypePolicyConfig::default(),
        "text/plain",
        "application/json"
    ));
    assert!(permits(
        &policy(&["text/*", "application/json"], &[]),
        "text/plain",
        "application/json"
    ));
    assert!(!permits(
        &policy(&["text/*"], &[]),
        "text/plain",
        "application/json"
    ));
    assert!(!permits(
        &policy(&["text/*"], &[]),
        "application/json",
        "text/plain"
    ));
    assert!(!permits(
        &policy(&["*/*"], &["application/json"]),
        "text/plain",
        "application/json"
    ));
    assert!(!permits(
        &policy(&["*/*"], &["application/json"]),
        "application/json",
        "text/plain"
    ));
}

#[test]
fn generic_declarations_only_match_when_no_concrete_declaration_exists() {
    let only_pdf = policy(&["application/pdf"], &[]);
    let unknown_denied = policy(&["*/*"], &[GENERIC_MEDIA_TYPE]);
    for unspecified in [
        "",
        "  ",
        GENERIC_MEDIA_TYPE,
        "Application/Octet-Stream; filename=a",
    ] {
        assert!(permits(&only_pdf, "application/pdf", unspecified));
        assert!(permits(&only_pdf, unspecified, "application/pdf"));
        assert!(permits(&unknown_denied, "application/pdf", unspecified));
        assert!(permits(&unknown_denied, unspecified, "application/pdf"));
        assert!(!permits(&only_pdf, unspecified, unspecified));
        assert!(!permits(&unknown_denied, unspecified, unspecified));
        assert!(permits(
            &policy(&[GENERIC_MEDIA_TYPE], &[]),
            unspecified,
            unspecified
        ));
        assert!(!permits(
            &policy(&["*/*"], &["application/pdf"]),
            "application/pdf",
            unspecified
        ));
    }
    assert!(permits(&unknown_denied, "binary/octet-stream", ""));
    assert!(!permits(
        &only_pdf,
        "binary/octet-stream",
        "application/pdf"
    ));
    assert!(permits(
        &policy(&["binary/octet-stream"], &[]),
        "binary/octet-stream",
        ""
    ));
}

#[test]
fn metadata_preflight_defers_only_unspecified_declarations() {
    let unspecified = MediaTypeDeclaration::unspecified();
    assert!(
        policy(&["image/*"], &[])
            .check_metadata(&unspecified)
            .is_ok()
    );
    assert!(
        policy(&["*/*"], &[GENERIC_MEDIA_TYPE])
            .check_metadata(&unspecified)
            .is_ok()
    );
    assert!(policy(&[], &[]).check_metadata(&unspecified).is_err());
    assert!(
        policy(&["*/*"], &["*/*"])
            .check_metadata(&unspecified)
            .is_err()
    );
    assert!(
        policy(&["image/*"], &[])
            .check_metadata(&MediaTypeDeclaration::parse("text/plain"))
            .is_err()
    );
    assert!(
        policy(&["*/*"], &["text/html"])
            .check_metadata(&MediaTypeDeclaration::parse("text/html"))
            .is_err()
    );
    assert!(
        policy(&["text/*"], &[])
            .check_metadata(&MediaTypeDeclaration::parse("text/plain"))
            .is_ok()
    );
}

#[test]
fn actual_parameters_are_ignored_but_wildcards_and_invalid_essences_are_malformed() {
    let plain = policy(&["TEXT/PLAIN"], &[]);
    for value in [
        "text/plain",
        " Text/Plain ; charset=utf-8",
        "text/plain;",
        "text/plain;garbage=\"unterminated",
    ] {
        assert!(permits(&plain, value, value), "{value}");
    }
    for value in [
        "*/*",
        "image/*",
        "text/pl*in",
        "text",
        "text/",
        "/plain",
        ";charset=utf-8",
        "text/plain,application/json",
        "text/pläin",
    ] {
        let malformed = MediaTypeDeclaration::parse(value);
        assert_eq!(malformed, MediaTypeDeclaration::malformed(), "{value}");
        assert!(
            MediaTypePolicyConfig::default()
                .check_metadata(&malformed)
                .is_ok()
        );
        assert!(permits(
            &MediaTypePolicyConfig::default(),
            value,
            "text/html"
        ));
        for restrictive in [
            plain.clone(),
            policy(&["*/*"], &["text/html"]),
            policy(&[], &[]),
        ] {
            let error = restrictive
                .check_download(&malformed, &MediaTypeDeclaration::parse("text/plain"))
                .unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::AttachmentMediaTypeDenied);
            assert!(error.message.contains("malformed"));
            assert!(!error.message.contains(value));
            assert!(restrictive.check_metadata(&malformed).is_err());
        }
    }
}

#[test]
fn response_headers_distinguish_missing_empty_duplicate_and_non_text_values() {
    let mut headers = HeaderMap::new();
    assert_eq!(
        MediaTypeDeclaration::from_headers(&headers),
        MediaTypeDeclaration::unspecified()
    );
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(""));
    assert_eq!(
        MediaTypeDeclaration::from_headers(&headers),
        MediaTypeDeclaration::unspecified()
    );
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    assert_eq!(
        MediaTypeDeclaration::from_headers(&headers),
        MediaTypeDeclaration::parse("text/plain")
    );
    headers.append(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    assert_eq!(
        MediaTypeDeclaration::from_headers(&headers),
        MediaTypeDeclaration::malformed()
    );
    headers.insert(CONTENT_TYPE, HeaderValue::from_bytes(b"text/\xff").unwrap());
    assert_eq!(
        MediaTypeDeclaration::from_headers(&headers),
        MediaTypeDeclaration::malformed()
    );
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain, text/html"),
    );
    assert_eq!(
        MediaTypeDeclaration::from_headers(&headers),
        MediaTypeDeclaration::malformed()
    );
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("*/*"));
    assert_eq!(
        MediaTypeDeclaration::from_headers(&headers),
        MediaTypeDeclaration::malformed()
    );
}

#[test]
fn upload_validation_uses_the_new_exact_key_without_changing_gitlab_validator() {
    for value in ["", "invalid", "*/*", "text/*", "text/pl*in"] {
        let config = AttachmentLimitsConfig {
            upload_media_types: vec![value.to_string()],
            ..Default::default()
        };
        let mut errors = Vec::new();
        validate_attachment_limits("providers.jira.attachments", &config, &mut errors);
        assert_eq!(errors.len(), 1, "{value}: {errors:?}");
        assert!(errors[0].contains("attachments.upload_media_types"));
    }
    let mut errors = Vec::new();
    validate_upload_limits(
        "providers.gitlab.attachments",
        1,
        1,
        &["invalid".to_string()],
        &mut errors,
    );
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("providers.gitlab.attachments.media_types"));
    let mut errors = Vec::new();
    validate_attachment_limits(
        "attachments",
        &AttachmentLimitsConfig::default(),
        &mut errors,
    );
    assert!(errors.is_empty());
}
