use super::*;
use crate::test_support::{InvocationBuilder, test_signing_key};
use crate::{CredentialMode, InvocationIdentity, ProviderInvocation, SigningError};

const FAMILY: ContinuationFamily = ContinuationFamily::new(
    "gitlab",
    "search-page",
    1,
    ContinuationLifetime::StableWhenConfigured,
    32,
)
.confidential()
.fixed_payload_length()
.expires_after(Duration::from_secs(900))
.clock_skew(Duration::from_secs(60));
const ISSUED: u64 = 1_800_000_000;

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

fn request() -> ProviderInvocation {
    InvocationBuilder::new("gitlab", "search.code")
        .identity(InvocationIdentity::new("alice", true))
        .build()
}

fn bind(family: &ContinuationFamily, request: &ProviderInvocation) -> ContinuationBinding {
    family
        .bind(request.context(), "https://gitlab.example/api/v4|basic")
        .text("query", "synthetic-query")
        .number("maxResults", 20)
}

fn payload(position: u64) -> [u8; 32] {
    let mut out = [0_u8; 32];
    out[0] = 2;
    out[1..9].copy_from_slice(&position.to_be_bytes());
    out
}

fn seal(signer: &ContinuationSigner, binding: &ContinuationBinding) -> String {
    signer
        .seal_until_at(binding, &payload(42), ISSUED + 900, at(ISSUED))
        .unwrap()
}

#[test]
fn confidential_v1_matches_independent_openssl_vector() {
    // Public test key 07*32, nonce 00..0b. Expected bytes independently
    // calculated with Python stdlib HMAC/HKDF and OpenSSL EVP AES-256-GCM.
    let signer = ContinuationSigner::new(Some(test_signing_key(7)));
    let binding = bind(&FAMILY, &request());
    let token = signer
        .seal_confidential_with_nonce(
            &binding,
            &payload(42),
            ISSUED + 900,
            std::array::from_fn(|i| i as u8),
        )
        .unwrap();
    assert_eq!(
        token,
        "QUFDRQEBAAAAAGtJ1YQAAQIDBAUGBwgJCgt_cD-3N-yuSGPVlTGPyD_nKvlva9t6fl0qAZgpdrTvoAYrLcPVx4UKMukmBm0OeUY"
    );
    assert_eq!(
        signer
            .open_confidential_at(&binding, &token, at(ISSUED))
            .unwrap()
            .payload(),
        &payload(42)
    );
    assert_eq!(FAMILY.max_token_bytes(), 99);
    assert_eq!(FAMILY.max_payload_bytes_within(99), 32);
    // Generation and unwrapped stable ports have the identical raw PRF path.
    let local = ContinuationSigner {
        generation: Arc::new([7; 32]),
        stable: None,
    };
    assert_eq!(
        local
            .seal_confidential_with_nonce(
                &binding,
                &payload(42),
                ISSUED + 900,
                std::array::from_fn(|i| i as u8),
            )
            .unwrap(),
        token
    );
}

#[test]
fn every_envelope_byte_is_authenticated_and_lengths_and_formats_are_strict() {
    let signer = ContinuationSigner::new(None);
    let binding = bind(&FAMILY, &request());
    let token = seal(&signer, &binding);
    let raw = URL_SAFE_NO_PAD.decode(&token).unwrap();
    for index in 0..raw.len() {
        let mut changed = raw.clone();
        changed[index] ^= 1;
        assert!(
            signer
                .open_confidential_at(&binding, &URL_SAFE_NO_PAD.encode(changed), at(ISSUED))
                .is_err(),
            "byte {index}"
        );
    }
    for length in 0..raw.len() {
        assert!(
            signer
                .open_confidential_at(
                    &binding,
                    &URL_SAFE_NO_PAD.encode(&raw[..length]),
                    at(ISSUED)
                )
                .is_err()
        );
    }
    for malformed in [format!("{token}="), format!("{token}A"), "💥".into()] {
        assert!(
            signer
                .open_confidential_at(&binding, &malformed, at(ISSUED))
                .is_err()
        );
    }
    assert!(matches!(
        signer.seal_until_at(&binding, &[0; 31], ISSUED + 900, at(ISSUED)),
        Err(ContinuationError::Invalid)
    ));
    assert!(matches!(
        signer.seal_until_at(&binding, &[0; 33], ISSUED + 900, at(ISSUED)),
        Err(ContinuationError::PayloadTooLarge { limit: 32 })
    ));
}

#[test]
fn modes_and_all_family_and_binding_inputs_are_separate() {
    let signer = ContinuationSigner::new(Some(test_signing_key(7)));
    let original = request();
    let binding = bind(&FAMILY, &original);
    let token = seal(&signer, &binding);
    for changed in [
        InvocationBuilder::from(original.clone())
            .service("elsewhere")
            .build(),
        InvocationBuilder::from(original.clone())
            .action("search.issues")
            .build(),
        InvocationBuilder::from(original.clone())
            .principal("bob")
            .build(),
        InvocationBuilder::from(original.clone())
            .identity(InvocationIdentity::new("alice", false))
            .build(),
        InvocationBuilder::from(original.clone())
            .execution_context("external")
            .build(),
        InvocationBuilder::from(original.clone())
            .credential_mode(CredentialMode::PerUser)
            .build(),
    ] {
        assert!(matches!(
            signer.open_confidential_at(&bind(&FAMILY, &changed), &token, at(ISSUED)),
            Err(ContinuationError::Invalid)
        ));
    }
    for changed in [
        ContinuationFamily {
            service: "other",
            ..FAMILY
        },
        ContinuationFamily {
            purpose: "other",
            ..FAMILY
        },
        ContinuationFamily {
            version: 2,
            ..FAMILY
        },
    ] {
        assert!(
            signer
                .open_confidential_at(&bind(&changed, &original), &token, at(ISSUED))
                .is_err()
        );
    }
    // Every provider-owned field enters both key derivation and AAD.
    for label in [
        "endpoint",
        "query",
        "engine",
        "pageSize",
        "boundary",
        "projectId",
        "projectPath",
        "credentialMethod",
        "delegatedBinding",
    ] {
        let before = binding.clone().text(label, "original");
        let after = binding.clone().text(label, "changed");
        let token = seal(&signer, &before);
        assert!(
            matches!(
                signer.open_confidential_at(&after, &token, at(ISSUED)),
                Err(ContinuationError::Invalid)
            ),
            "{label}"
        );
    }
    let signed = ContinuationFamily {
        confidential: false,
        ..FAMILY
    };
    let signed_binding = bind(&signed, &original);
    let signed_token = signer
        .seal_at(&signed_binding, &payload(42), at(ISSUED))
        .unwrap();
    assert!(
        signer
            .open_confidential_at(&binding, &signed_token, at(ISSUED))
            .is_err()
    );
    assert!(signer.open_at(&signed_binding, &token, at(ISSUED)).is_err());
    // No relative-expiry or relayed alternate path can renew a confidential token.
    assert!(signer.seal_at(&binding, &payload(42), at(ISSUED)).is_err());
    assert!(signer.open_at(&binding, &token, at(ISSUED)).is_err());
    assert!(
        signer
            .seal_relayed_at(&binding, None, "opaque", at(ISSUED))
            .is_err()
    );
    assert!(
        signer
            .open_relayed_at(&binding, None, &token, at(ISSUED))
            .is_err()
    );
}

#[test]
fn skewed_instances_carry_exact_expiry_and_fail_when_it_passes() {
    let signer = ContinuationSigner::new(Some(test_signing_key(3)));
    let receiver = ContinuationSigner::new(Some(test_signing_key(3)));
    let binding = bind(&FAMILY, &request());
    assert_eq!(
        signer.deadline_at(&binding, at(ISSUED)).unwrap(),
        ISSUED + 900
    );
    let token = seal(&signer, &binding);
    let opened = receiver
        .open_confidential_at(&binding, &token, at(ISSUED - 60))
        .unwrap();
    assert_eq!(opened.expiry(), ISSUED + 900);
    assert!(matches!(
        receiver.seal_until_at(&binding, &payload(43), opened.expiry(), at(ISSUED - 60)),
        Err(ContinuationError::Invalid)
    ));
    let resealed = receiver
        .seal_resumed_at(&binding, &payload(43), &opened, at(ISSUED - 60))
        .unwrap();
    assert_eq!(
        signer
            .open_confidential_at(&binding, &resealed, at(ISSUED + 899))
            .unwrap()
            .expiry(),
        ISSUED + 900
    );
    assert!(matches!(
        receiver.open_confidential_at(&binding, &token, at(ISSUED - 61)),
        Err(ContinuationError::Invalid)
    ));
    for now in [ISSUED + 900, ISSUED + 960] {
        assert!(matches!(
            receiver.open_confidential_at(&binding, &token, at(now)),
            Err(ContinuationError::Expired)
        ));
        assert!(matches!(
            receiver.seal_resumed_at(&binding, &payload(43), &opened, at(now)),
            Err(ContinuationError::Expired)
        ));
        assert!(matches!(
            receiver.seal_until_at(&binding, &payload(43), ISSUED + 900, at(now)),
            Err(ContinuationError::Expired)
        ));
    }
    assert!(matches!(
        receiver.seal_resumed_at(
            &binding.clone().text("query", "changed"),
            &payload(43),
            &opened,
            at(ISSUED)
        ),
        Err(ContinuationError::Invalid)
    ));
    let different = bind(
        &ContinuationFamily {
            purpose: "other",
            ..FAMILY
        },
        &request(),
    );
    assert!(matches!(
        receiver.seal_resumed_at(&different, &payload(43), &opened, at(ISSUED)),
        Err(ContinuationError::Invalid)
    ));
}

#[test]
fn fresh_nonces_hide_positions_and_debug_hides_plaintext_and_bindings() {
    let signer = ContinuationSigner::new(None);
    let binding = bind(&FAMILY, &request());
    let first = seal(&signer, &binding);
    let second = seal(&signer, &binding);
    assert_ne!(first, second);
    for position in [1, 42, u64::MAX] {
        let token = signer
            .seal_until_at(&binding, &payload(position), ISSUED + 900, at(ISSUED))
            .unwrap();
        assert_eq!(token.len(), 99);
        let raw = URL_SAFE_NO_PAD.decode(&token).unwrap();
        assert!(!raw.windows(8).any(|bytes| bytes == position.to_be_bytes()));
        assert!(!raw.windows(15).any(|bytes| bytes == b"synthetic-query"));
        let opened = signer
            .open_confidential_at(&binding, &token, at(ISSUED))
            .unwrap();
        assert_eq!(format!("{opened:?}"), "OpenedContinuation { .. }");
    }
}

#[test]
fn encryption_key_lifetimes_and_key_failures_do_not_downgrade() {
    let stable = ContinuationSigner::new(Some(test_signing_key(7)));
    let reloaded = ContinuationSigner::new(Some(test_signing_key(7)));
    let rotated = ContinuationSigner::new(Some(test_signing_key(8)));
    let ephemeral = ContinuationSigner::new(None);
    let binding = bind(&FAMILY, &request());
    let token = seal(&stable, &binding);
    assert!(
        reloaded
            .open_confidential_at(&binding, &token, at(ISSUED))
            .is_ok()
    );
    for different in [&rotated, &ephemeral] {
        assert!(
            different
                .open_confidential_at(&binding, &token, at(ISSUED))
                .is_err()
        );
    }
    let fallback = seal(&ephemeral, &binding);
    assert!(
        ContinuationSigner::new(None)
            .open_confidential_at(&binding, &fallback, at(ISSUED))
            .is_err()
    );
    let generation = bind(
        &ContinuationFamily {
            lifetime: ContinuationLifetime::Generation,
            ..FAMILY
        },
        &request(),
    );
    let token = seal(&stable, &generation);
    assert!(
        reloaded
            .open_confidential_at(&generation, &token, at(ISSUED))
            .is_err()
    );
    let durable = bind(
        &ContinuationFamily {
            lifetime: ContinuationLifetime::Durable,
            ..FAMILY
        },
        &request(),
    );
    assert!(matches!(
        ephemeral.seal_until_at(&durable, &payload(42), ISSUED + 900, at(ISSUED)),
        Err(ContinuationError::DurableKeyUnavailable)
    ));
    struct BrokenKey(Option<&'static str>);
    impl StableSigningKey for BrokenKey {
        fn hmac_base64url(&self, _: &[u8], _: &[u8]) -> Result<String, SigningError> {
            self.0.map(str::to_owned).ok_or(SigningError)
        }
    }
    for answer in [None, Some("invalid-base64!"), Some("AA")] {
        let broken = ContinuationSigner::new(Some(Arc::new(BrokenKey(answer))));
        assert!(matches!(
            broken.seal_until_at(&binding, &payload(42), ISSUED + 900, at(ISSUED)),
            Err(ContinuationError::SigningUnavailable)
        ));
        let token = seal(&stable, &binding);
        assert!(matches!(
            broken.open_confidential_at(&binding, &token, at(ISSUED)),
            Err(ContinuationError::SigningUnavailable)
        ));
    }
}

#[test]
fn confidential_domains_are_disjoint_from_all_sdk_signing_domains() {
    let domains = [
        SEED_DOMAIN,
        EXTRACT_DOMAIN,
        KEY_DOMAIN,
        ENVELOPE_DOMAIN,
        AEAD_BINDING_DOMAIN,
        MAC_DOMAIN,
        BINDING_DOMAIN,
        OWNER_DOMAIN,
        b"agent-access/service/",
        b"agent-access/credential-material/v1\0",
    ];
    for (index, domain) in domains.iter().enumerate() {
        for other in &domains[index + 1..] {
            assert!(!domain.starts_with(other) && !other.starts_with(domain));
        }
    }
}

#[test]
fn variable_payload_families_compute_their_own_caps() {
    let signer = ContinuationSigner::new(None);
    for cap in [0, 1, 7, 32, 100, 1000] {
        let family = ContinuationFamily {
            max_payload_bytes: cap,
            fixed_payload_length: false,
            ..FAMILY
        };
        let binding = bind(&family, &request());
        let token = signer
            .seal_until_at(&binding, &vec![7; cap], ISSUED + 900, at(ISSUED))
            .unwrap();
        assert_eq!(token.len(), family.max_token_bytes());
        assert_eq!(
            signer
                .open_confidential_at(&binding, &token, at(ISSUED))
                .unwrap()
                .payload()
                .len(),
            cap
        );
        assert_eq!(family.max_payload_bytes_within(token.len()), cap);
    }
    let no_expiry = bind(
        &ContinuationFamily {
            time_to_live: None,
            ..FAMILY
        },
        &request(),
    );
    assert!(signer.deadline_at(&no_expiry, at(ISSUED)).is_err());
}
