// Stored-credential golden vectors. `upsert_user_credential` wrote these rows
// for principal `alice` with key `k1` (`[7; 32]`): the first three at 808326b
// and the imported `username-token` row at 0b00bec. Upgrades must keep
// resolving them without reentry, so the row columns, the AAD inputs and
// encoding, the `basic_api_token`/`bearer_token` kind spellings, the profiles
// and the secret plaintext encoding are a persisted contract. Adapt assertions
// to a changed credential API, but never regenerate these vectors to make a
// change pass.

struct GoldenStoredCredential {
    credential_id: &'static str,
    service: &'static str,
    profile: &'static str,
    credential_kind: &'static str,
    metadata_json: &'static str,
    secret_ref: &'static str,
    material_version: &'static str,
    nonce_hex: &'static str,
    ciphertext_hex: &'static str,
    username: Option<&'static str>,
    token: &'static str,
}

const GOLDEN_STORED_CREDENTIALS: [GoldenStoredCredential; 4] = [
    GoldenStoredCredential {
        credential_id: "1f5455b1-7a4d-485d-9f44-764a44e0e986",
        service: "jira",
        profile: "jira-cloud-api-token",
        credential_kind: "basic_api_token",
        metadata_json: r#"{"displayName":"Golden jira"}"#,
        secret_ref: "sqlite:804ab3da-42ba-4b0b-8144-16289ad01822",
        material_version: "04bd9663-c38d-4ed3-8af0-3ad5cdd521b8",
        nonce_hex: "33c2e817be12209e69112325",
        ciphertext_hex: "cc4adac920f93242c9a1e1dbf7ec3226fc67220a56737606ee4d2a31315be67a1ef7297d7233ed0614f9282a29500765065578a7d04ab841b60006e1747fe41284d592235afba21ff237aa6dfd4b6e05e61ddcce",
        username: Some("golden-user@example.test"),
        token: "golden-basic-token",
    },
    GoldenStoredCredential {
        credential_id: "6ea4980a-d221-4b6d-9b91-8517d9ba3ef6",
        service: "gitlab",
        profile: "gitlab-access-token",
        credential_kind: "bearer_token",
        metadata_json: r#"{"displayName":"Golden gitlab"}"#,
        secret_ref: "sqlite:d2304881-5c3a-473d-919a-c12a8ace9fed",
        material_version: "500629d8-6f88-4251-b2d3-4de7a85b1db3",
        nonce_hex: "e549ad39165ab5ba568566e0",
        ciphertext_hex: "11fe309ca61f2a38f5b242e742f8e9f9e6a1e50d0a8cd054ab979cfe2efeea99c71de80769103782134fcebf6028dd",
        username: None,
        token: "golden-bearer-token",
    },
    // A personal credential for an imported service uses the same table with
    // the profile its accepted declaration fixes: `token` (`bearer_token`) for
    // MCP, OpenAPI and token command imports, and `username-token`
    // (`basic_api_token`) for command imports that declare `username_token`.
    GoldenStoredCredential {
        credential_id: "6b834d3a-33ee-40df-be85-54a3d3fd1595",
        service: "inventory",
        profile: "token",
        credential_kind: "bearer_token",
        metadata_json: r#"{"displayName":"Golden inventory"}"#,
        secret_ref: "sqlite:e2cec613-c234-450d-865e-96d7ade95d7d",
        material_version: "604fbaea-f817-49d3-a849-332962dbc391",
        nonce_hex: "9065e0c9112f78021006e402",
        ciphertext_hex: "0cb78e85403a49442a0897c7b8147b0311595a4ef6bc73f95720dec8f0e05c308a1a7e88add4ac63a67ba856922c82da5cd7bfba63686dda4da9",
        username: None,
        token: "golden-imported-personal-token",
    },
    GoldenStoredCredential {
        credential_id: "85073696-f3ad-4078-875e-8bf0effd22f4",
        service: "ticketing",
        profile: "username-token",
        credential_kind: "basic_api_token",
        metadata_json: r#"{"displayName":"Golden ticketing"}"#,
        secret_ref: "sqlite:4093d38d-3417-4429-9d0c-54bb0d20aa12",
        material_version: "8db173cf-4bc2-431c-b943-321446e0e821",
        nonce_hex: "721ecf97d4fb800994bb05e4",
        ciphertext_hex: "cf0b22a76330c238db50f75793afdf365bbe087a03084a1c32b11138bfe62520a53b7ae72da241ab3a94ff40563c29244d10581b40b6337a1362919149bdfdaeb991d4681a83362ba62ba5ab479d58d513916e3de9d578bdc2d9689e",
        username: Some("golden-imported-user"),
        token: "golden-imported-username-token",
    },
];

fn golden_hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn store_with_golden_stored_credentials() -> (TempDir, ManagedStore) {
    let temp = TempDir::new().unwrap();
    let store = ManagedStore::open(
        &store_config(&temp.path().join("store.sqlite")),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    create_alice(&store);
    {
        let conn = store.connection.lock().unwrap();
        for golden in &GOLDEN_STORED_CREDENTIALS {
            conn.execute(
                "INSERT INTO credentials
                 (credential_id, owner_principal_id, owner_kind, service, name, profile,
                  credential_kind, metadata_json, secret_backend, secret_ref, material_version,
                  status, created_at, updated_at, created_by, updated_by, verification_status)
                 VALUES (?1, 'alice', 'user', ?2, 'default', ?3, ?4, ?5, 'sqlite_encrypted', ?6, ?7,
                         'active', '2026-10-13T00:00:00Z', '2026-10-13T00:00:00Z', 'admin', 'admin',
                         'not_verified')",
                params![
                    golden.credential_id,
                    golden.service,
                    golden.profile,
                    golden.credential_kind,
                    golden.metadata_json,
                    golden.secret_ref,
                    golden.material_version,
                ],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO credential_secret_material
                 (secret_ref, credential_id, backend, secret_ciphertext, secret_nonce, key_id,
                  created_at, updated_at)
                 VALUES (?1, ?2, 'sqlite_encrypted', ?3, ?4, 'k1', '2026-10-13T00:00:00Z',
                         '2026-10-13T00:00:00Z')",
                params![
                    golden.secret_ref,
                    golden.credential_id,
                    golden_hex(golden.ciphertext_hex),
                    golden_hex(golden.nonce_hex),
                ],
            )
            .unwrap();
        }
    }
    (temp, store)
}

#[test]
fn stored_credential_rows_from_baseline_resolve_without_reentry() {
    let (_temp, store) = store_with_golden_stored_credentials();
    let ring = key_ring("k1");
    store.check_ready(Some(&ring)).unwrap();
    for golden in &GOLDEN_STORED_CREDENTIALS {
        let credential = store
            .resolve_user_credential(&ring, "alice", golden.service, "default", &[golden.profile.to_string()])
            .unwrap();
        assert_eq!(
            credential.kind().as_str(),
            golden.credential_kind,
            "{}",
            golden.service
        );
        // Lent as the row's own stored profile.
        let expected = credential_with_profile(
            match golden.username {
                Some(username) => basic_credential(username, golden.token),
                None => bearer_credential(golden.token),
            },
            golden.profile,
        );
        assert_eq!(credential, expected, "{}", golden.service);
    }
}

#[test]
fn imported_username_token_row_from_baseline_resolves_for_a_command() {
    let (_temp, store) = store_with_golden_stored_credentials();
    let ring = key_ring("k1");
    let credential = store
        .resolve_user_command_credential(&ring, "alice", "ticketing", "default", &["username-token".to_string()])
        .unwrap();
    assert_eq!(
        credential.kind(),
        crate::imports::ImportedCredentialKind::UsernameToken
    );
}

#[test]
fn stored_credential_aad_is_derived_from_frozen_row_fields() {
    let (_temp, store) = store_with_golden_stored_credentials();
    let conn = store.connection.lock().unwrap();
    let row = encrypted_credential_by_tuple(&conn, "alice", "jira", "default").unwrap();
    assert_eq!(
        credential_aad(&row).bytes(),
        "schema_version=002_credential_secret_material;\
         credential_id=1f5455b1-7a4d-485d-9f44-764a44e0e986;owner_kind=user;\
         owner_principal=alice;service=jira;name=default;\
         credential_profile=jira-cloud-api-token;credential_kind=basic_api_token;\
         secret_backend=sqlite_encrypted;secret_ref=sqlite:804ab3da-42ba-4b0b-8144-16289ad01822;\
         material_version=04bd9663-c38d-4ed3-8af0-3ad5cdd521b8;key_id=k1"
    );
    let row = encrypted_credential_by_tuple(&conn, "alice", "ticketing", "default").unwrap();
    assert_eq!(
        credential_aad(&row).bytes(),
        "schema_version=002_credential_secret_material;\
         credential_id=85073696-f3ad-4078-875e-8bf0effd22f4;owner_kind=user;\
         owner_principal=alice;service=ticketing;name=default;\
         credential_profile=username-token;credential_kind=basic_api_token;\
         secret_backend=sqlite_encrypted;secret_ref=sqlite:4093d38d-3417-4429-9d0c-54bb0d20aa12;\
         material_version=8db173cf-4bc2-431c-b943-321446e0e821;key_id=k1"
    );
}

// Vendor-level Atlassian rows. `upsert_user_credential` wrote these for
// `alice` with key `k1` at c0f5858: an `atlassian-api-token` row under the
// shared `atlassian` connection, which Jira and Confluence both consume, and
// an `atlassian-bearer-token` row under a per-product `confluence`
// connection. They are frozen like the rows above. The product-profile row
// above (`jira`/`jira-cloud-api-token`) stays beside them: no connection
// selects a product profile any longer, but its row must still decrypt for
// cleanup and rewrap.
const GOLDEN_ATLASSIAN_STORED_CREDENTIALS: [GoldenStoredCredential; 2] = [
    GoldenStoredCredential {
        credential_id: "3d881cd0-02cb-497e-b1c2-08ba76a4b4c3",
        service: "atlassian",
        profile: "atlassian-api-token",
        credential_kind: "basic_api_token",
        metadata_json: r#"{"displayName":"Golden atlassian"}"#,
        secret_ref: "sqlite:8679ed83-4294-4985-87fe-ced8638c90a8",
        material_version: "efc08149-29b8-4cd5-8262-d2acf02ce6a1",
        nonce_hex: "0f20334e090f7468cf05580a",
        ciphertext_hex: "c2db121b237a4ee8f9ab9b7d52a23af8b2fb34b7ed2d7b5720b069f6ef801ac2ca9d0ed42b060b4270f7c37d1a89a02b1a1503af06cae036d722b47cf8ec944426f668f3c07dd9d33b20d5db07a95b3384f1d64fdd69007ef0f7917debe9d6431a335d165bd7",
        username: Some("golden-atlassian-user@example.test"),
        token: "golden-atlassian-api-token",
    },
    GoldenStoredCredential {
        credential_id: "a221934a-f519-4cbb-9b3b-002334d847f7",
        service: "confluence",
        profile: "atlassian-bearer-token",
        credential_kind: "bearer_token",
        metadata_json: r#"{"displayName":"Golden confluence"}"#,
        secret_ref: "sqlite:19ff2e62-716d-4588-b943-98ffa9e3b073",
        material_version: "780f37a8-8e4c-4b71-8e64-f108c0532258",
        nonce_hex: "aedbd7907ab06494d3cd62ee",
        ciphertext_hex: "8dac1051d9042c21a7eedd20d26d29e776feebc9cbd23923646f05683b4bf08cd5b4a99345f144e1778019ddb60ab55a36c3e0c056f54c57eb",
        username: None,
        token: "golden-atlassian-bearer-token",
    },
];

/// The baseline store with the vendor-level Atlassian rows added beside the
/// rows above, inserted with the same columns.
fn store_with_golden_atlassian_stored_credentials() -> (TempDir, ManagedStore) {
    let (temp, store) = store_with_golden_stored_credentials();
    {
        let conn = store.connection.lock().unwrap();
        for golden in &GOLDEN_ATLASSIAN_STORED_CREDENTIALS {
            conn.execute(
                "INSERT INTO credentials
                 (credential_id, owner_principal_id, owner_kind, service, name, profile,
                  credential_kind, metadata_json, secret_backend, secret_ref, material_version,
                  status, created_at, updated_at, created_by, updated_by, verification_status)
                 VALUES (?1, 'alice', 'user', ?2, 'default', ?3, ?4, ?5, 'sqlite_encrypted', ?6, ?7,
                         'active', '2026-10-16T00:00:00Z', '2026-10-16T00:00:00Z', 'admin', 'admin',
                         'not_verified')",
                params![
                    golden.credential_id,
                    golden.service,
                    golden.profile,
                    golden.credential_kind,
                    golden.metadata_json,
                    golden.secret_ref,
                    golden.material_version,
                ],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO credential_secret_material
                 (secret_ref, credential_id, backend, secret_ciphertext, secret_nonce, key_id,
                  created_at, updated_at)
                 VALUES (?1, ?2, 'sqlite_encrypted', ?3, ?4, 'k1', '2026-10-16T00:00:00Z',
                         '2026-10-16T00:00:00Z')",
                params![
                    golden.secret_ref,
                    golden.credential_id,
                    golden_hex(golden.ciphertext_hex),
                    golden_hex(golden.nonce_hex),
                ],
            )
            .unwrap();
        }
    }
    (temp, store)
}

fn expected_golden_credential(golden: &GoldenStoredCredential) -> ExecutionCredential {
    credential_with_profile(
        match golden.username {
            Some(username) => basic_credential(username, golden.token),
            None => bearer_credential(golden.token),
        },
        golden.profile,
    )
}

#[test]
fn vendor_atlassian_rows_resolve_beside_the_product_profile_row() {
    let (_temp, store) = store_with_golden_atlassian_stored_credentials();
    let ring = key_ring("k1");
    store.check_ready(Some(&ring)).unwrap();
    for golden in &GOLDEN_ATLASSIAN_STORED_CREDENTIALS {
        let credential = store
            .resolve_user_credential(&ring, "alice", golden.service, "default", &[golden.profile.to_string()])
            .unwrap();
        assert_eq!(
            credential.kind().as_str(),
            golden.credential_kind,
            "{}",
            golden.service
        );
        assert_eq!(
            credential,
            expected_golden_credential(golden),
            "{}",
            golden.service
        );
    }
    // The product-profile row still decrypts under its own profile, and is
    // never read under a vendor-level profile its row does not carry.
    let product = &GOLDEN_STORED_CREDENTIALS[0];
    assert_eq!(
        store
            .resolve_user_credential(&ring, "alice", "jira", "default", &[product.profile.to_string()])
            .unwrap(),
        expected_golden_credential(product)
    );
    for profile in ["atlassian-api-token", "atlassian-bearer-token"] {
        let error = store
            .resolve_user_credential(&ring, "alice", "jira", "default", &[profile.to_string()])
            .unwrap_err();
        assert!(
            matches!(error, ManagedStoreError::CredentialInvalid(_)),
            "{profile}: {error:?}"
        );
    }
}

#[test]
fn vendor_atlassian_aad_is_derived_from_frozen_row_fields() {
    let (_temp, store) = store_with_golden_atlassian_stored_credentials();
    let conn = store.connection.lock().unwrap();
    let row = encrypted_credential_by_tuple(&conn, "alice", "atlassian", "default").unwrap();
    assert_eq!(
        credential_aad(&row).bytes(),
        "schema_version=002_credential_secret_material;\
         credential_id=3d881cd0-02cb-497e-b1c2-08ba76a4b4c3;owner_kind=user;\
         owner_principal=alice;service=atlassian;name=default;\
         credential_profile=atlassian-api-token;credential_kind=basic_api_token;\
         secret_backend=sqlite_encrypted;secret_ref=sqlite:8679ed83-4294-4985-87fe-ced8638c90a8;\
         material_version=efc08149-29b8-4cd5-8262-d2acf02ce6a1;key_id=k1"
    );
    let row = encrypted_credential_by_tuple(&conn, "alice", "confluence", "default").unwrap();
    assert_eq!(
        credential_aad(&row).bytes(),
        "schema_version=002_credential_secret_material;\
         credential_id=a221934a-f519-4cbb-9b3b-002334d847f7;owner_kind=user;\
         owner_principal=alice;service=confluence;name=default;\
         credential_profile=atlassian-bearer-token;credential_kind=bearer_token;\
         secret_backend=sqlite_encrypted;secret_ref=sqlite:19ff2e62-716d-4588-b943-98ffa9e3b073;\
         material_version=780f37a8-8e4c-4b71-8e64-f108c0532258;key_id=k1"
    );
}

/// Rewrap re-encrypts every stored row, including product-profile rows no
/// connection selects, and each still resolves under its own profile.
#[test]
fn rewrap_covers_product_and_vendor_atlassian_rows() {
    let (_temp, store) = store_with_golden_atlassian_stored_credentials();
    let ring = key_ring_with_keys("k2", &[("k1", 7), ("k2", 8)]);
    let summary = store
        .rewrap_credentials(&ring, "k1", "k2", "admin")
        .unwrap();
    let rows = GOLDEN_STORED_CREDENTIALS
        .iter()
        .chain(&GOLDEN_ATLASSIAN_STORED_CREDENTIALS)
        .collect::<Vec<_>>();
    assert_eq!(summary.rewrapped, rows.len() as u64);
    assert_eq!(summary.conflicts, 0);
    assert_eq!(store.active_credential_key_ids().unwrap(), vec!["k2"]);
    let rewrapped = key_ring_with_keys("k2", &[("k2", 8)]);
    for golden in rows {
        assert_eq!(
            store
                .resolve_user_credential(
                    &rewrapped,
                    "alice",
                    golden.service,
                    "default",
                    &[golden.profile.to_string()]
                )
                .unwrap(),
            expected_golden_credential(golden),
            "{}",
            golden.service
        );
    }
}


// The scoped API token row. `upsert_user_credential` wrote it for `alice`
// with key `k1` at de99fcc: an `atlassian-scoped-api-token`/`basic_api_token`
// row (email and token, presented as Basic through the Atlassian gateway)
// under an `atlassian_scoped` connection. Its profile spelling is a durable
// contract; it is frozen like the rows above.
const GOLDEN_SCOPED_ATLASSIAN_STORED_CREDENTIAL: GoldenStoredCredential = GoldenStoredCredential {
    credential_id: "133cd375-eae6-4dc5-bcae-52fcde06b56f",
    service: "atlassian_scoped",
    profile: "atlassian-scoped-api-token",
    credential_kind: "basic_api_token",
    metadata_json: r#"{"displayName":"Golden atlassian_scoped"}"#,
    secret_ref: "sqlite:b0c81448-ce22-4e03-adda-60db086d66d1",
    material_version: "704666a7-430e-452a-b726-c246ffe75d87",
    nonce_hex: "947880b70b621843cba1afd7",
    ciphertext_hex: "a48dc72de8ca75ec23ffea8eb9c09d01f170ee75372437d603ca9aa7a5341ba592598538bdd8909d5b203b58cf9d12e94e9b4be370170e4f3ef570f8d40604650c0bd6be190adeab815ec22317fbfe14782fbd07c5920c6429440cb20984f31bf56f7262b826dabb3277",
    username: Some("golden-scoped-user@example.test"),
    token: "golden-atlassian-scoped-api-token",
};

/// The baseline and vendor-level stores with the scoped API token row
/// added, inserted with the same columns.
fn store_with_golden_scoped_atlassian_stored_credential() -> (TempDir, ManagedStore) {
    let (temp, store) = store_with_golden_atlassian_stored_credentials();
    {
        let golden = &GOLDEN_SCOPED_ATLASSIAN_STORED_CREDENTIAL;
        let conn = store.connection.lock().unwrap();
        conn.execute(
            "INSERT INTO credentials
             (credential_id, owner_principal_id, owner_kind, service, name, profile,
              credential_kind, metadata_json, secret_backend, secret_ref, material_version,
              status, created_at, updated_at, created_by, updated_by, verification_status)
             VALUES (?1, 'alice', 'user', ?2, 'default', ?3, ?4, ?5, 'sqlite_encrypted', ?6, ?7,
                     'active', '2026-10-21T00:00:00Z', '2026-10-21T00:00:00Z', 'admin', 'admin',
                     'not_verified')",
            params![
                golden.credential_id,
                golden.service,
                golden.profile,
                golden.credential_kind,
                golden.metadata_json,
                golden.secret_ref,
                golden.material_version,
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO credential_secret_material
             (secret_ref, credential_id, backend, secret_ciphertext, secret_nonce, key_id,
              created_at, updated_at)
             VALUES (?1, ?2, 'sqlite_encrypted', ?3, ?4, 'k1', '2026-10-21T00:00:00Z',
                     '2026-10-21T00:00:00Z')",
            params![
                golden.secret_ref,
                golden.credential_id,
                golden_hex(golden.ciphertext_hex),
                golden_hex(golden.nonce_hex),
            ],
        )
        .unwrap();
    }
    (temp, store)
}

/// The scoped API token row decrypts as a Basic credential lent as its own
/// profile, is never read under the classic profile of the same kind, has
/// frozen AAD bytes and survives rewrap like every other row.
#[test]
fn scoped_atlassian_row_resolves_under_its_own_profile_only() {
    let golden = &GOLDEN_SCOPED_ATLASSIAN_STORED_CREDENTIAL;
    let (_temp, store) = store_with_golden_scoped_atlassian_stored_credential();
    let ring = key_ring("k1");
    store.check_ready(Some(&ring)).unwrap();
    let credential = store
        .resolve_user_credential(
            &ring,
            "alice",
            golden.service,
            "default",
            &[golden.profile.to_string()],
        )
        .unwrap();
    assert_eq!(credential.kind().as_str(), "basic_api_token");
    assert_eq!(credential.profile(), Some("atlassian-scoped-api-token"));
    assert_eq!(credential, expected_golden_credential(golden));
    // Accepted beside the classic profile, it is still lent as itself.
    assert_eq!(
        store
            .resolve_user_credential(
                &ring,
                "alice",
                golden.service,
                "default",
                &[
                    "atlassian-api-token".to_string(),
                    golden.profile.to_string()
                ],
            )
            .unwrap(),
        expected_golden_credential(golden)
    );
    for profile in ["atlassian-api-token", "atlassian-bearer-token"] {
        let error = store
            .resolve_user_credential(&ring, "alice", golden.service, "default", &[profile.to_string()])
            .unwrap_err();
        assert!(
            matches!(error, ManagedStoreError::CredentialInvalid(_)),
            "{profile}: {error:?}"
        );
    }
    {
        let conn = store.connection.lock().unwrap();
        let row = encrypted_credential_by_tuple(&conn, "alice", golden.service, "default").unwrap();
        assert_eq!(
            credential_aad(&row).bytes(),
            "schema_version=002_credential_secret_material;\
             credential_id=133cd375-eae6-4dc5-bcae-52fcde06b56f;owner_kind=user;\
             owner_principal=alice;service=atlassian_scoped;name=default;\
             credential_profile=atlassian-scoped-api-token;credential_kind=basic_api_token;\
             secret_backend=sqlite_encrypted;secret_ref=sqlite:b0c81448-ce22-4e03-adda-60db086d66d1;\
             material_version=704666a7-430e-452a-b726-c246ffe75d87;key_id=k1"
        );
    }
    let rewrap_ring = key_ring_with_keys("k2", &[("k1", 7), ("k2", 8)]);
    let summary = store
        .rewrap_credentials(&rewrap_ring, "k1", "k2", "admin")
        .unwrap();
    assert_eq!(
        summary.rewrapped,
        (GOLDEN_STORED_CREDENTIALS.len() + GOLDEN_ATLASSIAN_STORED_CREDENTIALS.len() + 1) as u64
    );
    assert_eq!(
        store
            .resolve_user_credential(
                &key_ring_with_keys("k2", &[("k2", 8)]),
                "alice",
                golden.service,
                "default",
                &[golden.profile.to_string()],
            )
            .unwrap(),
        expected_golden_credential(golden)
    );
}
