// Stored-credential golden vectors. `upsert_user_credential` wrote these rows
// at 808326b for principal `alice` with key `k1` (`[7; 32]`). Upgrades must
// keep resolving them without reentry, so the row columns, the AAD inputs and
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

const GOLDEN_STORED_CREDENTIALS: [GoldenStoredCredential; 3] = [
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
    // A personal token for an imported service uses the same table with the
    // fixed imported profile `token`.
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
            .resolve_user_credential(&ring, "alice", golden.service, "default", golden.profile)
            .unwrap();
        assert_eq!(
            credential.kind().as_str(),
            golden.credential_kind,
            "{}",
            golden.service
        );
        assert_eq!(credential_username(&credential), golden.username);
        assert_eq!(credential_token(&credential), golden.token);
    }
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
}
