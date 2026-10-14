// Golden persisted import JSON. These literals are the exact bytes the store
// wrote at 808326b for representative imported service definitions (including
// credential bindings and `adapterId`), accepted action definitions, and a
// discovery preview manifest. Stored rows outlive the code that wrote them and
// are read back with `deny_unknown_fields`; their action hashes and service
// identities are durable. A failure means existing imports would become
// unreadable or change identity. Never update these literals to make a
// refactor pass.

const GOLDEN_SERVICE_ROWS: [(&str, &str); 4] = [
    (
        "golden-header",
        r#"{"service":"golden-header","displayName":"Golden Header","adapterKind":"mcp_http","endpoint":"https://tools.example.test/header/mcp","connectionSettings":{"mode":"strict","region":"eu-1"},"executionBindings":[{"ownerMode":"service","mechanism":"static_token","delivery":{"kind":"raw_header","name":"X-Upstream-Token"},"status":"configured"},{"ownerMode":"per_user","mechanism":"static_token","delivery":{"kind":"raw_header","name":"X-Upstream-Token"},"status":"configured"}],"discovery":{"kind":"per_user","principal":"admin"},"transportAuth":true}"#,
    ),
    (
        "golden-oauth",
        r#"{"service":"golden-oauth","displayName":"Golden OAuth","adapterKind":"mcp_http","endpoint":"https://tools.example.test/mcp","connectionSettings":{},"executionBindings":[{"ownerMode":"service","mechanism":"static_token","delivery":{"kind":"bearer"},"status":"configured"},{"ownerMode":"per_user","mechanism":"oauth","delivery":{"kind":"bearer"},"status":"configured","adapterId":"mcp_oauth","registrationId":"golden-registration","profile":"access"}],"discovery":{"kind":"slot"},"transportAuth":false,"invocationLimit":{"requests":30,"windowSeconds":60}}"#,
    ),
    (
        "golden-openapi",
        r#"{"service":"golden-openapi","displayName":"Golden OpenAPI","adapterKind":"openapi_http","endpoint":"https://inventory.example.test/api","connectionSettings":{"definitionAuthKind":"none","definitionUrl":"https://inventory.example.test/openapi.json","securityScheme":"access"},"executionBindings":[{"ownerMode":"service","mechanism":"static_token","delivery":{"kind":"bearer"},"status":"configured"},{"ownerMode":"per_user","mechanism":"oauth","delivery":{"kind":"bearer"},"status":"unsupported","adapterId":"future-oauth-adapter"}],"discovery":{"kind":"anonymous"},"transportAuth":false}"#,
    ),
    (
        "observability",
        r#"{"service":"observability","displayName":"Observability","adapterKind":"mcp_http","endpoint":"https://tools.example/mcp","connectionSettings":{},"executionBindings":[{"ownerMode":"service","mechanism":"static_token","delivery":{"kind":"bearer"},"status":"configured"}],"discovery":{"kind":"execution"},"transportAuth":false}"#,
    ),
];

/// (action, source_json, definition_json, definition_hash, status, version)
const GOLDEN_ACTION_ROWS: [(&str, &str, &str, &str, &str, i64); 2] = [
    (
        "item.get",
        r#"{"operationId":"get_item"}"#,
        r#"{"action":"item.get","source":{"operationId":"get_item"},"label":"Read item","description":"Read one inventory item","inputSchema":{"additionalProperties":false,"properties":{"path":{"properties":{"id":{"type":"string"}},"required":["id"],"type":"object"}},"required":["path"],"type":"object"},"outputSchema":{"properties":{"value":{"type":"string"}},"type":"object"},"annotations":{"readOnlyHint":true,"title":"Read item"},"readOnly":true}"#,
        "46cdbfcc60d48e17027343e461ab85cedab91cf7c749556621ba928d0204e163",
        "enabled",
        1,
    ),
    (
        "item.update",
        r#"{"method":"PUT","path":"/items/{id}"}"#,
        r#"{"action":"item.update","source":{"method":"PUT","path":"/items/{id}"},"description":"Replace one inventory item","inputSchema":{"type":"object"},"annotations":{},"readOnly":false}"#,
        "ae469c65656cd0046b4e28960e00c536c83fde63f67043fd98f7c04db10e6c73",
        "disabled",
        1,
    ),
];

/// Preview row with its creation and expiry timestamps replaced.
const GOLDEN_PREVIEW_ROW: &str = r#"{"service":"golden-openapi","serviceVersion":3,"catalogRevision":6,"configRevision":"config-golden","credentialVersions":{},"manifestHash":"53cd51a42c444dd24f950085445ab626b2614b40af65ab4231e6b670adccc9f0","manifest":{"metadata":{"title":"Golden Inventory","version":"1"},"protocolVersion":"openapi-3.1","tools":[{"definition":{"action":"item.get","annotations":{"readOnlyHint":true,"title":"Read item"},"description":"Read one inventory item","inputSchema":{"additionalProperties":false,"properties":{"path":{"properties":{"id":{"type":"string"}},"required":["id"],"type":"object"}},"required":["path"],"type":"object"},"label":"Read item","outputSchema":{"properties":{"value":{"type":"string"}},"type":"object"},"readOnly":true,"source":{"operationId":"get_item"}},"readOnlyHint":true,"unsupportedReason":null},{"definition":{"action":"item.update","annotations":{},"description":"Replace one inventory item","inputSchema":{"type":"object"},"readOnly":false,"source":{"method":"PUT","path":"/items/{id}"}},"readOnlyHint":null,"unsupportedReason":"combined security requirements are unsupported"}]},"createdAt":"<createdAt>","expiresAt":"<expiresAt>","createdBy":"admin"}"#;

/// An execution slot written by `write_imported_secret` at 808326b with key
/// `old` (`[7; 32]`): (material_version, nonce, ciphertext, token).
const GOLDEN_IMPORTED_SLOT: (&str, &str, &str, &str) = (
    "3e3467b6-f61b-41d4-8b08-8b7a699c7eda",
    "8e7c45af3234bea86dfda944",
    "f1530ce7aec14aaa8358d7ea141fb83ec2c49c328beb3d36543d15a3fd541a6268f07255cae445a56d3ff97bd2",
    "golden-imported-service-token",
);

fn golden_definitions() -> Vec<ImportedServiceDefinition> {
    use crate::imports::{ImportedAuthMechanism, ImportedBindingStatus, ImportedInvocationLimit};
    let binding = |owner_mode, mechanism, delivery, status| ImportedCredentialBinding {
        owner_mode,
        mechanism,
        delivery,
        status,
        adapter_id: None,
        registration_id: None,
        profile: None,
    };
    let header = || ImportedCredentialDelivery::RawHeader {
        name: "X-Upstream-Token".into(),
    };
    vec![
        ImportedServiceDefinition {
            service: "golden-header".into(),
            display_name: "Golden Header".into(),
            adapter_kind: "mcp_http".into(),
            endpoint: "https://tools.example.test/header/mcp".into(),
            connection_settings: BTreeMap::from([
                ("region".into(), "eu-1".into()),
                ("mode".into(), "strict".into()),
            ]),
            execution_bindings: vec![
                binding(
                    ImportedCredentialMode::Service,
                    ImportedAuthMechanism::StaticToken,
                    header(),
                    ImportedBindingStatus::Configured,
                ),
                binding(
                    ImportedCredentialMode::PerUser,
                    ImportedAuthMechanism::StaticToken,
                    header(),
                    ImportedBindingStatus::Configured,
                ),
            ],
            discovery: ImportedDiscoveryCredential::PerUser {
                principal: "admin".into(),
            },
            transport_auth: true,
            invocation_limit: None,
        },
        ImportedServiceDefinition {
            service: "golden-oauth".into(),
            display_name: "Golden OAuth".into(),
            adapter_kind: "mcp_http".into(),
            endpoint: "https://tools.example.test/mcp".into(),
            connection_settings: BTreeMap::new(),
            execution_bindings: vec![
                binding(
                    ImportedCredentialMode::Service,
                    ImportedAuthMechanism::StaticToken,
                    ImportedCredentialDelivery::Bearer,
                    ImportedBindingStatus::Configured,
                ),
                ImportedCredentialBinding {
                    adapter_id: Some("mcp_oauth".into()),
                    registration_id: Some("golden-registration".into()),
                    profile: Some("access".into()),
                    ..binding(
                        ImportedCredentialMode::PerUser,
                        ImportedAuthMechanism::Oauth,
                        ImportedCredentialDelivery::Bearer,
                        ImportedBindingStatus::Configured,
                    )
                },
            ],
            discovery: ImportedDiscoveryCredential::Slot,
            transport_auth: false,
            invocation_limit: Some(ImportedInvocationLimit {
                requests: 30,
                window_seconds: 60,
            }),
        },
        ImportedServiceDefinition {
            service: "golden-openapi".into(),
            display_name: "Golden OpenAPI".into(),
            adapter_kind: "openapi_http".into(),
            endpoint: "https://inventory.example.test/api".into(),
            connection_settings: BTreeMap::from([
                (
                    "definitionUrl".into(),
                    "https://inventory.example.test/openapi.json".into(),
                ),
                ("definitionAuthKind".into(), "none".into()),
                ("securityScheme".into(), "access".into()),
            ]),
            execution_bindings: vec![
                binding(
                    ImportedCredentialMode::Service,
                    ImportedAuthMechanism::StaticToken,
                    ImportedCredentialDelivery::Bearer,
                    ImportedBindingStatus::Configured,
                ),
                ImportedCredentialBinding {
                    adapter_id: Some("future-oauth-adapter".into()),
                    ..binding(
                        ImportedCredentialMode::PerUser,
                        ImportedAuthMechanism::Oauth,
                        ImportedCredentialDelivery::Bearer,
                        ImportedBindingStatus::Unsupported,
                    )
                },
            ],
            discovery: ImportedDiscoveryCredential::Anonymous,
            transport_auth: false,
            invocation_limit: None,
        },
        definition(),
    ]
}

fn golden_actions() -> Vec<ImportedActionWrite> {
    vec![
        ImportedActionWrite {
            definition: ImportedActionDefinition {
                action: "item.get".into(),
                source: json!({"operationId":"get_item"}),
                label: Some("Read item".into()),
                description: "Read one inventory item".into(),
                input_schema: json!({"type":"object","additionalProperties":false,"required":["path"],"properties":{"path":{"type":"object","required":["id"],"properties":{"id":{"type":"string"}}}}}),
                output_schema: Some(
                    json!({"type":"object","properties":{"value":{"type":"string"}}}),
                ),
                annotations: json!({"readOnlyHint":true,"title":"Read item"}),
                read_only: true,
            },
            status: ImportedActionStatus::Enabled,
        },
        ImportedActionWrite {
            definition: ImportedActionDefinition {
                action: "item.update".into(),
                source: json!({"method":"PUT","path":"/items/{id}"}),
                label: None,
                description: "Replace one inventory item".into(),
                input_schema: json!({"type":"object"}),
                output_schema: None,
                annotations: json!({}),
                read_only: false,
            },
            status: ImportedActionStatus::Disabled,
        },
    ]
}

fn golden_discovery() -> crate::imports::ImportedDiscovery {
    let actions = golden_actions();
    crate::imports::ImportedDiscovery {
        protocol_version: "openapi-3.1".into(),
        metadata: json!({"title":"Golden Inventory","version":"1"}),
        tools: vec![
            crate::imports::ImportedDiscoveredTool {
                definition: actions[0].definition.clone(),
                unsupported_reason: None,
                read_only_hint: Some(true),
            },
            crate::imports::ImportedDiscoveredTool {
                definition: actions[1].definition.clone(),
                unsupported_reason: Some("combined security requirements are unsupported".into()),
                read_only_hint: None,
            },
        ],
    }
}

#[test]
fn imported_definitions_actions_and_previews_persist_frozen_json() {
    let (_temp, _config, store, _) = fixture();
    for definition in golden_definitions() {
        store
            .create_imported_service(definition, "admin", accept)
            .unwrap();
    }
    let catalog = store.imported_catalog().unwrap();
    let record = catalog.service("golden-openapi").unwrap();
    store
        .update_imported_service(
            ImportedServiceUpdateRequest {
                definition: record.definition.clone(),
                status: ImportedServiceStatus::Disabled,
                actions: golden_actions(),
                expected_version: record.version,
                expected_catalog_revision: catalog.revision,
                accepted_preview: None,
                actor: "admin".into(),
            },
            accept,
        )
        .unwrap();
    let catalog = store.imported_catalog().unwrap();
    let record = catalog.service("golden-openapi").unwrap();
    store
        .write_imported_preview(
            ImportedPreviewWriteRequest {
                service: "golden-openapi".into(),
                expected_version: record.version,
                expected_catalog_revision: catalog.revision,
                config_revision: "config-golden".into(),
                credential_versions: BTreeMap::new(),
                manifest: serde_json::to_value(golden_discovery()).unwrap(),
                quarantine_actions: Vec::new(),
                actor: "admin".into(),
            },
            accept,
        )
        .unwrap();

    let conn = store.connection.lock().unwrap();
    let services = conn
        .prepare("SELECT service, definition_json FROM imported_services ORDER BY service")
        .unwrap()
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let expected = GOLDEN_SERVICE_ROWS
        .iter()
        .map(|(service, json)| (service.to_string(), json.to_string()))
        .collect::<Vec<_>>();
    assert_eq!(services, expected);

    let actions = conn
        .prepare(
            "SELECT action, source_json, definition_json, definition_hash, status, version
             FROM imported_actions WHERE service = 'golden-openapi' ORDER BY action",
        )
        .unwrap()
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let expected = GOLDEN_ACTION_ROWS
        .iter()
        .map(|(action, source, definition, hash, status, version)| {
            (
                action.to_string(),
                source.to_string(),
                definition.to_string(),
                hash.to_string(),
                status.to_string(),
                *version,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(actions, expected);
    for (_, _, definition, hash, _, _) in GOLDEN_ACTION_ROWS {
        assert_eq!(sha256_hex(definition.as_bytes()), hash);
    }

    let preview: String = conn
        .query_row(
            "SELECT preview_json FROM imported_previews WHERE service = 'golden-openapi'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let stored: Value = serde_json::from_str(&preview).unwrap();
    let normalized = preview
        .replacen(stored["createdAt"].as_str().unwrap(), "<createdAt>", 1)
        .replacen(stored["expiresAt"].as_str().unwrap(), "<expiresAt>", 1);
    assert_eq!(normalized, GOLDEN_PREVIEW_ROW);
    assert_eq!(
        sha256_hex(
            serde_json::to_string(&stored["manifest"])
                .unwrap()
                .as_bytes()
        ),
        stored["manifestHash"].as_str().unwrap()
    );
}

#[test]
fn baseline_imported_rows_remain_readable() {
    let (_temp, _config, store, ring) = fixture();
    {
        let conn = store.connection.lock().unwrap();
        for (service, json) in GOLDEN_SERVICE_ROWS {
            let status = if service == "golden-openapi" {
                "disabled"
            } else {
                "draft"
            };
            conn.execute(
                "INSERT INTO imported_services(service,definition_json,status,version,created_at,created_by,updated_at,updated_by)
                 VALUES(?1,?2,?3,1,'2026-10-13T00:00:00Z','admin','2026-10-13T00:00:00Z','admin')",
                params![service, json, status],
            )
            .unwrap();
        }
        for (action, source, definition, hash, status, version) in GOLDEN_ACTION_ROWS {
            conn.execute(
                "INSERT INTO imported_actions(service,action,source_json,definition_json,definition_hash,status,version)
                 VALUES('golden-openapi',?1,?2,?3,?4,?5,?6)",
                params![action, source, definition, hash, status, version],
            )
            .unwrap();
        }
        let preview = GOLDEN_PREVIEW_ROW
            .replace("<createdAt>", "2026-10-13T00:00:00Z")
            .replace("<expiresAt>", "2026-10-13T00:15:00Z");
        conn.execute(
            "INSERT INTO imported_previews(service,preview_json) VALUES('golden-openapi',?1)",
            [preview],
        )
        .unwrap();
        let (version, nonce, ciphertext, _) = GOLDEN_IMPORTED_SLOT;
        conn.execute(
            "INSERT INTO imported_secret_material(service,purpose,credential_kind,material_version,key_id,nonce,ciphertext)
             VALUES('observability','execution','bearer_token',?1,'old',?2,?3)",
            params![version, golden_hex(nonce), golden_hex(ciphertext)],
        )
        .unwrap();
    }
    let catalog = store.imported_catalog().unwrap();
    for definition in golden_definitions() {
        assert_eq!(
            catalog.service(&definition.service).unwrap().definition,
            definition
        );
    }
    let record = catalog.service("golden-openapi").unwrap();
    let actions = record
        .actions
        .iter()
        .map(|record| ImportedActionWrite {
            definition: record.definition.clone(),
            status: record.status,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        serde_json::to_value(actions).unwrap(),
        serde_json::to_value(golden_actions()).unwrap()
    );
    // Read the stored row directly: the public accessor hides stale previews.
    let stored = preview(&store.connection.lock().unwrap(), "golden-openapi")
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_value::<crate::imports::ImportedDiscovery>(stored.manifest)
            .unwrap(),
        golden_discovery()
    );
    assert_eq!(
        catalog.service("observability").unwrap().slot_versions,
        BTreeMap::from([(
            ImportedCredentialPurpose::Execution,
            GOLDEN_IMPORTED_SLOT.0.to_string()
        )])
    );
    store.check_ready(Some(&ring)).unwrap();
}

#[test]
fn imported_secret_rows_from_baseline_decrypt_without_reentry() {
    let (_temp, _config, store, ring) = fixture();
    store
        .create_imported_service(definition(), "admin", accept)
        .unwrap();
    let (version, nonce, ciphertext, token) = GOLDEN_IMPORTED_SLOT;
    {
        let conn = store.connection.lock().unwrap();
        conn.execute(
            "INSERT INTO imported_secret_material(service,purpose,credential_kind,material_version,key_id,nonce,ciphertext)
             VALUES('observability','execution','bearer_token',?1,'old',?2,?3)",
            params![version, golden_hex(nonce), golden_hex(ciphertext)],
        )
        .unwrap();
        let row = secret_row(&conn, "observability", "execution")
            .unwrap()
            .unwrap();
        assert_eq!(
            String::from_utf8(aad(&row).unwrap()).unwrap(),
            r#"["aab-imported-service-credential:v1","observability","execution","bearer_token","3e3467b6-f61b-41d4-8b08-8b7a699c7eda","old"]"#
        );
    }
    store.check_ready(Some(&ring)).unwrap();
    let credential = store
        .resolve_imported_secret(
            "observability",
            ImportedCredentialPurpose::Execution,
            version,
            &ring,
        )
        .unwrap();
    assert_eq!(credential.kind().as_str(), "bearer_token");
    assert_eq!(credential_username(&credential), None);
    assert_eq!(credential_token(&credential), token);
}

fn golden_hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}
