//! Fixed local command contracts. These schemas grant no authority themselves.
use crate::backends::management_resources;
use crate::{BrokerConfig, DEFAULT_EXECUTION_CONTEXT};
use agent_access_provider::{
    ActionDescriptor, CredentialDescriptor, ProviderError, ResourceScopeCapabilities,
    ResourceScopes, SecretOutputDescriptor, ServiceDescriptor,
};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn descriptor(config: &BrokerConfig) -> ServiceDescriptor {
    let scopes = [
        ("principal", &management_resources::PRINCIPAL),
        ("group", &management_resources::GROUP),
        ("grant", &management_resources::GRANT),
        ("connection", &management_resources::CONNECTION),
    ]
    .into_iter()
    .map(|(name, resource)| {
        (
            name.to_owned(),
            ResourceScopeCapabilities::new(resource.id().clone(), vec!["exact".into()]),
        )
    })
    .collect();
    let mut actions = Vec::new();
    let principal = [("principalId", principal_id())];
    actions.push(action(
        "principal.create",
        "Create a service account at an authorized absent ID.",
        &["principal"],
        &["principalId"],
        &[
            ("principalId", principal_id()),
            ("displayName", principal_display_name()),
        ],
    ));
    actions.push(
        action(
            "principal.view",
            "Read one authorized service account's safe metadata.",
            &["principal"],
            &["principalId"],
            &principal,
        )
        .read_only(),
    );
    actions.push(
        action(
            "group.view",
            "Read one identity group's safe metadata; its authority remains live.",
            &["group"],
            &["groupId"],
            &[("groupId", key_id())],
        )
        .read_only(),
    );
    for (name, description, read) in [
        (
            "group.member.view",
            "Inspect one service account's membership edge.",
            true,
        ),
        (
            "group.member.add",
            "Add a service account to an eligible identity group.",
            false,
        ),
        (
            "group.member.remove",
            "Remove a service account's local membership from an eligible group.",
            false,
        ),
    ] {
        let mut item = action(
            name,
            description,
            &["group", "principal"],
            &["groupId", "principalId"],
            &[("groupId", key_id()), ("principalId", principal_id())],
        );
        if read {
            item = item.read_only();
        }
        actions.push(item);
    }
    actions.push(
        action(
            "grant.view",
            "Read one grant definition without its subjects.",
            &["grant"],
            &["grantId"],
            &[("grantId", key_id())],
        )
        .read_only(),
    );
    for (name, description, read) in [
        (
            "grant.subject.view",
            "Inspect one service account's direct grant assignment.",
            true,
        ),
        (
            "grant.subject.add",
            "Attach a service account to an eligible active grant at its current version.",
            false,
        ),
        (
            "grant.subject.remove",
            "Remove a service account's direct assignment without removing an active grant's final subject.",
            false,
        ),
    ] {
        let mut properties = vec![("grantId", key_id()), ("principalId", principal_id())];
        let mut required = vec!["grantId", "principalId"];
        if !read {
            properties.push(("expectedVersion", version()));
            required.push("expectedVersion");
        }
        let mut item = action(
            name,
            description,
            &["grant", "principal"],
            &required,
            &properties,
        );
        if read {
            item = item.read_only();
        }
        actions.push(item);
    }
    actions.push(
        action(
            "credential.view",
            "Read safe credential-slot metadata for one service account and connection.",
            &["principal", "connection"],
            &["principalId", "connectionId"],
            &[
                ("principalId", principal_id()),
                ("connectionId", connection_id()),
            ],
        )
        .read_only(),
    );
    let mut retained_reference = reference_schema();
    retained_reference["writeOnly"] = json!(true);
    retained_reference["x-agent-access-sensitive"] = json!(true);
    actions.push(action("credential.install", "Install a caller-owned GitLab token reference into an absent service-account credential slot.",
        &["principal", "connection"], &["principalId", "connectionId", "token"],
        &[("principalId", principal_id()), ("connectionId", connection_id()), ("token", retained_reference)])
        .documentation(json!({
            "description":"The token field accepts only a temporary reference owned by this exact invocation identity, caller and execution context. The destination must select the GitLab bearer-token profile. Existing slots, including disabled rows, conflict. All configured consumers of the connection may use the installed credential. Installation does not grant invocation access or verify the upstream account.",
            "recovery":"Use the independently authorized credential.view action to reconcile a lost response. Do not replace an existing slot or reissue an upstream token automatically."
        })));
    let contexts = config.execution_context.as_ref().map_or_else(
        || vec![DEFAULT_EXECUTION_CONTEXT.to_owned()],
        |context| context.allowed_values.clone(),
    );
    let finite_ttls = config
        .broker_tokens
        .as_ref()
        .into_iter()
        .flat_map(|tokens| &tokens.admin_agent_invoke_ttl_options)
        .filter_map(|option| option.ttl_seconds())
        .filter(|ttl| *ttl > 0)
        .collect::<BTreeSet<_>>();
    let ttl_schema = if finite_ttls.is_empty() {
        json!({"type":"integer","minimum":1,"not":{}})
    } else {
        json!({"type":"integer","minimum":1,"enum":finite_ttls})
    };
    actions.push(action("token.create", "Issue one bounded service-account invocation token as a temporary reference.",
        &["principal", "grant"], &["principalId", "grantId", "expectedVersion", "tokenId", "name", "allowedExecutionContexts", "ttlSeconds"], &[
            ("principalId", principal_id()), ("grantId", key_id()), ("expectedVersion", version()),
            ("tokenId", token_id()), ("name", display_name()), ("ttlSeconds", ttl_schema),
            ("allowedExecutionContexts", json!({"type":"array","minItems":1,"maxItems":contexts.len().max(1),"uniqueItems":true,"items":{"type":"string","enum":contexts}})),
        ]).secret_output(SecretOutputDescriptor::new("/result/issuedToken", 128))
        .documentation(json!({
            "description":"The recipient must currently belong to the selected active non-Broker grant. The token captures explicit service/actions/contexts and retains live selected resource references. Its bearer and reference capture commit atomically. It cannot invoke Broker administration. Only finite configured administrator TTL options are accepted.",
            "recovery":"Choose a canonical UUIDv4 tokenId before issuance. Repeating that ID conflicts and cannot recover the reference. Use separately granted token.view to reconcile. A lost reference requires existing administrator revocation followed by intentional issuance under a new UUID.",
            "expiry":"The token's expiresAt is independent of issuedToken.expiresAt. Handoff uses the original issuing identity and context. Reference expiry does not revoke an installed child token."
        })));
    actions.push(
        action(
            "token.view",
            "Read safe metadata of one invocation token owned by the selected service account.",
            &["principal"],
            &["principalId", "tokenId"],
            &[("principalId", principal_id()), ("tokenId", token_id())],
        )
        .read_only(),
    );
    for action in actions.iter_mut().filter(|action| !action.read_only) {
        let documentation = action.documentation.get_or_insert_with(|| json!({}));
        documentation["completion"] = json!({
            "description":"A write result may include this completion receipt beside safe operation metadata. Authorization failures before local admission may have no receipt. not_committed proves rollback; completed proves a settled commit even when later audit or delivery fails. unknown requires reconciliation. Never repeat a write automatically.",
            "receiptSchema": {
                "type":"object",
                "required":["executionState","retrySafe"],
                "properties": {
                    "executionState":{"type":"string","enum":["not_dispatched","not_committed","completed","unknown"]},
                    "retrySafe":{"const":false}
                }
            },
            "mcpDelivery":"A settled rollback retains execution.completion=completed with dispatched=true in an MCP delivery-failure receipt. Inspect the operation decision and result to distinguish rollback from a successful mutation."
        });
    }
    ServiceDescriptor::new(super::SERVICE_ID, "Broker administration")
        .with_actions(actions)
        .with_resource_scopes(scopes)
        .with_credentials(CredentialDescriptor::without_execution_credential())
}

fn action(
    name: &str,
    description: &str,
    scopes: &[&str],
    required: &[&str],
    properties: &[(&str, Value)],
) -> ActionDescriptor {
    ActionDescriptor::new(name, description, object(required, properties))
        .scopes(scopes.iter().copied())
        .credential_modes(["service"])
}

fn object(required: &[&str], properties: &[(&str, Value)]) -> Value {
    json!({"type":"object", "additionalProperties":false, "required":required,
        "properties":properties.iter().map(|(name, value)| (name.to_string(), value.clone())).collect::<Map<_,_>>()})
}
fn principal_id() -> Value {
    json!({"type":"string","minLength":1,"maxLength":256,"pattern":"^[A-Za-z0-9._@+\\-]{1,256}$"})
}
fn key_id() -> Value {
    json!({"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._-]{1,128}$"})
}
fn connection_id() -> Value {
    json!({"type":"string","minLength":1,"maxLength":63,"pattern":"^[a-z][a-z0-9_-]{0,62}$"})
}
fn token_id() -> Value {
    json!({"type":"string","minLength":36,"maxLength":36,"pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"})
}
fn principal_display_name() -> Value {
    json!({"type":"string","minLength":1,"maxLength":256,"pattern":"^[^\\x00-\\x1f\\x7f]+$"})
}
fn display_name() -> Value {
    json!({"type":"string","minLength":1,"maxLength":128,"pattern":"^[^\\x00-\\x1f\\x7f]+$"})
}
fn version() -> Value {
    json!({"type":"integer","minimum":1,"maximum":i64::MAX})
}

pub(crate) fn reference_schema() -> Value {
    object(
        &["secretRef"],
        &[
            (
                "secretRef",
                json!({"type":"string","pattern":"^sr_[A-Za-z0-9_-]{43}$","minLength":46,"maxLength":46}),
            ),
            (
                "expiresAt",
                json!({"type":"string","format":"date-time","maxLength":64,"description":"Informational expiry; the stored reference deadline is authoritative."}),
            ),
        ],
    )
}

pub(crate) fn resolve_scopes(
    action: &str,
    inputs: &Value,
) -> Result<ResourceScopes, ProviderError> {
    crate::management::ManagementCommand::parse(action, inputs)?.scopes()
}

/// A fixed, secret-free metadata contract. Only token creation adds the sealed
/// reference at completion; no schema marker can grant that completion path.
pub(crate) fn result_schema(action: &str) -> Value {
    let text = || json!({"type":"string","maxLength":4096});
    let nullable_text = || json!({"type":["string","null"],"maxLength":4096});
    let boolean = || json!({"type":"boolean"});
    let selection = || {
        object(
            &["resourceIds", "resourceGroupIds"],
            &[
                (
                    "resourceIds",
                    json!({"type":"array","maxItems":4096,"items":key_id()}),
                ),
                (
                    "resourceGroupIds",
                    json!({"type":"array","maxItems":4096,"items":key_id()}),
                ),
            ],
        )
    };
    let mut fields: BTreeMap<String, Value> = BTreeMap::new();
    let names: &[&str] = match action {
        "principal.create" | "principal.view" => &[
            "principalId",
            "displayName",
            "kind",
            "role",
            "selfServiceEnabled",
            "status",
            "createdAt",
            "updatedAt",
        ],
        "group.view" => &[
            "groupId",
            "displayName",
            "description",
            "status",
            "livePolicy",
        ],
        "group.member.view" | "group.member.add" | "group.member.remove" => &[
            "principalId",
            "groupId",
            "principalStatus",
            "groupStatus",
            "localMember",
            "effectiveMember",
            "changed",
        ],
        "grant.view" => &[
            "grantId",
            "version",
            "status",
            "description",
            "service",
            "actions",
            "resources",
            "executionContexts",
            "credentialMode",
            "priority",
            "livePolicy",
        ],
        "grant.subject.view" | "grant.subject.add" | "grant.subject.remove" => &[
            "principalId",
            "grantId",
            "principalStatus",
            "grantStatus",
            "directSubject",
            "changed",
            "version",
        ],
        "credential.view" | "credential.install" => &[
            "principalId",
            "connectionId",
            "profile",
            "credentialKind",
            "present",
            "status",
            "version",
            "lastVerifiedAt",
            "verificationStatus",
            "lastVerificationAttemptAt",
            "lastVerificationErrorCode",
        ],
        "token.create" | "token.view" => &[
            "tokenId",
            "principalId",
            "name",
            "tokenClass",
            "scopes",
            "createdAt",
            "expiresAt",
            "paused",
            "revoked",
            "expired",
            "lastUsedAt",
        ],
        _ => return json!(false),
    };
    for name in names {
        let schema = match *name {
            "selfServiceEnabled" | "livePolicy" | "localMember" | "effectiveMember" | "changed"
            | "directSubject" | "present" | "paused" | "revoked" | "expired" => boolean(),
            "version" if action.starts_with("credential.") => nullable_text(),
            "version" => version(),
            "priority" => json!({"type":["integer","null"]}),
            "displayName"
            | "description"
            | "lastVerifiedAt"
            | "verificationStatus"
            | "lastVerificationAttemptAt"
            | "lastVerificationErrorCode"
            | "lastUsedAt"
            | "expiresAt" => nullable_text(),
            "actions" | "executionContexts" => {
                json!({"type":"array","maxItems":4096,"items":text()})
            }
            "resources" => selection(),
            "scopes" => object(
                &[],
                &[
                    ("allowedServices", json!({"type":"array","items":text()})),
                    (
                        "allowedExecutionContexts",
                        json!({"type":"array","items":text()}),
                    ),
                    (
                        "serviceRestrictions",
                        json!({"type":"object","additionalProperties":object(&["actions"], &[
                            ("actions", json!({"type":"array","items":text()})),
                            ("resources", selection()),
                        ])}),
                    ),
                ],
            ),
            _ => text(),
        };
        fields.insert(name.to_string(), schema);
    }
    let read = matches!(
        action,
        "principal.view"
            | "group.view"
            | "group.member.view"
            | "grant.view"
            | "grant.subject.view"
            | "credential.view"
            | "token.view"
    );
    if !read {
        fields.insert("executionState".into(), json!({"const":"completed"}));
        fields.insert("retrySafe".into(), json!({"const":false}));
    }
    if action == "token.create" {
        fields.insert("issuedToken".into(), reference_schema());
        fields.insert(
            "secretReceipt".into(),
            object(
                &["receiptId", "expiresAt"],
                &[("receiptId", text()), ("expiresAt", text())],
            ),
        );
    }
    let required = fields
        .keys()
        .filter(|name| {
            !action.starts_with("credential.")
                || !matches!(
                    name.as_str(),
                    "status"
                        | "version"
                        | "lastVerifiedAt"
                        | "verificationStatus"
                        | "lastVerificationAttemptAt"
                        | "lastVerificationErrorCode"
                )
        })
        .cloned()
        .collect::<Vec<_>>();
    json!({"type":"object","additionalProperties":false,"required":required,"properties":fields})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_contract_has_only_reviewed_read_actions_and_no_provider_secret_sink() {
        let config = crate::tests::parse_test_config(
            r#"
            [deployment]
            environment = "development"
            [identity]
            mode = "anonymous"
            authority = "toml"
            [policy]
            authority = "toml"
            default_decision = "deny"
            [limits]
            upload_spool_dir = "upload-spool"
        "#,
        )
        .unwrap();
        let descriptor = descriptor(&config);
        descriptor.validate().unwrap();
        assert_eq!(descriptor.actions.len(), 14);
        assert_eq!(
            descriptor
                .actions
                .iter()
                .filter(|action| action.read_only)
                .count(),
            7
        );
        let install = descriptor.action("credential.install").unwrap();
        assert!(install.secret_inputs.is_empty());
        assert_eq!(
            install.input_schema.pointer("/properties/token/type"),
            Some(&json!("object"))
        );
        assert_eq!(
            install
                .input_schema
                .pointer("/properties/token/x-agent-access-sensitive"),
            Some(&json!(true))
        );
        let token = descriptor.action("token.create").unwrap();
        assert_eq!(token.secret_outputs[0].max_bytes(), 128);
        assert!(token.secret_outputs[0].is_required());
        for action in &descriptor.actions {
            let completion = action
                .documentation
                .as_ref()
                .and_then(|value| value.get("completion"));
            assert_eq!(completion.is_some(), !action.read_only);
            if let Some(completion) = completion {
                let validator = jsonschema::validator_for(&completion["receiptSchema"]).unwrap();
                for state in ["not_dispatched", "not_committed", "completed", "unknown"] {
                    assert!(validator.is_valid(&json!({"executionState":state,"retrySafe":false})));
                    assert!(!validator.is_valid(&json!({"executionState":state,"retrySafe":true})));
                }
            }
        }
    }
}
