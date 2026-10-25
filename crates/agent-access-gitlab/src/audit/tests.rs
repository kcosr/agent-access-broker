use super::*;
use agent_access_provider::host::prepare_audit_inputs;

fn fixture() -> GitlabProviderConfig {
    serde_json::from_value(json!({
        "api_base_url": "https://gitlab.example.test/api/v4",
        "web_base_url": "https://gitlab.example.test", "egress_proxy": null,
    }))
    .unwrap()
}

fn maximal_fixture() -> GitlabProviderConfig {
    let mut config = fixture();
    config.provisioning.enabled = true;
    config.provisioning.allowed_token_scopes = vec![
        "api",
        "read_api",
        "read_repository",
        "write_repository",
        "read_registry",
        "write_registry",
        "self_rotate",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    config.search.engines.advanced.project_categories =
        search::CATEGORIES.iter().map(|s| (*s).into()).collect();
    config.search.engines.advanced.instance_categories =
        search::CATEGORIES.iter().map(|s| (*s).into()).collect();
    config.search.engines.zoekt.project_categories = vec!["code".into()];
    config.search.engines.zoekt.instance_categories = vec!["code".into()];
    config
}

// This coverage walker records named leaves and known record containers. It
// deliberately does not infer an audit policy from a name or a schema type.
fn schema_paths(schema: &Value, prefix: &str, paths: &mut BTreeSet<String>) {
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        for (name, child) in properties {
            let path = format!("{prefix}/{name}");
            let mut descendants = BTreeSet::new();
            schema_paths(child, &path, &mut descendants);
            if descendants.is_empty() || child.get("items").is_some() {
                paths.insert(path.clone());
            }
            paths.extend(descendants);
            if let Some(items) = child.get("items") {
                schema_paths(items, &format!("{path}/*"), paths);
            }
        }
    }
    for keyword in ["allOf", "anyOf", "oneOf"] {
        if let Some(branches) = schema.get(keyword).and_then(Value::as_array) {
            for branch in branches {
                schema_paths(branch, prefix, paths);
            }
        }
    }
}

fn rule_paths(rules: &[Value], prefix: &str, paths: &mut BTreeSet<String>) {
    for rule in rules {
        let path = format!("{prefix}{}", rule["pointer"].as_str().unwrap());
        paths.insert(path.clone());
        if let Some(fields) = rule.get("fields").and_then(Value::as_array) {
            rule_paths(fields, &format!("{path}/*"), paths);
        }
    }
}

fn canonical_inventory_rule(rule: &Value) -> Value {
    let mut rule = rule.clone();
    let object = rule.as_object_mut().unwrap();
    // These IDs share the native inventory vocabulary. credential.secret
    // describes supplied secret presence only; operation.records describes
    // correlated, explicitly projected action/suggestion rows.
    let element = object.remove("element").unwrap();
    assert!(
        matches!(
            element.as_str().unwrap(),
            "object.identity"
                | "object.title"
                | "search.query"
                | "operation.control"
                | "operation.flag"
                | "operation.number"
                | "operation.projection"
                | "selection.identities"
                | "operation.records"
                | "content.body"
                | "content.message"
                | "content.format"
                | "content.fingerprint"
                | "credential.secret"
                | "continuation.opaque"
                | "locator.url"
                | "attachment.metadata"
                | "attachment.filename"
                | "attachment.media_type"
                | "attachment.size"
                | "transport.multipart_field"
        ),
        "unknown semantic element: {element}"
    );
    object.remove("reason");
    let kind = match object["capture"].as_str().unwrap() {
        "presence" => Some("boolean"),
        "utf8ByteCount" => Some("bytes"),
        "itemCount" => Some("number"),
        _ => None,
    };
    if let Some(kind) = kind {
        object.insert("kind".into(), json!(kind));
    }
    if let Some(fields) = object.get_mut("fields") {
        *fields = Value::Array(
            fields
                .as_array()
                .unwrap()
                .iter()
                .map(canonical_inventory_rule)
                .collect(),
        );
    }
    rule
}

#[test]
fn every_published_property_has_a_reviewed_inventory_decision() {
    let inventory: Value =
        serde_json::from_str(include_str!("../../audit-input-inventory.json")).unwrap();
    assert_eq!(inventory["fixture"], "audit-inventory-maximal");
    let entries: BTreeMap<_, _> = inventory["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| (entry["action"].as_str().unwrap(), entry))
        .collect();
    let mut minimal = fixture();
    minimal.search.engines.basic = GitlabSearchEngineConfig::default();
    minimal.provisioning.allowed_token_scopes = vec!["read_api".into()];
    for (name, config) in [
        ("default", fixture()),
        ("minimal", minimal),
        ("audit-inventory-maximal", maximal_fixture()),
    ] {
        let descriptor = gitlab_descriptor(&config);
        descriptor
            .validate()
            .unwrap_or_else(|error| panic!("{name}: {error:?}"));
        if name == "audit-inventory-maximal" {
            assert_eq!(descriptor.actions.len(), entries.len());
        }
        for action in &descriptor.actions {
            let projection = action.audit_inputs.as_ref().unwrap();
            prepare_audit_inputs(&action.input_schema, projection)
                .unwrap_or_else(|error| panic!("{name} {}: {error:?}", action.action));
            let actual = serde_json::to_value(projection).unwrap();
            let mut expected = entries[action.action.as_str()]["fields"]
                .as_array()
                .unwrap()
                .clone();
            if action.action == "search.code" && name != "audit-inventory-maximal" {
                expected.retain(|rule| rule["pointer"] != "/regex");
            }
            let expected: Vec<_> = expected.iter().map(canonical_inventory_rule).collect();
            assert_eq!(
                actual,
                json!(expected),
                "{name} {} declaration drift",
                action.action
            );
            let mut schema = BTreeSet::new();
            schema_paths(&action.input_schema, "", &mut schema);
            let mut reviewed = BTreeSet::new();
            rule_paths(actual.as_array().unwrap(), "", &mut reviewed);
            assert_eq!(
                schema, reviewed,
                "{name} {} has unclassified or stale properties",
                action.action
            );
        }
    }
}

fn capture(action: &str, inputs: Value) -> Value {
    let descriptor = gitlab_descriptor(&maximal_fixture());
    let action = descriptor.action(action).unwrap();
    let plan =
        prepare_audit_inputs(&action.input_schema, action.audit_inputs.as_ref().unwrap()).unwrap();
    serde_json::to_value(plan.project(&inputs)).unwrap()
}

fn field<'a>(audit: &'a Value, key: &str) -> &'a Value {
    audit["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["key"] == key)
        .unwrap()
}

#[test]
fn caller_text_is_bounded_and_body_tokens_and_urls_are_never_values() {
    let audit = capture(
        "issue.update",
        json!({
            "project":"sample/repository", "iid":u64::MAX,
            "title":"Requested title", "content":"BODY_SECRET", "contentFormat":"markdown",
            "labels":["first", "second"], "unexpected":"UNKNOWN_SECRET",
        }),
    );
    assert_eq!(field(&audit, "title")["value"], "Requested title");
    assert_eq!(field(&audit, "iid")["encoding"], "decimalInteger");
    assert_eq!(field(&audit, "iid")["value"], u64::MAX.to_string());
    assert_eq!(field(&audit, "content")["value"], "BODY_SECRET".len());
    assert!(!audit.to_string().contains("BODY_SECRET"));
    assert!(!audit.to_string().contains("UNKNOWN_SECRET"));
    let webhook = capture(
        "webhook.update",
        json!({
            "project":"sample/repository", "webhookId":1,"name":"Build webhook",
            "url":"https://hooks.example.test/URL_SECRET", "token":"TOKEN_SECRET",
            "signingToken":"SIGNING_SECRET", "description":"DESCRIPTION_SECRET",
            "customWebhookTemplate":"TEMPLATE_SECRET", "events":["pushEvents"],
        }),
    );
    for key in ["url", "token", "signingToken"] {
        assert_eq!(field(&webhook, key)["value"], true);
    }
    for secret in [
        "URL_SECRET",
        "TOKEN_SECRET",
        "SIGNING_SECRET",
        "DESCRIPTION_SECRET",
        "TEMPLATE_SECRET",
    ] {
        assert!(!webhook.to_string().contains(secret));
    }
    let header = capture(
        "webhook.custom_header.set",
        json!({"project":"p/r","webhookId":1,"key":"X-Delivery-Key","value":"HEADER_SECRET"}),
    );
    assert_eq!(field(&header, "key")["value"], "X-Delivery-Key");
    assert_eq!(field(&header, "value")["value"], true);
    assert!(!header.to_string().contains("HEADER_SECRET"));
    let query = capture(
        "branch.list",
        json!({"project":"p/r","regex":"é".repeat(3000)}),
    );
    assert_eq!(field(&query, "regex")["originalBytes"], 6000);
    assert_eq!(
        field(&query, "regex")["value"].as_str().unwrap().len(),
        4096
    );
    assert_eq!(field(&query, "regex")["truncated"], true);
}

#[test]
fn commit_and_suggestion_records_preserve_identity_and_source_indices() {
    let audit = capture(
        "commit.create",
        json!({
            "project":"sample/repository","branch":"feature","commitMessage":"MESSAGE_SECRET",
            "authorName":"Synthetic Author","authorEmail":"author@example.test",
            "actions":[
                {"action":"move","filePath":"new.txt","previousPath":"old.txt","content":"CONTENT_SECRET","encoding":"text","executeFilemode":false,"lastCommitId":"abc"},
                {"action":"delete","filePath":"deleted.txt"},
            ]
        }),
    );
    let rows = field(&audit, "actions")["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["index"], 0);
    assert_eq!(rows[0]["cells"]["filePath"]["value"], "new.txt");
    assert_eq!(rows[0]["cells"]["previousPath"]["value"], "old.txt");
    assert_eq!(rows[0]["cells"]["executeFilemode"]["value"], false);
    assert_eq!(rows[1]["cells"]["filePath"]["value"], "deleted.txt");
    assert_eq!(field(&audit, "authorEmail")["value"], "author@example.test");
    assert!(!audit.to_string().contains("MESSAGE_SECRET"));
    assert!(!audit.to_string().contains("CONTENT_SECRET"));
    let suggestions: Vec<_> = (0..25)
        .map(|i| json!({"discussionId":format!("d-{i}"),"noteId":100+i,"suggestionId":200+i}))
        .collect();
    let batch = capture(
        "merge_request.suggestion.batch_apply",
        json!({"project":"p/r","iid":7,"expectedHeadSha":"abc","suggestions":suggestions}),
    );
    let records = field(&batch, "suggestions");
    assert_eq!(records["totalCount"], 25);
    assert_eq!(records["limitedCount"], 5);
    assert_eq!(records["rows"].as_array().unwrap().len(), 20);
    for row in records["rows"].as_array().unwrap() {
        let index = row["index"].as_u64().unwrap();
        assert!(index < 20);
        assert_eq!(row["cells"]["discussionId"]["value"], format!("d-{index}"));
        assert_eq!(row["cells"]["noteId"]["value"], 100 + index);
        assert_eq!(row["cells"]["suggestionId"]["value"], 200 + index);
    }
}

#[test]
fn upload_projection_excludes_transport_names_and_requested_checksums() {
    let audit = capture(
        "project.upload",
        json!({"project":"p/r","url":"URL_SECRET","attachments":[{
            "field":"FIELD_SECRET","sha256":"HASH_SECRET","filename":"report.txt","contentType":"text/plain","size":12
        }]}),
    );
    let row = &field(&audit, "attachments")["rows"][0];
    assert_eq!(row["cells"]["filename"]["value"], "report.txt");
    assert_eq!(row["cells"]["size"]["value"], 12);
    for secret in ["URL_SECRET", "FIELD_SECRET", "HASH_SECRET"] {
        assert!(!audit.to_string().contains(secret));
    }
}

// Build representative runtime shapes from the schema, independently of the
// audit declaration. Branch constraints stay with invocation validation; this
// test detects a declaration using the wrong scalar/list representation.
fn schema_sample(schema: &Value) -> Option<Value> {
    if let Some(value) = schema.get("const") {
        return Some(value.clone());
    }
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        return values.first().cloned();
    }
    let mut object = serde_json::Map::new();
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        for (key, value) in properties {
            if let Some(value) = schema_sample(value) {
                object.insert(key.clone(), value);
            }
        }
    }
    let mut scalar_branch = None;
    for keyword in ["allOf", "oneOf", "anyOf"] {
        if let Some(branches) = schema.get(keyword).and_then(Value::as_array) {
            for branch in branches {
                match schema_sample(branch) {
                    Some(Value::Object(values)) => object.extend(values),
                    Some(value) if scalar_branch.is_none() => scalar_branch = Some(value),
                    _ => {}
                }
            }
        }
    }
    if !object.is_empty() {
        return Some(Value::Object(object));
    }
    if scalar_branch.is_some() {
        return scalar_branch;
    }
    let kind = schema.get("type").and_then(|value| {
        value
            .as_str()
            .or_else(|| value.as_array()?.first()?.as_str())
    });
    match kind {
        Some("string") => Some(json!("sample")),
        Some("integer" | "number") => Some(json!(1)),
        Some("boolean") => Some(json!(true)),
        Some("array") => Some(json!([schema_sample(&schema["items"]).unwrap()])),
        Some("object") => Some(json!({})),
        Some("null") => Some(Value::Null),
        _ => None,
    }
}

#[test]
fn every_value_rule_matches_its_published_runtime_shape() {
    for config in [fixture(), maximal_fixture()] {
        for action in gitlab_descriptor(&config).actions {
            let inputs = schema_sample(&action.input_schema).unwrap();
            let plan =
                prepare_audit_inputs(&action.input_schema, action.audit_inputs.as_ref().unwrap())
                    .unwrap();
            let audit = serde_json::to_value(plan.project(&inputs)).unwrap();
            for field in audit["fields"].as_array().unwrap() {
                assert_eq!(
                    field["supplied"], true,
                    "{} {}: {field}",
                    action.action, field["key"]
                );
                assert_ne!(
                    field["state"], "invalid",
                    "{} {}: {field}",
                    action.action, field["key"]
                );
                if let Some(rows) = field.get("rows").and_then(Value::as_array) {
                    for row in rows {
                        assert_ne!(
                            row["state"], "invalid",
                            "{} {}: {row}",
                            action.action, field["key"]
                        );
                        if let Some(cells) = row.get("cells").and_then(Value::as_object) {
                            for (key, cell) in cells {
                                assert_ne!(
                                    cell["state"], "invalid",
                                    "{} {key}: {cell}",
                                    action.action
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn draft_object_descriptors_include_the_existing_required_parent_iid() {
    let descriptor = gitlab_descriptor(&fixture());
    for name in [
        "merge_request.draft_note.view",
        "merge_request.draft_note.delete",
        "merge_request.draft_note.publish",
    ] {
        let action = descriptor.action(name).unwrap();
        assert_eq!(
            action.input_schema["properties"]["iid"]["type"],
            json!(["integer", "string"])
        );
        assert!(
            action.input_schema["required"]
                .as_array()
                .unwrap()
                .contains(&json!("iid"))
        );
        let inputs = json!({"project":"sample/repository", "iid":7,"draftNoteId":42});
        assert!(parse_draft_note_object_inputs(&inputs).is_ok());
        assert_eq!(field(&capture(name, inputs), "iid")["value"], 7);
    }
}

#[test]
fn provider_observations_keep_processing_and_safety_without_request_echoes() {
    let safety = GitlabBranchSafety {
        branch: "feature".into(),
        default_branch: Some("main".into()),
        target_branch_exists: true,
        existing_branch_default: Some(false),
        existing_branch_protected: Some(false),
        matched_protected_branch: None,
    };
    let request = GitlabCommitCreateRequest {
        branch: "feature".into(),
        commit_message: "MESSAGE_SECRET".into(),
        start_branch: None,
        start_sha: None,
        author_name: None,
        author_email: None,
        actions: vec![GitlabCommitActionRequest {
            action: "update".into(),
            file_path: "path.txt".into(),
            previous_path: None,
            content: Some("CONTENT_SECRET".into()),
            encoding: Some("text".into()),
            execute_filemode: Some(false),
            last_commit_id: Some("abc".into()),
            decoded_content_bytes: Some(14),
        }],
    };
    let audit = commit_create_audit(&request, &safety);
    assert_eq!(
        audit["branchSafety"],
        json!({"branch":"feature","defaultBranch":"main","targetBranchExists":true,"existingBranchDefault":false,"existingBranchProtected":false,"matchedProtectedBranch":null})
    );
    assert_eq!(
        audit["contentProcessing"]["actions"],
        json!([{"inputIndex":0,"decodedContentBytes":14}])
    );
    for removed in [
        "requestBody",
        "jsonFields",
        "textByteCounts",
        "listCounts",
        "filePath",
        "executeFilemode",
        "lastCommitId",
        "MESSAGE_SECRET",
        "CONTENT_SECRET",
    ] {
        assert!(!audit.to_string().contains(removed));
    }
    let ci = GitlabCiRefSafety {
        ref_name: "feature".into(),
        default_branch: Some("main".into()),
        existing_branch_default: Some(false),
        existing_branch_protected: Some(false),
        matched_protected_branch: None,
        denial_reason: None,
    };
    assert_eq!(
        ci_ref_audit(&ci)["refSafety"],
        json!({"ref":"feature","defaultBranch":"main","existingBranchDefault":false,"existingBranchProtected":false,"matchedProtectedBranch":null,"denialReason":null})
    );
    let file = GitlabFileWriteRequest {
        path: "path.txt".into(),
        branch: "feature".into(),
        content: "BASE64_SECRET".into(),
        commit_message: "MESSAGE_SECRET".into(),
        start_branch: None,
        author_name: None,
        author_email: None,
        encoding: Some("base64".into()),
        execute_filemode: None,
        last_commit_id: None,
        decoded_content_bytes: 10,
    };
    assert_eq!(
        file_mutation_audit(&file, &safety),
        json!({"branchSafety":audit["branchSafety"],"contentProcessing":{"decodedContentBytes":10}})
    );
}

#[test]
fn merge_observations_keep_exact_derived_keys() {
    let existing: GitlabMergeRequest = serde_json::from_value(json!({
        "id":1,"iid":7,"projectId":42,"sourceBranch":"feature","targetBranch":"main",
        "mergeStatus":"checking","detailedMergeStatus":"ci_still_running"
    }))
    .unwrap();
    let merged: GitlabMergeRequest = serde_json::from_value(json!({
        "id":1,"iid":7,"projectId":42,"sourceBranch":"feature","targetBranch":"main",
        "mergeStatus":"can_be_merged","detailedMergeStatus":"mergeable","mergeCommitSha":"def"
    }))
    .unwrap();
    assert_eq!(
        merge_observation_audit(&existing, &merged),
        json!({"merge":{
            "sourceBranch":"feature","targetBranch":"main","currentMergeStatus":"checking",
            "currentDetailedMergeStatus":"ci_still_running","upstreamMergeStatus":"can_be_merged",
            "upstreamDetailedMergeStatus":"mergeable","mergeCommitSha":"def"
        }})
    );
}

#[test]
fn identity_names_are_omitted_whole_while_titles_can_be_clipped() {
    let long = "x".repeat(1025);
    let token = capture(
        "project.access_token.create",
        json!({"project":"p/r","name":long,"scopes":["read_api"],"accessLevel":30,"expiresAt":"2027-01-01"}),
    );
    assert_eq!(field(&token, "name")["state"], "tooLarge");
    assert!(field(&token, "name").get("value").is_none());
    let file = capture(
        "file.create",
        json!({"project":"p/r","path":"a.txt","branch":"feature","content":"body","commitMessage":"message","authorName":long,"authorEmail":long}),
    );
    for key in ["authorName", "authorEmail"] {
        assert_eq!(field(&file, key)["state"], "tooLarge");
        assert!(field(&file, key).get("value").is_none());
    }
    let issue = capture("issue.create", json!({"project":"p/r","title":long}));
    assert_eq!(field(&issue, "title")["truncated"], true);
    assert_eq!(
        field(&issue, "title")["value"].as_str().unwrap().len(),
        1024
    );
}
