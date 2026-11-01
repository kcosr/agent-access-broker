use super::*;

#[test]
fn optional_rendered_body_prefixes_follow_declarations_and_required_paths_win() {
    use agent_access_provider::presentation::{
        ActionPresentation, BodyPathSegment, EmbeddedBody, EmbeddedBodyCodec, ReadContentFormat,
        RenderBudget, RenderError, RenderedBody,
    };

    struct EmptyBody;
    impl EmbeddedBodyCodec for EmptyBody {
        fn render(
            &self,
            _: &serde_json::Map<String, Value>,
            _: ReadContentFormat,
            _: u64,
            _: &mut RenderBudget,
        ) -> Result<Option<RenderedBody>, RenderError> {
            Ok(None)
        }
    }

    const BODIES: &[EmbeddedBody] = &[
        EmbeddedBody::new(
            &[
                BodyPathSegment::OptionalField("page"),
                BodyPathSegment::Field("items"),
                BodyPathSegment::Each,
            ],
            &EmptyBody,
        ),
        EmbeddedBody::new(
            &[
                BodyPathSegment::OptionalField("page"),
                BodyPathSegment::Field("extras"),
                BodyPathSegment::Each,
            ],
            &EmptyBody,
        ),
        EmbeddedBody::new(
            &[
                BodyPathSegment::Field("pageRequired"),
                BodyPathSegment::Each,
                BodyPathSegment::OptionalField("a/b~c"),
            ],
            &EmptyBody,
        ),
    ];
    let descriptor = ActionDescriptor::new("view", "View bodies", json!({"type":"object"}))
        .presentation(Some(ActionPresentation::new(BODIES, None)));
    let action = api_action_spec("example", &descriptor).unwrap();
    assert_eq!(
        action.rendered_body_owners,
        [
            "/result/page/items/*",
            "/result/page/extras/*",
            "/result/pageRequired/*/a~1b~0c"
        ]
    );
    let wire = serde_json::to_value(&action).unwrap();
    assert_eq!(
        wire["optionalRenderedBodyOwnerPrefixes"],
        json!(["/result/page", "/result/pageRequired/*/a~1b~0c"])
    );
    assert_eq!(
        serde_json::from_value::<ApiActionSpec>(wire).unwrap(),
        action
    );

    const OVERLAPPING_BODIES: &[EmbeddedBody] = &[
        EmbeddedBody::new(
            &[
                BodyPathSegment::OptionalField("page"),
                BodyPathSegment::Each,
            ],
            &EmptyBody,
        ),
        EmbeddedBody::new(
            &[BodyPathSegment::Field("page"), BodyPathSegment::Each],
            &EmptyBody,
        ),
    ];
    let required = descriptor.presentation(Some(ActionPresentation::new(OVERLAPPING_BODIES, None)));
    let required = api_action_spec("example", &required).unwrap();
    assert_eq!(required.rendered_body_owners, ["/result/page/*"]);
    assert!(required.optional_rendered_body_owner_prefixes.is_empty());
    assert!(
        serde_json::to_value(required)
            .unwrap()
            .get("optionalRenderedBodyOwnerPrefixes")
            .is_none()
    );
}

#[test]
fn companion_metadata_flows_to_capabilities_catalog_openapi_and_send() {
    let descriptor = ActionDescriptor::new(
        "view",
        "Read optionally related content",
        json!({"type":"object"}),
    )
    .read_only()
    .scope("project")
    .companion_read("comment.list")
    .companion_read("comment.view");
    let expected = json!(["comment.list", "comment.view"]);
    assert_eq!(
        serde_json::to_value(descriptor.capabilities()).unwrap()["companionReadActions"],
        expected
    );
    let action = api_action_spec("example", &descriptor).unwrap();
    let mut catalog = empty_catalog(json!({}));
    catalog.services.push(ApiServiceSpec {
        availability: None,
        scoped_mcp_ready: true,
        service: "example".into(),
        display_name: "Example".into(),
        surface: "invoke".into(),
        scope_types: vec![],
        resource_scopes: Default::default(),
        actions: vec![action],
    });
    assert_eq!(
        serde_json::to_value(&catalog).unwrap()["services"][0]["actions"][0]["companionReadActions"],
        expected
    );
    let openapi = openapi_from_catalog(&catalog, RenderAuthMode::Omit, &[], "session");
    assert_eq!(
        openapi["paths"]["/v1/invoke/example/view"]["post"]["x-agent-access-companion-read-actions"],
        expected
    );
    assert_eq!(
        send_schema_from_catalog(&catalog)["oneOf"][0]["x-agent-access-companion-read-actions"],
        expected
    );
    catalog.services[0].actions[0]
        .companion_read_actions
        .clear();
    assert!(
        serde_json::to_value(&catalog).unwrap()["services"][0]["actions"][0]
            .get("companionReadActions")
            .is_none()
    );
    assert!(
        send_schema_from_catalog(&catalog)["oneOf"][0]
            .get("x-agent-access-companion-read-actions")
            .is_none()
    );
}

#[test]
fn explicit_resource_listing_metadata_flows_to_catalog_openapi_and_send() {
    let descriptor = ActionDescriptor::new("inventory", "List projects", json!({"type":"object"}))
        .read_only()
        .scope("project")
        .native_search(agent_access_provider::NativeSearchEnforcement::ResultFiltered)
        .listing_of(agent_access_provider::ResourceType::new("fake_project").unwrap());
    let action = api_action_spec("example", &descriptor).unwrap();
    assert_eq!(
        serde_json::to_value(descriptor.capabilities()).unwrap()["listingOf"],
        "fake_project"
    );
    let mut catalog = empty_catalog(json!({}));
    catalog.services.push(ApiServiceSpec {
        availability: None,
        scoped_mcp_ready: true,
        service: "example".into(),
        display_name: "Example".into(),
        surface: "invoke".into(),
        scope_types: vec![],
        resource_scopes: Default::default(),
        actions: vec![action],
    });
    assert_eq!(
        serde_json::to_value(&catalog).unwrap()["services"][0]["actions"][0]["listingOf"],
        "fake_project"
    );
    let openapi = openapi_from_catalog(&catalog, RenderAuthMode::Omit, &[], "session");
    assert_eq!(
        openapi["paths"]["/v1/invoke/example/inventory"]["post"]["x-agent-access-listing-of"],
        "fake_project"
    );
    assert_eq!(
        send_schema_from_catalog(&catalog)["oneOf"][0]["x-agent-access-listing-of"],
        "fake_project"
    );
    catalog.services[0].actions[0].listing_of = None;
    let openapi = openapi_from_catalog(&catalog, RenderAuthMode::Omit, &[], "session");
    assert!(
        openapi["paths"]["/v1/invoke/example/inventory"]["post"]
            .get("x-agent-access-listing-of")
            .is_none()
    );
    assert!(
        send_schema_from_catalog(&catalog)["oneOf"][0]
            .get("x-agent-access-listing-of")
            .is_none()
    );
}

#[test]
fn extended_action_documentation_flows_to_specs_but_not_tool_definitions() {
    let documentation = json!({
        "language":"example", "fields":["status"], "examples":["status = Open"],
        "inputExamples":[{"label":"DOC_SENTINEL: quotes and backslashes", "inputs":{
            "query":"status = \"Open\" AND path = \"C:\\work\\notes\"", "nested":{"lines":["one\ntwo", "é"]}
        }}]
    });
    let descriptor = ActionDescriptor::new(
        "search",
        "Search authorized resources",
        json!({"type":"object"}),
    )
    .documentation(documentation.clone());
    assert_eq!(
        descriptor.capabilities().documentation,
        Some(documentation.clone())
    );
    let action = api_action_spec("example", &descriptor).unwrap();
    let mut catalog = empty_catalog(json!({}));
    catalog.services.push(ApiServiceSpec {
        availability: None,
        scoped_mcp_ready: true,
        service: "example".into(),
        display_name: "Example".into(),
        surface: "invoke".into(),
        scope_types: vec![],
        resource_scopes: Default::default(),
        actions: vec![action],
    });
    assert_eq!(
        serde_json::to_value(&catalog).unwrap()["services"][0]["actions"][0]["documentation"],
        documentation
    );
    let openapi = openapi_from_catalog(&catalog, RenderAuthMode::Omit, &[], "session");
    assert_eq!(
        openapi["paths"]["/v1/invoke/example/search"]["post"]["x-agent-access-documentation"],
        documentation
    );
    let send = send_schema_from_catalog(&catalog);
    assert_eq!(
        send["oneOf"][0]["x-agent-access-documentation"],
        documentation
    );
    for view in [
        crate::mcp::McpView::Aggregate,
        crate::mcp::McpView::Service("example".into()),
    ] {
        for mode in [
            crate::mcp::ProjectionMode::Http,
            crate::mcp::ProjectionMode::Stdio,
        ] {
            let registry = crate::mcp::ToolRegistry::build(
                &catalog,
                &view,
                mode,
                crate::mcp::STDIO_MAX_CATALOG_BYTES,
            )
            .unwrap();
            let definitions = registry.definitions();
            let tool = definitions
                .iter()
                .find(|tool| tool["_meta"]["agent-access/action"] == "search")
                .unwrap();
            assert!(
                tool["description"].as_str().unwrap().contains(
                    "request action details for service=\"example\" and action=\"search\""
                )
            );
            assert!(tool.get("documentation").is_none());
            assert!(
                !serde_json::to_string(tool)
                    .unwrap()
                    .contains("status = Open")
            );
            assert!(
                !serde_json::to_string(&definitions)
                    .unwrap()
                    .contains("DOC_SENTINEL")
            );
        }
    }
}

#[test]
fn imported_local_schema_refs_remain_scoped_in_send_openapi_and_mcp() {
    let schema = |minimum| {
        json!({
            "type":"object","additionalProperties":false,"required":["number","items","literal"],
            "$defs":{"a%41 space":{"$anchor":"Count","type":"integer","minimum":minimum}},
            "properties":{
                "number":{"$ref":"#Count"},
                "items":{"type":"array","items":{"$ref":"#/$defs/a%2541%20space"}},
                "literal":{"const":{"$ref":"literal data remains literal"}}
            }
        })
    };
    let mut catalog = empty_catalog(json!({}));
    catalog.services.push(ApiServiceSpec {
        availability: None,
        scoped_mcp_ready: true,
        service: "imported".into(),
        display_name: "Imported".into(),
        surface: "invoke".into(),
        scope_types: vec![],
        resource_scopes: Default::default(),
        actions: vec![
            api_action_spec(
                "imported",
                &ActionDescriptor::new("small", "Small", schema(2)),
            )
            .unwrap(),
            api_action_spec(
                "imported",
                &ActionDescriptor::new("large", "Large", schema(10)),
            )
            .unwrap(),
        ],
    });
    let inputs = |number| json!({"number":number,"items":[number],"literal":{"$ref":"literal data remains literal"}});
    let send = send_schema_from_catalog(&catalog);
    let validator = jsonschema::validator_for(&send).unwrap();
    assert!(validator.is_valid(&json!({"version":SEND_SCHEMA_VERSION,"kind":"invoke","service":"imported","action":"small","inputs":inputs(2)})));
    assert!(!validator.is_valid(&json!({"version":SEND_SCHEMA_VERSION,"kind":"invoke","service":"imported","action":"large","inputs":inputs(2)})));
    assert!(validator.is_valid(&json!({"version":SEND_SCHEMA_VERSION,"kind":"invoke","service":"imported","action":"large","inputs":inputs(10)})));
    assert_eq!(
        send["oneOf"][1]["properties"]["inputs"]["properties"]["number"]["$ref"],
        "#/oneOf/1/properties/inputs/$defs/a%2541%20space"
    );
    let openapi = openapi_from_catalog(&catalog, RenderAuthMode::Omit, &[], "session");
    for action in &catalog.services[0].actions {
        // An OpenAPI reference addresses the document root; compile a reference to
        // its request schema with the complete document available to the resolver.
        let mut document = openapi.clone();
        document["$ref"] = json!(format!(
            "#/paths/~1v1~1invoke~1imported~1{}/post/requestBody/content/application~1json/schema",
            action.action
        ));
        let validator = jsonschema::validator_for(&document).unwrap();
        assert!(validator.is_valid(&json!({"inputs":inputs(10)})));
        assert_eq!(
            validator.is_valid(&json!({"inputs":inputs(2)})),
            action.action == "small"
        );
        for mode in [
            crate::mcp::ProjectionMode::Http,
            crate::mcp::ProjectionMode::Stdio,
        ] {
            let mcp = crate::mcp::input_schema(action, mode);
            let validator = jsonschema::validator_for(&mcp).unwrap();
            assert!(validator.is_valid(&json!({"inputs":inputs(10)})));
            assert_eq!(
                validator.is_valid(&json!({"inputs":inputs(2)})),
                action.action == "small"
            );
        }
    }
}

#[test]
fn resource_attribute_schemas_require_private_fields_only_on_exact_creation() {
    static ATTRIBUTES: [agent_access_provider::ResourceAttributeDescriptor; 1] = [
        agent_access_provider::ResourceAttributeDescriptor::required(
            "webhookUrl",
            "Webhook URL",
            "Private destination",
            |_| true,
        ),
    ];
    static RESOURCE: agent_access_provider::ResourceTypeDescriptor =
        agent_access_provider::ResourceTypeDescriptor::new(
            agent_access_provider::ResourceType::from_static("test_destination"),
            "Destination",
            "Destinations",
            "alerts",
            |_| true,
            &ATTRIBUTES,
        );
    let types = agent_access_provider::ResourceTypeRegistry::new([&RESOURCE]).unwrap();
    let routes = http_route_specs(&types);
    let create = routes
        .iter()
        .find(|route| route.method == "POST" && route.route == "/v1/admin/policy/resources")
        .unwrap();
    assert_eq!(create.sensitive_request_pointers, ["/body/attributes"]);
    let validator =
        jsonschema::validator_for(create.request_body_schema.as_ref().unwrap()).unwrap();
    let mut exact = json!({"resourceType":"test_destination","selector":{"kind":"exact","value":"alerts"},"allowedExecutionContexts":["internal"]});
    assert!(!validator.is_valid(&exact));
    exact["attributes"] = json!({"webhookUrl":"private"});
    assert!(validator.is_valid(&exact));
    exact["attributes"] = json!({"unknown":"private"});
    assert!(!validator.is_valid(&exact));
    exact["selector"] = json!({"kind":"all"});
    exact["attributes"] = json!({"webhookUrl":"private"});
    assert!(!validator.is_valid(&exact));
    exact.as_object_mut().unwrap().remove("attributes");
    assert!(validator.is_valid(&exact));
    let patch = routes
        .iter()
        .find(|route| route.method == "PATCH" && route.route == "/v1/admin/policy/resources/{id}")
        .unwrap();
    let validator = jsonschema::validator_for(patch.request_body_schema.as_ref().unwrap()).unwrap();
    assert!(validator.is_valid(&json!({"expectedVersion":1,"displayName":"New label"})));
    assert!(
        validator.is_valid(&json!({"expectedVersion":1,"attributes":{"webhookUrl":"replacement"}}))
    );
    assert!(!validator.is_valid(&json!({"expectedVersion":1,"attributes":{"webhookUrl":null}})));
    let reveal = routes
        .iter()
        .find(|route| route.operation == "admin.policy.resources.attribute.reveal")
        .unwrap();
    assert_eq!(reveal.access, RouteAccess::AdminWrite);
    assert_eq!(reveal.sensitive_response_pointers, ["/result/value"]);
}

#[test]
fn resource_catalog_schemas_describe_typed_selectors_and_manual_deletion() {
    let routes = http_route_specs(&crate::tests::test_resource_types());
    let create = routes
        .iter()
        .find(|r| r.method == "POST" && r.route == "/v1/admin/policy/resources")
        .unwrap();
    assert_eq!(create.access, RouteAccess::AdminWrite);
    let validator =
        jsonschema::validator_for(create.request_body_schema.as_ref().unwrap()).unwrap();
    for resource in [
        json!({"resourceType":"git_repository","selector":{"kind":"exact","value":"engineering/payments"},"allowedExecutionContexts":["internal"]}),
        json!({"resourceType":"git_repository","selector":{"kind":"namespace","value":"engineering/platform"},"allowedExecutionContexts":["internal"]}),
        json!({"resourceType":"confluence_space","selector":{"kind":"all"},"allowedExecutionContexts":["internal","external"]}),
    ] {
        assert!(validator.is_valid(&resource), "rejected {resource}");
    }
    for resource in [
        json!({"resourceType":"confluence_page","selector":{"kind":"exact","value":"123"},"allowedExecutionContexts":["internal"]}),
        json!({"resourceType":"jira_project","selector":{"kind":"namespace","value":"ENG"},"allowedExecutionContexts":["internal"]}),
        json!({"resourceType":"git_repository","selector":{"kind":"all","value":"*"},"allowedExecutionContexts":["internal"]}),
        json!({"resourceType":"jira_project","selector":{"kind":"exact","value":"ENG"},"allowedExecutionContexts":[]}),
    ] {
        assert!(!validator.is_valid(&resource), "accepted {resource}");
    }
    let group = routes
        .iter()
        .find(|r| r.method == "POST" && r.route == "/v1/admin/policy/resource-groups")
        .unwrap();
    let validator = jsonschema::validator_for(group.request_body_schema.as_ref().unwrap()).unwrap();
    assert!(validator.is_valid(&json!({"name":"External","includedResourceIds":["all-repositories"],"excludedResourceIds":["private"]})));
    assert!(validator.is_valid(&json!({"name":"Initially empty"})));
    assert!(!validator.is_valid(&json!({"name":"Nested","resourceGroupIds":["other"]})));
    assert!(!validator.is_valid(&json!({"name":"Disabled group","enabled":false})));
    for base in ["resources", "resource-groups"] {
        let detail = format!("/v1/admin/policy/{base}/{{id}}");
        let delete = routes
            .iter()
            .find(|r| r.method == "DELETE" && r.route == detail)
            .unwrap();
        assert_eq!(delete.access, RouteAccess::AdminWrite);
        assert!(
            delete
                .query_params
                .iter()
                .any(|p| p.name == "expectedVersion" && p.required)
        );
        assert!(
            routes
                .iter()
                .any(|r| r.method == "GET" && r.route == format!("{detail}/used-by"))
        );
    }
}

#[test]
fn resource_mutation_schemas_match_core_selector_kind_support() {
    let routes = http_route_specs(&crate::tests::test_resource_types());
    for (method, path) in [
        ("POST", "/v1/admin/policy/resources"),
        ("PATCH", "/v1/admin/policy/resources/{id}"),
    ] {
        let route = routes
            .iter()
            .find(|route| route.method == method && route.route == path)
            .unwrap();
        let validator =
            jsonschema::validator_for(route.request_body_schema.as_ref().unwrap()).unwrap();
        for (resource_type, value, supports_namespace) in [
            ("git_repository", "engineering/payments", true),
            ("cloudbees_ci_job", "team-ci/payments", true),
            ("jira_project", "ENG", false),
            ("confluence_space", "ENG", false),
            ("oauth_collection", "alpha", false),
        ] {
            for kind in ["exact", "namespace", "all"] {
                let selector = if kind == "all" {
                    json!({"kind": kind})
                } else {
                    json!({"kind": kind, "value": value})
                };
                let mut body = json!({
                    "resourceType": resource_type,
                    "selector": selector,
                    "allowedExecutionContexts": ["internal"]
                });
                let mut definition = body.clone();
                definition["id"] = json!("test-resource");
                let definition =
                    serde_json::from_value::<crate::ResourceDefinition>(definition).unwrap();
                let core_accepts =
                    crate::ResourceCatalog::new(std::slice::from_ref(&definition), &[]).is_ok()
                        && definition
                            .validate_type(&crate::tests::test_resource_types())
                            .is_ok();
                let expected = kind != "namespace" || supports_namespace;
                assert_eq!(core_accepts, expected, "core: {body}");
                if method == "PATCH" {
                    body["expectedVersion"] = json!(1);
                }
                assert_eq!(validator.is_valid(&body), expected, "{method}: {body}");
            }
        }
        if method == "PATCH" {
            // Partial updates need the stored resource to validate a combination.
            for body in [
                json!({"expectedVersion":1,"resourceType":"oauth_collection"}),
                json!({"expectedVersion":1,"selector":{"kind":"namespace","value":"engineering"}}),
            ] {
                assert!(validator.is_valid(&body), "rejected partial update {body}");
            }
        }
    }
}

#[test]
fn catalog_execution_context_metadata_is_optional_and_typed() {
    let mut catalog = empty_catalog(json!({"principal": "agent"}));
    let without_context = serde_json::to_value(&catalog).unwrap();
    assert!(without_context.get("executionContext").is_none());

    catalog.execution_context = Some(ExecutionContext::new("external").unwrap());
    let with_context = serde_json::to_value(&catalog).unwrap();
    assert_eq!(with_context["executionContext"], "external");
    assert_eq!(
        serde_json::from_value::<ApiCatalog>(with_context)
            .unwrap()
            .execution_context
            .unwrap()
            .as_str(),
        "external"
    );
}

#[test]
fn action_projection_preserves_optional_upstream_resource_ownership() {
    let action = agent_access_provider::ActionDescriptor::new(
        "draft.list",
        "List acting-user resources",
        json!({ "type": "object" }),
    )
    .scope("repository")
    .credential_modes(["per_user"])
    .lookup(agent_access_provider::LookupRequirement::ScopeResolution)
    .upstream_resource_ownership(agent_access_provider::UpstreamResourceOwnership::ActingUser);
    let projected = api_action_spec("gitlab", &action).expect("action is valid");
    let value = serde_json::to_value(projected).unwrap();
    assert_eq!(value["upstreamResourceOwnership"], "acting_user");

    let mut without_ownership: ApiActionSpec = serde_json::from_value(value).unwrap();
    without_ownership.upstream_resource_ownership = None;
    assert!(
        serde_json::to_value(without_ownership)
            .unwrap()
            .get("upstreamResourceOwnership")
            .is_none()
    );
}

#[test]
fn gitlab_project_upload_projects_single_file_transport_contract() {
    let action = api_action_spec(
        "gitlab",
        &agent_access_provider::ActionDescriptor::new(
            "project.upload",
            "Upload a project attachment",
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["attachments"],
                "properties": {
                    "project": {"type": "string"},
                    "url": {"type": "string"},
                    "attachments": {"type": "array", "minItems": 1, "maxItems": 1}
                },
                "oneOf": [{"required": ["project"]}, {"required": ["url"]}]
            }),
        )
        .scope("repository")
        .credential_modes(["service"])
        .lookup(agent_access_provider::LookupRequirement::ScopeResolution)
        .multipart_upload(agent_access_provider::attachment_upload_plan(
            &["project", "url"],
            Some(1),
        )),
    )
    .unwrap();
    let ActionIo::MultipartUpload { plan } = &action.io else {
        panic!("GitLab project uploads must use multipart transport");
    };
    assert_eq!(plan.max_files, Some(1));
    assert_eq!(plan.locator_inputs, ["project", "url"]);
    let mut catalog = empty_catalog(json!({}));
    catalog.services.push(ApiServiceSpec {
        availability: None,
        scoped_mcp_ready: true,
        service: "gitlab".to_string(),
        display_name: "GitLab".to_string(),
        surface: "invoke".to_string(),
        scope_types: vec!["repository".to_string()],
        resource_scopes: BTreeMap::new(),
        actions: vec![action],
    });
    let openapi = openapi_from_catalog(&catalog, RenderAuthMode::Omit, &[], "aab_session");
    let content =
        &openapi["paths"]["/v1/invoke/gitlab/project.upload"]["post"]["requestBody"]["content"];
    assert!(content.get("multipart/form-data").is_some());
    let send = send_schema_from_catalog(&catalog);
    let variant = send["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .find(|variant| variant["properties"]["action"]["const"] == "project.upload")
        .unwrap();
    assert_eq!(variant["properties"]["files"]["minItems"], 1);
    assert_eq!(variant["properties"]["files"]["maxItems"], 1);
    assert!(
        variant["properties"]["inputs"]["properties"]
            .get("attachments")
            .is_none()
    );
    assert_eq!(
        variant["properties"]["inputs"]["oneOf"][1]["required"],
        json!(["url"])
    );
}

fn built_in_descriptor(service: &str) -> agent_access_provider::ServiceDescriptor {
    match service {
        "jira" => agent_access_jira::jira_descriptor(
            &toml::from_str(r#"tenant_host = "example.atlassian.net""#).unwrap(),
        ),
        "confluence" => agent_access_confluence::confluence_descriptor(
            &toml::from_str(r#"tenant_host = "example.atlassian.net""#).unwrap(),
        ),
        "gitlab" => agent_access_gitlab::gitlab_descriptor(
            &toml::from_str(
                r#"
api_base_url = "https://gitlab.example.com/api/v4"
web_base_url = "https://gitlab.example.com"
"#,
            )
            .unwrap(),
        ),
        other => panic!("no built-in descriptor fixture for {other}"),
    }
}

fn descriptor_io(service: &str, action: &str) -> ActionIo {
    built_in_descriptor(service)
        .action(action)
        .unwrap_or_else(|| panic!("{service}.{action} is not declared"))
        .io
        .clone()
}

#[test]
fn descriptors_mark_current_upload_and_download_actions() {
    assert!(matches!(
        descriptor_io("jira", "attachment.add"),
        ActionIo::MultipartUpload { .. }
    ));
    assert!(matches!(
        descriptor_io("confluence", "page.draft.attachment.add"),
        ActionIo::MultipartUpload { .. }
    ));
    assert!(matches!(
        descriptor_io("gitlab", "file.raw.download"),
        ActionIo::RawDownload { .. }
    ));
    assert!(matches!(
        descriptor_io("gitlab", "merge_request.diff.raw.download"),
        ActionIo::RawDownload { .. }
    ));
    assert!(matches!(
        descriptor_io("jira", "issue.view"),
        ActionIo::Json
    ));
    for action in [
        "merge_request.discussion.inline.add",
        "merge_request.discussion.note.add",
        "merge_request.draft_note.list",
        "merge_request.draft_note.view",
        "merge_request.draft_note.add",
        "merge_request.draft_note.update",
        "merge_request.draft_note.delete",
        "merge_request.draft_note.publish",
        "merge_request.draft_note.publish_all",
        "merge_request.review.submit",
        "merge_request.approval.view",
        "merge_request.approval_state.view",
        "merge_request.approval_rule.list",
        "merge_request.approval_rule.view",
        "merge_request.approve",
        "merge_request.unapprove",
        "merge_request.suggestion.apply",
        "merge_request.suggestion.batch_apply",
        "webhook.list",
        "webhook.view",
        "webhook.create",
        "webhook.update",
        "webhook.delete",
        "webhook.test",
        "webhook.event.list",
        "webhook.event.resend",
        "webhook.custom_header.set",
        "webhook.custom_header.delete",
    ] {
        assert!(
            matches!(descriptor_io("gitlab", action), ActionIo::Json),
            "gitlab.{action} must use the JSON invoke contract"
        );
    }
}

#[test]
fn service_projection_removes_gateway_metadata() {
    let projected = api_service_spec(
        &agent_access_provider::ServiceDescriptor::new("repo", "Repo gateway")
            .with_surface(agent_access_provider::ServiceSurface::Gateway {
                kind: "git_http".to_string(),
                broker_hosts: vec!["git.example.test".to_string()],
            })
            .with_actions(vec![
                agent_access_provider::ActionDescriptor::new(
                    "repo.fetch",
                    "Fetch",
                    json!({ "type": "object" }),
                )
                .credential_modes(["service"]),
            ]),
        true,
    );
    assert!(projected.is_none());
}

#[test]
fn service_projection_marks_sensitive_configured_http_headers() {
    let projected = api_service_spec(
        &agent_access_provider::ServiceDescriptor::new("api", "API").with_actions(vec![
            agent_access_provider::ActionDescriptor::new(
                "call",
                "Call",
                json!({
                    "type": "object",
                    "properties": {
                        "headers": {
                            "type": "object",
                            "properties": {
                                "Accept": { "type": "string" },
                                "Password": { "type": "string" },
                                "Private-Key": { "type": "string" },
                                "X-Auth": { "type": "string" },
                                "X-Api-Key": { "type": "string" },
                                "X-Bearer": { "type": "string" },
                                "X-Cred": { "type": "string" },
                                "X-Credential": { "type": "string" },
                                "X-Key": { "type": "string" },
                                "X-Passwd": { "type": "string" },
                                "X-Pwd": { "type": "string" },
                                "X-Session": { "type": "string" },
                                "X/Secret~Header": { "type": "string" }
                            },
                            "additionalProperties": false
                        }
                    }
                }),
            )
            .credential_modes(["service"]),
        ]),
        true,
    )
    .unwrap();

    let pointers = &projected.actions[0].sensitive_input_pointers;
    assert_eq!(
        pointers,
        &vec![
            "/inputs/headers/Password".to_string(),
            "/inputs/headers/Private-Key".to_string(),
            "/inputs/headers/X-Api-Key".to_string(),
            "/inputs/headers/X-Auth".to_string(),
            "/inputs/headers/X-Bearer".to_string(),
            "/inputs/headers/X-Cred".to_string(),
            "/inputs/headers/X-Credential".to_string(),
            "/inputs/headers/X-Key".to_string(),
            "/inputs/headers/X-Passwd".to_string(),
            "/inputs/headers/X-Pwd".to_string(),
            "/inputs/headers/X-Session".to_string(),
            "/inputs/headers/X~1Secret~0Header".to_string()
        ]
    );
}

#[test]
fn service_projection_recursively_marks_explicit_sensitive_inputs() {
    let pointers = sensitive_input_pointers_from_schema(&json!({
        "type": "object",
        "properties": {
            "token": {
                "type": "string",
                "x-agent-access-sensitive": true
            },
            "nested": {
                "type": "object",
                "properties": {
                    "signing/token~value": {
                        "type": "string",
                        "x-agent-access-sensitive": true
                    }
                }
            },
            "credentials": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "value": {
                            "type": "string",
                            "x-agent-access-sensitive": true
                        }
                    }
                }
            },
            "entireObject": {
                "type": "object",
                "x-agent-access-sensitive": true,
                "properties": {
                    "ignoredChild": { "type": "string" }
                }
            },
            "headers": {
                "type": "object",
                "properties": {
                    "X-Token": {
                        "type": "string",
                        "x-agent-access-sensitive": true
                    }
                }
            }
        }
    }));

    assert_eq!(
        pointers,
        vec![
            "/inputs/credentials",
            "/inputs/entireObject",
            "/inputs/headers/X-Token",
            "/inputs/nested/signing~1token~0value",
            "/inputs/token",
        ]
    );
}

#[test]
fn generated_send_schema_uses_required_version() {
    let schema = generic_send_schema();
    let variants = schema["oneOf"].as_array().unwrap();
    assert!(
        variants
            .iter()
            .all(|variant| variant["properties"]["version"]["const"] == SEND_SCHEMA_VERSION)
    );
    let invoke = variants
        .iter()
        .find(|variant| variant["properties"]["kind"]["const"] == "invoke")
        .unwrap();
    assert_eq!(
        invoke["properties"]["readContentFormat"]["enum"],
        json!(["native", "markdown", "text"])
    );
    assert_eq!(
        invoke["properties"]["responseFormat"]["enum"],
        json!(["json", "markdown"])
    );
}

#[test]
fn invoke_formats_project_into_openapi_and_send_schema() {
    let action = ApiActionSpec {
        listing_of: None,
        companion_read_actions: Vec::new(),
        scoped_mcp_name: None,
        documentation: None,
        read_only: false,
        action: "issue.view".to_string(),
        description: "View issue".to_string(),
        required_scope_types: vec!["project".to_string()],
        credential_modes: vec!["service".to_string()],
        lookup_required: false,
        upstream_resource_ownership: None,
        input_schema: json!({
            "type": "object",
            "additionalProperties": false,
            "properties": { "issue": { "type": "string" } }
        }),
        sensitive_input_pointers: Vec::new(),
        sensitive_output_pointers: Vec::new(),
        io: ActionIo::Json,
        response_kind: ResponseKind::ResponseEnvelope,
        exit_policy: ExitPolicy::InvokeDecision,
        read_content_formats: vec![
            "native".to_string(),
            "markdown".to_string(),
            "text".to_string(),
        ],
        response_formats: vec!["json".to_string(), "markdown".to_string()],
        rendered_body_owners: Vec::new(),
        optional_rendered_body_owner_prefixes: Vec::new(),
    };
    let mut catalog = empty_catalog(json!({}));
    catalog.services.push(ApiServiceSpec {
        availability: None,
        scoped_mcp_ready: true,
        service: "jira".to_string(),
        display_name: "Jira".to_string(),
        surface: "invoke".to_string(),
        scope_types: vec!["project".to_string()],
        resource_scopes: BTreeMap::new(),
        actions: vec![action],
    });

    let openapi = openapi_from_catalog(&catalog, RenderAuthMode::Omit, &[], "aab_session");
    let request = &openapi["paths"]["/v1/invoke/jira/issue.view"]["post"]["requestBody"]["content"]
        ["application/json"]["schema"];
    assert_eq!(
        request["properties"]["readContentFormat"]["enum"],
        json!(["native", "markdown", "text"])
    );
    assert_eq!(
        request["properties"]["responseFormat"]["enum"],
        json!(["json", "markdown"])
    );
    assert_eq!(request["additionalProperties"], false);

    let send = send_schema_from_catalog(&catalog);
    let variant = &send["oneOf"][0];
    assert_eq!(
        variant["properties"]["readContentFormat"]["enum"],
        json!(["native", "markdown", "text"])
    );
    assert_eq!(
        variant["properties"]["responseFormat"]["enum"],
        json!(["json", "markdown"])
    );
}

#[test]
fn non_advertising_actions_accept_only_explicit_default_response_formats() {
    let base = ApiActionSpec {
        listing_of: None,
        companion_read_actions: Vec::new(),
        scoped_mcp_name: None,
        documentation: None,
        read_only: false,
        action: "issue.delete".to_string(),
        description: "Delete issue".to_string(),
        required_scope_types: vec!["project".to_string()],
        credential_modes: vec!["service".to_string()],
        lookup_required: false,
        upstream_resource_ownership: None,
        input_schema: json!({
            "type": "object",
            "additionalProperties": false,
            "properties": { "issue": { "type": "string" } }
        }),
        sensitive_input_pointers: Vec::new(),
        sensitive_output_pointers: Vec::new(),
        io: ActionIo::Json,
        response_kind: ResponseKind::ResponseEnvelope,
        exit_policy: ExitPolicy::InvokeDecision,
        read_content_formats: Vec::new(),
        response_formats: Vec::new(),
        rendered_body_owners: Vec::new(),
        optional_rendered_body_owner_prefixes: Vec::new(),
    };
    let mut upload = base.clone();
    upload.action = "attachment.add".to_string();
    upload.io = descriptor_io("jira", "attachment.add");
    let mut download = base.clone();
    download.action = "attachment.download".to_string();
    download.io = descriptor_io("jira", "attachment.download");
    download.response_kind = ResponseKind::RawStream;
    download.exit_policy = ExitPolicy::RawStream;

    let mut catalog = empty_catalog(json!({}));
    catalog.services.push(ApiServiceSpec {
        availability: None,
        scoped_mcp_ready: true,
        service: "jira".to_string(),
        display_name: "Jira".to_string(),
        surface: "invoke".to_string(),
        scope_types: vec!["project".to_string()],
        resource_scopes: BTreeMap::new(),
        actions: vec![base, upload, download],
    });

    let serialized = serde_json::to_value(&catalog).unwrap();
    for action in serialized["services"][0]["actions"].as_array().unwrap() {
        assert!(action.get("readContentFormats").is_none());
        assert!(action.get("responseFormats").is_none());
    }

    let openapi = openapi_from_catalog(&catalog, RenderAuthMode::Omit, &[], "aab_session");
    let json_request = &openapi["paths"]["/v1/invoke/jira/issue.delete"]["post"]["requestBody"]["content"]
        ["application/json"]["schema"];
    assert_default_invoke_formats(json_request);

    let upload_request = &openapi["paths"]["/v1/invoke/jira/attachment.add"]["post"]["requestBody"]
        ["content"]["multipart/form-data"]["schema"]["properties"]["request"];
    assert_eq!(upload_request["contentMediaType"], "application/json");
    assert_default_invoke_formats(&upload_request["contentSchema"]);

    let stream_request = &openapi["paths"]["/v1/invoke/jira/attachment.download"]["post"]["requestBody"]
        ["content"]["application/json"]["schema"];
    assert_default_invoke_formats(stream_request);

    let send = send_schema_from_catalog(&catalog);
    for action in ["issue.delete", "attachment.add", "attachment.download"] {
        let variant = send["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|variant| variant["properties"]["action"]["const"] == action)
            .unwrap();
        assert_default_invoke_formats(variant);
    }
}

fn assert_default_invoke_formats(schema: &Value) {
    assert_eq!(
        schema["properties"]["readContentFormat"]["enum"],
        json!(["native"])
    );
    assert_eq!(
        schema["properties"]["responseFormat"]["enum"],
        json!(["json"])
    );
}

#[test]
fn generated_invoke_send_schema_exposes_secret_sources_only_for_sensitive_actions() {
    let action = ApiActionSpec {
        listing_of: None,
        companion_read_actions: Vec::new(),
        scoped_mcp_name: None,
        documentation: None,
        read_only: false,
        action: "echo".to_string(),
        description: "Echo".to_string(),
        required_scope_types: vec!["project".to_string()],
        credential_modes: vec!["service".to_string()],
        lookup_required: false,
        upstream_resource_ownership: None,
        input_schema: json!({ "type": "object" }),
        sensitive_input_pointers: Vec::new(),
        sensitive_output_pointers: Vec::new(),
        io: ActionIo::Json,
        response_kind: ResponseKind::ResponseEnvelope,
        exit_policy: ExitPolicy::InvokeDecision,
        read_content_formats: Vec::new(),
        response_formats: Vec::new(),
        rendered_body_owners: Vec::new(),
        optional_rendered_body_owner_prefixes: Vec::new(),
    };
    let mut sensitive_action = action.clone();
    sensitive_action.action = "secret.echo".to_string();
    sensitive_action.sensitive_input_pointers = vec!["/inputs/token".to_string()];
    let mut catalog = empty_catalog(json!({}));
    catalog.services.push(ApiServiceSpec {
        availability: None,
        scoped_mcp_ready: true,
        service: "fake".to_string(),
        display_name: "Fake".to_string(),
        surface: "invoke".to_string(),
        scope_types: vec!["project".to_string()],
        resource_scopes: BTreeMap::new(),
        actions: vec![action, sensitive_action],
    });

    let schema = send_schema_from_catalog(&catalog);
    let variants = schema["oneOf"].as_array().unwrap();
    let plain = variants
        .iter()
        .find(|variant| variant["properties"]["action"]["const"] == "echo")
        .unwrap();
    assert!(plain["properties"].get("secretSources").is_none());
    let sensitive = variants
        .iter()
        .find(|variant| variant["properties"]["action"]["const"] == "secret.echo")
        .unwrap();
    assert!(sensitive["properties"].get("secretSources").is_some());
}

#[test]
fn generated_http_send_schema_exposes_secret_sources_only_for_sensitive_routes() {
    let mut catalog = empty_catalog(json!({}));
    catalog.routes = vec![
        get_route(
            "/v1/me",
            "me",
            RouteAccess::Authenticated,
            ResponseKind::RawJson,
        ),
        body_route(
            "PUT",
            "/v1/credentials/connections/{connection}",
            "credentials.put",
            RouteAccess::UserManagement,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            vec!["/body/secret".to_string()],
        ),
    ];

    let schema = send_schema_from_catalog(&catalog);
    let variants = schema["oneOf"].as_array().unwrap();
    let plain = variants
        .iter()
        .find(|variant| variant["properties"]["route"]["const"] == "/v1/me")
        .unwrap();
    assert!(plain["properties"].get("secretSources").is_none());
    let sensitive = variants
        .iter()
        .find(|variant| {
            variant["properties"]["route"]["const"] == "/v1/credentials/connections/{connection}"
        })
        .unwrap();
    assert!(sensitive["properties"].get("secretSources").is_some());
}

#[test]
fn generated_specs_describe_multipart_uploads() {
    let mut catalog = empty_catalog(json!({}));
    catalog.services.push(ApiServiceSpec {
        availability: None,
        scoped_mcp_ready: true,
        service: "confluence".to_string(),
        display_name: "Confluence".to_string(),
        surface: "invoke".to_string(),
        scope_types: vec!["space".to_string()],
        resource_scopes: BTreeMap::new(),
        actions: vec![ApiActionSpec {
            listing_of: None,
            companion_read_actions: Vec::new(),
            scoped_mcp_name: None,
            documentation: None,
            read_only: false,
            action: "attachment.add".to_string(),
            description: "Upload".to_string(),
            required_scope_types: vec!["space".to_string()],
            credential_modes: vec!["service".to_string()],
            lookup_required: false,
            upstream_resource_ownership: None,
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["pageId", "attachments"],
                "properties": {
                    "pageId": { "type": "string" },
                    "attachments": {
                        "type": "array",
                        "items": { "type": "object" }
                    }
                }
            }),
            sensitive_input_pointers: Vec::new(),
            sensitive_output_pointers: Vec::new(),
            io: descriptor_io("confluence", "attachment.add"),
            response_kind: ResponseKind::ResponseEnvelope,
            exit_policy: ExitPolicy::InvokeDecision,
            read_content_formats: Vec::new(),
            response_formats: Vec::new(),
            rendered_body_owners: Vec::new(),
            optional_rendered_body_owner_prefixes: Vec::new(),
        }],
    });

    let schema = send_schema_from_catalog(&catalog);
    let variant = schema["oneOf"].as_array().unwrap().first().unwrap();
    assert!(
        variant["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "files")
    );
    assert_eq!(variant["properties"]["files"]["minItems"], 1);
    assert_eq!(
        variant["properties"]["files"]["items"]["properties"]["role"]["const"],
        "attachment"
    );
    assert!(
        variant["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "inputs")
    );
    assert_eq!(
        variant["properties"]["inputs"]["required"],
        json!(["pageId"])
    );
    assert!(
        variant["properties"]["inputs"]["properties"]
            .get("attachments")
            .is_none()
    );
    assert_eq!(
        variant["properties"]["inputs"]["properties"]["pageId"]["type"],
        "string"
    );
    assert!(variant["properties"].get("secretSources").is_none());

    let openapi = openapi_from_catalog(
        &catalog,
        RenderAuthMode::Include,
        &["X-Broker-Token".to_string()],
        "aab_session",
    );
    let upload_content =
        &openapi["paths"]["/v1/invoke/confluence/attachment.add"]["post"]["requestBody"]["content"];
    assert!(upload_content.get("multipart/form-data").is_some());
    assert!(
        upload_content["multipart/form-data"]["encoding"]
            .get("request")
            .is_some()
    );
    assert_eq!(
        openapi["components"]["securitySchemes"]["brokerIdentity"]["name"],
        "X-Broker-Token"
    );
}

#[test]
fn generated_upload_send_schema_uses_catalog_plan_constraints() {
    let mut catalog = empty_catalog(json!({}));
    catalog.services.push(ApiServiceSpec {
        availability: None,
        scoped_mcp_ready: true,
        service: "files".to_string(),
        display_name: "Files".to_string(),
        surface: "invoke".to_string(),
        scope_types: vec!["file".to_string()],
        resource_scopes: BTreeMap::new(),
        actions: vec![ApiActionSpec {
            listing_of: None,
            companion_read_actions: Vec::new(),
            scoped_mcp_name: None,
            documentation: None,
            read_only: false,
            action: "asset.add".to_string(),
            description: "Upload".to_string(),
            required_scope_types: vec!["file".to_string()],
            credential_modes: vec!["service".to_string()],
            lookup_required: false,
            upstream_resource_ownership: None,
            input_schema: json!({ "type": "object" }),
            sensitive_input_pointers: Vec::new(),
            sensitive_output_pointers: Vec::new(),
            io: ActionIo::MultipartUpload {
                plan: MultipartUploadSpec::new(
                    "asset".to_string(),
                    "/uploads".to_string(),
                    "asset".to_string(),
                )
                .with_file_count(2, Some(4))
                .with_metadata_fields(vec!["field".to_string()]),
            },
            response_kind: ResponseKind::ResponseEnvelope,
            exit_policy: ExitPolicy::InvokeDecision,
            read_content_formats: Vec::new(),
            response_formats: Vec::new(),
            rendered_body_owners: Vec::new(),
            optional_rendered_body_owner_prefixes: Vec::new(),
        }],
    });

    let schema = send_schema_from_catalog(&catalog);
    let files = &schema["oneOf"][0]["properties"]["files"];
    assert_eq!(files["minItems"], 2);
    assert_eq!(files["maxItems"], 4);
    assert_eq!(files["items"]["properties"]["role"]["const"], "asset");
    assert!(files["items"]["properties"].get("contentType").is_none());
}

#[test]
fn generated_upload_send_schema_removes_nested_generated_metadata_inputs() {
    let mut catalog = empty_catalog(json!({}));
    catalog.services.push(ApiServiceSpec {
        availability: None,
        scoped_mcp_ready: true,
        service: "files".to_string(),
        display_name: "Files".to_string(),
        surface: "invoke".to_string(),
        scope_types: vec!["file".to_string()],
        resource_scopes: BTreeMap::new(),
        actions: vec![ApiActionSpec {
            listing_of: None,
            companion_read_actions: Vec::new(),
            scoped_mcp_name: None,
            documentation: None,
            read_only: false,
            action: "asset.add".to_string(),
            description: "Upload".to_string(),
            required_scope_types: vec!["file".to_string()],
            credential_modes: vec!["service".to_string()],
            lookup_required: false,
            upstream_resource_ownership: None,
            input_schema: json!({
                "type": "object",
                "required": ["payload"],
                "properties": {
                    "payload": {
                        "type": "object",
                        "required": ["pageId", "uploads"],
                        "properties": {
                            "pageId": { "type": "string" },
                            "uploads": {
                                "type": "array",
                                "items": { "type": "object" }
                            }
                        }
                    }
                }
            }),
            sensitive_input_pointers: Vec::new(),
            sensitive_output_pointers: Vec::new(),
            io: ActionIo::MultipartUpload {
                plan: MultipartUploadSpec::new(
                    "asset".to_string(),
                    "/payload/uploads".to_string(),
                    "asset".to_string(),
                )
                .with_locator_inputs(vec!["payload.pageId".to_string()])
                .with_metadata_fields(vec!["field".to_string()])
                .allowing_caller_content_type(),
            },
            response_kind: ResponseKind::ResponseEnvelope,
            exit_policy: ExitPolicy::InvokeDecision,
            read_content_formats: Vec::new(),
            response_formats: Vec::new(),
            rendered_body_owners: Vec::new(),
            optional_rendered_body_owner_prefixes: Vec::new(),
        }],
    });

    let schema = send_schema_from_catalog(&catalog);
    let variant = &schema["oneOf"][0];
    assert!(
        variant["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "inputs")
    );
    let inputs = &variant["properties"]["inputs"];
    let payload = &inputs["properties"]["payload"];
    assert_eq!(inputs["required"], json!(["payload"]));
    assert_eq!(payload["required"], json!(["pageId"]));
    assert!(payload["properties"].get("uploads").is_none());
    assert_eq!(payload["properties"]["pageId"]["type"], "string");
}

#[test]
fn raw_json_routes_keep_exact_byte_metadata_and_are_excluded_from_json_send() {
    let mut raw = http_route_specs(&crate::tests::test_resource_types())
        .into_iter()
        .find(|route| route.operation == "admin.imports.document.upload")
        .unwrap();
    assert_eq!(raw.request_body_kind, RequestBodyKind::RawJson);
    // Projection depends on the transport contract, not this import's route or
    // operation identity.
    raw.route = "/v1/source-documents".into();
    raw.operation = "documents.replace".into();
    raw.path_params.clear();
    let ordinary = body_route(
        "POST",
        "/v1/ordinary-json",
        "ordinary.create",
        RouteAccess::AdminWrite,
        ResponseKind::ManagementEnvelope,
        ExitPolicy::ManagementOk,
        vec![],
    );
    let encoded = serde_json::to_value(&raw).unwrap();
    assert_eq!(encoded["requestBodyKind"], "raw_json");
    assert_eq!(
        serde_json::from_value::<HttpRouteSpec>(encoded.clone()).unwrap(),
        raw
    );
    let mut unknown = encoded;
    unknown["requestBodyKind"] = json!("future_binary_kind");
    assert!(serde_json::from_value::<HttpRouteSpec>(unknown).is_err());
    let encoded = serde_json::to_value(&ordinary).unwrap();
    assert!(encoded.get("requestBodyKind").is_none());
    assert_eq!(
        serde_json::from_value::<HttpRouteSpec>(encoded)
            .unwrap()
            .request_body_kind,
        RequestBodyKind::Json
    );

    let mut catalog = empty_catalog(json!({}));
    catalog.routes = vec![raw, ordinary];
    let openapi = openapi_from_catalog(&catalog, RenderAuthMode::Omit, &[], "session");
    let operation = &openapi["paths"]["/v1/source-documents"]["put"];
    assert_eq!(operation["x-agent-access-request-body-kind"], "raw_json");
    assert_eq!(
        operation["requestBody"]["content"]["application/json"]["schema"]["type"],
        "object"
    );
    assert!(
        operation["requestBody"]["description"]
            .as_str()
            .unwrap()
            .contains("without parsing or reserialization")
    );
    assert!(
        openapi["paths"]["/v1/ordinary-json"]["post"]
            .get("x-agent-access-request-body-kind")
            .is_none()
    );
    let send = send_schema_from_catalog(&catalog);
    let variants = send["oneOf"].as_array().unwrap();
    assert_eq!(variants.len(), 1);
    assert_eq!(
        variants[0]["properties"]["route"]["const"],
        "/v1/ordinary-json"
    );
    let validator = jsonschema::validator_for(&send).unwrap();
    assert!(validator.is_valid(&json!({"version":SEND_SCHEMA_VERSION,"kind":"http","method":"POST","route":"/v1/ordinary-json","body":{}})));
    assert!(!validator.is_valid(&json!({"version":SEND_SCHEMA_VERSION,"kind":"http","method":"PUT","route":"/v1/source-documents","body":{}})));
}

#[test]
fn generated_openapi_omits_request_body_for_no_body_routes() {
    let mut catalog = empty_catalog(json!({}));
    catalog.routes = http_route_specs(&crate::tests::test_resource_types())
        .into_iter()
        .filter(|route| {
            (route.method == "GET" && route.route == "/v1/me")
                || (route.method == "POST" && route.route == "/v1/tokens")
        })
        .collect();

    let openapi = openapi_from_catalog(
        &catalog,
        RenderAuthMode::Include,
        &["Authorization".to_string()],
        "aab_session",
    );
    assert!(
        openapi["paths"]["/v1/me"]["get"]
            .get("requestBody")
            .is_none()
    );
    assert!(
        openapi["paths"]["/v1/tokens"]["post"]
            .get("requestBody")
            .is_some()
    );
}

#[test]
fn broker_status_route_has_catalog_openapi_and_send_parity() {
    let route = http_route_specs(&crate::tests::test_resource_types())
        .into_iter()
        .find(|route| route.method == "GET" && route.route == "/v1/broker/status")
        .expect("broker status route is present");
    assert_eq!(route.operation, "broker.status");
    assert_eq!(route.access, RouteAccess::Authenticated);
    assert_eq!(route.response_kind, ResponseKind::RawJson);
    assert_eq!(route.exit_policy, ExitPolicy::HttpStatus);
    assert!(!route.body_allowed);
    assert!(route.request_body_schema.is_none());

    let mut catalog = empty_catalog(json!({}));
    catalog.routes = vec![route];
    let openapi = openapi_from_catalog(
        &catalog,
        RenderAuthMode::Include,
        &["Authorization".to_string()],
        "aab_session",
    );
    assert_eq!(
        openapi["paths"]["/v1/broker/status"]["get"]["operationId"],
        "broker.status"
    );
    assert!(
        openapi["paths"]["/v1/broker/status"]["get"]
            .get("requestBody")
            .is_none()
    );

    let send = send_schema_from_catalog(&catalog);
    let variant = send["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .find(|variant| variant["properties"]["route"]["const"] == "/v1/broker/status")
        .expect("broker status send variant is present");
    assert_eq!(variant["properties"]["method"]["const"], "GET");
    assert!(variant["properties"].get("body").is_none());
}

#[test]
fn local_password_operations_have_catalog_openapi_and_send_parity() {
    let routes = http_route_specs(&crate::tests::test_resource_types());
    let mut catalog = empty_catalog(json!({}));
    catalog.routes = routes;
    let openapi = openapi_from_catalog(&catalog, RenderAuthMode::Omit, &[], "aab_session");
    let send = send_schema_from_catalog(&catalog);
    for (method, path, operation, required) in [
        (
            "PUT",
            "/v1/admin/principals/{principal}/login-methods/local-password",
            "admin.principals.local_password.reset",
            json!(["password"]),
        ),
        (
            "POST",
            "/v1/admin/principals/{principal}/login-methods/local-password/enable",
            "admin.principals.local_password.enable",
            json!(["password", "acknowledgeSeparateSignIn"]),
        ),
    ] {
        let route = catalog
            .routes
            .iter()
            .find(|route| route.method == method && route.route == path)
            .unwrap();
        assert_eq!(route.operation, operation);
        assert_eq!(
            route.access,
            if route.method == "GET" {
                RouteAccess::AdminRead
            } else {
                RouteAccess::AdminWrite
            }
        );
        assert_eq!(route.sensitive_request_pointers, ["/body/password"]);
        let schema = route.request_body_schema.as_ref().unwrap();
        assert_eq!(schema["required"], required);
        assert_eq!(schema["additionalProperties"], false);
        if method == "POST" {
            assert_eq!(
                schema["properties"]["acknowledgeSeparateSignIn"]["const"],
                true
            );
        }
        assert_eq!(
            openapi["paths"][path][method.to_ascii_lowercase()]["operationId"],
            operation
        );
        let variant = send["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|variant| {
                variant["properties"]["method"]["const"] == method
                    && variant["properties"]["route"]["const"] == path
            })
            .unwrap();
        assert_eq!(&variant["properties"]["body"], schema);
    }
}

#[test]
fn microsoft_oidc_management_routes_have_catalog_openapi_and_send_parity() {
    let expected = [
        (
            "GET",
            "/v1/admin/groups/{group}/external-group-bindings",
            "admin.groups.external_group_bindings.list",
            false,
        ),
        (
            "POST",
            "/v1/admin/groups/{group}/external-group-bindings",
            "admin.groups.external_group_bindings.create",
            true,
        ),
        (
            "PATCH",
            "/v1/admin/groups/{group}/external-group-bindings/{binding}",
            "admin.groups.external_group_bindings.patch",
            true,
        ),
        (
            "DELETE",
            "/v1/admin/groups/{group}/external-group-bindings/{binding}",
            "admin.groups.external_group_bindings.delete",
            false,
        ),
        (
            "PUT",
            "/v1/admin/principals/{principal}/login-methods/oidc/microsoft",
            "admin.principals.login_methods.oidc.microsoft.link",
            true,
        ),
        (
            "DELETE",
            "/v1/admin/principals/{principal}/login-methods/oidc/microsoft",
            "admin.principals.login_methods.oidc.microsoft.unlink",
            false,
        ),
    ];
    let routes = http_route_specs(&crate::tests::test_resource_types());
    for (method, path, operation, body) in expected {
        let route = routes
            .iter()
            .find(|candidate| candidate.method == method && candidate.route == path)
            .unwrap();
        assert_eq!(route.operation, operation);
        assert_eq!(
            route.access,
            if route.method == "GET" {
                RouteAccess::AdminRead
            } else {
                RouteAccess::AdminWrite
            }
        );
        assert_eq!(route.request_body_schema.is_some(), body);
        assert_eq!(route.body_allowed, body);
    }

    let binding_create = routes
        .iter()
        .find(|route| {
            route.method == "POST"
                && route.route == "/v1/admin/groups/{group}/external-group-bindings"
        })
        .unwrap();
    assert_eq!(
        binding_create.request_body_schema.as_ref().unwrap()["required"],
        json!(["externalGroupId"])
    );
    let binding_patch = routes
        .iter()
        .find(|route| {
            route.method == "PATCH"
                && route.route == "/v1/admin/groups/{group}/external-group-bindings/{binding}"
        })
        .unwrap();
    assert_eq!(
        binding_patch.request_body_schema.as_ref().unwrap()["properties"]["status"]["enum"],
        json!(["active", "disabled"])
    );

    let mut catalog = empty_catalog(json!({}));
    catalog.routes = routes
        .into_iter()
        .filter(|route| expected.iter().any(|(_, path, _, _)| route.route == *path))
        .collect();
    let openapi = openapi_from_catalog(&catalog, RenderAuthMode::Omit, &[], "aab_session");
    let send = send_schema_from_catalog(&catalog);
    let send_variants = send["oneOf"].as_array().unwrap();
    for (method, path, operation, body) in expected {
        let openapi_operation = &openapi["paths"][path][method.to_ascii_lowercase()];
        assert_eq!(openapi_operation["operationId"], operation);
        assert_eq!(openapi_operation.get("requestBody").is_some(), body);
        let send_variant = send_variants
            .iter()
            .find(|variant| {
                variant["properties"]["method"]["const"] == method
                    && variant["properties"]["route"]["const"] == path
            })
            .unwrap();
        assert_eq!(send_variant["properties"].get("body").is_some(), body);
    }
}

#[test]
fn token_issue_runtime_schemas_describe_expiration_inputs() {
    let routes = http_route_specs(&crate::tests::test_resource_types());
    for route_path in [
        "/v1/tokens",
        "/v1/admin/principals/{principal}/agent-tokens",
        "/v1/admin/principals/{principal}/tokens",
    ] {
        let route = routes
            .iter()
            .find(|candidate| candidate.method == "POST" && candidate.route == route_path)
            .unwrap();
        let body = route.request_body_schema.as_ref().unwrap();
        assert_eq!(body["properties"]["never"]["type"], "boolean");
        assert_eq!(body["properties"]["ttl"]["type"], "string");
        assert!(body["allOf"].is_array());
    }

    let mut catalog = empty_catalog(json!({}));
    catalog.routes = routes
        .into_iter()
        .filter(|route| {
            route.method == "POST"
                && matches!(
                    route.route.as_str(),
                    "/v1/tokens"
                        | "/v1/admin/principals/{principal}/agent-tokens"
                        | "/v1/admin/principals/{principal}/tokens"
                )
        })
        .collect();

    let openapi = openapi_from_catalog(
        &catalog,
        RenderAuthMode::Include,
        &["Authorization".to_string()],
        "aab_session",
    );
    assert_eq!(
        openapi["paths"]["/v1/tokens"]["post"]["requestBody"]["content"]["application/json"]["schema"]
            ["properties"]["never"]["type"],
        "boolean"
    );

    let send_schema = send_schema_from_catalog(&catalog);
    let generic_admin = send_schema["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .find(|variant| {
            variant["properties"]["route"]["const"] == "/v1/admin/principals/{principal}/tokens"
        })
        .unwrap();
    assert_eq!(
        generic_admin["properties"]["body"]["properties"]["never"]["type"],
        "boolean"
    );
    assert!(generic_admin["properties"]["body"]["allOf"].is_array());
}

#[test]
fn token_options_routes_have_catalog_openapi_and_send_parity() {
    let routes = http_route_specs(&crate::tests::test_resource_types());
    let expected = [
        (
            "/v1/tokens/options",
            "tokens.options",
            RouteAccess::UserTokenManagement,
        ),
        (
            "/v1/admin/principals/{principal}/agent-token-options",
            "admin.principals.agent_tokens.options",
            RouteAccess::AdminRead,
        ),
    ];
    for (path, operation, access) in expected {
        let route = routes
            .iter()
            .find(|candidate| candidate.method == "GET" && candidate.route == path)
            .unwrap();
        assert_eq!(route.operation, operation);
        assert_eq!(route.access, access);
        assert!(!route.body_allowed);
    }

    let self_options = routes
        .iter()
        .position(|route| route.route == "/v1/tokens/options")
        .unwrap();
    let self_dynamic = routes
        .iter()
        .position(|route| route.route == "/v1/tokens/{token_id}")
        .unwrap();
    assert!(self_options < self_dynamic);
    let admin_options = routes
        .iter()
        .position(|route| route.route == "/v1/admin/principals/{principal}/agent-token-options")
        .unwrap();
    let admin_dynamic = routes
        .iter()
        .position(|route| route.route == "/v1/admin/principals/{principal}/agent-tokens/{token_id}")
        .unwrap();
    assert!(admin_options < admin_dynamic);

    let mut catalog = empty_catalog(json!({}));
    catalog.routes = routes
        .into_iter()
        .filter(|route| expected.iter().any(|(path, _, _)| route.route == *path))
        .collect();
    let openapi = openapi_from_catalog(&catalog, RenderAuthMode::Include, &[], "aab_session");
    let send = send_schema_from_catalog(&catalog);
    for (path, operation, _) in expected {
        assert_eq!(openapi["paths"][path]["get"]["operationId"], operation);
        assert!(send["oneOf"].as_array().unwrap().iter().any(|variant| {
            variant["properties"]["method"]["const"] == "GET"
                && variant["properties"]["route"]["const"] == path
        }));
    }
}

#[test]
fn token_pause_resume_routes_have_catalog_openapi_and_send_parity() {
    let expected = [
        (
            "/v1/tokens/{token_id}/pause",
            "tokens.pause",
            RouteAccess::UserTokenManagement,
        ),
        (
            "/v1/tokens/{token_id}/resume",
            "tokens.resume",
            RouteAccess::UserTokenManagement,
        ),
        (
            "/v1/admin/principals/{principal}/agent-tokens/{token_id}/pause",
            "admin.principals.agent_tokens.pause",
            RouteAccess::AdminWrite,
        ),
        (
            "/v1/admin/principals/{principal}/agent-tokens/{token_id}/resume",
            "admin.principals.agent_tokens.resume",
            RouteAccess::AdminWrite,
        ),
        (
            "/v1/admin/tokens/{token_id}/pause",
            "admin.tokens.pause",
            RouteAccess::AdminWrite,
        ),
        (
            "/v1/admin/tokens/{token_id}/resume",
            "admin.tokens.resume",
            RouteAccess::AdminWrite,
        ),
    ];
    let routes = http_route_specs(&crate::tests::test_resource_types());
    for (path, operation, access) in expected {
        let route = routes
            .iter()
            .find(|candidate| candidate.method == "POST" && candidate.route == path)
            .unwrap();
        assert_eq!(route.operation, operation);
        assert_eq!(route.access, access);
        assert_eq!(route.response_kind, ResponseKind::ManagementEnvelope);
        assert_eq!(route.exit_policy, ExitPolicy::ManagementOk);
        assert!(!route.body_allowed);
        assert!(!route.null_body_allowed);
        assert!(route.request_body_schema.is_none());
    }

    let mut catalog = empty_catalog(json!({}));
    catalog.routes = routes
        .into_iter()
        .filter(|route| expected.iter().any(|(path, _, _)| route.route == *path))
        .collect();
    assert_eq!(catalog.routes.len(), expected.len());

    let openapi = openapi_from_catalog(&catalog, RenderAuthMode::Include, &[], "aab_session");
    let send = send_schema_from_catalog(&catalog);
    let send_variants = send["oneOf"].as_array().unwrap();
    for (path, operation, _) in expected {
        let openapi_operation = &openapi["paths"][path]["post"];
        assert_eq!(openapi_operation["operationId"], operation);
        assert!(openapi_operation.get("requestBody").is_none());

        let send_variant = send_variants
            .iter()
            .find(|variant| {
                variant["properties"]["method"]["const"] == "POST"
                    && variant["properties"]["route"]["const"] == path
            })
            .unwrap();
        assert!(send_variant["properties"].get("body").is_none());
    }
}

#[test]
fn agent_token_issue_schemas_enforce_caveat_contracts() {
    let routes = http_route_specs(&crate::tests::test_resource_types());
    let self_schema = routes
        .iter()
        .find(|route| route.method == "POST" && route.route == "/v1/tokens")
        .unwrap()
        .request_body_schema
        .as_ref()
        .unwrap();
    let self_validator = jsonschema::validator_for(self_schema).unwrap();
    assert!(self_validator.is_valid(&json!({
        "name": "coding agent",
        "allowedExecutionContexts": ["external"]
    })));
    let service_restrictions = json!({
        "confluence": {
            "actions": ["page.view", "search"],
            "resources": {"resourceIds":["eng", "research"]}
        },
        "gitlab_git": {
            "actions": ["repo.fetch"],
            "resources": {"resourceGroupIds":["engineering"]}
        }
    });
    assert!(self_validator.is_valid(&json!({
        "name": "bounded agent",
        "allowedExecutionContexts": ["external"],
        "allowedServices": ["confluence", "gitlab_git"],
        "serviceRestrictions": service_restrictions
    })));
    assert!(self_validator.is_valid(&json!({
        "name": "action-only ceiling",
        "allowedExecutionContexts": ["external"],
        "allowedServices": ["confluence"],
        "serviceRestrictions": {
            "confluence": {
                "actions": ["page.view"],
                "resources": {}
            }
        }
    })));
    assert!(self_validator.is_valid(&json!({
        "name":"follow current grants", "allowedExecutionContexts":["external"],
        "allowedServices":["confluence"], "serviceRestrictions":{"confluence":{"actions":["page.view"]}}
    })));
    assert!(!self_validator.is_valid(&json!({
        "name": "restriction without service ceiling",
        "allowedExecutionContexts": ["external"],
        "serviceRestrictions": {
            "confluence": { "actions": ["page.view"], "resources": {} }
        }
    })));
    for invalid_restrictions in [
        json!({}),
        json!({"Bad.Service": {"actions":["page.view"],"resources":{}}}),
        json!({"confluence":{"actions":[]}}),
        json!({"confluence":{"actions":["page.view","page.view"]}}),
        json!({"confluence":{"actions":["Page.View"]}}),
        json!({"confluence":{"actions":["page.view"],"unknown":true}}),
        json!({"confluence":{"actions":["page.view"],"resources":null}}),
        json!({"confluence":{"actions":["page.view"],"resources":{"resourceIds":["same","same"]}}}),
        json!({"confluence":{"actions":["page.view"],"resources":{"resourceGroupIds":["same","same"]}}}),
        json!({"confluence":{"actions":["page.view"],"resources":{"resourceIds":[""]}}}),
        json!({"confluence":{"actions":["page.view"],"resources":{"resourceIds":null}}}),
        json!({"confluence":{"actions":["page.view"],"resources":{"space":["ENG"]}}}),
        json!({"confluence":{"actions":["page.view"],"resourceScopes":{"space":["ENG"]}}}),
        json!({"gitlab_git":{"actions":["repo.fetch"],"resources":{"resourceIds":[{"namespace":"engineering"}]}}}),
    ] {
        assert!(!self_validator.is_valid(&json!({
            "name": "invalid restriction",
            "allowedExecutionContexts": ["external"],
            "allowedServices": ["confluence", "gitlab_git"],
            "serviceRestrictions": invalid_restrictions
        })));
    }
    assert!(!self_validator.is_valid(&json!({ "name": "missing" })));
    assert!(self_validator.is_valid(&json!({
        "name": "multiple contexts",
        "allowedExecutionContexts": ["external", "internal"]
    })));
    assert!(!self_validator.is_valid(&json!({
        "name": "empty contexts",
        "allowedExecutionContexts": []
    })));
    assert!(!self_validator.is_valid(&json!({
        "name": "duplicate",
        "allowedExecutionContexts": ["external", "external"]
    })));
    assert!(!self_validator.is_valid(&json!({
        "name": "invalid",
        "allowedExecutionContexts": ["External"]
    })));
    assert!(!self_validator.is_valid(&json!({
        "name": "legacy device metadata",
        "allowedExecutionContexts": ["external"],
        "deviceName": "workstation"
    })));

    let admin_schema = routes
        .iter()
        .find(|route| {
            route.method == "POST" && route.route == "/v1/admin/principals/{principal}/agent-tokens"
        })
        .unwrap()
        .request_body_schema
        .as_ref()
        .unwrap();
    let admin_validator = jsonschema::validator_for(admin_schema).unwrap();
    assert!(admin_validator.is_valid(&json!({
        "name": "multi-context agent",
        "allowedExecutionContexts": ["external", "internal"],
        "allowedServices": ["jira"],
        "serviceRestrictions": {
            "jira": {
                "actions": ["issue.view", "search"],
                "resources": { "resourceIds": ["eng"] }
            }
        }
    })));
    assert!(!admin_validator.is_valid(&json!({
        "name": "empty contexts",
        "allowedExecutionContexts": []
    })));
    let maximum_contexts = (0..64).map(|index| format!("ctx{index}"));
    assert!(admin_validator.is_valid(&json!({
        "name": "maximum contexts",
        "allowedExecutionContexts": maximum_contexts.clone().collect::<Vec<_>>()
    })));
    assert!(!admin_validator.is_valid(&json!({
        "name": "too many contexts",
        "allowedExecutionContexts": maximum_contexts
            .chain(["overflow".to_string()])
            .collect::<Vec<_>>()
    })));
    assert!(!admin_validator.is_valid(&json!({
        "name": "invalid service",
        "allowedExecutionContexts": ["external"],
        "allowedServices": ["Bad.Service"]
    })));
    assert!(!admin_validator.is_valid(&json!({
        "name": "legacy device metadata",
        "allowedExecutionContexts": ["external"],
        "deviceName": "workstation"
    })));

    let mut catalog = empty_catalog(json!({}));
    catalog.routes = routes
        .into_iter()
        .filter(|route| {
            route.method == "POST"
                && matches!(
                    route.route.as_str(),
                    "/v1/tokens"
                        | "/v1/admin/principals/{principal}/agent-tokens"
                        | "/v1/admin/principals/{principal}/tokens"
                )
        })
        .collect();
    let openapi = openapi_from_catalog(&catalog, RenderAuthMode::Include, &[], "aab_session");
    let self_openapi = &openapi["paths"]["/v1/tokens"]["post"]["requestBody"]["content"]["application/json"]
        ["schema"];
    assert_eq!(
        self_openapi["properties"]["allowedExecutionContexts"]["maxItems"],
        64
    );
    assert!(self_openapi["properties"].get("deviceName").is_none());
    assert_eq!(
        self_openapi["properties"]["serviceRestrictions"]["minProperties"],
        1
    );
    assert_eq!(
        self_openapi["properties"]["serviceRestrictions"]["additionalProperties"]["properties"]["actions"]
            ["uniqueItems"],
        true
    );
    assert_eq!(
        self_openapi["properties"]["serviceRestrictions"]["additionalProperties"]["required"],
        json!(["actions"])
    );
    let admin_openapi = &openapi["paths"]["/v1/admin/principals/{principal}/agent-tokens"]["post"]
        ["requestBody"]["content"]["application/json"]["schema"];
    assert_eq!(
        admin_openapi["properties"]["allowedExecutionContexts"]["maxItems"],
        64
    );
    assert_eq!(
        admin_openapi["properties"]["allowedServices"]["items"]["pattern"],
        "^[a-z][a-z0-9_-]{0,62}$"
    );

    let send = send_schema_from_catalog(&catalog);
    let send_variants = send["oneOf"].as_array().unwrap();
    let self_send = send_variants
        .iter()
        .find(|variant| variant["properties"]["route"]["const"] == "/v1/tokens")
        .unwrap();
    assert_eq!(
        self_send["properties"]["body"]["properties"]["allowedExecutionContexts"]["maxItems"],
        64
    );
    assert_eq!(
        self_send["properties"]["body"]["properties"]["allowedServices"]["items"]["pattern"],
        "^[a-z][a-z0-9_-]{0,62}$"
    );
    assert_eq!(
        self_send["properties"]["body"]["properties"]["serviceRestrictions"]["minProperties"],
        1
    );
    assert!(
        self_send["properties"]["body"]["properties"]
            .get("deviceName")
            .is_none()
    );
    let specialized_admin_send = send_variants
        .iter()
        .find(|variant| {
            variant["properties"]["route"]["const"]
                == "/v1/admin/principals/{principal}/agent-tokens"
        })
        .unwrap();
    assert_eq!(
        specialized_admin_send["properties"]["body"]["properties"]["allowedExecutionContexts"]["maxItems"],
        64
    );
    let generic_admin_send = send_variants
        .iter()
        .find(|variant| {
            variant["properties"]["route"]["const"] == "/v1/admin/principals/{principal}/tokens"
        })
        .unwrap();
    assert!(
        generic_admin_send["properties"]["body"]["properties"]
            .get("deviceName")
            .is_none()
    );
    assert!(
        generic_admin_send["properties"]["body"]["allOf"]
            .as_array()
            .unwrap()
            .iter()
            .any(|constraint| {
                constraint["if"]["properties"]["tokenClass"]["const"] == "agent_invoke"
                    && constraint["then"]["properties"]["scopes"]["required"]
                        == json!(["allowedExecutionContexts"])
            })
    );
    let agent_constraint = generic_admin_send["properties"]["body"]["allOf"]
        .as_array()
        .unwrap()
        .iter()
        .find(|constraint| constraint["if"]["properties"]["tokenClass"]["const"] == "agent_invoke")
        .unwrap();
    assert_eq!(
        agent_constraint["then"]["properties"]["scopes"]["properties"]["allowedExecutionContexts"]
            ["maxItems"],
        64
    );
    assert_eq!(
        agent_constraint["then"]["properties"]["scopes"]["properties"]["allowedServices"]["items"]
            ["pattern"],
        "^[a-z][a-z0-9_-]{0,62}$"
    );
    assert_eq!(
        agent_constraint["then"]["properties"]["scopes"]["properties"]["serviceRestrictions"]["minProperties"],
        1
    );
    assert_eq!(
        agent_constraint["else"]["properties"]["scopes"]["not"]["anyOf"],
        json!([
            { "required": ["allowedExecutionContexts"] },
            { "required": ["allowedServices"] },
            { "required": ["serviceRestrictions"] }
        ])
    );
}

#[test]
fn generic_admin_agent_token_schema_is_typed_without_changing_management_scopes() {
    let schema = admin_token_issue_body_schema();
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(validator.is_valid(&json!({
        "name": "agent",
        "tokenClass": "agent_invoke",
        "scopes": {
            "allowedExecutionContexts": ["external", "internal"],
            "allowedServices": ["jira"],
            "serviceRestrictions": {
                "jira": {
                    "actions": ["issue.view"],
                    "resources": { "resourceIds": ["eng"] }
                }
            }
        },
        "ttl": "1h"
    })));
    assert!(!validator.is_valid(&json!({
        "name": "missing allowed services",
        "tokenClass": "agent_invoke",
        "scopes": {
            "allowedExecutionContexts": ["external"],
            "serviceRestrictions": {
                "jira": { "actions": ["issue.view"], "resources": {} }
            }
        },
        "ttl": "1h"
    })));
    assert!(!validator.is_valid(&json!({
        "name": "unbound agent",
        "tokenClass": "agent_invoke",
        "scopes": {}
    })));
    assert!(!validator.is_valid(&json!({
        "name": "missing scopes",
        "tokenClass": "agent_invoke"
    })));
    assert!(!validator.is_valid(&json!({
        "name": "untyped agent",
        "tokenClass": "agent_invoke",
        "scopes": {
            "allowedExecutionContexts": ["external"],
            "arbitrary": true
        }
    })));
    assert!(!validator.is_valid(&json!({
        "name": "invalid service",
        "tokenClass": "agent_invoke",
        "scopes": {
            "allowedExecutionContexts": ["external"],
            "allowedServices": ["Bad.Service"]
        }
    })));
    for token_class in ["user_manage", "admin"] {
        assert!(validator.is_valid(&json!({
            "name": "management token",
            "tokenClass": token_class,
            "scopes": { "existingSemantics": true },
            "ttlSeconds": 60
        })));
        assert!(!validator.is_valid(&json!({
            "name": "management token with context caveat",
            "tokenClass": token_class,
            "scopes": { "allowedExecutionContexts": ["external"] },
            "ttlSeconds": 60
        })));
        assert!(!validator.is_valid(&json!({
            "name": "management token with service caveat",
            "tokenClass": token_class,
            "scopes": { "allowedServices": ["jira"] },
            "ttlSeconds": 60
        })));
        assert!(!validator.is_valid(&json!({
            "name": "management token with action/resource caveat",
            "tokenClass": token_class,
            "scopes": {
                "serviceRestrictions": {
                    "jira": { "actions": ["issue.view"], "resources": {} }
                }
            },
            "ttlSeconds": 60
        })));
    }
    assert!(!validator.is_valid(&json!({
        "name": "conflicting expiry",
        "tokenClass": "agent_invoke",
        "scopes": { "allowedExecutionContexts": ["external"] },
        "ttl": "1h",
        "expiresAt": "2026-08-12T00:00:00Z"
    })));
}

#[test]
fn policy_status_change_routes_accept_expected_version_body() {
    let routes = http_route_specs(&crate::tests::test_resource_types());
    for route in [
        "/v1/admin/policy/grants/{grant_ref}/enable",
        "/v1/admin/policy/grants/{grant_ref}/disable",
        "/v1/admin/policy/grants/{grant_ref}/subjects",
        "/v1/admin/policy/grants/{grant_ref}/subjects/remove",
    ] {
        let spec = routes
            .iter()
            .find(|candidate| candidate.method == "POST" && candidate.route == route)
            .unwrap();
        assert!(spec.body_allowed);
        assert!(spec.request_body_schema.is_some());
    }

    let delete_spec = routes
        .iter()
        .find(|candidate| {
            candidate.method == "DELETE" && candidate.route == "/v1/admin/policy/grants/{grant_ref}"
        })
        .unwrap();
    let expected_version = delete_spec
        .query_params
        .iter()
        .find(|param| param.name == "expectedVersion")
        .unwrap();
    assert!(expected_version.required);
    assert_eq!(
        expected_version.schema,
        json!({ "type": "integer", "minimum": 1 })
    );
}

#[test]
fn policy_management_routes_have_the_reviewed_access_boundary() {
    let routes = http_route_specs(&crate::tests::test_resource_types());
    let policy_management_operations = BTreeSet::from([
        "admin.policy.resources.list",
        "admin.policy.resources.get",
        "admin.policy.resource_groups.list",
        "admin.policy.resource_groups.get",
        "admin.policy.effective_access",
        "admin.policy.status",
        "admin.policy.catalog",
        "admin.policy.grants.list",
        "admin.policy.grants.create",
        "admin.policy.grants.validate",
        "admin.policy.grants.inspect",
        "admin.policy.grants.patch",
        "admin.policy.grants.delete",
        "admin.policy.grants.enable",
        "admin.policy.grants.disable",
        "admin.policy.grants.subjects.add",
        "admin.policy.grants.subjects.remove",
        // Admins see every record; service policy managers their services'.
        "admin.audit.options",
        "admin.audit.events.list",
        "admin.audit.requests.inspect",
    ]);

    for route in routes.iter().filter(|route| {
        route.route.starts_with("/v1/admin/policy/") || route.route.starts_with("/v1/admin/audit/")
    }) {
        let read = route.method == "GET"
            || matches!(
                route.operation.as_str(),
                "admin.policy.grants.validate" | "admin.policy.effective_access"
            );
        let expected = match (
            policy_management_operations.contains(route.operation.as_str()),
            read,
        ) {
            (true, true) => RouteAccess::PolicyRead,
            (true, false) => RouteAccess::PolicyWrite,
            (false, true) => RouteAccess::AdminRead,
            (false, false) => RouteAccess::AdminWrite,
        };
        assert_eq!(route.access, expected, "{} {}", route.method, route.route);
    }

    assert_eq!(
        routes
            .iter()
            .filter(|route| matches!(
                route.access,
                RouteAccess::PolicyRead | RouteAccess::PolicyWrite
            ))
            .map(|route| route.operation.as_str())
            .collect::<BTreeSet<_>>(),
        policy_management_operations
    );
}

#[test]
fn policy_grant_list_filters_are_optional_scalar_parameters() {
    let route = http_route_specs(&crate::tests::test_resource_types())
        .into_iter()
        .find(|route| route.method == "GET" && route.route == "/v1/admin/policy/grants")
        .unwrap();
    assert_eq!(
        route
            .query_params
            .iter()
            .map(|param| param.name.as_str())
            .collect::<Vec<_>>(),
        ["subject", "service", "executionContext", "status"]
    );
    assert!(route.query_params.iter().all(|param| !param.required));
    assert!(
        route
            .query_params
            .iter()
            .all(|param| param.schema["type"] == "string")
    );
    assert_eq!(
        route.query_params[1].schema["pattern"],
        "^[a-z][a-z0-9_-]{0,62}$"
    );
    assert_eq!(
        route.query_params[2].schema["pattern"],
        "^[a-z][a-z0-9_-]{0,63}$"
    );
    assert_eq!(
        route.query_params[3].schema["enum"],
        json!(["active", "disabled", "deleted"])
    );
}

#[test]
fn service_manager_routes_have_catalog_openapi_and_send_parity() {
    const ASSIGNMENT_PATH: &str = "/v1/admin/policy/services/{service}/managers/{principal}";
    let routes = http_route_specs(&crate::tests::test_resource_types());
    let expected = [
        (
            "GET",
            "/v1/admin/policy/service-managers",
            "admin.policy.service_managers.list",
        ),
        (
            "PUT",
            ASSIGNMENT_PATH,
            "admin.policy.service_managers.grant",
        ),
        (
            "DELETE",
            ASSIGNMENT_PATH,
            "admin.policy.service_managers.revoke",
        ),
    ];

    for (method, path, operation) in expected {
        let route = routes
            .iter()
            .find(|route| route.method == method && route.route == path)
            .unwrap();
        assert_eq!(route.operation, operation);
        assert_eq!(
            route.access,
            if route.method == "GET" {
                RouteAccess::AdminRead
            } else {
                RouteAccess::AdminWrite
            }
        );
        assert!(!route.body_allowed);
        assert!(route.request_body_schema.is_none());
    }

    let list = routes
        .iter()
        .find(|route| route.method == "GET" && route.route == "/v1/admin/policy/service-managers")
        .unwrap();
    assert_eq!(list.query_params.len(), 1);
    assert_eq!(list.query_params[0].name, "service");
    assert!(!list.query_params[0].required);
    assert_eq!(list.query_params[0].schema, service_name_schema());

    let put = routes
        .iter()
        .find(|route| route.method == "PUT" && route.route == ASSIGNMENT_PATH)
        .unwrap();
    assert_eq!(
        put.path_params
            .iter()
            .map(|param| param.name.as_str())
            .collect::<Vec<_>>(),
        ["service", "principal"]
    );
    assert_eq!(put.path_params[0].schema, service_name_schema());
    assert_eq!(
        put.path_params[1].schema,
        json!({ "type": "string", "minLength": 1, "maxLength": 256 })
    );

    let mut catalog = empty_catalog(json!({}));
    catalog.routes = routes
        .into_iter()
        .filter(|route| expected.iter().any(|(_, path, _)| route.route == *path))
        .collect();
    let openapi = openapi_from_catalog(&catalog, RenderAuthMode::Include, &[], "aab_session");
    let send = send_schema_from_catalog(&catalog);
    let send_variants = send["oneOf"].as_array().unwrap();
    for (method, path, operation) in expected {
        let openapi_operation = &openapi["paths"][path][method.to_ascii_lowercase()];
        assert_eq!(openapi_operation["operationId"], operation);
        assert!(openapi_operation.get("requestBody").is_none());
        let send_variant = send_variants
            .iter()
            .find(|variant| {
                variant["properties"]["method"]["const"] == method
                    && variant["properties"]["route"]["const"] == path
            })
            .unwrap();
        assert!(send_variant["properties"].get("body").is_none());
    }

    let put_send = send_variants
        .iter()
        .find(|variant| {
            variant["properties"]["method"]["const"] == "PUT"
                && variant["properties"]["route"]["const"] == ASSIGNMENT_PATH
        })
        .unwrap();
    assert_eq!(
        put_send["properties"]["pathParams"]["properties"]["principal"]["type"],
        json!("string")
    );
}

#[test]
fn discovery_routes_project_queries_and_typed_responses() {
    let routes = http_route_specs(&crate::tests::test_resource_types());
    assert!(
        !routes
            .iter()
            .any(|route| route.route == "/v1/services/{service}/resources")
    );
    for (kind, operation, names) in [
        (
            "resource-access",
            "resource_access.describe",
            vec!["action", "resourceType", "prefix", "limit", "cursor"],
        ),
        (
            "actions",
            "actions.list",
            vec!["resource", "resourceType", "prefix"],
        ),
    ] {
        let route = routes
            .iter()
            .find(|route| route.route == format!("/v1/services/{{service}}/{kind}"))
            .unwrap();
        assert_eq!(route.access, RouteAccess::Authenticated);
        assert_eq!(route.operation, operation);
        assert_eq!(
            route
                .query_params
                .iter()
                .map(|param| param.name.as_str())
                .collect::<Vec<_>>(),
            names
        );
        assert!(route.query_params.iter().all(|param| !param.required));
        assert_eq!(route.path_params[0].name, "service");
        let schema = route_response_schema(route, &["fake_project".to_string()]);
        let validator = jsonschema::validator_for(&schema).unwrap();
        let response = if kind == "resource-access" {
            json!({
                "service":"fake", "executionContext":"default",
                "availability":{"state":"available","requirements":[],"message":"Locally available"},
                "coverageSemantics":"single_target",
                "access":[
                    {"action":"echo","scope":"resource","resourceType":"fake_project","enforcement":"request","coverage":[
                        {"selector":{"kind":"all"},"restricted":true},
                        {"selector":{"kind":"exact","value":"TEST"},"restricted":false}
                    ]},
                    {"action":"ping","scope":"unscoped"}
                ],
                "registeredResources":{"source":"broker_configuration", "items":[
                    {"id":"project-test", "type":"fake_project", "value":"TEST"}
                ], "nextCursor":null},
                "liveListings":[{"service":"fake","action":"projects","resourceType":"fake_project"}]
            })
        } else {
            json!({"service":"fake", "resource":"TEST", "actions":["echo"]})
        };
        assert!(validator.is_valid(&response));
        assert!(!validator.is_valid(&json!([])));
        if kind == "resource-access" {
            for pointer in [
                "/access/0/resourceType",
                "/registeredResources/items/0/type",
                "/liveListings/0/resourceType",
            ] {
                let mut invalid = response.clone();
                *invalid.pointer_mut(pointer).unwrap() = json!("jira_project");
                assert!(!validator.is_valid(&invalid), "{pointer}");
            }
            let mut invalid = response.clone();
            invalid["access"][1]["coverage"] = json!([]);
            assert!(!validator.is_valid(&invalid));
            invalid = response.clone();
            invalid["access"][0]["coverage"][0]["excluded"] = json!(["PRIVATE"]);
            assert!(!validator.is_valid(&invalid));
            assert!(
                !validator.is_valid(&json!({"service":"fake","resources":[],"nextCursor":null}))
            );
        }
    }
}

#[test]
fn oauth_management_specs_require_browser_auth_and_mark_authorization_url_sensitive() {
    let mut catalog = empty_catalog(json!({}));
    catalog.routes = oauth_route_specs();
    assert!(
        catalog
            .routes
            .iter()
            .all(|r| r.access == RouteAccess::BrowserManagement)
    );
    assert!(!catalog.routes.iter().any(|r| r.route.contains("callback")));
    let document = openapi_from_catalog(&catalog, RenderAuthMode::Include, &[], "custom_session");
    assert_eq!(
        document["components"]["securitySchemes"]["browserSession"]["name"],
        "custom_session"
    );
    assert_eq!(
        document["paths"]["/v1/oauth/connect"]["post"]["security"],
        json!([{"browserSession": []}])
    );
    assert_eq!(
        document["paths"]["/v1/oauth/connect"]["post"]["x-agent-access-sensitive-output-pointers"],
        json!(["/result/authorizationUrl"])
    );
    let schema = send_schema_from_catalog(&catalog);
    let connect = schema["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["properties"]["route"]["const"] == "/v1/oauth/connect")
        .unwrap();
    assert_eq!(connect["properties"]["body"]["additionalProperties"], false);
    assert_eq!(
        connect["properties"]["body"]["properties"]["intent"]["enum"],
        json!(["connect", "reconnect", "replace_account"])
    );
    assert_eq!(
        connect["properties"]["body"]["properties"]["returnPath"]["enum"],
        json!(["/ui/credentials", "/ui/admin/catalog"])
    );
}

#[test]
fn file_output_is_independent_of_read_only_and_includes_upload_responses() {
    let base = agent_access_provider::ActionDescriptor::new(
        "item.view",
        "Read-shaped name",
        json!({"type":"object"}),
    );
    let unreviewed = api_action_spec("files", &base).unwrap();
    assert!(!unreviewed.read_only);
    assert!(unreviewed.supports_json_file_output());
    let read = api_action_spec("files", &base.clone().read_only()).unwrap();
    assert!(read.supports_json_file_output());
    let mut wire_read = serde_json::to_value(&read).unwrap();
    assert_eq!(wire_read["readOnly"], true);
    wire_read.as_object_mut().unwrap().remove("readOnly");
    assert!(serde_json::from_value::<ApiActionSpec>(wire_read).is_err());
    let download = api_action_spec("files", &base.clone().raw_download()).unwrap();
    assert!(download.supports_file_output());
    assert!(!download.supports_json_file_output());
    let upload = api_action_spec(
        "files",
        &base.multipart_upload(agent_access_provider::attachment_upload_plan(&[], None)),
    )
    .unwrap();
    assert!(upload.supports_json_file_output());

    for (action, eligible) in [
        (unreviewed, true),
        (read, true),
        (download, true),
        (upload, true),
    ] {
        let variant = invoke_send_variant("files", &action);
        let mut schema = variant.clone();
        schema["definitions"] = generic_send_definitions();
        let validator = jsonschema::validator_for(&schema).unwrap();
        let mut request = json!({"version":SEND_SCHEMA_VERSION,"kind":"invoke","service":"files","action":"item.view"});
        if matches!(action.io, ActionIo::RawDownload { .. }) {
            request["responseMode"] = json!("stream");
        }
        if matches!(action.io, ActionIo::MultipartUpload { .. }) {
            request["files"] = json!([{"role":"attachment","path":"input.txt"}]);
        }
        request["output"] = json!({"type":"file","path":"result.json"});
        assert_eq!(
            validator.is_valid(&request),
            eligible,
            "{request}: {variant}"
        );
        request["metadataOutput"] = json!({"type":"stderr"});
        assert_eq!(validator.is_valid(&request), eligible, "{request}");
        request.as_object_mut().unwrap().remove("output");
        assert!(
            !validator.is_valid(&request),
            "metadata requires a destination: {request}"
        );
        assert_eq!(variant["x-agent-access-read-only"], action.read_only);
    }
}

#[test]
fn read_only_projection_does_not_advertise_broker_local_paths() {
    let mut catalog = empty_catalog(json!({}));
    let action = api_action_spec(
        "files",
        &agent_access_provider::ActionDescriptor::new(
            "item.view",
            "Read",
            json!({"type":"object"}),
        )
        .read_only(),
    )
    .unwrap();
    catalog.services.push(ApiServiceSpec {
        availability: None,
        scoped_mcp_ready: true,
        service: "files".into(),
        display_name: "Files".into(),
        surface: "invoke".into(),
        scope_types: Vec::new(),
        resource_scopes: BTreeMap::new(),
        actions: vec![action],
    });
    let openapi = openapi_from_catalog(&catalog, RenderAuthMode::Omit, &[], "aab_session");
    let operation = &openapi["paths"]["/v1/invoke/files/item.view"]["post"];
    assert_eq!(operation["x-agent-access-read-only"], true);
    let properties =
        &operation["requestBody"]["content"]["application/json"]["schema"]["properties"];
    assert!(properties.get("output").is_none());
    assert!(properties.get("outputPath").is_none());
    assert!(properties.get("metadataOutput").is_none());
}

#[test]
fn send_output_requires_explicit_stdout_and_preserves_literal_dash_paths() {
    let read = api_action_spec(
        "files",
        &agent_access_provider::ActionDescriptor::new(
            "item.view",
            "Read",
            json!({"type":"object"}),
        )
        .read_only(),
    )
    .unwrap();
    let mut specialized = invoke_send_variant("files", &read);
    specialized["definitions"] = generic_send_definitions();
    for schema in [generic_send_schema(), specialized] {
        let validator = jsonschema::validator_for(&schema).unwrap();
        for (output, accepted) in [
            (json!({"type":"file","path":"-"}), false),
            (json!({"type":"stdout"}), true),
            (json!({"type":"file","path":"./-"}), true),
        ] {
            let request = json!({
                "version":SEND_SCHEMA_VERSION, "kind":"invoke", "service":"files",
                "action":"item.view", "output":output,
                "metadataOutput":{"type":"file","path":"-"}
            });
            assert_eq!(validator.is_valid(&request), accepted, "{request}");
        }
    }
}

#[test]
fn principal_service_limit_routes_are_admin_only_with_a_bounded_body() {
    let routes = http_route_specs(&crate::tests::test_resource_types());
    let route = |method: &str, operation: &str| {
        routes
            .iter()
            .find(|route| route.method == method && route.operation == operation)
            .unwrap_or_else(|| panic!("{method} {operation}"))
    };
    let list = route("GET", "admin.principals.service_limits.list");
    assert_eq!(
        list.route,
        "/v1/admin/principals/{principal}/service-limits"
    );
    let set = route("PUT", "admin.principals.service_limits.set");
    let clear = route("DELETE", "admin.principals.service_limits.clear");
    for spec in [list, set, clear] {
        assert_eq!(
            spec.access,
            if spec.method == "GET" {
                RouteAccess::AdminRead
            } else {
                RouteAccess::AdminWrite
            }
        );
        assert_eq!(spec.response_kind, ResponseKind::ManagementEnvelope);
    }
    for spec in [set, clear] {
        assert_eq!(
            spec.route,
            "/v1/admin/principals/{principal}/service-limits/{service}"
        );
        let service = spec
            .path_params
            .iter()
            .find(|param| param.name == "service")
            .unwrap();
        assert_eq!(service.schema["pattern"], "^[a-z][a-z0-9_-]{0,62}$");
    }
    assert!(clear.request_body_schema.is_none());
    let validator = jsonschema::validator_for(set.request_body_schema.as_ref().unwrap()).unwrap();
    for valid in [
        json!({"requests": 1, "windowSeconds": 1}),
        json!({"requests": 1_000_000, "windowSeconds": 86_400}),
    ] {
        assert!(validator.is_valid(&valid), "{valid}");
    }
    for invalid in [
        json!({"requests": 0, "windowSeconds": 60}),
        json!({"requests": 1_000_001, "windowSeconds": 60}),
        json!({"requests": 10, "windowSeconds": 0}),
        json!({"requests": 10, "windowSeconds": 86_401}),
        json!({"requests": 1.5, "windowSeconds": 60}),
        json!({"requests": 10}),
        json!({"requests": 10, "windowSeconds": 60, "window": "1m"}),
    ] {
        assert!(!validator.is_valid(&invalid), "{invalid}");
    }
}

#[test]
fn audit_query_routes_have_catalog_openapi_and_send_parity() {
    let routes = http_route_specs(&crate::tests::test_resource_types());
    let expected = [
        (
            "/v1/admin/audit/options",
            "admin.audit.options",
            RouteAccess::PolicyRead,
        ),
        (
            "/v1/audit/options",
            "audit.options",
            RouteAccess::UserTokenManagement,
        ),
        (
            "/v1/admin/audit/events",
            "admin.audit.events.list",
            RouteAccess::PolicyRead,
        ),
        (
            "/v1/admin/audit/requests/{brokerRequestId}",
            "admin.audit.requests.inspect",
            RouteAccess::PolicyRead,
        ),
        (
            "/v1/audit/events",
            "audit.events.list",
            RouteAccess::UserTokenManagement,
        ),
        (
            "/v1/audit/requests/{brokerRequestId}",
            "audit.requests.inspect",
            RouteAccess::UserTokenManagement,
        ),
    ];
    let audit_routes = routes
        .iter()
        .filter(|route| route.required_feature == Some(RouteFeature::AuditQuery))
        .collect::<Vec<_>>();
    assert_eq!(audit_routes.len(), expected.len());
    for (path, operation, access) in expected {
        let route = routes
            .iter()
            .find(|candidate| candidate.method == "GET" && candidate.route == path)
            .unwrap();
        assert_eq!(route.operation, operation);
        assert_eq!(route.access, access);
        assert_eq!(route.required_feature, Some(RouteFeature::AuditQuery));
        assert_eq!(route.response_kind, ResponseKind::ManagementEnvelope);
        assert_eq!(route.exit_policy, ExitPolicy::ManagementOk);
        assert!(!route.body_allowed);
        assert!(route.result_schema.is_some());
    }

    let query_names = |path: &str| {
        routes
            .iter()
            .find(|route| route.route == path)
            .unwrap()
            .query_params
            .iter()
            .map(|param| param.name.clone())
            .collect::<Vec<_>>()
    };
    let admin_params = query_names("/v1/admin/audit/events");
    assert_eq!(
        admin_params,
        crate::AuditFilterParams::NAMES
            .iter()
            .map(|name| name.to_string())
            .chain(["limit".to_string(), "cursor".to_string()])
            .collect::<Vec<_>>()
    );
    let self_params = query_names("/v1/audit/events");
    assert!(!self_params.iter().any(|name| name == "principal"));
    assert_eq!(self_params.len(), admin_params.len() - 1);
    let list = routes
        .iter()
        .find(|route| route.route == "/v1/audit/events")
        .unwrap();
    let limit = list
        .query_params
        .iter()
        .find(|param| param.name == "limit")
        .unwrap();
    assert_eq!(
        limit.schema,
        json!({"type": "integer", "minimum": 1, "maximum": 200, "default": 50})
    );
    assert!(list.query_params.iter().all(|param| !param.required));

    let mut catalog = empty_catalog(json!({}));
    catalog.routes = audit_routes.into_iter().cloned().collect();
    let catalog_json = serde_json::to_value(&catalog).unwrap();
    assert!(
        catalog_json["routes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|route| {
                route["requiredFeature"] == "audit_query" && route["resultSchema"].is_object()
            })
    );
    let openapi = openapi_from_catalog(&catalog, RenderAuthMode::Include, &[], "aab_session");
    let send = send_schema_from_catalog(&catalog);
    for (path, operation, _) in expected {
        let get = &openapi["paths"][path]["get"];
        assert_eq!(get["operationId"], operation);
        let schema = &get["responses"]["200"]["content"]["application/json"]["schema"];
        assert_eq!(
            schema["required"],
            json!(["requestId", "brokerRequestId", "decision"])
        );
        let result = &schema["properties"]["result"];
        if path.ends_with("/options") {
            assert_eq!(result["required"], json!(["services"]));
            assert!(query_names(path).is_empty());
        } else if path.ends_with("/events") {
            assert_eq!(result["required"], json!(["items", "nextCursor"]));
            assert_eq!(
                result["properties"]["nextCursor"]["type"],
                json!(["string", "null"])
            );
        } else {
            assert_eq!(result["required"], json!(["brokerRequestId", "items"]));
            let path_param = get["parameters"]
                .as_array()
                .unwrap()
                .iter()
                .find(|param| param["in"] == "path")
                .unwrap();
            assert_eq!(path_param["name"], "brokerRequestId");
            assert_eq!(path_param["schema"]["format"], "uuid");
        }
        let variant = send["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|variant| {
                variant["properties"]["method"]["const"] == "GET"
                    && variant["properties"]["route"]["const"] == path
            })
            .unwrap();
        assert!(variant["properties"].get("body").is_none());
        if path.ends_with("/options") {
            assert_eq!(
                variant["required"],
                json!(["version", "kind", "method", "route"])
            );
            let query = &variant["properties"]["query"];
            assert_eq!(query["additionalProperties"], false);
            assert_eq!(query["properties"], json!({}));
        } else if path.ends_with("/events") {
            let query = &variant["properties"]["query"];
            assert_eq!(query["additionalProperties"], false);
            assert_eq!(query["properties"]["limit"]["maximum"], 200);
            assert_eq!(
                query["properties"].get("principal").is_some(),
                path.starts_with("/v1/admin/")
            );
        } else {
            assert_eq!(
                variant["required"],
                json!(["version", "kind", "method", "route", "pathParams"])
            );
        }
    }
    let validator = jsonschema::validator_for(&send).unwrap();
    for path in ["/v1/audit/options", "/v1/admin/audit/options"] {
        assert!(validator.is_valid(&json!({
            "version": SEND_SCHEMA_VERSION, "kind": "http", "method": "GET", "route": path
        })));
        assert!(!validator.is_valid(&json!({
            "version": SEND_SCHEMA_VERSION, "kind": "http", "method": "GET", "route": path,
            "query": {"principal": "bob"}
        })));
    }
    assert!(validator.is_valid(&json!({
        "version": SEND_SCHEMA_VERSION, "kind": "http", "method": "GET",
        "route": "/v1/audit/events", "query": {"action": "tokens.*", "limit": 20}
    })));
    assert!(!validator.is_valid(&json!({
        "version": SEND_SCHEMA_VERSION, "kind": "http", "method": "GET",
        "route": "/v1/audit/events", "query": {"principal": "bob"}
    })));
}

#[test]
fn catalog_v2_names_are_required_nullable_and_never_repair_imported_sources() {
    let mut action = ActionDescriptor::new("accepted.action", "Read", json!({"type":"object"}));
    let builtin = api_action_spec("imported", &action).unwrap();
    assert_eq!(builtin.scoped_mcp_name.as_deref(), Some("accepted.action"));
    action.scoped_mcp_name_source = agent_access_provider::ScopedMcpNameSource::Imported {
        name: Some("Raw.Tool-Name".into()),
    };
    assert_eq!(
        api_action_spec("imported", &action)
            .unwrap()
            .scoped_mcp_name
            .as_deref(),
        Some("Raw.Tool-Name")
    );
    for name in [
        None,
        Some("invalid/source name".into()),
        Some("x".repeat(129)),
    ] {
        action.scoped_mcp_name_source =
            agent_access_provider::ScopedMcpNameSource::Imported { name };
        let projected = api_action_spec("imported", &action).unwrap();
        assert_eq!(projected.scoped_mcp_name, None);
        let mut wire = serde_json::to_value(&projected).unwrap();
        assert!(wire.get("scopedMcpName").unwrap().is_null());
        assert!(serde_json::from_value::<ApiActionSpec>(wire.clone()).is_ok());
        wire.as_object_mut().unwrap().remove("scopedMcpName");
        assert!(serde_json::from_value::<ApiActionSpec>(wire).is_err());
    }
    let mut catalog = empty_catalog(json!({}));
    assert_eq!(catalog.version, "agent-access.catalog.v2");
    catalog.services.push(ApiServiceSpec {
        availability: None,
        scoped_mcp_ready: false,
        service: "imported".into(),
        display_name: "Imported".into(),
        surface: "invoke".into(),
        scope_types: vec![],
        resource_scopes: Default::default(),
        actions: vec![builtin],
    });
    let mut wire = serde_json::to_value(&catalog).unwrap();
    wire["services"][0]
        .as_object_mut()
        .unwrap()
        .remove("scopedMcpReady");
    assert!(serde_json::from_value::<ApiCatalog>(wire).is_err());
}

#[test]
fn principal_access_contract_rejects_legacy_empty_null_and_unknown_shapes() {
    let routes = http_route_specs(&crate::tests::test_resource_types());
    assert!(
        !routes.iter().any(
            |route| route.route.contains("/roles/admin") || route.route.contains("holder_kind")
        )
    );
    let access = routes
        .iter()
        .find(|route| route.operation == "admin.principals.access.patch")
        .unwrap();
    assert_eq!(access.method, "PATCH");
    assert_eq!(access.access, RouteAccess::AdminWrite);
    let schema = access.request_body_schema.as_ref().unwrap();
    let validator = jsonschema::validator_for(schema).unwrap();
    for body in [
        json!({"role":"auditor"}),
        json!({"selfServiceEnabled":false}),
        json!({"role":"service_policy_manager","selfServiceEnabled":true}),
    ] {
        assert!(validator.is_valid(&body), "{body}");
    }
    for body in [
        json!({}),
        json!({"role":null}),
        json!({"selfServiceEnabled":null}),
        json!({"roles":["admin"]}),
        json!({"role":"owner"}),
        json!({"role":"auditor","extra":true}),
    ] {
        assert!(!validator.is_valid(&body), "{body}");
    }
    let validate = routes
        .iter()
        .find(|route| route.operation == "admin.policy.grants.validate")
        .unwrap();
    assert_eq!(validate.access, RouteAccess::PolicyRead);
    let reveal = routes
        .iter()
        .find(|route| route.operation == "admin.principals.identity_token.reveal")
        .unwrap();
    assert_eq!(reveal.access, RouteAccess::AdminWrite);
}

#[test]
fn every_supported_io_kind_is_published_with_its_response_shape() {
    let action = ActionDescriptor::new("item.view", "View", json!({"type":"object"}));
    for (descriptor, response_kind, exit_policy) in [
        (
            action.clone(),
            ResponseKind::ResponseEnvelope,
            ExitPolicy::InvokeDecision,
        ),
        (
            action
                .clone()
                .multipart_upload(agent_access_provider::attachment_upload_plan(&[], None)),
            ResponseKind::ResponseEnvelope,
            ExitPolicy::InvokeDecision,
        ),
        (
            action.clone().raw_download(),
            ResponseKind::RawStream,
            ExitPolicy::RawStream,
        ),
    ] {
        assert!(supported_action_io(&descriptor.io));
        let spec = api_action_spec("example", &descriptor).expect("supported I/O is published");
        assert_eq!(spec.response_kind, response_kind);
        assert_eq!(spec.exit_policy, exit_policy);
    }
}
