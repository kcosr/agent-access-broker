//! Canonical administrative API contract for database-managed imports.
use super::*;

pub(super) fn route_specs() -> Vec<HttpRouteSpec> {
    const BASE: &str = "/v1/admin/imports";
    const DETAIL: &str = "/v1/admin/imports/{service}";
    let mut routes = Vec::new();
    let mut list = get_management_route(BASE, "admin.imports.list", RouteAccess::AdminRead);
    list.result_schema = Some(json!({"type":"object","additionalProperties":false,
    "required":["catalogRevision","operatorEnabled","services","availableKinds","oauthRegistrations"],"properties":{
        "operatorEnabled":{"type":"boolean"},"availableKinds":{"type":"array","items":service_name_schema()},"oauthRegistrations":oauth_registrations(),
        "catalogRevision":revision(),"services":{"type":"array","items":service_record()}
    }}));
    routes.push(list);
    let mut get = get_management_route(DETAIL, "admin.imports.inspect", RouteAccess::AdminRead);
    get.result_schema = Some(service_result());
    routes.push(get);
    routes.push(mutation(
        "POST",
        BASE,
        "admin.imports.create",
        service_definition(),
        service_result(),
        vec![],
    ));
    let mut patch = versioned_request();
    patch["properties"]["definition"] = service_definition();
    patch["properties"]["confirmAffectedGrants"] = json!({"type":"boolean","default":false});
    patch["required"]
        .as_array_mut()
        .unwrap()
        .push(json!("definition"));
    routes.push(mutation(
        "PATCH",
        DETAIL,
        "admin.imports.update",
        patch,
        service_result(),
        vec![],
    ));
    routes.push(mutation(
        "POST",
        &format!("{DETAIL}/discover"),
        "admin.imports.discover",
        versioned_request(),
        preview_result(),
        vec![],
    ));
    let mut preview = get_management_route(
        &format!("{DETAIL}/preview"),
        "admin.imports.preview",
        RouteAccess::AdminRead,
    );
    preview.result_schema = Some(preview_result());
    routes.push(preview);
    let mut accept = versioned_request();
    accept["properties"]["manifestHash"] = json!({"type":"string","minLength":1,"maxLength":128});
    accept["properties"]["selections"] = json!({"type":"array","maxItems":crate::IMPORT_MAX_TOOLS,"items":{
        "type":"object","additionalProperties":false,"required":["source","action","readOnly"],"properties":{
            "source":{"type":"object","minProperties":1},"action":action_name(),
            "label":{"type":["string","null"],"maxLength":256},"readOnly":{"type":"boolean"}
        }
    }});
    accept["properties"]["confirmAffectedGrants"] = json!({"type":"boolean","default":false});
    accept["required"]
        .as_array_mut()
        .unwrap()
        .extend([json!("manifestHash"), json!("selections")]);
    routes.push(mutation(
        "POST",
        &format!("{DETAIL}/accept"),
        "admin.imports.accept",
        accept,
        service_result(),
        vec![],
    ));
    for (path, operation) in [
        (format!("{DETAIL}/status"), "admin.imports.status"),
        (
            format!("{DETAIL}/actions/{{action}}/status"),
            "admin.imports.actions.status",
        ),
    ] {
        let mut schema = versioned_request();
        schema["properties"]["status"] = json!({"enum":["enabled","disabled","retired"]});
        schema["properties"]["confirm"] = json!({"type":"boolean","default":false});
        schema["required"]
            .as_array_mut()
            .unwrap()
            .push(json!("status"));
        routes.push(mutation(
            "POST",
            &path,
            operation,
            schema,
            service_result(),
            vec![],
        ));
    }
    let credential_path = format!("{DETAIL}/credentials/{{purpose}}");
    let mut secret = versioned_request();
    secret["properties"]["token"] = json!({"type":"string","minLength":1,"maxLength":32768,
        "pattern":"^[!-~]+$","writeOnly":true,"description":"Backend token; never returned by management reads."});
    secret["required"]
        .as_array_mut()
        .unwrap()
        .push(json!("token"));
    routes.push(mutation(
        "PUT",
        &credential_path,
        "admin.imports.credentials.put",
        secret,
        service_result(),
        vec!["/body/token".into()],
    ));
    routes.push(mutation(
        "DELETE",
        &credential_path,
        "admin.imports.credentials.delete",
        versioned_request(),
        service_result(),
        vec![],
    ));
    for route in &mut routes {
        for param in &mut route.path_params {
            param.schema = match param.name.as_str() {
                "service" => service_name_schema(),
                "action" => action_name(),
                "purpose" => json!({"enum":["execution","discovery","transport"]}),
                _ => param.schema.clone(),
            };
        }
    }
    routes
}

fn mutation(
    method: &str,
    path: &str,
    operation: &str,
    schema: Value,
    result: Value,
    sensitive: Vec<String>,
) -> HttpRouteSpec {
    let mut route = body_route(
        method,
        path,
        operation,
        RouteAccess::AdminWrite,
        ResponseKind::ManagementEnvelope,
        ExitPolicy::ManagementOk,
        sensitive,
    );
    route.request_body_schema = Some(schema);
    route.result_schema = Some(result);
    route
}
fn revision() -> Value {
    json!({"type":"integer","minimum":0})
}
fn version() -> Value {
    json!({"type":"integer","minimum":1})
}
fn versioned_request() -> Value {
    json!({"type":"object","additionalProperties":false,"required":["expectedVersion","expectedCatalogRevision"],
        "properties":{"expectedVersion":version(),"expectedCatalogRevision":revision()}})
}
fn action_name() -> Value {
    json!({"type":"string","minLength":1,"maxLength":256,"pattern":"^[a-z][a-z0-9_-]*(\\.[a-z][a-z0-9_-]*)*$"})
}
fn delivery() -> Value {
    json!({"oneOf":[
        {"type":"object","additionalProperties":false,"required":["kind"],"properties":{"kind":{"const":"bearer"}}},
        {"type":"object","additionalProperties":false,"required":["kind","name"],"properties":{"kind":{"const":"raw_header"},"name":{"type":"string","minLength":1,"maxLength":128}}}
    ]})
}
fn service_definition() -> Value {
    json!({"type":"object","additionalProperties":false,
        "required":["service","displayName","adapterKind","endpoint","executionBindings","discovery"],"properties":{
            "service":service_name_schema(),"displayName":{"type":"string","minLength":1,"maxLength":256},
            "adapterKind":service_name_schema(),"endpoint":{"type":"string","format":"uri","maxLength":4096},
            "connectionSettings":{"type":"object","maxProperties":16,"propertyNames":{"type":"string","minLength":1,"maxLength":64,"pattern":"^[A-Za-z0-9._-]+$"},"additionalProperties":{"type":"string","maxLength":4096},"default":{}},
            "executionBindings":{"type":"array","minItems":1,"maxItems":2,"items":{
                "type":"object","additionalProperties":false,"required":["ownerMode","mechanism","delivery","status"],"properties":{
                    "ownerMode":{"enum":["service","per_user"]},"mechanism":{"enum":["static_token","oauth"]},"delivery":delivery(),
                    "status":{"enum":["configured","unsupported"]},"adapterId":{"type":["string","null"],"minLength":1,"maxLength":256},
                    "registrationId":{"type":["string","null"],"minLength":1,"maxLength":256},"profile":{"type":["string","null"],"minLength":1,"maxLength":256}
                }
            }},
            "discovery":{"oneOf":[
                {"type":"object","additionalProperties":false,"required":["kind"],"properties":{"kind":{"const":"anonymous"}}},
                {"type":"object","additionalProperties":false,"required":["kind"],"properties":{"kind":{"const":"execution"}}},
                {"type":"object","additionalProperties":false,"required":["kind"],"properties":{"kind":{"const":"slot"}}},
                {"type":"object","additionalProperties":false,"required":["kind","principal"],"properties":{"kind":{"const":"per_user"},"principal":{"type":"string","minLength":1,"maxLength":256}}}
            ]},
            "transportAuth":{"type":"boolean","default":false},
            "invocationLimit":{"oneOf":[{"type":"null"},{"type":"object","additionalProperties":false,"required":["requests","windowSeconds"],"properties":{
                "requests":{"type":"integer","minimum":1,"maximum":1_000_000},"windowSeconds":{"type":"integer","minimum":1,"maximum":86_400}
            }}]}
        }
    })
}
// Stored records can outlive the validation profile that accepted them. Keep
// their typed wire shape readable so operators can inspect and retire them.
fn stored_service_definition() -> Value {
    fn retain_shape(schema: &mut Value) {
        match schema {
            Value::Object(fields) => {
                for constraint in [
                    "pattern",
                    "format",
                    "minLength",
                    "maxLength",
                    "minItems",
                    "maxItems",
                    "minimum",
                    "maximum",
                ] {
                    fields.remove(constraint);
                }
                for child in fields.values_mut() {
                    retain_shape(child);
                }
            }
            Value::Array(children) => {
                for child in children {
                    retain_shape(child);
                }
            }
            _ => {}
        }
    }
    let mut schema = service_definition();
    retain_shape(&mut schema);
    schema["properties"]["service"] = service_name_schema();
    schema["properties"]["connectionSettings"] =
        json!({"type":"object","additionalProperties":{"type":"string"}});
    // These integers are physically represented as u32, including retained
    // values that the current invocation-limit policy no longer accepts.
    for field in ["requests", "windowSeconds"] {
        schema["properties"]["invocationLimit"]["oneOf"][1]["properties"][field] =
            json!({"type":"integer","minimum":0,"maximum":u32::MAX});
    }
    schema
}
fn action_definition() -> Value {
    json!({"type":"object","additionalProperties":false,
    "required":["action","source","description","inputSchema","readOnly"],"properties":{
        "action":{"type":"string"},"source":{"type":"object"},"label":{"type":["string","null"]},"description":{"type":"string"},
        "inputSchema":{},"outputSchema":{},"annotations":{},"readOnly":{"type":"boolean"}
    }})
}
fn service_record() -> Value {
    json!({"type":"object","additionalProperties":false,
    "required":["definition","status","version","actions","slotVersions","createdAt","createdBy","updatedAt","updatedBy"],"properties":{
        "definition":stored_service_definition(),"status":{"enum":["draft","disabled","enabled","retired"]},"version":version(),
        "actions":{"type":"array","items":{"type":"object","additionalProperties":false,
            "required":["definition","status","version","definitionHash"],"properties":{
                "definition":action_definition(),"status":{"enum":["enabled","disabled","quarantined","retired"]},
                "version":version(),"definitionHash":{"type":"string"}
            }}},
        "slotVersions":{"type":"object","additionalProperties":{"type":"string"},"description":"Opaque credential slot versions; no token values."},
        "createdAt":{"type":"string","format":"date-time"},"createdBy":{"type":"string"},
        "updatedAt":{"type":"string","format":"date-time"},"updatedBy":{"type":"string"}
    }})
}
fn oauth_registrations() -> Value {
    json!({"type":"array","items":{"type":"object","additionalProperties":false,"required":["id","adapterId","issuer","resource","permissionProfiles"],"properties":{
        "id":{"type":"string"},"adapterId":{"type":"string"},"issuer":{"type":"string"},"resource":{"type":"string"},
        "permissionProfiles":{"type":"array","items":{"type":"object","additionalProperties":false,"required":["id","scopeMode","scopes"],"properties":{
            "id":{"type":"string"},"scopeMode":{"enum":["explicit","server_default"]},"scopes":{"type":"array","items":{"type":"string"}}
        }}}
    }}})
}
fn scoped_mcp_issue_code() -> Value {
    json!({"enum":["service_unavailable","missing_name","invalid_name","reserved_name","duplicate_name","projection_budget"]})
}
fn scoped_mcp_readiness() -> Value {
    json!({"type":"object","additionalProperties":false,"required":["ready","issues","truncated"],"properties":{
        "ready":{"type":"boolean"},"truncated":{"type":"boolean"},
        "issues":{"type":"array","maxItems":128,"items":{"type":"object","additionalProperties":false,"required":["code","actions"],"properties":{
            "code":scoped_mcp_issue_code(),"actions":{"type":"array","maxItems":16,"items":{"type":"string"}}
        }}}
    }})
}
fn scoped_mcp_warnings() -> Value {
    json!({"type":"array","maxItems":crate::IMPORT_MAX_TOOLS,"items":{"type":"object","additionalProperties":false,"required":["toolIndex","proposedAction","codes"],"properties":{
        "toolIndex":{"type":"integer","minimum":0},"proposedAction":{"type":"string"},
        "codes":{"type":"array","minItems":1,"uniqueItems":true,"items":scoped_mcp_issue_code()}
    }}})
}
fn service_result() -> Value {
    json!({"type":"object","additionalProperties":false,"required":["catalogRevision","operatorAllowed","available","unavailableReason","service","oauthRegistrations","scopedMcp"],"properties":{
        "operatorAllowed":{"type":"boolean"},"available":{"type":"boolean"},"unavailableReason":{"type":["string","null"]},"oauthRegistrations":oauth_registrations(),
        "catalogRevision":revision(),"service":service_record(),"scopedMcp":scoped_mcp_readiness()
    }})
}
fn discovery_manifest() -> Value {
    let tool = json!({"type":"object","additionalProperties":false,
    "required":["definition","unsupportedReason","readOnlyHint"],"properties":{
        "definition":action_definition(),"unsupportedReason":{"type":["string","null"]},
        "readOnlyHint":{"type":["boolean","null"]}
    }});
    json!({"type":"object","additionalProperties":false,"required":["protocolVersion","metadata","tools"],"properties":{
        "protocolVersion":{"type":"string"},"metadata":{},
        "tools":{"type":"array","maxItems":crate::IMPORT_MAX_TOOLS,"items":tool}
    }})
}
fn preview_record() -> Value {
    json!({"type":"object","additionalProperties":false,
    "required":["service","serviceVersion","catalogRevision","configRevision","credentialVersions","manifestHash","manifest","createdAt","expiresAt","createdBy"],"properties":{
        "service":{"type":"string"},"serviceVersion":version(),"catalogRevision":revision(),"configRevision":{"type":"string"},
        "credentialVersions":{"type":"object","additionalProperties":{"type":"string"}},"manifestHash":{"type":"string"},
        "createdAt":{"type":"string","format":"date-time"},"expiresAt":{"type":"string","format":"date-time"},"createdBy":{"type":"string"},
        "manifest":discovery_manifest()
    }})
}
fn preview_result() -> Value {
    json!({"type":"object","additionalProperties":false,"required":["catalogRevision","operatorAllowed","available","unavailableReason","service","preview","affectedGrants","affectedGrantsByAction","oauthRegistrations","scopedMcp","scopedMcpWarnings"],"properties":{
        "catalogRevision":revision(),"operatorAllowed":{"type":"boolean"},"available":{"type":"boolean"},"unavailableReason":{"type":["string","null"]},"oauthRegistrations":oauth_registrations(),"service":service_record(),
        "affectedGrants":{"type":"array","items":{"type":"string"},"uniqueItems":true},
        "affectedGrantsByAction":{"type":"object","additionalProperties":{"type":"array","items":{"type":"string"},"uniqueItems":true}},
        "preview":{"oneOf":[{"type":"null"},preview_record()]},"scopedMcp":scoped_mcp_readiness(),"scopedMcpWarnings":scoped_mcp_warnings()
    }})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_mcp_management_metadata_is_required_bounded_and_not_persisted() {
        let routes = route_specs();
        for route in routes
            .iter()
            .filter(|route| route.operation != "admin.imports.list")
        {
            let schema = route.result_schema.as_ref().unwrap();
            assert!(
                schema["required"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("scopedMcp")),
                "{}",
                route.operation
            );
        }
        let readiness = jsonschema::validator_for(&scoped_mcp_readiness()).unwrap();
        let mut value = json!({"ready":false,"issues":[{"code":"duplicate_name","actions":["one","two"]}],"truncated":false});
        assert!(readiness.is_valid(&value));
        value["issues"][0]["name"] = json!("invalid raw name");
        assert!(!readiness.is_valid(&value));
        value["issues"][0].as_object_mut().unwrap().remove("name");
        value["issues"][0]["actions"] = json!(vec!["action"; 17]);
        assert!(!readiness.is_valid(&value));
        let preview = preview_result();
        assert!(
            preview["required"]
                .as_array()
                .unwrap()
                .contains(&json!("scopedMcpWarnings"))
        );
        assert!(
            preview_record()["properties"]
                .get("scopedMcpWarnings")
                .is_none()
        );
        assert!(
            discovery_manifest()["properties"]
                .get("scopedMcpWarnings")
                .is_none()
        );
    }

    #[test]
    fn imported_oauth_profiles_require_a_supported_permission_mode() {
        let schema = oauth_registrations();
        let validator = jsonschema::validator_for(&schema).unwrap();
        let mut rows = json!([{"id":"metrics","adapterId":"mcp_oauth","issuer":"https://issuer.example.test","resource":"https://tools.example.test/mcp","permissionProfiles":[{"id":"access","scopeMode":"server_default","scopes":[]}]}]);
        assert!(validator.is_valid(&rows));
        rows[0]["permissionProfiles"][0]["scopeMode"] = json!("explicit");
        rows[0]["permissionProfiles"][0]["scopes"] = json!(["metrics.read"]);
        assert!(validator.is_valid(&rows));
        rows[0]["permissionProfiles"][0]["scopeMode"] = json!("unknown");
        assert!(!validator.is_valid(&rows));
        rows[0]["permissionProfiles"][0]
            .as_object_mut()
            .unwrap()
            .remove("scopeMode");
        assert!(!validator.is_valid(&rows));
    }

    #[test]
    fn imports_are_admin_only_and_preserve_credential_secret_markers() {
        let routes = route_specs();
        assert_eq!(routes.len(), 11);
        for route in &routes {
            assert_eq!(
                route.access,
                if route.method == "GET" {
                    RouteAccess::AdminRead
                } else {
                    RouteAccess::AdminWrite
                }
            );
            assert_eq!(route.exit_policy, ExitPolicy::ManagementOk);
            assert!(route.required_feature.is_none());
            if let Some(schema) = &route.request_body_schema {
                jsonschema::validator_for(schema).unwrap();
            }
            jsonschema::validator_for(route.result_schema.as_ref().unwrap()).unwrap();
        }
        let secret = routes
            .iter()
            .find(|route| route.operation == "admin.imports.credentials.put")
            .unwrap();
        assert_eq!(secret.sensitive_request_pointers, ["/body/token"]);
        assert_eq!(
            secret.request_body_schema.as_ref().unwrap()["properties"]["token"]["writeOnly"],
            true
        );
        let mut catalog = empty_catalog(json!({}));
        catalog.routes = routes;
        let openapi = openapi_from_catalog(&catalog, RenderAuthMode::Omit, &[], "session");
        let send = send_schema_from_catalog(&catalog);
        let uri = "/v1/admin/imports/{service}/credentials/{purpose}";
        assert_eq!(
            openapi["paths"][uri]["put"]["requestBody"]["content"]["application/json"]["schema"]["properties"]
                ["token"]["writeOnly"],
            true
        );
        let variant = send["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|variant| {
                variant["properties"]["route"]["const"] == uri
                    && variant["properties"]["method"]["const"] == "PUT"
            })
            .unwrap();
        assert_eq!(
            variant["x-agent-access-sensitive-pointers"],
            json!(["/body/token"])
        );
        assert!(variant["properties"].get("secretSources").is_some());
    }

    #[test]
    fn retained_metadata_remains_readable_without_relaxing_creation_constraints() {
        let definition = json!({"service":"retained","displayName":"","adapterKind":"unsupported future adapter",
            "endpoint":"no-longer-valid","connectionSettings":{"futureSetting":"true"},"executionBindings":[],
            "discovery":{"kind":"per_user","principal":"old owner"},"invocationLimit":{"requests":0,"windowSeconds":0}});
        assert!(
            !jsonschema::validator_for(&service_definition())
                .unwrap()
                .is_valid(&definition)
        );
        let validator = jsonschema::validator_for(&stored_service_definition()).unwrap();
        assert!(validator.is_valid(&definition));
        let mut wrong_identity = definition;
        wrong_identity["service"] = json!("Invalid ID");
        assert!(!validator.is_valid(&wrong_identity));
    }

    #[test]
    fn acceptance_and_status_require_versions_and_explicit_classification() {
        let routes = route_specs();
        let schema = routes
            .iter()
            .find(|route| route.operation == "admin.imports.accept")
            .unwrap()
            .request_body_schema
            .as_ref()
            .unwrap();
        let validator = jsonschema::validator_for(schema).unwrap();
        let mut request = json!({"expectedVersion":1,"expectedCatalogRevision":0,"manifestHash":"hash","selections":[{"source":{"toolName":"search"},"action":"search","readOnly":true}]});
        assert!(validator.is_valid(&request));
        request["selections"][0]
            .as_object_mut()
            .unwrap()
            .remove("readOnly");
        assert!(!validator.is_valid(&request));
        request = json!({"expectedVersion":1,"status":"enabled"});
        let status = routes
            .iter()
            .find(|route| route.operation == "admin.imports.status")
            .unwrap()
            .request_body_schema
            .as_ref()
            .unwrap();
        assert!(
            !jsonschema::validator_for(status)
                .unwrap()
                .is_valid(&request)
        );
    }
}
