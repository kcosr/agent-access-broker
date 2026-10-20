//! Canonical administrative API contract for database-managed imports.
use super::*;

pub(super) fn route_specs() -> Vec<HttpRouteSpec> {
    const BASE: &str = "/v1/admin/imports";
    const DETAIL: &str = "/v1/admin/imports/{service}";
    let mut routes = Vec::new();
    let mut list = get_management_route(BASE, "admin.imports.list", RouteAccess::AdminRead);
    list.result_schema = Some(json!({"type":"object","additionalProperties":false,
    "required":["catalogRevision","operatorEnabled","services","availableKinds","commandImports","importAuthentication"],"properties":{
        "operatorEnabled":{"type":"boolean"},"availableKinds":{"type":"array","items":service_name_schema()},"importAuthentication":import_authentication(),
        "commandImports":{"type":"array","description":"Operator-approved command names a command import may name as command:<name>; paths are never returned.",
            "items":{"type":"object","additionalProperties":false,"required":["name"],"properties":{"name":{"type":"string"}}}},
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
    accept["properties"]["selections"] = json!({"type":"array","maxItems":crate::imports::IMPORT_MAX_TOOLS,"items":{
        "type":"object","additionalProperties":false,"required":["source","action","readOnly"],"properties":{
            "source":{"type":"object","minProperties":1},"action":action_name(),
            "label":{"type":["string","null"],"maxLength":256},"readOnly":{"type":"boolean"}
        }
    }});
    accept["properties"]["confirmAffectedGrants"] = json!({"type":"boolean","default":false});
    accept["properties"]["resourceTypeIds"] = json!({"type":"object","maxProperties":crate::imports::IMPORT_MAX_RESOURCE_TYPES,
        "description":"Broker type IDs chosen for the resource types this acceptance adds, by the source's type id. Accepted types keep their IDs.",
        "propertyNames":{"pattern":"^[a-z][a-z0-9_]{0,31}$"},
        "additionalProperties":{"type":"string","pattern":"^[a-z][a-z0-9_]{0,63}$"}});
    accept["required"]
        .as_array_mut()
        .unwrap()
        .extend([json!("manifestHash"), json!("selections")]);
    routes.push(mutation(
        "POST",
        &format!("{DETAIL}/accept"),
        "admin.imports.accept",
        accept,
        accept_result(),
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
    secret["properties"]["username"] = json!({"type":"string","minLength":1,"maxLength":256,
        "description":"Username of a username_token command credential; required for that execution slot and rejected for every other slot."});
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
        {"type":"object","additionalProperties":false,"required":["kind","name"],"properties":{"kind":{"const":"raw_header"},"name":{"type":"string","minLength":1,"maxLength":128}}},
        {"type":"object","additionalProperties":false,"required":["kind"],"properties":{"kind":{"const":"stdin"}}}
    ]})
}
fn service_definition() -> Value {
    json!({"type":"object","additionalProperties":false,
        "required":["service","displayName","adapterKind","endpoint","executionBindings","discovery"],"properties":{
            "service":service_name_schema(),"displayName":{"type":"string","minLength":1,"maxLength":256},
            "adapterKind":service_name_schema(),"endpoint":{"type":"string","format":"uri","maxLength":4096},
            "connectionSettings":{"type":"object","maxProperties":16,"propertyNames":{"type":"string","minLength":1,"maxLength":64,"pattern":"^[A-Za-z0-9._-]+$"},"additionalProperties":{"type":"string","maxLength":4096},"default":{}},
            "executionBindings":{"type":"array","minItems":0,"maxItems":2,"description":"One or two bindings; a command import without a credential has none.","items":{
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
        "acceptedMetadata":accepted_metadata(),
        "createdAt":{"type":"string","format":"date-time"},"createdBy":{"type":"string"},
        "updatedAt":{"type":"string","format":"date-time"},"updatedBy":{"type":"string"}
    }})
}
/// The enumerations of a resource type change recorded in a preview.
fn resource_type_change_properties() -> Value {
    json!({
        "id":{"type":"string"},"brokerType":{"type":"string"},
        "change":{"enum":["added","changed","restored","removed"]},
        "outcome":{"enum":["applied","needs_new_id","retained","dropped"]},
        "details":{"type":"array","items":{"enum":["label","plural_label","example","attribute_added",
            "attribute_made_optional","attribute_text","attribute_order","attribute_removed","pattern",
            "max_length","attribute_added_required","attribute_made_required","attribute_pattern"]}}
    })
}
/// A preview's decision for one resource type, as recorded with the preview.
fn resource_type_change() -> Value {
    json!({"type":"object","additionalProperties":false,"required":["id","brokerType","change","outcome","details"],
        "properties":resource_type_change_properties()})
}
/// A preview's decision for one resource type with the stored resources it
/// currently depends on.
fn resource_type_change_status() -> Value {
    let mut properties = resource_type_change_properties();
    let ids = json!({"type":"array","maxItems":crate::imports::IMPORT_TYPE_RESOURCE_SAMPLE,"items":{"type":"string"}});
    properties["resourceCount"] = json!({"type":"integer","minimum":0});
    properties["blockingResources"] = ids.clone();
    properties["affectedResources"] = ids;
    properties["editable"] = json!({"type":"boolean"});
    properties["blocked"] = json!({"type":"boolean"});
    json!({"type":"array","items":{"type":"object","additionalProperties":false,
        "required":["id","brokerType","change","outcome","details","resourceCount","blockingResources","affectedResources","editable","blocked"],
        "properties":properties}})
}
/// A managed policy revision: its generation and who advanced it, when.
fn policy_revision() -> Value {
    json!({"type":"object","additionalProperties":false,"required":["generation","updatedAt","updatedBy"],"properties":{
        "generation":{"type":"integer","minimum":0},
        "updatedAt":{"type":"string","format":"date-time"},"updatedBy":{"type":"string"}
    }})
}
/// What an acceptance's resource type changes did to stored resources, and
/// the managed policy revisions before and after it when it deleted
/// attribute values or dropped types.
fn resource_type_effects() -> Value {
    json!({"type":"object","additionalProperties":false,"required":["deletedAttributeValues","droppedTypes"],"properties":{
        "deletedAttributeValues":{"type":"array","items":{"type":"object","additionalProperties":false,
            "required":["resourceId","attributes"],"properties":{
                "resourceId":{"type":"string"},"attributes":{"type":"array","items":{"type":"string"}}
            }}},
        "droppedTypes":{"type":"array","items":{"type":"string"}},
        "previousRevision":policy_revision(),
        "revision":policy_revision()
    }})
}
/// The service-level metadata a command import accepted with its actions.
fn accepted_metadata() -> Value {
    let attribute = json!({"type":"object","additionalProperties":false,"required":["name","label","description","required","pattern"],"properties":{
        "name":{"type":"string"},"label":{"type":"string"},"description":{"type":"string"},"required":{"type":"boolean"},
        "pattern":{"type":["string","null"]}
    }});
    json!({"type":"object","additionalProperties":false,"required":["format","version","credential","verify","resourceTypes"],"properties":{
        "format":{"type":"string"},"version":{"type":"string"},
        "credential":{"oneOf":[{"type":"null"},{"type":"object","additionalProperties":false,"required":["kind","modes"],"properties":{
            "kind":{"enum":["token","username_token"]},"modes":{"type":"array","items":{"enum":["service","per_user"]}}
        }}]},
        "verify":{"type":"boolean"},
        "resourceTypes":{"type":"array","items":{"type":"object","additionalProperties":false,
            "required":["id","brokerType","removed","label","pluralLabel","pattern","maxLength","example","attributes"],"properties":{
                "id":{"type":"string"},"brokerType":{"type":"string"},"removed":{"type":"boolean"},"label":{"type":"string"},"pluralLabel":{"type":"string"},
                "pattern":{"type":"string"},"maxLength":{"type":"integer","minimum":1},"example":{"type":"string"},
                "attributes":{"type":"array","items":attribute}
            }}}
    }})
}
/// The import-authentication projection: one group per selected import kind
/// with an OAuth companion, listing the operator registrations it approves.
fn import_authentication() -> Value {
    let registration = json!({"type":"object","additionalProperties":false,"required":["id","issuer","resource","permissionProfiles"],"properties":{
        "id":{"type":"string"},"issuer":{"type":"string"},"resource":{"type":"string"},
        "permissionProfiles":{"type":"array","items":{"type":"object","additionalProperties":false,"required":["id","scopeMode","scopes"],"properties":{
            "id":{"type":"string"},"scopeMode":{"enum":["explicit","server_default"]},"scopes":{"type":"array","items":{"type":"string"}}
        }}}
    }});
    json!({"type":"array","items":{"type":"object","additionalProperties":false,"required":["importKind","dialectId","registrations"],"properties":{
        "importKind":service_name_schema(),"dialectId":{"type":"string"},
        "registrations":{"type":"array","items":registration}
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
    json!({"type":"array","maxItems":crate::imports::IMPORT_MAX_TOOLS,"items":{"type":"object","additionalProperties":false,"required":["toolIndex","proposedAction","codes"],"properties":{
        "toolIndex":{"type":"integer","minimum":0},"proposedAction":{"type":"string"},
        "codes":{"type":"array","minItems":1,"uniqueItems":true,"items":scoped_mcp_issue_code()}
    }}})
}
fn command_version() -> Value {
    json!({"type":"string","description":"The version a command import's accepted manifest reported; display only."})
}
fn service_result() -> Value {
    json!({"type":"object","additionalProperties":false,"required":["catalogRevision","operatorAllowed","available","unavailableReason","service","importAuthentication","scopedMcp"],"properties":{
        "operatorAllowed":{"type":"boolean"},"available":{"type":"boolean"},"unavailableReason":{"type":["string","null"]},"importAuthentication":import_authentication(),
        "catalogRevision":revision(),"service":service_record(),"scopedMcp":scoped_mcp_readiness(),"commandVersion":command_version(),
        "resourceTypeEffects":resource_type_effects()
    }})
}
/// How an acceptance reclassified its selected actions, against their
/// current accepted definitions: each one whose `readOnly` changed, and each
/// one it added, with `from` null. Unchanged and unselected actions are
/// omitted. A confirmation refusal reports the same list in its target.
fn classification_changes() -> Value {
    json!({"type":"array","maxItems":crate::imports::IMPORT_MAX_TOOLS,"items":{"type":"object","additionalProperties":false,
    "required":["action","from","to"],"properties":{
        "action":action_name(),"from":{"enum":[null,"read","write"]},"to":{"enum":["read","write"]}
    }}})
}
fn accept_result() -> Value {
    let mut result = service_result();
    result["properties"]["classificationChanges"] = classification_changes();
    result["required"]
        .as_array_mut()
        .unwrap()
        .push(json!("classificationChanges"));
    result
}
fn discovery_manifest() -> Value {
    let tool = json!({"type":"object","additionalProperties":false,
    "required":["definition","unsupportedReason","readOnlyHint"],"properties":{
        "definition":action_definition(),"unsupportedReason":{"type":["string","null"]},
        "readOnlyHint":{"type":["boolean","null"]}
    }});
    json!({"type":"object","additionalProperties":false,"required":["protocolVersion","metadata","tools"],"properties":{
        "protocolVersion":{"type":"string"},"metadata":{},
        "tools":{"type":"array","maxItems":crate::imports::IMPORT_MAX_TOOLS,"items":tool},
        "serviceMetadata":accepted_metadata(),
        "resourceTypeChanges":{"type":"array","items":resource_type_change()}
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
    json!({"type":"object","additionalProperties":false,"required":["catalogRevision","operatorAllowed","available","unavailableReason","service","preview","affectedGrants","affectedGrantsByAction","importAuthentication","scopedMcp","scopedMcpWarnings","resourceTypeChanges"],"properties":{
        "resourceTypeChanges":resource_type_change_status(),
        "catalogRevision":revision(),"operatorAllowed":{"type":"boolean"},"available":{"type":"boolean"},"unavailableReason":{"type":["string","null"]},"importAuthentication":import_authentication(),"service":service_record(),
        "affectedGrants":{"type":"array","items":{"type":"string"},"uniqueItems":true},
        "affectedGrantsByAction":{"type":"object","additionalProperties":{"type":"array","items":{"type":"string"},"uniqueItems":true}},
        "preview":{"oneOf":[{"type":"null"},preview_record()]},"scopedMcp":scoped_mcp_readiness(),"scopedMcpWarnings":scoped_mcp_warnings(),
        "commandVersion":command_version()
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
    fn import_authentication_groups_safe_registration_metadata_by_import_kind() {
        let schema = import_authentication();
        let validator = jsonschema::validator_for(&schema).unwrap();
        let mut groups = json!([{"importKind":"mcp_http","dialectId":"mcp_oauth","registrations":[
            {"id":"metrics","issuer":"https://issuer.example.test","resource":"https://tools.example.test/mcp","permissionProfiles":[{"id":"access","scopeMode":"server_default","scopes":[]}]}
        ]}]);
        assert!(validator.is_valid(&groups));
        assert!(validator.is_valid(
            &json!([{"importKind":"mcp_http","dialectId":"mcp_oauth","registrations":[]}])
        ));
        let profile = &mut groups[0]["registrations"][0]["permissionProfiles"][0];
        profile["scopeMode"] = json!("explicit");
        profile["scopes"] = json!(["metrics.read"]);
        assert!(validator.is_valid(&groups));
        groups[0]["registrations"][0]["permissionProfiles"][0]["scopeMode"] = json!("unknown");
        assert!(!validator.is_valid(&groups));
        groups[0]["registrations"][0]["permissionProfiles"][0]
            .as_object_mut()
            .unwrap()
            .remove("scopeMode");
        assert!(!validator.is_valid(&groups));
        // No secrets, secret references or adapter settings at any level.
        for (pointer, field) in [
            ("/0", "clientSecretRef"),
            ("/0/registrations/0", "adapterSettings"),
            ("/0/registrations/0", "clientSecretRef"),
            ("/0/registrations/0", "adapterId"),
        ] {
            let mut extra = json!([{"importKind":"mcp_http","dialectId":"mcp_oauth","registrations":[
                {"id":"metrics","issuer":"https://issuer.example.test","resource":"https://tools.example.test/mcp","permissionProfiles":[]}
            ]}]);
            extra.pointer_mut(pointer).unwrap()[field] = json!("value");
            assert!(!validator.is_valid(&extra), "{pointer} {field}");
        }
        assert!(!validator.is_valid(&json!([{"importKind":"mcp_http","registrations":[]}])));
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
    fn acceptance_effects_publish_both_policy_revisions() {
        let validator = jsonschema::validator_for(&resource_type_effects()).unwrap();
        let revision = |generation| crate::ManagedPolicyRevision {
            generation,
            updated_at: "2026-10-15T00:00:00Z".into(),
            updated_by: "admin".into(),
        };
        let mut effects = crate::ImportedTypeEffects {
            dropped_types: vec!["tickets_queue".into()],
            ..Default::default()
        };
        assert!(validator.is_valid(&serde_json::to_value(&effects).unwrap()));
        effects.previous_revision = Some(revision(4));
        effects.revision = Some(revision(5));
        let encoded = serde_json::to_value(&effects).unwrap();
        assert!(validator.is_valid(&encoded), "{encoded}");
        let mut extra = encoded;
        extra["revision"]["etag"] = json!("x");
        assert!(!validator.is_valid(&extra));
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
    fn acceptance_reports_classification_changes_and_other_mutations_do_not() {
        let routes = route_specs();
        let result = |operation: &str| {
            routes
                .iter()
                .find(|route| route.operation == operation)
                .unwrap()
                .result_schema
                .clone()
                .unwrap()
        };
        let accepted = result("admin.imports.accept");
        assert!(
            accepted["required"]
                .as_array()
                .unwrap()
                .contains(&json!("classificationChanges"))
        );
        for operation in [
            "admin.imports.update",
            "admin.imports.status",
            "admin.imports.preview",
        ] {
            assert!(
                result(operation)["properties"]
                    .get("classificationChanges")
                    .is_none(),
                "{operation}"
            );
        }
        let validator = jsonschema::validator_for(&classification_changes()).unwrap();
        let mut changes = json!([
            {"action":"issue.create","from":null,"to":"write"},
            {"action":"issue.view","from":"write","to":"read"}
        ]);
        assert!(validator.is_valid(&changes));
        changes[1]["from"] = json!("unknown");
        assert!(!validator.is_valid(&changes));
        changes[1]["from"] = json!("read");
        changes[1]["to"] = json!(null);
        assert!(!validator.is_valid(&changes));
        changes[1]["to"] = json!("write");
        changes[1]["readOnly"] = json!(false);
        assert!(!validator.is_valid(&changes));
        changes[1].as_object_mut().unwrap().remove("readOnly");
        changes[1].as_object_mut().unwrap().remove("from");
        assert!(!validator.is_valid(&changes));
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
