//! Route specs for usernames and access keys: a person's own tokens,
//! and administration of names, tokens and the configured access key types.
use super::{
    ExitPolicy, HttpRouteSpec, ResponseKind, RouteAccess, RouteFeature, add_query_params,
    body_route, get_management_route, no_body_route, set_request_body_schema,
};
use crate::{ACCESS_KEY_MAX_LIFETIME_OPTIONS, ACCESS_KEY_MAX_TYPES, ACCESS_KEY_NAME_MAX_BYTES};
use serde_json::{Value, json};

const PRINCIPAL_ACCOUNT_USERNAME: &str = "/v1/admin/principals/{principal}/account-username";
const PRINCIPAL_ACCOUNT_USERNAME_CONFIRM: &str =
    "/v1/admin/principals/{principal}/account-username/confirm";
const ACCOUNT_USERNAMES: &str = "/v1/admin/account-usernames";
const OWN_TOKENS: &str = "/v1/access-keys";
const OWN_TOKEN_OPTIONS: &str = "/v1/access-keys/options";
const OWN_TOKEN: &str = "/v1/access-keys/{key_id}";
const ADMIN_TOKENS: &str = "/v1/admin/access-keys";
const ADMIN_TOKEN: &str = "/v1/admin/access-keys/{key_id}";
const PRINCIPAL_TOKENS: &str = "/v1/admin/principals/{principal}/access-keys";
const ACCESS_KEY_TYPES: &str = "/v1/admin/access-key-types";

fn nullable(schema: Value) -> Value {
    json!({"anyOf": [schema, {"type": "null"}]})
}

fn date_time() -> Value {
    json!({"type": "string", "format": "date-time"})
}

/// One allocation of a username.
fn account_username_record_schema() -> Value {
    json!({
        "title": "AccountUsername", "type": "object", "additionalProperties": false,
        "required": ["principalId", "accountUsername", "holderKind", "incarnation", "origin",
            "assignedAt", "assignedBy", "confirmedAt", "confirmedBy", "state"],
        "properties": {
            "principalId": {"type": "string"},
            "accountUsername": {"type": "string", "description": "The ID the holder is known by to the services that resolve its access keys."},
            "holderKind": {"enum": ["user", "service_account"]},
            "incarnation": {"type": "string", "description": "A new value for every allocation. Access keys minted under an earlier one no longer resolve."},
            "origin": {"enum": ["derived", "administrator", "service_account"],
                "description": "How this name was allocated: derived from the profile email, set by an administrator, or a service account's principal ID."},
            "assignedAt": date_time(),
            "assignedBy": {"type": "string"},
            "confirmedAt": nullable(date_time()),
            "confirmedBy": {"type": ["string", "null"]},
            "state": {"enum": ["usable", "awaiting_confirmation", "reserved"],
                "description": "Under the current configuration. Only a usable name mints or resolves access keys: awaiting_confirmation is a name on the operator's list that no administrator has confirmed; reserved is a name the operator reserved."}
        }
    })
}

fn account_username_mode_schema() -> Value {
    json!({"enum": ["from_email", "manual"],
        "description": "from_email: the name is the lower-cased local part of the profile email while the email's domain is listed, and follows the email. manual: an administrator sets it, and it stays until an administrator changes it."})
}

fn account_username_state_schema() -> Value {
    json!({"enum": ["usable", "awaiting_confirmation", "reserved", "conflict", "none"],
        "description": "usable, awaiting_confirmation and reserved describe the name held. conflict: no name is held because another principal holds the one the email derives. none: no name is held, for the reason given."})
}

fn account_username_reason_schema() -> Value {
    json!({"enum": ["no_email", "email_unusable", "domain_not_listed", "name_invalid", "name_reserved",
        "name_taken", "not_set", "not_yet_assigned", "id_unusable", null],
        "description": "Why no name is held; null while one is. not_set: manual mode with no value. not_yet_assigned: the email derives a free name that is allocated at the person's next sign-in or the next startup or reload. id_unusable: a service account whose principal ID is not a valid name."})
}

fn account_username_conflict_schema(description: &str) -> Value {
    nullable(json!({
        "type": "object", "additionalProperties": false,
        "required": ["accountUsername", "heldBy"],
        "properties": {
            "accountUsername": {"type": "string"},
            "heldBy": {"type": "string", "description": "The principal that holds the name: a person, or the service account whose ID it is."}
        },
        "description": description
    }))
}

/// Why a person's saved email gives no name.
fn account_username_from_email_reason_schema() -> Value {
    json!({"enum": ["no_email", "email_unusable", "domain_not_listed", "name_invalid", "name_reserved",
        "name_taken", null],
        "description": "Why the saved email gives no name; null when it gives one. domain_not_listed: the email's domain is not a listed one. name_invalid: the lower-cased local part is not a valid name. name_reserved: the operator reserved it. name_taken: another principal holds it."})
}

/// What an operation did to a person's username.
fn account_username_change_schema() -> Value {
    json!({
        "title": "AccountUsernameChange", "type": "object", "additionalProperties": false,
        "required": ["previousMode", "mode", "before", "after", "renamed", "endedKeys", "reason", "conflict"],
        "properties": {
            "previousMode": account_username_mode_schema(),
            "mode": account_username_mode_schema(),
            "before": nullable(account_username_record_schema()),
            "after": nullable(account_username_record_schema()),
            "renamed": {"type": "boolean", "description": "Whether the name held is another allocation or none: another name, the same name allocated again, or no name. False when the name and its incarnation stayed, whatever else the operation changed."},
            "endedKeys": {"type": "integer", "minimum": 0, "description": "Unexpired, unrevoked access keys of the previous name, which no longer resolve. Zero unless renamed."},
            "reason": account_username_reason_schema(),
            "conflict": account_username_conflict_schema("Who holds the name the email derives, when the person holds none for that reason.")
        }
    })
}

/// The username of one person or service account, as administrators see
/// it. `extra` adds the members of one operation's result.
pub(super) fn principal_account_username_schema(extra: &[(&str, Value)]) -> Value {
    let mut schema = json!({
        "title": "PrincipalAccountUsername", "type": "object", "additionalProperties": false,
        "required": ["principalId", "holderKind", "displayName", "email", "mode", "state", "reason", "name", "conflict",
            "fromEmail", "liveKeys"],
        "properties": {
            "principalId": {"type": "string"},
            "holderKind": {"enum": ["user", "service_account"]},
            "displayName": {"type": ["string", "null"]},
            "email": {"type": ["string", "null"], "description": "The profile email a from_email name follows. It never finds or merges accounts."},
            "mode": nullable(account_username_mode_schema()),
            "state": account_username_state_schema(),
            "reason": account_username_reason_schema(),
            "name": nullable(account_username_record_schema()),
            "conflict": account_username_conflict_schema("Set in the conflict state: the name the email derives and who holds it."),
            "fromEmail": nullable(json!({
                "type": "object", "additionalProperties": false,
                "required": ["accountUsername", "reason", "conflict"],
                "properties": {
                    "accountUsername": {"type": ["string", "null"], "description": "The name the saved email gives the person, or null."},
                    "reason": account_username_from_email_reason_schema(),
                    "conflict": account_username_conflict_schema("For name_taken: the name the email derives and who holds it.")
                },
                "description": "What from_email gives the person for the email saved on the account now, whatever their mode: for a manual person, what switching to from_email would give. Null for a service account. No other email is evaluated."
            })),
            "liveKeys": {"type": "integer", "minimum": 0,
                "description": "The account's unexpired, unrevoked access keys minted under the name held: the keys that stop resolving when the name changes or is released."}
        }
    });
    for (name, member) in extra {
        schema["required"]
            .as_array_mut()
            .expect("required list")
            .push(json!(name));
        schema["properties"][name] = member.clone();
    }
    schema
}

fn resolved_access_key_type_schema() -> Value {
    json!({
        "type": "object", "additionalProperties": false,
        "required": ["name", "validUntil"],
        "properties": {
            "name": {"type": "string"},
            "validUntil": nullable(date_time())
        }
    })
}

fn access_key_record_properties() -> (Vec<&'static str>, Value) {
    (
        vec![
            "keyId",
            "principalId",
            "name",
            "origin",
            "accessKeyTypes",
            "usernameIncarnation",
            "createdAt",
            "createdBy",
            "expiresAt",
            "revokedAt",
            "revokedBy",
            "lastUsedAt",
        ],
        json!({
            "keyId": {"type": "string"},
            "principalId": {"type": "string"},
            "name": {"type": "string"},
            "origin": {"enum": ["portal", "administrator", "application"],
                "description": "portal: a person created it for themselves. administrator: an administrator issued it for the owner, a person or a service account; createdBy is that administrator."},
            "accessKeyTypes": {"type": "array", "items": {"type": "string"}, "description": "The access key type IDs the key names, in request order."},
            "usernameIncarnation": {"type": "string"},
            "createdAt": date_time(),
            "createdBy": {"type": "string"},
            "expiresAt": nullable(date_time()),
            "revokedAt": nullable(date_time()),
            "revokedBy": {"type": ["string", "null"]},
            "lastUsedAt": nullable(date_time())
        }),
    )
}

/// A stored access key, without its secret.
fn access_key_record_schema() -> Value {
    let (required, properties) = access_key_record_properties();
    json!({"title": "AccessKey", "type": "object", "additionalProperties": false,
        "required": required, "properties": properties})
}

/// A listed access key: the record with what it would resolve as now.
fn access_key_view_schema() -> Value {
    let (mut required, mut properties) = access_key_record_properties();
    required.extend([
        "status",
        "usableAccessKeyTypes",
        "accessKeyTypeStates",
        "access",
    ]);
    properties["status"] = json!({
        "enum": ["active", "revoked", "expired", "principal_disabled", "identity_access_paused",
            "identity_access_missing", "origin_unsupported", "no_account_username",
            "account_username_awaiting_confirmation", "account_username_reserved", "username_incarnation_changed",
            "group_limit_exceeded", "no_access_key_type"],
        "description": "active, or why the stored key does not resolve now."
    });
    properties["usableAccessKeyTypes"] = json!({
        "type": "array", "items": resolved_access_key_type_schema(),
        "description": "What an active key may use now and when each stops, if bounded; empty otherwise."
    });
    properties["accessKeyTypeStates"] = json!({
        "type": "array",
        "items": {
            "type": "object", "additionalProperties": false,
            "required": ["id", "displayName", "held"],
            "properties": {
                "id": {"type": "string"},
                "displayName": {"type": ["string", "null"],
                    "description": "The type's configured display name; null when the configuration no longer defines the type."},
                "held": {"type": "boolean",
                    "description": "Whether the key still holds the type, by the decision a resolution makes for each type: it is configured, the owner's access key type setting allows it, and its current maximum lifetime has not ended it before the key's own expiry, if any. The key's own state is in status."}
            }
        },
        "description": "Every type the key carries, in the key's order."
    });
    properties["access"] = json!({
        "enum": ["full", "partial", "none"],
        "description": "full: the key is active with every type it carries. partial: it is active with only some of them. none: it is not active."
    });
    json!({"title": "AccessKeyView", "type": "object", "additionalProperties": false,
        "required": required, "properties": properties})
}

fn issue_body_schema() -> Value {
    json!({
        "type": "object", "additionalProperties": false,
        "required": ["name", "accessKeyTypes", "lifetime"],
        "properties": {
            "name": {"type": "string", "minLength": 1, "maxLength": ACCESS_KEY_NAME_MAX_BYTES},
            "accessKeyTypes": {"type": "array", "minItems": 1, "maxItems": ACCESS_KEY_MAX_TYPES,
                "uniqueItems": true, "items": {"type": "string", "pattern": "^[a-z][a-z0-9_-]{0,63}$"},
                "description": "The access key type IDs the key carries. One access key type that the owner may not hold or, for a person, that is not self-service refuses the request; nothing is trimmed. A person's own request is refused the same way for a type they may not hold and for one that is not configured."},
            "lifetime": {"type": "string",
                "description": "A positive duration in s, m, h or d of at most 3650d, or never, matching by effective duration an option offered by every selected access key type. Required; the server applies no default."}
        }
    })
}

fn issued_schema() -> Value {
    json!({
        "type": "object", "additionalProperties": false, "required": ["key", "record"],
        "properties": {
            "key": {"type": "string", "description": "The access key. Returned once; only its keyed hash is stored."},
            "record": access_key_record_schema()
        }
    })
}

fn revoked_schema() -> Value {
    json!({
        "type": "object", "additionalProperties": false,
        "required": ["revoked", "newlyRevoked", "record"],
        "properties": {
            "revoked": {"const": true},
            "newlyRevoked": {"type": "boolean", "description": "false when the key was revoked already; revocation is final."},
            "record": access_key_record_schema()
        }
    })
}

fn token_list_schema() -> Value {
    json!({"type": "object", "additionalProperties": false, "required": ["keys"],
        "properties": {"keys": {"type": "array", "items": access_key_view_schema()}}})
}

fn access_key_type_schema() -> Value {
    json!({
        "title": "AccessKeyType", "type": "object", "additionalProperties": false,
        "required": ["id", "displayName", "description", "lifetimeOptions", "defaultLifetime", "selfService"],
        "properties": {
            "id": {"type": "string"},
            "displayName": {"type": "string"},
            "description": {"type": ["string", "null"],
                "description": "Plain text for people, such as where to point their tool; null when the configuration gives none."},
            "lifetimeOptions": {"type": "array", "minItems": 1, "maxItems": ACCESS_KEY_MAX_LIFETIME_OPTIONS, "items": {"type": "string"},
                "description": "Configured duration strings or never, in operator-defined order."},
            "defaultLifetime": {"type": "string", "description": "The configured default, matching an offered option by effective duration."},
            "selfService": {"type": "boolean",
                "description": "Whether a person who may hold this type may create keys of it for themselves."}
        }
    })
}

fn options_schema() -> Value {
    json!({
        "type": "object", "additionalProperties": false,
        "required": ["accountUsername", "refusal", "accessKeyTypes", "hasSelfServiceType", "hasKeys", "problem"],
        "properties": {
            "accountUsername": nullable(json!({
                "type": "object", "additionalProperties": false,
                "required": ["name", "state", "mode", "reason", "fromEmail"],
                "properties": {"name": {"type": ["string", "null"]},
                    "state": account_username_state_schema(),
                    "mode": nullable(account_username_mode_schema()),
                    "reason": account_username_reason_schema(),
                    "fromEmail": nullable(json!({
                        "type": "object", "additionalProperties": false,
                        "required": ["accountUsername", "reason"],
                        "properties": {
                            "accountUsername": {"type": ["string", "null"]},
                            "reason": account_username_from_email_reason_schema()
                        },
                        "description": "What from_email gives the person for the email saved on their account now, or why it gives none."
                    }))},
                "description": "The person's own name and where it stands, with the reason when there is none. Who holds a name the person's email would derive is not shown."
            })),
            "refusal": {"enum": ["principal_disabled", "identity_access_paused", "identity_access_missing", "owner_kind",
                "no_account_username", "account_username_awaiting_confirmation", "account_username_reserved",
                "group_limit_exceeded", null],
                "description": "Why the person can create no key of any type now, as a request of theirs would be refused: the account is in a state in which no key of it resolves, so none is issued. Null when they can."},
            "accessKeyTypes": {"type": "array", "items": access_key_type_schema(),
                "description": "The types the person's access key type setting allows. The person may create a key only of those with selfService true; an administrator can issue any of them for the person."},
            "hasSelfServiceType": {"type": "boolean",
                "description": "Whether at least one of those types is one the person may create themselves."},
            "hasKeys": {"type": "boolean",
                "description": "Whether the person owns any access key, whoever issued it and whatever its state."},
            "problem": {"enum": ["no_account_username", "account_username_awaiting_confirmation",
                "account_username_reserved", "group_limit_exceeded", null],
                "description": "Why no access key of the person's can work now, when they can create a key or own one and only an administrator can remove the cause: no usable username, or more than 64 local groups (group_limit_exceeded). The value is the status every key of theirs lists. Null otherwise: for a person with hasSelfServiceType and hasKeys both false, and when refusal is principal_disabled, identity_access_paused or identity_access_missing, which a resolution finds first."}
        }
    })
}

pub(super) fn route_specs() -> Vec<HttpRouteSpec> {
    let write = |method: &str, route: &str, operation: &str, access: RouteAccess| {
        body_route(
            method,
            route,
            operation,
            access,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            Vec::new(),
        )
    };
    let bodiless = |method: &str, route: &str, operation: &str, access: RouteAccess| {
        no_body_route(
            method,
            route,
            operation,
            access,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        )
    };
    let mut routes = vec![
        // A person's own tokens. Not gated by self-service; a browser
        // session is additionally required.
        get_management_route(
            OWN_TOKENS,
            "access_keys.list",
            RouteAccess::AccountManagement,
        ),
        get_management_route(
            OWN_TOKEN_OPTIONS,
            "access_keys.options",
            RouteAccess::AccountManagement,
        ),
        write(
            "POST",
            OWN_TOKENS,
            "access_keys.issue",
            RouteAccess::AccountManagement,
        ),
        bodiless(
            "DELETE",
            OWN_TOKEN,
            "access_keys.revoke",
            RouteAccess::AccountManagement,
        ),
        // Administration.
        get_management_route(
            ADMIN_TOKENS,
            "admin.access_keys.list",
            RouteAccess::AdminRead,
        ),
        bodiless(
            "DELETE",
            ADMIN_TOKEN,
            "admin.access_keys.revoke",
            RouteAccess::AdminWrite,
        ),
        write(
            "POST",
            PRINCIPAL_TOKENS,
            "admin.principals.access_keys.issue",
            RouteAccess::AdminWrite,
        ),
        get_management_route(
            ACCESS_KEY_TYPES,
            "admin.access_key_types.list",
            RouteAccess::AdminRead,
        ),
        get_management_route(
            ACCOUNT_USERNAMES,
            "admin.account_usernames.list",
            RouteAccess::AdminRead,
        ),
        get_management_route(
            PRINCIPAL_ACCOUNT_USERNAME,
            "admin.principals.account_username.inspect",
            RouteAccess::AdminRead,
        ),
        write(
            "PUT",
            PRINCIPAL_ACCOUNT_USERNAME,
            "admin.principals.account_username.set",
            RouteAccess::AdminWrite,
        ),
        write(
            "POST",
            PRINCIPAL_ACCOUNT_USERNAME_CONFIRM,
            "admin.principals.account_username.confirm",
            RouteAccess::AdminWrite,
        ),
    ];
    add_query_params(
        &mut routes,
        "GET",
        OWN_TOKENS,
        &["includeRevoked", "includeExpired"],
    );
    add_query_params(
        &mut routes,
        "GET",
        ADMIN_TOKENS,
        &["principal", "includeRevoked", "includeExpired"],
    );
    set_request_body_schema(&mut routes, "POST", OWN_TOKENS, issue_body_schema());
    set_request_body_schema(&mut routes, "POST", PRINCIPAL_TOKENS, issue_body_schema());
    set_request_body_schema(
        &mut routes,
        "PUT",
        PRINCIPAL_ACCOUNT_USERNAME,
        json!({"type": "object", "additionalProperties": false, "required": ["mode"],
            "description": "How the person's name is decided, and in manual mode the name. from_email takes no accountUsername: for a person in manual mode it derives at once, and for one already in from_email mode it only fills in a missing name. manual without accountUsername keeps the name held now; with a string it holds that name; with null it holds none.",
            "properties": {
                "mode": account_username_mode_schema(),
                "accountUsername": {"type": ["string", "null"], "minLength": 1, "maxLength": 256,
                    "pattern": "^[A-Za-z0-9._@+-]+$",
                    "description": "Manual mode only."}
            },
            "if": {"properties": {"mode": {"const": "from_email"}}},
            "then": {"not": {"required": ["accountUsername"]}}}),
    );
    set_request_body_schema(
        &mut routes,
        "POST",
        PRINCIPAL_ACCOUNT_USERNAME_CONFIRM,
        json!({"type": "object", "additionalProperties": false, "required": ["accountUsername"],
            "properties": {"accountUsername": {"type": "string",
                "description": "The name the account holds now; a confirmation never applies to a name allocated since."}}}),
    );
    for route in &mut routes {
        // A person's own routes: offered while a type is configured, and
        // to a browser session only, which is all they accept.
        if route.access == RouteAccess::AccountManagement {
            route.required_feature = Some(RouteFeature::AccessKeys);
            route.browser_session_only = true;
        }
        route.result_schema = Some(match route.operation.as_str() {
            "access_keys.list" | "admin.access_keys.list" => token_list_schema(),
            "access_keys.options" => options_schema(),
            "access_keys.issue" | "admin.principals.access_keys.issue" => {
                // Where `issued_schema` puts the secret.
                route.sensitive_response_pointers = vec!["/result/key".to_string()];
                issued_schema()
            }
            "access_keys.revoke" | "admin.access_keys.revoke" => revoked_schema(),
            "admin.access_key_types.list" => json!({
                "type": "object", "additionalProperties": false, "required": ["accessKeyTypes"],
                "properties": {"accessKeyTypes": {"type": "array", "items": access_key_type_schema()}}
            }),
            "admin.account_usernames.list" => json!({
                "type": "object", "additionalProperties": false, "required": ["accountUsernames"],
                "properties": {"accountUsernames": {"type": "array", "items": principal_account_username_schema(&[])}}
            }),
            "admin.principals.account_username.set" => principal_account_username_schema(&[(
                "accountUsernameChange",
                account_username_change_schema(),
            )]),
            _ => principal_account_username_schema(&[]),
        });
    }
    routes
}
