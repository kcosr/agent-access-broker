use super::*;

/// The administrator-owned principal setting. Inheritance grants nothing by itself.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalAgentTokenIssuance {
    #[default]
    Inherit,
    Disabled,
    ReadOnly,
    WriteCapable,
}

/// Effective permission, also used for a managed group's contribution.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AgentTokenIssuanceMode {
    #[default]
    Disabled,
    ReadOnly,
    WriteCapable,
}

macro_rules! issuance_enum_text {
    ($name:ident, $message:literal, {$($variant:ident => $text:literal),+ $(,)?}) => {
        impl $name {
            pub fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $text),+ }
            }
        }
        impl std::str::FromStr for $name {
            type Err = ManagedStoreError;
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value { $($text => Ok(Self::$variant),)+ _ => Err(input_invalid($message)) }
            }
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}
issuance_enum_text!(PrincipalAgentTokenIssuance, "principal agent token issuance is invalid", {
    Inherit => "inherit", Disabled => "disabled", ReadOnly => "read_only", WriteCapable => "write_capable"
});
issuance_enum_text!(AgentTokenIssuanceMode, "group agent token issuance is invalid", {
    Disabled => "disabled", ReadOnly => "read_only", WriteCapable => "write_capable"
});

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentTokenIssuanceSource {
    User,
    Groups,
    Default,
}
issuance_enum_text!(AgentTokenIssuanceSource, "agent token issuance source is invalid", {
    User => "user", Groups => "groups", Default => "default"
});

/// Trusted runtime context, never a request-controlled bypass or persisted authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentTokenIssuanceAuthority {
    Managed,
    Toml,
}
issuance_enum_text!(AgentTokenIssuanceAuthority, "identity authority is invalid", {
    Managed => "managed", Toml => "toml"
});

/// Trusted snapshot inputs for policy projection and personal token issuance.
#[derive(Debug, Clone)]
pub struct AgentTokenIssuanceEnvironment {
    authority: AgentTokenIssuanceAuthority,
    contexts: ConfiguredExecutionContexts,
}
impl AgentTokenIssuanceEnvironment {
    pub fn new(
        authority: AgentTokenIssuanceAuthority,
        contexts: ConfiguredExecutionContexts,
    ) -> Self {
        Self {
            authority,
            contexts,
        }
    }
    pub fn authority(&self) -> AgentTokenIssuanceAuthority {
        self.authority
    }
    pub fn contexts(&self) -> &ConfiguredExecutionContexts {
        &self.contexts
    }
}

macro_rules! configured_setting {
    ($name:ident, $mode:ty, $enabled:expr) => {
        #[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
        #[serde(rename_all = "camelCase")]
        #[non_exhaustive]
        pub struct $name {
            pub mode: $mode,
            pub allowed_execution_contexts: Vec<String>,
        }
        impl $name {
            pub fn new(
                mode: $mode,
                mut allowed_execution_contexts: Vec<String>,
            ) -> Result<Self, ManagedStoreError> {
                validate_contexts(&allowed_execution_contexts, ($enabled)(mode))?;
                allowed_execution_contexts.sort();
                Ok(Self {
                    mode,
                    allowed_execution_contexts,
                })
            }
            pub fn validate(
                &self,
                registry: &ConfiguredExecutionContexts,
            ) -> Result<(), ManagedStoreError> {
                validate_contexts(&self.allowed_execution_contexts, ($enabled)(self.mode))?;
                if self
                    .allowed_execution_contexts
                    .iter()
                    .any(|context| !registry.contains(context))
                {
                    return Err(input_invalid(
                        "agent token issuance names an unconfigured execution context",
                    ));
                }
                Ok(())
            }
            pub(super) fn validate_stored(
                &self,
                registry: &ConfiguredExecutionContexts,
            ) -> Result<(), ManagedStoreError> {
                validate_contexts(&self.allowed_execution_contexts, ($enabled)(self.mode))
                    .map_err(|_| invalid_stored_policy())?;
                // A projection may retain an admitted snapshot while a newer
                // runtime publishes a valid policy containing a newly added context.
                if self
                    .allowed_execution_contexts
                    .iter()
                    .any(|context| !registry.contains(context))
                {
                    return Err(ManagedStoreError::VersionConflict);
                }
                Ok(())
            }
            pub(super) fn canonicalized(
                &self,
                registry: &ConfiguredExecutionContexts,
            ) -> Result<Self, ManagedStoreError> {
                self.validate(registry)?;
                Self::new(self.mode, self.allowed_execution_contexts.clone())
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                #[derive(Deserialize)]
                #[serde(rename_all = "camelCase", deny_unknown_fields)]
                struct Wire {
                    mode: $mode,
                    allowed_execution_contexts: Vec<String>,
                }
                let wire = Wire::deserialize(deserializer)?;
                Self::new(wire.mode, wire.allowed_execution_contexts)
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}
configured_setting!(
    PrincipalAgentTokenIssuanceSetting,
    PrincipalAgentTokenIssuance,
    |mode| matches!(
        mode,
        PrincipalAgentTokenIssuance::ReadOnly | PrincipalAgentTokenIssuance::WriteCapable
    )
);
configured_setting!(
    GroupAgentTokenIssuanceSetting,
    AgentTokenIssuanceMode,
    |mode| mode != AgentTokenIssuanceMode::Disabled
);

pub(super) fn invalid_stored_policy() -> ManagedStoreError {
    ManagedStoreError::SchemaInvalid("stored agent token issuance setting is invalid".into())
}

fn validate_contexts(contexts: &[String], enabled: bool) -> Result<(), ManagedStoreError> {
    if contexts.len() > EXECUTION_CONTEXT_MAX_VALUES
        || contexts
            .iter()
            .any(|value| !is_valid_execution_context_value(value))
        || contexts.iter().collect::<BTreeSet<_>>().len() != contexts.len()
        || enabled == contexts.is_empty()
    {
        return Err(input_invalid(
            "agent token issuance requires unique valid contexts and a nonempty list exactly when enabled",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct AgentTokenIssuanceContextPolicy {
    pub execution_context: String,
    pub mode: AgentTokenIssuanceMode,
    pub group_ids: Vec<String>,
}
impl AgentTokenIssuanceContextPolicy {
    pub fn new(
        execution_context: String,
        mode: AgentTokenIssuanceMode,
        group_ids: Vec<String>,
    ) -> Self {
        Self {
            execution_context,
            mode,
            group_ids,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentTokenIssuancePolicy {
    pub source: AgentTokenIssuanceSource,
    pub contexts: Vec<AgentTokenIssuanceContextPolicy>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TokenIssuanceDenial {
    Disabled,
    ContextNotAllowed,
    ReadOnlyRequired,
}
issuance_enum_text!(TokenIssuanceDenial, "agent token issuance denial is invalid", {
    Disabled => "disabled", ContextNotAllowed => "context_not_allowed", ReadOnlyRequired => "read_only_required"
});
impl TokenIssuanceDenial {
    pub fn message(self) -> &'static str {
        match self {
            Self::Disabled => "Agent token issuance is disabled for this account",
            Self::ContextNotAllowed => {
                "Personal agent tokens are not allowed in every requested execution context"
            }
            Self::ReadOnlyRequired => {
                "The selected execution contexts require a read-only agent token"
            }
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupAgentTokenIssuanceChange {
    pub previous: GroupAgentTokenIssuanceSetting,
    pub current: GroupAgentTokenIssuanceSetting,
}

pub(super) fn resolve_policy(
    setting: &PrincipalAgentTokenIssuanceSetting,
    contributions: impl IntoIterator<Item = (String, GroupAgentTokenIssuanceSetting)>,
    registry: &ConfiguredExecutionContexts,
) -> AgentTokenIssuancePolicy {
    let contributions: Vec<_> = contributions.into_iter().collect();
    let override_mode = match setting.mode {
        PrincipalAgentTokenIssuance::Inherit => None,
        PrincipalAgentTokenIssuance::Disabled => Some(AgentTokenIssuanceMode::Disabled),
        PrincipalAgentTokenIssuance::ReadOnly => Some(AgentTokenIssuanceMode::ReadOnly),
        PrincipalAgentTokenIssuance::WriteCapable => Some(AgentTokenIssuanceMode::WriteCapable),
    };
    let mut contexts = Vec::new();
    for context in registry.iter() {
        let mut mode = AgentTokenIssuanceMode::Disabled;
        let mut group_ids = BTreeSet::new();
        if let Some(value) = override_mode {
            if setting
                .allowed_execution_contexts
                .iter()
                .any(|value| value == context)
            {
                mode = value;
            }
        } else {
            for (group_id, contribution) in &contributions {
                if !contribution
                    .allowed_execution_contexts
                    .iter()
                    .any(|value| value == context)
                    || contribution.mode == AgentTokenIssuanceMode::Disabled
                    || contribution.mode < mode
                {
                    continue;
                }
                if contribution.mode > mode {
                    group_ids.clear();
                    mode = contribution.mode;
                }
                group_ids.insert(group_id.clone());
            }
        }
        if mode != AgentTokenIssuanceMode::Disabled {
            contexts.push(AgentTokenIssuanceContextPolicy {
                execution_context: context.to_owned(),
                mode,
                group_ids: group_ids.into_iter().collect(),
            });
        }
    }
    AgentTokenIssuancePolicy {
        source: if override_mode.is_some() {
            AgentTokenIssuanceSource::User
        } else if contexts.is_empty() {
            AgentTokenIssuanceSource::Default
        } else {
            AgentTokenIssuanceSource::Groups
        },
        contexts,
    }
}

pub(super) fn policy_at_conn(
    conn: &Connection,
    principal: &PrincipalRecord,
    environment: &AgentTokenIssuanceEnvironment,
    resolved_at: &str,
) -> Result<AgentTokenIssuancePolicy, ManagedStoreError> {
    principal
        .agent_token_issuance
        .validate_stored(environment.contexts())?;
    let mut contributions = Vec::new();
    if principal.agent_token_issuance.mode == PrincipalAgentTokenIssuance::Inherit
        && environment.authority() == AgentTokenIssuanceAuthority::Managed
    {
        let membership = effective_membership_at_conn(conn, &principal.principal_id, resolved_at)?;
        for group_id in membership.policy_groups {
            let mode: Option<String> = conn
                .query_row(
                    "SELECT agent_token_issuance FROM groups WHERE group_id=?1 AND status='active'",
                    [&group_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_unavailable)?;
            if let Some(mode) = mode {
                let setting = GroupAgentTokenIssuanceSetting::new(
                    mode.parse().map_err(|_| invalid_stored_policy())?,
                    load_contexts(conn, false, &group_id)?,
                )
                .map_err(|_| invalid_stored_policy())?;
                setting.validate_stored(environment.contexts())?;
                contributions.push((group_id, setting));
            }
        }
    }
    Ok(resolve_policy(
        &principal.agent_token_issuance,
        contributions,
        environment.contexts(),
    ))
}

pub(super) fn authorize(
    policy: &AgentTokenIssuancePolicy,
    read_only: bool,
    requested_contexts: &[crate::ExecutionContext],
) -> Result<(), ManagedStoreError> {
    let category = if policy.contexts.is_empty() {
        Some(TokenIssuanceDenial::Disabled)
    } else if requested_contexts.iter().any(|requested| {
        !policy
            .contexts
            .iter()
            .any(|row| row.execution_context == requested.as_str())
    }) {
        Some(TokenIssuanceDenial::ContextNotAllowed)
    } else if !read_only
        && requested_contexts.iter().any(|requested| {
            policy.contexts.iter().any(|row| {
                row.execution_context == requested.as_str()
                    && row.mode == AgentTokenIssuanceMode::ReadOnly
            })
        })
    {
        Some(TokenIssuanceDenial::ReadOnlyRequired)
    } else {
        None
    };
    match category {
        Some(category) => Err(ManagedStoreError::TokenIssuanceDenied { category }),
        None => Ok(()),
    }
}

impl ManagedStore {
    pub fn agent_token_issuance_policy(
        &self,
        principal_id: &str,
        environment: &AgentTokenIssuanceEnvironment,
    ) -> Result<AgentTokenIssuancePolicy, ManagedStoreError> {
        validate_principal_id(principal_id)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        let principal = principal_by_id_without_groups(&tx, principal_id)?;
        let policy = policy_at_conn(&tx, &principal, environment, &normalized_now_string())?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(policy)
    }
    pub fn validate_agent_token_issuance_context_references(
        &self,
        environment: &AgentTokenIssuanceEnvironment,
    ) -> Result<(), ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        for (table, owner_column) in [
            ("principal_agent_token_issuance_contexts", "principal_id"),
            ("group_agent_token_issuance_contexts", "group_id"),
        ] {
            if owner_column == "group_id"
                && environment.authority() == AgentTokenIssuanceAuthority::Toml
            {
                continue;
            }
            let mut statement = conn.prepare(&format!("SELECT {owner_column}, execution_context FROM {table} ORDER BY {owner_column}, execution_context")).map_err(sql_unavailable)?;
            let rows = collect_rows(
                statement
                    .query_map([], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })
                    .map_err(sql_unavailable)?,
            )?;
            let invalid: Vec<_> = rows
                .iter()
                .filter(|(_, context)| !environment.contexts().contains(context))
                .take(10)
                .map(|(owner, context)| {
                    format!("{owner_column}={owner:.128} context={context:.64}")
                })
                .collect();
            if !invalid.is_empty() {
                return Err(ManagedStoreError::SchemaInvalid(format!(
                    "stored agent token issuance references unconfigured contexts: {}",
                    invalid.join(", ")
                )));
            }
        }
        Ok(())
    }
}

pub(super) fn load_contexts(
    conn: &Connection,
    principal: bool,
    owner: &str,
) -> Result<Vec<String>, ManagedStoreError> {
    let (table, column) = if principal {
        ("principal_agent_token_issuance_contexts", "principal_id")
    } else {
        ("group_agent_token_issuance_contexts", "group_id")
    };
    let mut statement = conn
        .prepare(&format!(
            "SELECT execution_context FROM {table} WHERE {column}=?1 ORDER BY execution_context"
        ))
        .map_err(sql_unavailable)?;
    collect_rows(
        statement
            .query_map([owner], |row| row.get(0))
            .map_err(sql_unavailable)?,
    )
}
pub(super) fn replace_contexts(
    conn: &Connection,
    principal: bool,
    owner: &str,
    contexts: &[String],
) -> Result<(), ManagedStoreError> {
    let (table, column) = if principal {
        ("principal_agent_token_issuance_contexts", "principal_id")
    } else {
        ("group_agent_token_issuance_contexts", "group_id")
    };
    conn.execute(&format!("DELETE FROM {table} WHERE {column}=?1"), [owner])
        .map_err(sql_unavailable)?;
    for context in contexts {
        conn.execute(
            &format!("INSERT INTO {table} ({column}, execution_context) VALUES (?1,?2)"),
            params![owner, context],
        )
        .map_err(sql_unavailable)?;
    }
    Ok(())
}

pub(super) fn seed_contexts(
    conn: &Connection,
    contexts: &ConfiguredExecutionContexts,
) -> Result<(), ManagedStoreError> {
    for (owners, table, column) in [
        (
            "principals",
            "principal_agent_token_issuance_contexts",
            "principal_id",
        ),
        ("groups", "group_agent_token_issuance_contexts", "group_id"),
    ] {
        for context in contexts.iter() {
            conn.execute(&format!("INSERT INTO {table} ({column}, execution_context) SELECT {column}, ?1 FROM {owners} WHERE agent_token_issuance IN ('read_only','write_capable')"), [context]).map_err(sql_unavailable)?;
        }
    }
    Ok(())
}
pub(super) fn validate_context_structure(conn: &Connection) -> Result<(), ManagedStoreError> {
    // Admission of an already-current store is not a migration transaction.
    // Keep modes and child rows in one snapshot even while another process writes.
    if conn.is_autocommit() {
        let tx = conn.unchecked_transaction().map_err(sql_unavailable)?;
        validate_context_structure(&tx)?;
        tx.commit().map_err(sql_unavailable)?;
        return Ok(());
    }
    imported_store::validate_structure_through(
        conn,
        MANAGED_STORE_AGENT_TOKEN_ISSUANCE_CONTEXTS_VERSION,
    )?;
    validate_context_rows(conn)
}

pub(super) fn validate_context_rows(conn: &Connection) -> Result<(), ManagedStoreError> {
    identity_access::check_identity_token_rows(conn)?;
    oidc_membership_renewal::check_rows(conn)?;
    imported_documents::check_rows(conn)?;
    sqlite_support::run_foreign_key_check(conn, MANAGED_STORE_LABEL)?;
    for (owners, column, principal) in [
        ("principals", "principal_id", true),
        ("groups", "group_id", false),
    ] {
        let mut statement = conn
            .prepare(&format!(
                "SELECT {column}, agent_token_issuance FROM {owners}"
            ))
            .map_err(sql_unavailable)?;
        let rows = collect_rows(
            statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(sql_unavailable)?,
        )?;
        for (owner, mode) in rows {
            let contexts = load_contexts(conn, principal, &owner)?;
            let valid = if principal {
                mode.parse().and_then(|mode| {
                    PrincipalAgentTokenIssuanceSetting::new(mode, contexts).map(|_| ())
                })
            } else {
                mode.parse().and_then(|mode| {
                    GroupAgentTokenIssuanceSetting::new(mode, contexts).map(|_| ())
                })
            };
            valid.map_err(|_| {
                ManagedStoreError::SchemaInvalid(format!(
                    "invalid agent token issuance mode/context list for {column}={owner:.128}"
                ))
            })?;
        }
    }
    Ok(())
}

pub(super) fn seed(
    conn: &Connection,
    _: &ConfiguredExecutionContexts,
) -> Result<(), ManagedStoreError> {
    let mut statement = conn.prepare("SELECT token_id, scopes_json, revoked_at FROM broker_tokens WHERE token_class='agent_invoke' ORDER BY token_id").map_err(sql_unavailable)?;
    let rows: Vec<(String, String, Option<String>)> = collect_rows(
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(sql_unavailable)?,
    )?;
    let mut collisions = Vec::new();
    let mut updates = Vec::new();
    for (token_id, mut scopes, revoked_at) in rows {
        let Ok(Value::Object(object)) = serde_json::from_str::<Value>(&scopes) else {
            continue;
        };
        if object.contains_key("readOnly") {
            if revoked_at.is_none() {
                collisions.push(token_id);
            }
            continue;
        }
        // Keep original member bytes, including unknown members and number
        // spellings. Parsing decides eligibility, never normalizes old data.
        let closing_brace = scopes
            .rfind('}')
            .expect("parsed object has a closing brace");
        scopes.insert_str(
            closing_brace,
            if object.is_empty() {
                "\"readOnly\":false"
            } else {
                ",\"readOnly\":false"
            },
        );
        updates.push((token_id, scopes));
    }
    // Scan every row before writing any token. Revoked collisions remain exactly as stored.
    if !collisions.is_empty() {
        return Err(ManagedStoreError::SchemaInvalid(format!(
            "agent token issuance migration found unsupported readOnly in unrevoked token IDs: {}",
            collisions.join(", ")
        )));
    }
    for (token_id, scopes) in updates {
        conn.execute(
            "UPDATE broker_tokens SET scopes_json=?2 WHERE token_id=?1",
            params![token_id, scopes],
        )
        .map_err(sql_unavailable)?;
    }
    Ok(())
}

pub(super) fn validate_structure(conn: &Connection) -> Result<(), ManagedStoreError> {
    imported_store::validate_structure_through(conn, MANAGED_STORE_AGENT_TOKEN_ISSUANCE_VERSION)?;
    identity_access::check_identity_token_rows(conn)?;
    oidc_membership_renewal::check_rows(conn)?;
    imported_documents::check_rows(conn)
}
