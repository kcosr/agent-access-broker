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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentTokenIssuancePolicy {
    pub mode: AgentTokenIssuanceMode,
    pub source: AgentTokenIssuanceSource,
    pub group_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TokenIssuanceDenial {
    Disabled,
    ReadOnlyRequired,
}
issuance_enum_text!(TokenIssuanceDenial, "agent token issuance denial is invalid", {
    Disabled => "disabled", ReadOnlyRequired => "read_only_required"
});
impl TokenIssuanceDenial {
    pub fn message(self) -> &'static str {
        match self {
            Self::Disabled => "Agent token issuance is disabled for this account",
            Self::ReadOnlyRequired => "This account may issue only read-only agent tokens",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupAgentTokenIssuanceChange {
    pub previous: AgentTokenIssuanceMode,
    pub current: AgentTokenIssuanceMode,
}

pub(super) fn resolve_policy(
    setting: PrincipalAgentTokenIssuance,
    contributions: impl IntoIterator<Item = (String, AgentTokenIssuanceMode)>,
) -> AgentTokenIssuancePolicy {
    let override_mode = match setting {
        PrincipalAgentTokenIssuance::Inherit => None,
        PrincipalAgentTokenIssuance::Disabled => Some(AgentTokenIssuanceMode::Disabled),
        PrincipalAgentTokenIssuance::ReadOnly => Some(AgentTokenIssuanceMode::ReadOnly),
        PrincipalAgentTokenIssuance::WriteCapable => Some(AgentTokenIssuanceMode::WriteCapable),
    };
    if let Some(mode) = override_mode {
        return AgentTokenIssuancePolicy {
            mode,
            source: AgentTokenIssuanceSource::User,
            group_ids: Vec::new(),
        };
    }
    let mut mode = AgentTokenIssuanceMode::Disabled;
    let mut group_ids = BTreeSet::new();
    for (group_id, contribution) in contributions {
        if contribution == AgentTokenIssuanceMode::Disabled || contribution < mode {
            continue;
        }
        if contribution > mode {
            group_ids.clear();
            mode = contribution;
        }
        group_ids.insert(group_id);
    }
    AgentTokenIssuancePolicy {
        mode,
        source: if group_ids.is_empty() {
            AgentTokenIssuanceSource::Default
        } else {
            AgentTokenIssuanceSource::Groups
        },
        group_ids: group_ids.into_iter().collect(),
    }
}

pub(super) fn policy_at_conn(
    conn: &Connection,
    principal: &PrincipalRecord,
    authority: AgentTokenIssuanceAuthority,
    resolved_at: &str,
) -> Result<AgentTokenIssuancePolicy, ManagedStoreError> {
    let mut contributions = Vec::new();
    if principal.agent_token_issuance == PrincipalAgentTokenIssuance::Inherit
        && authority == AgentTokenIssuanceAuthority::Managed
    {
        // One timestamp and one membership resolution for this transaction.
        let membership = effective_membership_at_conn(conn, &principal.principal_id, resolved_at)?;
        let mut statement = conn
            .prepare(
                "SELECT agent_token_issuance FROM groups WHERE group_id=?1 AND status='active'",
            )
            .map_err(sql_unavailable)?;
        for group_id in membership.policy_groups {
            let mode: Option<String> = statement
                .query_row([&group_id], |row| row.get(0))
                .optional()
                .map_err(sql_unavailable)?;
            if let Some(mode) = mode {
                contributions.push((group_id, mode.parse()?));
            }
        }
    }
    Ok(resolve_policy(
        principal.agent_token_issuance,
        contributions,
    ))
}

pub(super) fn authorize(
    policy: &AgentTokenIssuancePolicy,
    read_only: bool,
) -> Result<(), ManagedStoreError> {
    let category = match policy.mode {
        AgentTokenIssuanceMode::Disabled => Some(TokenIssuanceDenial::Disabled),
        AgentTokenIssuanceMode::ReadOnly if !read_only => {
            Some(TokenIssuanceDenial::ReadOnlyRequired)
        }
        AgentTokenIssuanceMode::ReadOnly | AgentTokenIssuanceMode::WriteCapable => None,
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
        authority: AgentTokenIssuanceAuthority,
    ) -> Result<AgentTokenIssuancePolicy, ManagedStoreError> {
        validate_principal_id(principal_id)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        let principal = principal_by_id_without_groups(&tx, principal_id)?;
        let policy = policy_at_conn(&tx, &principal, authority, &normalized_now_string())?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(policy)
    }
}

pub(super) fn seed(conn: &Connection) -> Result<(), ManagedStoreError> {
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
