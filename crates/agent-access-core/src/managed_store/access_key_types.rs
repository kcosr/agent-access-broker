//! Access key types: which access key types an account may hold, decided
//! separately for each access key type. An account allows or denies an
//! access key type, or says nothing about it and inherits from its groups; a
//! managed group allows an access key type or says nothing, and never denies.
//!
//! The setting is administrator-owned and sits beside agent-token issuance,
//! whose transactions, reload fence and reference checks it shares. It
//! differs in two ways: each access key type is overridden alone, where an
//! issuance setting replaces group permission for everything at once, and
//! it is read at every evaluation of a token as well as at its mint, so
//! withdrawing access also stops existing tokens. Access key types exist only
//! under managed identity authority, so the groups are managed groups.
use super::*;
use crate::{AccessKeyTypes, is_valid_execution_context_value};

/// The most access key types one list names.
pub const ACCESS_KEY_TYPES_MAX_ENTRIES: usize = 256;

fn validate_list(access_key_types: &[String]) -> Result<(), ManagedStoreError> {
    if access_key_types.len() > ACCESS_KEY_TYPES_MAX_ENTRIES
        || access_key_types
            .iter()
            .any(|id| !is_valid_execution_context_value(id))
        || access_key_types.iter().collect::<BTreeSet<_>>().len() != access_key_types.len()
    {
        return Err(input_invalid(
            "an access key type setting lists unique valid access key type IDs",
        ));
    }
    Ok(())
}

fn require_configured<'a>(
    access_key_types: impl IntoIterator<Item = &'a String>,
    configured: &AccessKeyTypes,
) -> Result<(), ManagedStoreError> {
    if access_key_types
        .into_iter()
        .any(|id| configured.get(id).is_none())
    {
        return Err(input_invalid(
            "an access key type setting names an access key type that is not configured",
        ));
    }
    Ok(())
}

/// An account's complete setting: the access key types it allows and the ones it
/// denies, whatever its groups allow. An access key type in neither list
/// inherits.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct PrincipalAccessKeyTypes {
    /// Sorted access key type IDs.
    pub allow: Vec<String>,
    /// Sorted access key type IDs, none of them in `allow`.
    pub deny: Vec<String>,
}

impl PrincipalAccessKeyTypes {
    pub fn new(mut allow: Vec<String>, mut deny: Vec<String>) -> Result<Self, ManagedStoreError> {
        validate_list(&allow)?;
        validate_list(&deny)?;
        if allow.iter().any(|id| deny.contains(id)) {
            return Err(input_invalid(
                "an access key type setting cannot allow and deny the same access key type",
            ));
        }
        allow.sort();
        deny.sort();
        Ok(Self { allow, deny })
    }

    /// Refuses a setting that names an access key type `configured` does not
    /// define: a setting never refers to a type a later configuration could
    /// introduce.
    pub fn validate(&self, configured: &AccessKeyTypes) -> Result<(), ManagedStoreError> {
        Self::new(self.allow.clone(), self.deny.clone())?;
        require_configured(self.allow.iter().chain(&self.deny), configured)
    }
}

impl<'de> Deserialize<'de> for PrincipalAccessKeyTypes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            allow: Vec<String>,
            deny: Vec<String>,
        }
        // An object only: `[["inference"], []]` is not this setting.
        let wire: Wire = crate::object_only(deserializer)?;
        Self::new(wire.allow, wire.deny).map_err(serde::de::Error::custom)
    }
}

/// A managed group's complete setting: the access key types it allows its local
/// members that inherit them. A group never denies.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct GroupAccessKeyTypes {
    /// Sorted access key type IDs.
    pub allow: Vec<String>,
}

impl GroupAccessKeyTypes {
    pub fn new(mut allow: Vec<String>) -> Result<Self, ManagedStoreError> {
        validate_list(&allow)?;
        allow.sort();
        Ok(Self { allow })
    }

    /// Refuses a setting that names an access key type `configured` does not
    /// define.
    pub fn validate(&self, configured: &AccessKeyTypes) -> Result<(), ManagedStoreError> {
        Self::new(self.allow.clone())?;
        require_configured(&self.allow, configured)
    }
}

impl<'de> Deserialize<'de> for GroupAccessKeyTypes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            allow: Vec<String>,
        }
        // An object only: `[["inference"]]` is not this setting.
        let wire: Wire = crate::object_only(deserializer)?;
        Self::new(wire.allow).map_err(serde::de::Error::custom)
    }
}

/// A change to an owner's setting, read in its transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessKeyTypesChange<S> {
    pub previous: S,
    pub current: S,
}

/// Where the decision for one access key type comes from.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessKeyTypeSource {
    /// The account's own `allow` or `deny`.
    Account,
    /// The account inherits and at least one of its groups allows it.
    Groups,
    /// The account inherits and no group allows it.
    None,
}

/// Whether an account may hold one access key type now, and why. Written, never
/// read from outside.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AccessKeyTypeDecision {
    pub access_key_type: String,
    pub allowed: bool,
    pub source: AccessKeyTypeSource,
    /// The groups that allow it, when the source is `groups`.
    pub group_ids: Vec<String>,
}

/// What an account may hold now: one decision for every configured
/// access key type, by ID, under the current settings and local membership.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AccessKeyTypePolicy {
    pub access_key_types: Vec<AccessKeyTypeDecision>,
}

impl AccessKeyTypePolicy {
    /// Whether the account may hold `access_key_type`.
    pub fn allows(&self, access_key_type: &str) -> bool {
        self.access_key_types
            .iter()
            .any(|decision| decision.access_key_type == access_key_type && decision.allowed)
    }
}

fn invalid_stored() -> ManagedStoreError {
    ManagedStoreError::SchemaInvalid("stored access key type setting is invalid".into())
}

/// The stored setting of the account `principal_id`.
pub(super) fn principal_setting(
    conn: &Connection,
    principal_id: &str,
) -> Result<PrincipalAccessKeyTypes, ManagedStoreError> {
    let mut statement = conn
        .prepare(
            "SELECT access_key_type, decision FROM principal_access_key_types
             WHERE principal_id = ?1 ORDER BY access_key_type",
        )
        .map_err(sql_unavailable)?;
    let rows: Vec<(String, String)> = collect_rows(
        statement
            .query_map([principal_id], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(sql_unavailable)?,
    )?;
    let (mut allow, mut deny) = (Vec::new(), Vec::new());
    for (access_key_type, decision) in rows {
        match decision.as_str() {
            "allow" => allow.push(access_key_type),
            "deny" => deny.push(access_key_type),
            _ => return Err(invalid_stored()),
        }
    }
    PrincipalAccessKeyTypes::new(allow, deny).map_err(|_| invalid_stored())
}

/// The stored setting of the group `group_id`.
pub(super) fn group_setting(
    conn: &Connection,
    group_id: &str,
) -> Result<GroupAccessKeyTypes, ManagedStoreError> {
    let mut statement = conn
        .prepare(
            "SELECT access_key_type FROM group_access_key_types
             WHERE group_id = ?1 ORDER BY access_key_type",
        )
        .map_err(sql_unavailable)?;
    let allow = collect_rows(
        statement
            .query_map([group_id], |row| row.get(0))
            .map_err(sql_unavailable)?,
    )?;
    GroupAccessKeyTypes::new(allow).map_err(|_| invalid_stored())
}

/// Replaces an account's setting, when `setting` differs from the stored
/// one, and returns the change. The caller's transaction owns the write.
pub(super) fn replace_principal_setting(
    conn: &Connection,
    principal_id: &str,
    setting: &PrincipalAccessKeyTypes,
    configured: &AccessKeyTypes,
) -> Result<Option<AccessKeyTypesChange<PrincipalAccessKeyTypes>>, ManagedStoreError> {
    setting.validate(configured)?;
    let previous = principal_setting(conn, principal_id)?;
    if previous == *setting {
        return Ok(None);
    }
    conn.execute(
        "DELETE FROM principal_access_key_types WHERE principal_id = ?1",
        [principal_id],
    )
    .map_err(sql_unavailable)?;
    for (decision, access_key_types) in [("allow", &setting.allow), ("deny", &setting.deny)] {
        for access_key_type in access_key_types {
            conn.execute(
                "INSERT INTO principal_access_key_types (principal_id, access_key_type, decision)
                 VALUES (?1, ?2, ?3)",
                params![principal_id, access_key_type, decision],
            )
            .map_err(sql_unavailable)?;
        }
    }
    Ok(Some(AccessKeyTypesChange {
        previous,
        current: setting.clone(),
    }))
}

/// Replaces a group's setting, when `setting` differs from the stored one,
/// and returns the change. The caller's transaction owns the write.
pub(super) fn replace_group_setting(
    conn: &Connection,
    group_id: &str,
    setting: &GroupAccessKeyTypes,
    configured: &AccessKeyTypes,
) -> Result<Option<AccessKeyTypesChange<GroupAccessKeyTypes>>, ManagedStoreError> {
    setting.validate(configured)?;
    let previous = group_setting(conn, group_id)?;
    if previous == *setting {
        return Ok(None);
    }
    conn.execute(
        "DELETE FROM group_access_key_types WHERE group_id = ?1",
        [group_id],
    )
    .map_err(sql_unavailable)?;
    for access_key_type in &setting.allow {
        conn.execute(
            "INSERT INTO group_access_key_types (group_id, access_key_type) VALUES (?1, ?2)",
            params![group_id, access_key_type],
        )
        .map_err(sql_unavailable)?;
    }
    Ok(Some(AccessKeyTypesChange {
        previous,
        current: setting.clone(),
    }))
}

/// Applies `write` to an account, when one is given, and reports the
/// setting before and after: equal when nothing was written. `report`
/// false, without a write, reads nothing and reports nothing.
pub(super) fn write_principal_setting(
    conn: &Connection,
    principal_id: &str,
    write: Option<AccessKeyTypesWrite<'_, PrincipalAccessKeyTypes>>,
    report: bool,
) -> Result<Option<AccessKeyTypesChange<PrincipalAccessKeyTypes>>, ManagedStoreError> {
    match write {
        Some(write) => Ok(Some(
            match replace_principal_setting(conn, principal_id, write.setting, write.configured)? {
                Some(change) => change,
                None => AccessKeyTypesChange {
                    previous: write.setting.clone(),
                    current: write.setting.clone(),
                },
            },
        )),
        None if report => {
            let current = principal_setting(conn, principal_id)?;
            Ok(Some(AccessKeyTypesChange {
                previous: current.clone(),
                current,
            }))
        }
        None => Ok(None),
    }
}

/// Applies `write` to a group, when one is given, and reports the setting
/// before and after: equal when nothing was written. `report` false,
/// without a write, reads nothing and reports nothing.
pub(super) fn write_group_setting(
    conn: &Connection,
    group_id: &str,
    write: Option<AccessKeyTypesWrite<'_, GroupAccessKeyTypes>>,
    report: bool,
) -> Result<Option<AccessKeyTypesChange<GroupAccessKeyTypes>>, ManagedStoreError> {
    match write {
        Some(write) => Ok(Some(
            match replace_group_setting(conn, group_id, write.setting, write.configured)? {
                Some(change) => change,
                None => AccessKeyTypesChange {
                    previous: write.setting.clone(),
                    current: write.setting.clone(),
                },
            },
        )),
        None if report => {
            let current = group_setting(conn, group_id)?;
            Ok(Some(AccessKeyTypesChange {
                previous: current.clone(),
                current,
            }))
        }
        None => Ok(None),
    }
}

/// What `principal_id` may hold now, one decision for every configured
/// access key type. The account's `deny` means no and its `allow` means yes;
/// an access key type in neither is allowed when at least one active managed
/// group the account belongs to by current local membership allows it.
/// Membership that comes only from Microsoft group evidence contributes
/// nothing, and neither does a disabled group.
pub(super) fn policy_at_conn(
    conn: &Connection,
    configured: &AccessKeyTypes,
    principal_id: &str,
) -> Result<AccessKeyTypePolicy, ManagedStoreError> {
    let setting = principal_setting(conn, principal_id)?;
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut statement = conn
        .prepare(
            "SELECT e.access_key_type, g.group_id
             FROM principal_groups pg
             JOIN groups g ON g.group_id = pg.group_id
             JOIN group_access_key_types e ON e.group_id = g.group_id
             WHERE pg.principal_id = ?1 AND g.status = 'active'
             ORDER BY e.access_key_type, g.group_id",
        )
        .map_err(sql_unavailable)?;
    let rows: Vec<(String, String)> = collect_rows(
        statement
            .query_map([principal_id], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(sql_unavailable)?,
    )?;
    for (access_key_type, group_id) in rows {
        groups.entry(access_key_type).or_default().push(group_id);
    }
    let access_key_types = configured
        .iter()
        .map(|access_key_type| {
            let id = &access_key_type.id;
            let (allowed, source, group_ids) = if setting.deny.contains(id) {
                (false, AccessKeyTypeSource::Account, Vec::new())
            } else if setting.allow.contains(id) {
                (true, AccessKeyTypeSource::Account, Vec::new())
            } else if let Some(group_ids) = groups.remove(id) {
                (true, AccessKeyTypeSource::Groups, group_ids)
            } else {
                (false, AccessKeyTypeSource::None, Vec::new())
            };
            AccessKeyTypeDecision {
                access_key_type: id.clone(),
                allowed,
                source,
                group_ids,
            }
        })
        .collect();
    Ok(AccessKeyTypePolicy { access_key_types })
}

impl ManagedStore {
    /// The stored setting of the account `principal_id`.
    pub fn principal_access_key_types(
        &self,
        principal_id: &str,
    ) -> Result<PrincipalAccessKeyTypes, ManagedStoreError> {
        validate_principal_id(principal_id)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        principal_by_id_without_groups(&tx, principal_id)?;
        let setting = principal_setting(&tx, principal_id)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(setting)
    }

    /// The stored setting of every group that allows something, by group
    /// ID. A group that is not listed allows nothing.
    pub fn group_access_key_types(
        &self,
    ) -> Result<BTreeMap<String, GroupAccessKeyTypes>, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        let mut statement = conn
            .prepare(
                "SELECT group_id, access_key_type FROM group_access_key_types
                 ORDER BY group_id, access_key_type",
            )
            .map_err(sql_unavailable)?;
        let rows: Vec<(String, String)> = collect_rows(
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .map_err(sql_unavailable)?,
        )?;
        let mut settings: BTreeMap<String, GroupAccessKeyTypes> = BTreeMap::new();
        for (group_id, access_key_type) in rows {
            settings
                .entry(group_id)
                .or_default()
                .allow
                .push(access_key_type);
        }
        Ok(settings)
    }

    /// What `principal_id` may hold now, with where each decision comes
    /// from.
    pub fn access_key_type_policy(
        &self,
        configured: &AccessKeyTypes,
        principal_id: &str,
    ) -> Result<AccessKeyTypePolicy, ManagedStoreError> {
        validate_principal_id(principal_id)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        principal_by_id_without_groups(&tx, principal_id)?;
        let policy = policy_at_conn(&tx, configured, principal_id)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(policy)
    }

    /// The access key types that saved settings name and `configured` does
    /// not define, by ID, each with who still names it. A configuration is
    /// refused while there is one: a new access key type ID must never
    /// switch itself on through a setting saved before it existed, and
    /// removing an access key type while a setting names it is an
    /// operator's explicit step. Every account's and every group's
    /// references are found, disabled ones included. A key that carries
    /// the type refuses nothing: it only stops holding it.
    pub fn access_key_types_still_referenced(
        &self,
        configured: &AccessKeyTypes,
    ) -> Result<Vec<AccessKeyTypeStillReferenced>, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        let mut found = BTreeMap::<String, AccessKeyTypeStillReferenced>::new();
        for (table, column, accounts) in [
            ("principal_access_key_types", "principal_id", true),
            ("group_access_key_types", "group_id", false),
        ] {
            let mut statement = conn
                .prepare(&format!(
                    "SELECT {column}, access_key_type FROM {table} ORDER BY {column}, access_key_type"
                ))
                .map_err(sql_unavailable)?;
            let rows: Vec<(String, String)> = collect_rows(
                statement
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                    .map_err(sql_unavailable)?,
            )?;
            for (owner, access_key_type) in rows {
                if configured.get(&access_key_type).is_some() {
                    continue;
                }
                let entry = found.entry(access_key_type.clone()).or_insert_with(|| {
                    AccessKeyTypeStillReferenced {
                        access_key_type,
                        account_settings: 0,
                        accounts: Vec::new(),
                        group_settings: 0,
                        groups: Vec::new(),
                        unexpired_keys: 0,
                    }
                });
                let (count, sample) = if accounts {
                    (&mut entry.account_settings, &mut entry.accounts)
                } else {
                    (&mut entry.group_settings, &mut entry.groups)
                };
                *count += 1;
                if sample.len() < ACCESS_KEY_TYPE_REFERENCE_SAMPLE {
                    sample.push(owner);
                }
            }
        }
        let now = normalized_now_string();
        for entry in found.values_mut() {
            entry.unexpired_keys = conn
                .query_row(
                    "SELECT COUNT(1) FROM access_key_type_links l
                     JOIN access_keys k ON k.key_id = l.key_id
                     WHERE l.access_key_type = ?1 AND k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at > ?2)",
                    params![entry.access_key_type, now],
                    |row| row.get::<_, i64>(0),
                )
                .map(|count| count.max(0) as u64)
                .map_err(sql_unavailable)?;
        }
        Ok(found.into_values().collect())
    }
}

/// The most owners of each kind a reference diagnostic names.
const ACCESS_KEY_TYPE_REFERENCE_SAMPLE: usize = 10;

/// An access key type the configuration does not define, and who still
/// names it in a saved access key type setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessKeyTypeStillReferenced {
    pub access_key_type: String,
    /// The accounts whose setting names it, in `allow` or `deny`.
    pub account_settings: u64,
    /// Some of those accounts, by principal ID.
    pub accounts: Vec<String>,
    /// The groups whose setting allows it.
    pub group_settings: u64,
    /// Some of those groups, by group ID.
    pub groups: Vec<String>,
    /// Unexpired, unrevoked access keys that carry it. They block nothing:
    /// without the type they stop holding it.
    pub unexpired_keys: u64,
}

impl AccessKeyTypeStillReferenced {
    /// What an operator is told: which type cannot be removed yet, who
    /// still names it, and what to do.
    pub fn message(&self) -> String {
        let named = |count: u64, sample: &[String], one: &str, many: &str| {
            let noun = if count == 1 { one } else { many };
            let mut listed = sample
                .iter()
                .map(|id| format!("{id:.128}"))
                .collect::<Vec<_>>()
                .join(", ");
            let more = count.saturating_sub(sample.len() as u64);
            if more > 0 {
                listed.push_str(&format!(" and {more} more"));
            }
            if count == 0 {
                format!("no {many}")
            } else {
                format!("{count} {noun} ({listed})")
            }
        };
        format!(
            "access key type {:.64} is not in [access_key_types] and is still named by {} and {}; \
             {} unexpired access key{} carr{} it. Take it out of those settings, or keep its table, \
             then reload or start again: see \"Retire an access key type\" in the administrator guide",
            self.access_key_type,
            named(
                self.account_settings,
                &self.accounts,
                "account setting",
                "account settings"
            ),
            named(
                self.group_settings,
                &self.groups,
                "group setting",
                "group settings"
            ),
            self.unexpired_keys,
            if self.unexpired_keys == 1 { "" } else { "s" },
            if self.unexpired_keys == 1 { "ies" } else { "y" },
        )
    }
}

#[cfg(test)]
impl ManagedStore {
    /// Sets an account's access key type setting directly.
    pub(crate) fn set_principal_access_key_types_for_test(
        &self,
        principal_id: &str,
        allow: &[&str],
        deny: &[&str],
        configured: &AccessKeyTypes,
    ) {
        let ids = |ids: &[&str]| ids.iter().map(|id| (*id).to_string()).collect();
        let setting = PrincipalAccessKeyTypes::new(ids(allow), ids(deny)).unwrap();
        let conn = self.connection.lock().unwrap();
        replace_principal_setting(&conn, principal_id, &setting, configured).unwrap();
    }

    /// Sets a group's access key type setting directly.
    pub(crate) fn set_group_access_key_types_for_test(
        &self,
        group_id: &str,
        allow: &[&str],
        configured: &AccessKeyTypes,
    ) {
        let setting =
            GroupAccessKeyTypes::new(allow.iter().map(|id| (*id).to_string()).collect()).unwrap();
        let conn = self.connection.lock().unwrap();
        replace_group_setting(&conn, group_id, &setting, configured).unwrap();
    }
}

#[cfg(test)]
#[path = "access_key_types_tests.rs"]
mod tests;
