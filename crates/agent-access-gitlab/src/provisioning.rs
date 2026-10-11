//! Project-owned automation identities and deliberately exported, newly issued credentials.
use super::*;

pub const PROVISIONING_ACTIONS: &[&str] = &[
    "project.access_token.list",
    "project.access_token.view",
    "project.access_token.create",
    "project.access_token.rotate",
    "project.access_token.revoke",
    "service_account.list",
    "service_account.view",
    "service_account.create",
    "service_account.delete",
    "service_account.member.set",
    "service_account.token.list",
    "service_account.token.create",
    "service_account.token.rotate",
    "service_account.token.revoke",
];
const TOKEN_SCOPES: &[&str] = &[
    "api",
    "read_api",
    "read_repository",
    "write_repository",
    "read_registry",
    "write_registry",
    "self_rotate",
];

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GitlabProvisioningConfig {
    pub enabled: bool,
    pub max_access_level: u32,
    pub max_token_lifetime_days: u32,
    pub allowed_token_scopes: Vec<String>,
}
impl Default for GitlabProvisioningConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_access_level: 30,
            max_token_lifetime_days: 30,
            allowed_token_scopes: vec!["api".into(), "read_api".into(), "read_repository".into()],
        }
    }
}
impl GitlabProvisioningConfig {
    pub(crate) fn validate(&self, errors: &mut Vec<String>) {
        if ![10, 15, 20, 25, 30, 40].contains(&self.max_access_level) {
            errors.push("providers.gitlab.provisioning.max_access_level must be a supported project role (10, 15, 20, 25, 30, 40)".into());
        }
        if !(1..=365).contains(&self.max_token_lifetime_days) {
            errors.push(
                "providers.gitlab.provisioning.max_token_lifetime_days must be between 1 and 365"
                    .into(),
            );
        }
        if self.allowed_token_scopes.is_empty()
            || self
                .allowed_token_scopes
                .iter()
                .any(|s| !TOKEN_SCOPES.contains(&s.as_str()))
        {
            errors.push("providers.gitlab.provisioning.allowed_token_scopes must be a nonempty list of supported token scopes".into());
        }
    }
}

pub(crate) fn issues_token(action: &str) -> bool {
    matches!(
        action,
        "project.access_token.create"
            | "project.access_token.rotate"
            | "service_account.token.create"
            | "service_account.token.rotate"
    )
}

// This is a closed operation enum, never a caller-supplied path or HTTP method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitlabProvisioningOperation {
    ProjectTokenList,
    ProjectTokenView,
    ProjectTokenCreate,
    ProjectTokenRotate,
    ProjectTokenRevoke,
    AccountList,
    AccountView,
    AccountCreate,
    AccountDelete,
    MemberView,
    MemberAdd,
    MemberUpdate,
    AccountTokenList,
    AccountTokenCreate,
    AccountTokenRotate,
    AccountTokenRevoke,
}
impl GitlabProvisioningOperation {
    fn from_action(action: &str) -> Option<Self> {
        Some(match action {
            "project.access_token.list" => Self::ProjectTokenList,
            "project.access_token.view" => Self::ProjectTokenView,
            "project.access_token.create" => Self::ProjectTokenCreate,
            "project.access_token.rotate" => Self::ProjectTokenRotate,
            "project.access_token.revoke" => Self::ProjectTokenRevoke,
            "service_account.list" => Self::AccountList,
            "service_account.view" => Self::AccountView,
            "service_account.create" => Self::AccountCreate,
            "service_account.delete" => Self::AccountDelete,
            "service_account.member.set" => Self::MemberUpdate,
            "service_account.token.list" => Self::AccountTokenList,
            "service_account.token.create" => Self::AccountTokenCreate,
            "service_account.token.rotate" => Self::AccountTokenRotate,
            "service_account.token.revoke" => Self::AccountTokenRevoke,
            _ => return None,
        })
    }
    fn operation(self) -> &'static str {
        use GitlabProvisioningOperation::*;
        match self {
            ProjectTokenList => "project.access_token.list",
            ProjectTokenView => "project.access_token.view",
            ProjectTokenCreate => "project.access_token.create",
            ProjectTokenRotate => "project.access_token.rotate",
            ProjectTokenRevoke => "project.access_token.revoke",
            AccountList => "service_account.list",
            AccountView => "service_account.view",
            AccountCreate => "service_account.create",
            AccountDelete => "service_account.delete",
            MemberView => "service_account.member.view",
            MemberAdd | MemberUpdate => "service_account.member.set",
            AccountTokenList => "service_account.token.list",
            AccountTokenCreate => "service_account.token.create",
            AccountTokenRotate => "service_account.token.rotate",
            AccountTokenRevoke => "service_account.token.revoke",
        }
    }
    fn is_list(self) -> bool {
        matches!(
            self,
            Self::ProjectTokenList | Self::AccountList | Self::AccountTokenList
        )
    }
    fn is_read(self) -> bool {
        self.is_list()
            || matches!(
                self,
                Self::ProjectTokenView | Self::AccountView | Self::MemberView
            )
    }
    fn is_account(self) -> bool {
        matches!(
            self,
            Self::AccountList | Self::AccountView | Self::AccountCreate | Self::AccountDelete
        )
    }
    fn is_member(self) -> bool {
        matches!(
            self,
            Self::MemberView | Self::MemberAdd | Self::MemberUpdate
        )
    }
}

pub(crate) fn provisioning_schema(action: &str, config: &GitlabProviderConfig) -> Value {
    let mut properties = serde_json::Map::new();
    properties.insert("project".into(), json!({"type":"string", "minLength":1}));
    let mut required = vec!["project"];
    let mut add = |key, schema| {
        properties.insert(key, schema);
    };
    let operation = GitlabProvisioningOperation::from_action(action).expect("known action");
    if action.starts_with("service_account.")
        && !matches!(action, "service_account.list" | "service_account.create")
    {
        add("userId".into(), json!({"type":"integer", "minimum":1}));
        required.push("userId");
    }
    if matches!(
        operation,
        GitlabProvisioningOperation::ProjectTokenView
            | GitlabProvisioningOperation::ProjectTokenRotate
            | GitlabProvisioningOperation::ProjectTokenRevoke
            | GitlabProvisioningOperation::AccountTokenRotate
            | GitlabProvisioningOperation::AccountTokenRevoke
    ) {
        add("tokenId".into(), json!({"type":"integer", "minimum":1}));
        required.push("tokenId");
    }
    if operation.is_list() {
        add(
            "maxResults".into(),
            json!({"type":"integer", "minimum":1, "maximum":config.search.max_results}),
        );
        add("pageToken".into(), json!({"type":"string", "minLength":1}));
    }
    if action.ends_with(".create") {
        add(
            "name".into(),
            json!({"type":"string", "minLength":1, "maxLength":255}),
        );
        required.push("name");
        if operation.is_account() {
            add(
                "username".into(),
                json!({"type":"string", "minLength":1, "maxLength":255}),
            );
        } else {
            add(
                "scopes".into(),
                json!({"type":"array", "minItems":1, "maxItems":TOKEN_SCOPES.len(), "uniqueItems":true, "items":{"type":"string", "enum":config.provisioning.allowed_token_scopes}}),
            );
            required.push("scopes");
        }
    }
    if matches!(
        operation,
        GitlabProvisioningOperation::ProjectTokenCreate | GitlabProvisioningOperation::MemberUpdate
    ) {
        add(
            "accessLevel".into(),
            json!({"type":"integer", "enum":[10,15,20,25,30,40], "maximum":config.provisioning.max_access_level}),
        );
        required.push("accessLevel");
    }
    if issues_token(action) {
        add(
            "expiresAt".into(),
            json!({"type":"string", "format":"date", "pattern":"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"}),
        );
        required.push("expiresAt");
    }
    json!({"type":"object", "properties":properties, "required":required, "additionalProperties":false})
}

#[derive(Default)]
pub struct GitlabProvisioningRequest {
    pub user_id: u64,
    pub token_id: u64,
    pub page: u32,
    pub max_results: u32,
    pub body: Value,
}

fn provisioning_invalid() -> ProviderError {
    ProviderError::deny(
        ReasonCode::InputInvalid,
        "GitLab provisioning inputs violate the action schema or configured issuance limits",
    )
}
fn provisioning_protocol() -> ProviderError {
    ProviderError::error(
        ReasonCode::UpstreamProtocolFailed,
        "GitLab provisioning response is invalid",
    )
}
fn provisioning_unverified(locators: &Value) -> ProviderError {
    mutation_verification_failed(
        MutationVerificationStage::MutationResponse,
        MutationSafeLocators::new().with_provisioning_ids(
            locators["userId"].as_u64(),
            locators["tokenId"].as_u64(),
            locators["previousTokenId"].as_u64(),
        ),
    )
}
fn provisioning_failure(error: GitlabBackendError, mutation: Option<&Value>) -> ProviderError {
    let status = match &error {
        GitlabBackendError::HttpStatus(status) | GitlabBackendError::Validation { status, .. } => {
            Some(*status)
        }
        GitlabBackendError::Unauthorized => Some(401),
        GitlabBackendError::Forbidden => Some(403),
        GitlabBackendError::NotFound => Some(404),
        GitlabBackendError::RateLimited(_) => Some(429),
        _ => None,
    };
    let uncertain = matches!(
        error,
        GitlabBackendError::Transport(_)
            | GitlabBackendError::Timeout
            | GitlabBackendError::Protocol(_)
            | GitlabBackendError::ResponseTooLarge
            | GitlabBackendError::HttpStatus(500..=599)
    );
    let result = if let Some(locators) = mutation.filter(|_| uncertain) {
        provisioning_unverified(locators)
    } else if matches!(
        error,
        GitlabBackendError::Validation { .. } | GitlabBackendError::HttpStatus(400 | 422)
    ) {
        // Never forward upstream validation messages: they can contain credentials.
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "GitLab rejected the provisioning inputs",
        )
    } else {
        gitlab_backend_error(error)
    };
    result.with_upstream(status, None)
}
fn token_metadata(
    value: &Value,
    expected_id: Option<u64>,
    user_id: Option<u64>,
) -> Result<Value, ProviderError> {
    let id = value["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .ok_or_else(provisioning_protocol)?;
    let user = value["user_id"]
        .as_u64()
        .filter(|id| *id > 0)
        .ok_or_else(provisioning_protocol)?;
    if expected_id.is_some_and(|expected| expected != id)
        || user_id.is_some_and(|expected| expected != user)
    {
        return Err(provisioning_protocol());
    }
    if !value["scopes"]
        .as_array()
        .is_some_and(|scopes| scopes.iter().all(Value::is_string))
        || !value["name"].is_string()
    {
        return Err(provisioning_protocol());
    }
    for key in ["expires_at", "created_at", "last_used_at"] {
        if value
            .get(key)
            .is_some_and(|v| !v.is_null() && !v.is_string())
        {
            return Err(provisioning_protocol());
        }
    }
    for key in ["active", "revoked"] {
        if value.get(key).is_some_and(|v| !v.is_boolean()) {
            return Err(provisioning_protocol());
        }
    }
    if value
        .get("access_level")
        .is_some_and(|v| v.as_u64().is_none())
    {
        return Err(provisioning_protocol());
    }
    let mut result = serde_json::Map::new();
    for (source, target) in [
        ("id", "id"),
        ("user_id", "userId"),
        ("name", "name"),
        ("scopes", "scopes"),
        ("expires_at", "expiresAt"),
        ("created_at", "createdAt"),
        ("last_used_at", "lastUsedAt"),
        ("active", "active"),
        ("revoked", "revoked"),
        ("access_level", "accessLevel"),
    ] {
        if let Some(v) = value.get(source) {
            result.insert(target.into(), v.clone());
        }
    }
    Ok(Value::Object(result))
}
fn account_metadata(value: &Value, user_id: Option<u64>) -> Result<Value, ProviderError> {
    let id = value["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .ok_or_else(provisioning_protocol)?;
    if user_id.is_some_and(|expected| expected != id)
        || !value["name"].is_string()
        || !value["username"].is_string()
    {
        return Err(provisioning_protocol());
    }
    Ok(json!({"id":id, "name":value["name"], "username":value["username"]}))
}
fn check_role(level: u64, config: &GitlabProvisioningConfig) -> Result<(), ProviderError> {
    if ![10, 15, 20, 25, 30, 40].contains(&level) || level > u64::from(config.max_access_level) {
        return Err(provisioning_invalid());
    }
    Ok(())
}
fn check_scopes(scopes: &Value, config: &GitlabProvisioningConfig) -> Result<(), ProviderError> {
    let scopes = scopes.as_array().ok_or_else(provisioning_invalid)?;
    if scopes.is_empty()
        || scopes.len() > TOKEN_SCOPES.len()
        || scopes.iter().any(|s| {
            s.as_str().is_none_or(|s| {
                !config
                    .allowed_token_scopes
                    .iter()
                    .any(|allowed| allowed == s)
            })
        })
    {
        return Err(provisioning_invalid());
    }
    Ok(())
}

fn provisioning_locators(
    op: GitlabProvisioningOperation,
    user_id: u64,
    token_id: u64,
    response: &Value,
) -> Value {
    let mut locators = serde_json::Map::new();
    let account_id = if op.is_account() || op.is_member() {
        response["id"].as_u64()
    } else {
        response["user_id"].as_u64()
    }
    .filter(|id| *id > 0)
    .unwrap_or(user_id);
    if account_id > 0 {
        locators.insert("userId".into(), json!(account_id));
    }
    if !op.is_account() && !op.is_member() {
        let rotating = matches!(
            op,
            GitlabProvisioningOperation::ProjectTokenRotate
                | GitlabProvisioningOperation::AccountTokenRotate
        );
        let current_token_id = response["id"]
            .as_u64()
            .filter(|id| *id > 0 && (!rotating || *id != token_id))
            .or_else(|| (!rotating && token_id > 0).then_some(token_id));
        if let Some(id) = current_token_id {
            locators.insert("tokenId".into(), json!(id));
        }
        if rotating && token_id > 0 {
            locators.insert("previousTokenId".into(), json!(token_id));
        }
    }
    Value::Object(locators)
}

fn provisioning_result(
    op: GitlabProvisioningOperation,
    body: &Value,
    previous: Option<&Value>,
    response: &Value,
    user_id: u64,
    token_id: u64,
) -> Result<Value, ProviderError> {
    use GitlabProvisioningOperation::*;
    let mut result = if matches!(op, ProjectTokenRevoke | AccountTokenRevoke | AccountDelete) {
        provisioning_locators(op, user_id, token_id, response)
    } else if op.is_account() {
        if op == AccountCreate
            && (response["name"] != body["name"]
                || (body.get("username").is_some() && response["username"] != body["username"]))
        {
            return Err(provisioning_protocol());
        }
        json!({"serviceAccount": account_metadata(response, (user_id > 0).then_some(user_id))?})
    } else if op.is_member() {
        if response["id"].as_u64() != Some(user_id)
            || response["access_level"] != body["access_level"]
        {
            return Err(provisioning_protocol());
        }
        json!({"member": {"userId": user_id, "accessLevel": response["access_level"]}})
    } else {
        json!({"accessToken": token_metadata(response,
            (op == ProjectTokenView).then_some(token_id), (user_id > 0).then_some(user_id))?})
    };
    if issues_token(op.operation()) {
        let expected = previous.unwrap_or(body);
        if response["name"] != expected["name"]
            || response["expires_at"] != body["expires_at"]
            || response["active"] != true
            || response["revoked"] != false
        {
            return Err(provisioning_protocol());
        }
        let mut actual_scopes = response["scopes"]
            .as_array()
            .ok_or_else(provisioning_protocol)?
            .clone();
        let mut expected_scopes = expected["scopes"]
            .as_array()
            .ok_or_else(provisioning_protocol)?
            .clone();
        actual_scopes.sort_by_key(Value::to_string);
        expected_scopes.sort_by_key(Value::to_string);
        if actual_scopes != expected_scopes
            || (matches!(op, ProjectTokenCreate | ProjectTokenRotate)
                && response["access_level"] != expected["access_level"])
        {
            return Err(provisioning_protocol());
        }
        if let Some(previous) = previous
            && (response["user_id"] != previous["user_id"] || response["id"] == previous["id"])
        {
            return Err(provisioning_protocol());
        }
        let secret = response["token"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 8192 && !s.chars().any(char::is_control))
            .ok_or_else(provisioning_protocol)?;
        result["issuedToken"] = json!(secret);
    }
    if !op.is_read() {
        result["mutationStatus"] = json!("applied");
        result["retrySafe"] = json!(false);
    }
    Ok(result)
}

fn validate_provisioning_inputs(inputs: &Value, schema: &Value) -> Result<(), ProviderError> {
    let object = inputs.as_object().ok_or_else(provisioning_invalid)?;
    let properties = schema["properties"]
        .as_object()
        .ok_or_else(provisioning_invalid)?;
    for key in schema["required"]
        .as_array()
        .ok_or_else(provisioning_invalid)?
    {
        if !object.contains_key(key.as_str().ok_or_else(provisioning_invalid)?) {
            return Err(provisioning_invalid());
        }
    }
    for (key, value) in object {
        let spec = properties.get(key).ok_or_else(provisioning_invalid)?;
        let valid = match spec["type"].as_str() {
            Some("string") => value.as_str().is_some_and(|s| {
                !s.trim().is_empty()
                    && s.chars().count() <= spec["maxLength"].as_u64().unwrap_or(4096) as usize
                    && !s.chars().any(char::is_control)
            }),
            Some("integer") => value.as_u64().is_some_and(|n| {
                n >= spec["minimum"].as_u64().unwrap_or(0)
                    && n <= spec["maximum"].as_u64().unwrap_or(u64::MAX)
                    && spec.get("enum").is_none_or(|items| {
                        items.as_array().is_some_and(|items| items.contains(value))
                    })
            }),
            Some("array") => value.as_array().is_some_and(|a| {
                !a.is_empty()
                    && a.len() <= TOKEN_SCOPES.len()
                    && a.iter().all(|v| v.is_string())
                    && a.iter()
                        .map(Value::to_string)
                        .collect::<BTreeSet<_>>()
                        .len()
                        == a.len()
            }),
            _ => false,
        };
        if !valid {
            return Err(provisioning_invalid());
        }
    }
    Ok(())
}

impl GitlabProvider {
    pub(super) async fn invoke_provisioning(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        use GitlabProvisioningOperation::*;
        if !self.config.provisioning.enabled {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "GitLab provisioning is disabled by the operator",
            ));
        }
        let action = request.action.as_str();
        let mut op =
            GitlabProvisioningOperation::from_action(action).ok_or_else(provisioning_invalid)?;
        let schema = provisioning_schema(action, &self.config);
        // Validate here as well as the catalog boundary; direct provider callers must obey the same contract.
        validate_provisioning_inputs(&request.inputs, &schema)?;
        let inputs = &request.inputs;
        let user_id = inputs["userId"].as_u64().unwrap_or(0);
        let token_id = inputs["tokenId"].as_u64().unwrap_or(0);
        let mut body = json!({});
        for (source, target) in [
            ("name", "name"),
            ("username", "username"),
            ("scopes", "scopes"),
            ("accessLevel", "access_level"),
            ("expiresAt", "expires_at"),
        ] {
            if let Some(v) = inputs.get(source) {
                body[target] = v.clone();
            }
        }
        if let Some(expiry) = inputs.get("expiresAt") {
            let expiry = expiry
                .as_str()
                .filter(|s| s.len() == 10 && s.as_bytes()[4] == b'-' && s.as_bytes()[7] == b'-')
                .ok_or_else(provisioning_invalid)?;
            let date = chrono::NaiveDate::parse_from_str(expiry, "%Y-%m-%d")
                .map_err(|_| provisioning_invalid())?;
            let days = (date - Utc::now().date_naive()).num_days();
            if days < 1 || days > i64::from(self.config.provisioning.max_token_lifetime_days) {
                return Err(provisioning_invalid());
            }
        }
        if let Some(level) = inputs.get("accessLevel") {
            check_role(
                level.as_u64().ok_or_else(provisioning_invalid)?,
                &self.config.provisioning,
            )?;
        }
        if let Some(scopes) = inputs.get("scopes") {
            check_scopes(scopes, &self.config.provisioning)?;
        }
        let (project, credential) = self.webhook_project_and_credential(&request).await?;
        let call = |op, body| {
            self.backend.provisioning(
                project.id,
                op,
                GitlabProvisioningRequest {
                    user_id,
                    token_id,
                    body,
                    ..Default::default()
                },
                credential,
            )
        };
        if user_id > 0 {
            let account = call(AccountView, json!({}))
                .await
                .map_err(|e| provisioning_failure(e, None))?;
            account_metadata(&account.value, Some(user_id))?;
        }
        if op == MemberUpdate || matches!(op, AccountTokenCreate | AccountTokenRotate) {
            let member = call(MemberView, json!({})).await;
            match member {
                Ok(member) => {
                    if member.value["id"].as_u64() != Some(user_id) {
                        return Err(provisioning_protocol());
                    }
                    if op != MemberUpdate {
                        check_role(
                            member.value["access_level"]
                                .as_u64()
                                .ok_or_else(provisioning_protocol)?,
                            &self.config.provisioning,
                        )?;
                    }
                }
                Err(GitlabBackendError::NotFound) if op == MemberUpdate => {
                    op = MemberAdd;
                    body["user_id"] = json!(user_id);
                }
                Err(e) => return Err(provisioning_failure(e, None)),
            }
        }
        let mut previous = None;
        if matches!(op, ProjectTokenRotate | AccountTokenRotate) {
            let value = if op == ProjectTokenRotate {
                call(ProjectTokenView, json!({}))
                    .await
                    .map_err(|e| provisioning_failure(e, None))?
                    .value
            } else {
                self.find_service_account_token(project.id, user_id, token_id, credential)
                    .await?
            };
            token_metadata(&value, Some(token_id), (user_id > 0).then_some(user_id))?;
            check_scopes(&value["scopes"], &self.config.provisioning)?;
            if op == ProjectTokenRotate {
                check_role(
                    value["access_level"]
                        .as_u64()
                        .ok_or_else(provisioning_protocol)?,
                    &self.config.provisioning,
                )?;
            }
            if value["active"] != true || value["revoked"] != false {
                return Err(ProviderError::deny(
                    ReasonCode::InputInvalid,
                    "Only an active token can be rotated; rotating a revoked token can revoke its token family",
                ));
            }
            previous = Some(value);
        }
        if op.is_list() {
            let max_results = inputs["maxResults"]
                .as_u64()
                .unwrap_or(u64::from(self.config.search.max_results))
                as u32;
            let hash = sha256_serialized(&json!({"userId":user_id}));
            let page = self.page_from_token(
                inputs["pageToken"].as_str(),
                &request,
                &project,
                &hash,
                max_results,
            )?;
            let response = self
                .backend
                .provisioning(
                    project.id,
                    op,
                    GitlabProvisioningRequest {
                        user_id,
                        token_id,
                        page,
                        max_results,
                        body,
                    },
                    credential,
                )
                .await
                .map_err(|e| provisioning_failure(e, None))?;
            let items = response.value["items"]
                .as_array()
                .ok_or_else(provisioning_protocol)?;
            validate_gitlab_page_count(items.len(), max_results)?;
            let items = items
                .iter()
                .map(|v| {
                    if op.is_account() {
                        account_metadata(v, None)
                    } else {
                        token_metadata(v, None, (user_id > 0).then_some(user_id))
                    }
                })
                .collect::<Result<Vec<_>, _>>()?;
            let next = response.value["nextPage"]
                .as_u64()
                .map(u32::try_from)
                .transpose()
                .map_err(|_| provisioning_protocol())?;
            if next.is_some_and(|next| next <= page) {
                return Err(provisioning_protocol());
            }
            let next = self.next_page_token(next, &request, &project, &hash, max_results)?;
            return Ok(gitlab_result(
                action,
                &project,
                None,
                response.status,
                response.duration_ms,
                json!({"items":items,"count":items.len(),"maxResults":max_results,"isLast":next.is_none(),"nextPageToken":next}),
                self.backend.egress_proxy_audit(credential),
            ));
        }
        let audit = json!({"gitlab": {
            "operation": action,
            "project": project.path_with_namespace,
            "namespace": project.path_with_namespace.split('/').next().unwrap_or(""),
            "projectId": project.id,
            "egressProxy": self.backend.egress_proxy_audit(credential),
        }});
        let known_locators = provisioning_locators(op, user_id, token_id, &Value::Null);
        let started = Instant::now();
        let response = call(op, body.clone()).await.map_err(|e| {
            let mut error = provisioning_failure(e, (!op.is_read()).then_some(&known_locators));
            error.upstream_duration_ms = Some(elapsed_ms(started));
            error
                .with_object_ids(known_locators)
                .with_audit(audit.clone())
        })?;
        let locators = provisioning_locators(op, user_id, token_id, &response.value);
        let parsed = provisioning_result(
            op,
            &body,
            previous.as_ref(),
            &response.value,
            user_id,
            token_id,
        )
        .map_err(|error| {
            let error = if op.is_read() {
                error
            } else {
                provisioning_unverified(&locators)
            };
            error
                .with_object_ids(locators.clone())
                .with_upstream(Some(response.status), Some(response.duration_ms))
                .with_audit(audit)
        })?;
        Ok(gitlab_result(
            action,
            &project,
            Some(locators),
            response.status,
            response.duration_ms,
            parsed,
            self.backend.egress_proxy_audit(credential),
        ))
    }

    async fn find_service_account_token(
        &self,
        project_id: u64,
        user_id: u64,
        token_id: u64,
        credential: &ExecutionCredential,
    ) -> Result<Value, ProviderError> {
        let mut page = 1;
        for _ in 0..100 {
            let response = self
                .backend
                .provisioning(
                    project_id,
                    GitlabProvisioningOperation::AccountTokenList,
                    GitlabProvisioningRequest {
                        user_id,
                        page,
                        max_results: 100,
                        ..Default::default()
                    },
                    credential,
                )
                .await
                .map_err(|e| provisioning_failure(e, None))?;
            let items = response.value["items"]
                .as_array()
                .ok_or_else(provisioning_protocol)?;
            validate_gitlab_page_count(items.len(), 100)?;
            for value in items {
                if value["id"].as_u64() == Some(token_id) {
                    return Ok(value.clone());
                }
            }
            match response.value["nextPage"]
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
            {
                Some(next) if next > page => page = next,
                None => {
                    return Err(ProviderError::deny(
                        ReasonCode::ScopeUnresolved,
                        "Service account token was not found",
                    ));
                }
                _ => return Err(provisioning_protocol()),
            }
        }
        Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Service account token lookup exceeded its page bound",
        ))
    }
}

impl HttpGitlabBackend {
    pub(super) async fn provisioning_request(
        &self,
        project_id: u64,
        op: GitlabProvisioningOperation,
        request: GitlabProvisioningRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<Value>, GitlabBackendError> {
        use GitlabProvisioningOperation::*;
        let prefix = format!("projects/{project_id}");
        let account = format!("{prefix}/service_accounts/{}", request.user_id);
        let tokens = format!("{account}/personal_access_tokens");
        let path = match op {
            ProjectTokenList | ProjectTokenCreate => format!("{prefix}/access_tokens"),
            ProjectTokenView | ProjectTokenRevoke => {
                format!("{prefix}/access_tokens/{}", request.token_id)
            }
            ProjectTokenRotate => format!("{prefix}/access_tokens/{}/rotate", request.token_id),
            AccountList | AccountCreate => format!("{prefix}/service_accounts"),
            AccountView | AccountDelete => account,
            MemberView | MemberUpdate => format!("{prefix}/members/{}", request.user_id),
            MemberAdd => format!("{prefix}/members"),
            AccountTokenList | AccountTokenCreate => tokens,
            AccountTokenRotate => format!("{tokens}/{}/rotate", request.token_id),
            AccountTokenRevoke => format!("{tokens}/{}", request.token_id),
        };
        let mut url = self.endpoint(&path)?;
        if op.is_list() {
            url.query_pairs_mut()
                .append_pair("per_page", &request.max_results.to_string())
                .append_pair("page", &request.page.to_string());
            let response = self.get_json_page(op.operation(), url, credential).await?;
            return Ok(GitlabBackendResponse {
                value: json!({"items":response.value.items,"nextPage":response.value.next_page}),
                status: response.status,
                duration_ms: response.duration_ms,
            });
        }
        match op {
            ProjectTokenView | AccountView | MemberView => {
                self.get_json(op.operation(), url, credential).await
            }
            ProjectTokenRevoke | AccountTokenRevoke | AccountDelete => {
                let response = self
                    .delete_no_content(op.operation(), url, credential)
                    .await?;
                Ok(GitlabBackendResponse {
                    value: Value::Null,
                    status: response.status,
                    duration_ms: response.duration_ms,
                })
            }
            MemberUpdate => {
                self.put_json(op.operation(), url, request.body, credential)
                    .await
            }
            _ => {
                self.post_json(op.operation(), url, request.body, credential)
                    .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provisioning_operator_limits_reject_invalid_configuration() {
        let valid = GitlabProvisioningConfig::default();
        let mut errors = vec![];
        valid.validate(&mut errors);
        assert!(errors.is_empty());
        for invalid in [
            GitlabProvisioningConfig {
                max_access_level: 50,
                ..valid.clone()
            },
            GitlabProvisioningConfig {
                max_token_lifetime_days: 0,
                ..valid.clone()
            },
            GitlabProvisioningConfig {
                max_token_lifetime_days: 366,
                ..valid.clone()
            },
            GitlabProvisioningConfig {
                allowed_token_scopes: vec![],
                ..valid.clone()
            },
            GitlabProvisioningConfig {
                allowed_token_scopes: vec!["sudo".into()],
                ..valid.clone()
            },
        ] {
            let mut errors = vec![];
            invalid.validate(&mut errors);
            assert!(!errors.is_empty());
        }
    }

    #[test]
    fn provisioning_metadata_rejects_nested_secret_fields_instead_of_forwarding_them() {
        let token = json!({"id":10,"user_id":70,"name":"reviewer","scopes":["api"],"active":true,"revoked":false,"token":"issued-secret","unrecognized":{"token":"hidden-secret"}});
        let metadata = token_metadata(&token, Some(10), Some(70)).unwrap();
        assert!(!metadata.to_string().contains("secret"));
        for key in [
            "scopes",
            "name",
            "expires_at",
            "created_at",
            "last_used_at",
            "active",
            "revoked",
            "access_level",
        ] {
            let mut malformed = token.clone();
            malformed[key] = if key == "scopes" {
                json!([{"token":"hidden-secret"}])
            } else {
                json!({"token":"hidden-secret"})
            };
            assert!(
                token_metadata(&malformed, Some(10), Some(70)).is_err(),
                "{key}"
            );
        }
        assert!(token_metadata(&token, Some(11), Some(70)).is_err());
        assert!(token_metadata(&token, Some(10), Some(71)).is_err());
    }

    #[test]
    fn provisioning_write_uncertainty_uses_canonical_contract_and_read_errors_stay_distinct() {
        let locators = json!({"userId":70,"previousTokenId":10});
        for error in [
            GitlabBackendError::Transport("secret".into()),
            GitlabBackendError::Timeout,
            GitlabBackendError::Protocol("secret".into()),
            GitlabBackendError::ResponseTooLarge,
            GitlabBackendError::HttpStatus(503),
        ] {
            let failure = provisioning_failure(error, Some(&locators));
            assert_eq!(failure.reason_code, ReasonCode::MutationVerificationFailed);
            assert_eq!(failure.result.unwrap()["safeLocators"], locators);
            assert!(!failure.message.contains("secret"));
        }
        assert_eq!(
            provisioning_failure(GitlabBackendError::Timeout, None).reason_code,
            ReasonCode::UpstreamTimeout
        );
        for status in [400, 422] {
            let failure = provisioning_failure(
                GitlabBackendError::Validation {
                    status,
                    message: "secret".into(),
                },
                Some(&locators),
            );
            assert_eq!(failure.reason_code, ReasonCode::InputInvalid);
            assert_eq!(failure.upstream_status, Some(status));
            assert!(failure.result.is_none());
            assert!(!failure.message.contains("secret"));
        }
    }

    #[test]
    fn provisioning_rotation_without_new_id_never_labels_old_token_as_current() {
        for response in [Value::Null, json!({"id":10}), json!({"id":0})] {
            for op in [
                GitlabProvisioningOperation::ProjectTokenRotate,
                GitlabProvisioningOperation::AccountTokenRotate,
            ] {
                let locators = provisioning_locators(op, 70, 10, &response);
                assert_eq!(locators, json!({"userId":70,"previousTokenId":10}));
                let error = provisioning_unverified(&locators);
                assert_eq!(error.result.unwrap()["safeLocators"], locators);
            }
        }
    }

    #[test]
    fn provisioning_success_audit_locators_identify_new_account_and_rotated_token() {
        use GitlabProvisioningOperation::*;
        assert_eq!(
            provisioning_locators(AccountCreate, 0, 0, &json!({"id":70})),
            json!({"userId":70})
        );
        assert_eq!(
            provisioning_locators(ProjectTokenCreate, 0, 0, &json!({"id":10,"user_id":70})),
            json!({"userId":70,"tokenId":10})
        );
        assert_eq!(
            provisioning_locators(AccountTokenRotate, 70, 10, &json!({"id":11,"user_id":70})),
            json!({"userId":70,"tokenId":11,"previousTokenId":10})
        );
    }
}
