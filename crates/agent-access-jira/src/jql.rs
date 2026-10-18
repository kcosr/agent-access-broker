//! Search inputs, scope-bounded query building, and the bounded JQL parser.
use super::*;

// Declare the enum and its complete discovery inventory together so adding a
// grammar variant cannot silently omit it from documentation or diagnostics.
macro_rules! jql_inventory {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub(crate) enum $name { $($variant),+ }

        impl $name {
            pub(crate) const ALL: &'static [Self] = &[$(Self::$variant),+];
        }
    };
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SearchInputs {
    pub(crate) query: JiraSearchQueryInput,
    pub(crate) projects: Option<Vec<String>>,
    pub(crate) max_results: Option<u32>,
    pub(crate) next_page_token: Option<String>,
}

pub(crate) const MAX_JIRA_TEXT_QUERY_BYTES: usize = 512;
pub(crate) const MAX_JIRA_RAW_QUERY_BYTES: usize = 4096;
pub(crate) const MAX_JIRA_QUERY_DEPTH: usize = 32;
pub(crate) const MAX_JIRA_QUERY_TOKENS: usize = 512;
pub(crate) const MAX_JIRA_IN_LIST_VALUES: usize = 100;
pub(crate) const MAX_JIRA_STRING_LITERAL_BYTES: usize = 512;
pub(crate) const MAX_JIRA_ORDER_TERMS: usize = 5;
pub(crate) const JIRA_QUERY_AST_VERSION: u32 = 2;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum JiraSearchQueryInput {
    Jql { value: String },
    Text { value: String },
}

/// Extended grammar guidance stays out of the initial MCP input schema.
pub(crate) fn jql_documentation() -> Value {
    json!({
        "jql": {
            "fields": JqlField::ALL.iter().map(|field| json!({
                "name": field.canonical(), "operators": field.operator_names(),
            })).collect::<Vec<_>>(),
            "aliases": JqlField::alias_documentation(),
            "functions": JqlFunctionName::ALL.iter().map(|function| json!({
                "name": function.canonical(),
                "fields": JqlField::ALL.iter().filter(|field| if function.is_date() { field.is_date() } else { field.is_user() }).map(|field| field.canonical()).collect::<Vec<_>>(),
                "arguments": if matches!(function, JqlFunctionName::CurrentUser | JqlFunctionName::Now) { "none" } else { "zero or one unquoted relative offset, e.g. -7d" },
                "credentialModes": if matches!(function, JqlFunctionName::CurrentUser) { vec!["per_user"] } else { vec!["service", "per_user"] },
            })).collect::<Vec<_>>(),
            "orderBy": {"fields": JqlSortField::ALL.iter().map(|field| field.canonical()).collect::<Vec<_>>(), "aliases": JqlSortField::alias_documentation(), "directions": ["ASC", "DESC"], "defaultDirection": "ASC", "maxTerms": MAX_JIRA_ORDER_TERMS},
            "grouping": "AND, OR, and parentheses; mixed AND/OR requires explicit grouping. Prefix NOT, history predicates, text negation, custom fields, and nested functions are unsupported.",
            "values": "Text operands must be quoted. Bare identifiers use ASCII letters, digits, underscore, hyphen, or dot; quote other values. Single or double quotes delimit ASCII strings, with only the matching quote and backslash escapable; non-ASCII and control characters are rejected. Dates accept YYYY-MM-DD or quoted YYYY/MM/DD, optionally with HH:mm in a quoted string; relative dates use a sign, positive integer, and m/h/d/w, e.g. -7d. Function offsets must be unquoted. Project and issue keys must be canonical uppercase keys; project keys may contain underscores, e.g. OPS_TOOLS and OPS_TOOLS-12345.",
            "scope": "Omit projects to use effective broker authorization, including token restrictions and exclusions. Explicit projects must be authorized and only narrow access. Finite scopes inject project IN; all except injects project NOT IN; unrestricted all adds no project predicate. Returned issues are checked against the authorized boundary, not against named projects: Jira resolves a previous project key to the renamed project.",
            "emptyFilter": "Empty or ORDER BY-only JQL browses a finite authorized project set. With all-project or all-except access, supply explicit projects or a filter such as updated >= -7d: Jira enhanced search requires a bounded query, and exclusions alone are not treated as a sufficient bound.",
            "limits": {"rawQueryBytes": MAX_JIRA_RAW_QUERY_BYTES, "tokens": MAX_JIRA_QUERY_TOKENS, "depth": MAX_JIRA_QUERY_DEPTH, "inListValues": MAX_JIRA_IN_LIST_VALUES, "stringLiteralBytes": MAX_JIRA_STRING_LITERAL_BYTES, "textQueryBytes": MAX_JIRA_TEXT_QUERY_BYTES},
            "errors": "Invalid syntax, unsupported grammar, and query caps return input_invalid. Parser diagnostics report token positions and supported choices without echoing query literals. Scope authorization and returned-issue containment errors remain distinct."
        },
        "text": "A nonempty text query becomes key = value for a valid issue key, otherwise text ~ quoted-value; it uses the same authorization containment.",
        "pagination": "maxResults is a positive integer capped by broker configuration. nextPageToken is an opaque broker-signed continuation: pass it back unchanged with the same query, projects, and maxResults in the same execution context. It is bound to the principal, credential mode, and Jira configuration, and expires after 15 minutes or when the broker reloads. Effective authorization is checked on every request; if the effective project scope changed since the token was issued, repeat the search without nextPageToken.",
        "examples": [
            {"query": {"type": "jql", "value": "ORDER BY updated DESC"}},
            {"query": {"type": "jql", "value": ""}, "projects": ["PROJ"]},
            {"query": {"type": "jql", "value": "status = Done ORDER BY updated DESC"}},
            {"query": {"type": "jql", "value": "updated >= startOfDay(-7d) ORDER BY updated DESC, key"}},
            {"query": {"type": "text", "value": "release notes"}, "maxResults": 10}
        ]
    })
}

pub(crate) fn parse_search_inputs(inputs: &Value) -> Result<SearchInputs, ProviderError> {
    let inputs: SearchInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(ReasonCode::InputInvalid, "jira.search inputs are invalid")
    })?;
    // The continuation's size bound follows the configured limits and is
    // enforced when the continuation is opened.
    if inputs
        .next_page_token
        .as_ref()
        .is_some_and(String::is_empty)
    {
        return Err(search_page_token_invalid());
    }
    Ok(inputs)
}

pub(crate) fn requested_projects(inputs: &SearchInputs) -> Result<BTreeSet<String>, ProviderError> {
    let mut projects = BTreeSet::new();
    if let Some(values) = &inputs.projects {
        if values.is_empty() {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "jira.search projects must not be empty",
            ));
        }
        for project in values {
            projects.insert(validate_project_key(project)?);
        }
    }
    Ok(projects)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EffectiveSearchScope {
    Finite(BTreeSet<String>),
    AllExcept(BTreeSet<String>),
}

impl EffectiveSearchScope {
    pub(crate) fn values_for_backend(&self) -> Vec<String> {
        match self {
            Self::Finite(values) => values.iter().cloned().collect(),
            Self::AllExcept(_) => Vec::new(),
        }
    }

    pub(crate) fn authorizes_value(&self, value: &str) -> bool {
        match self {
            Self::Finite(values) => values.contains(value),
            Self::AllExcept(excluded) => !excluded.contains(value),
        }
    }

    pub(crate) fn audit_value(&self, scope_type: &str) -> Value {
        match self {
            Self::Finite(values) => json!({
                "type": "finite",
                "scopeType": scope_type,
                "values": values,
            }),
            Self::AllExcept(excluded) => json!({
                "type": "all_except",
                "scopeType": scope_type,
                "excludedValues": excluded,
            }),
        }
    }
}

#[derive(Debug)]
pub(crate) struct BuiltJiraSearchQuery {
    pub(crate) jql: String,
    pub(crate) kind: &'static str,
    pub(crate) injected_scope_predicate: &'static str,
    /// The caller's query re-emitted canonically, before scope composition.
    /// Continuations bind it; diagnostics carry only its hash.
    pub(crate) canonical_caller_jql: String,
    pub(crate) canonical_caller_jql_hash: String,
    pub(crate) query_shape: Value,
    pub(crate) text_operand_hashes: Vec<String>,
    pub(crate) sort_fields: Vec<Value>,
}

pub(crate) fn search_authorization(
    request: &ProviderInvocation,
) -> Result<SearchAuthorization, ProviderError> {
    request.authority().search().cloned().ok_or_else(|| {
        ProviderError::deny(
            ReasonCode::ServiceActionDenied,
            "search authorization is unavailable",
        )
    })
}

/// The authorized project boundary: the finite projects or the all-except
/// exclusions the host admitted, with token restrictions already applied.
/// Returned issues are checked against it, never against the caller's own
/// project names: Jira resolves a previous project key in `projects` or JQL to
/// the renamed project, whose issues carry its current key.
pub(crate) fn authorized_search_scope(
    authorization: &SearchAuthorization,
) -> Result<EffectiveSearchScope, ProviderError> {
    if authorization.scope_type != "project" {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Jira search authorization used an invalid scope type",
        ));
    }
    match authorization.scope.exact_projection()? {
        agent_access_provider::ExactSearchProjection::Finite { values } => {
            let allowed = values.iter().cloned().collect::<BTreeSet<_>>();
            if allowed.is_empty() {
                return Err(ProviderError::deny(
                    ReasonCode::ServiceActionDenied,
                    "Jira search policy scope is empty",
                ));
            }
            Ok(EffectiveSearchScope::Finite(allowed))
        }
        agent_access_provider::ExactSearchProjection::AllExcept { excluded_values } => Ok(
            EffectiveSearchScope::AllExcept(excluded_values.iter().cloned().collect()),
        ),
        _ => Err(agent_access_provider::SearchProjectionError.into()),
    }
}

/// The scope the upstream query is composed with: the authorized boundary,
/// narrowed to explicit `projects`, which must each be authorized.
pub(crate) fn effective_search_scope(
    authorization: &SearchAuthorization,
    requested: &BTreeSet<String>,
) -> Result<EffectiveSearchScope, ProviderError> {
    let authorized = authorized_search_scope(authorization)?;
    if requested.is_empty() {
        return Ok(authorized);
    }
    if !requested
        .iter()
        .all(|project| authorized.authorizes_value(project))
    {
        return Err(ProviderError::deny(
            ReasonCode::ServiceActionDenied,
            "requested Jira projects are not authorized",
        ));
    }
    Ok(EffectiveSearchScope::Finite(requested.clone()))
}

pub(crate) fn build_jira_search_query(
    query: &JiraSearchQueryInput,
    effective_scope: &EffectiveSearchScope,
    limits: &SearchLimitsConfig,
    credential_mode: CredentialMode,
) -> Result<BuiltJiraSearchQuery, ProviderError> {
    let (ast, kind) = match query {
        JiraSearchQueryInput::Jql { value } => (parse_jql_query(value, credential_mode)?, "jql"),
        JiraSearchQueryInput::Text { value } => (jira_text_query(value, limits)?, "text"),
    };
    let caller_jql = ast.emit();
    // Jira enhanced search rejects unbounded queries. A negative exclusion alone
    // is not a positive bound, so scope-only browsing needs a finite selection.
    if ast.filter.is_none() && matches!(effective_scope, EffectiveSearchScope::AllExcept(_)) {
        return Err(jql_input_invalid(
            "Jira enhanced search requires a filter or explicit projects when access covers all projects (including all except exclusions); provide projects or a filter such as updated >= -7d",
        ));
    }
    let filter_jql = ast.filter.as_ref().map(JqlExpr::emit);
    let order_by_jql = ast.emit_order_by();
    let (jql, injected_scope_predicate) =
        match effective_scope {
            EffectiveSearchScope::Finite(projects) => {
                let predicate = jira_project_predicate(projects.iter().map(String::as_str));
                let mut jql = match &filter_jql {
                    Some(filter) => format!("({filter}) AND {predicate}"),
                    None => predicate,
                };
                if !order_by_jql.is_empty() {
                    jql.push(' ');
                    jql.push_str(&order_by_jql);
                }
                (jql, "project_in")
            }
            EffectiveSearchScope::AllExcept(excluded) if excluded.is_empty() => {
                (caller_jql.clone(), "none")
            }
            EffectiveSearchScope::AllExcept(excluded) => {
                let predicate = jira_project_predicate(excluded.iter().map(String::as_str))
                    .replacen(" IN (", " NOT IN (", 1);
                let mut jql = match &filter_jql {
                    Some(filter) => format!("({filter}) AND {predicate}"),
                    None => predicate,
                };
                if !order_by_jql.is_empty() {
                    jql.push(' ');
                    jql.push_str(&order_by_jql);
                }
                (jql, "project_not_in")
            }
        };
    let query_shape = ast.query_shape();
    let text_operand_hashes = ast.text_operand_hashes();
    let sort_fields = ast.sort_fields();
    Ok(BuiltJiraSearchQuery {
        jql,
        kind,
        injected_scope_predicate,
        canonical_caller_jql_hash: sha256_hex(caller_jql.as_bytes()),
        canonical_caller_jql: caller_jql,
        query_shape,
        text_operand_hashes,
        sort_fields,
    })
}

pub(crate) fn jira_text_query(
    raw: &str,
    _limits: &SearchLimitsConfig,
) -> Result<JqlQueryAst, ProviderError> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.search text query must not be empty",
        ));
    }
    if value.len() > MAX_JIRA_TEXT_QUERY_BYTES {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.search text query exceeded the byte cap",
        ));
    }
    validate_jql_string_value(value).map_err(|message| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            format!("jira.search text query {message}"),
        )
    })?;
    let clause = if is_issue_key(value) {
        JqlClause {
            field: JqlField::Key,
            operator: JqlOperator::Eq,
            operand: JqlOperand::Single(JqlValue::Identifier(value.to_string())),
        }
    } else {
        JqlClause {
            field: JqlField::Text,
            operator: JqlOperator::Contains,
            operand: JqlOperand::Single(JqlValue::String(value.to_string())),
        }
    };
    Ok(JqlQueryAst {
        filter: Some(JqlExpr::Clause(clause)),
        order_by: Vec::new(),
    })
}

pub(crate) fn jira_project_predicate<'a>(projects: impl Iterator<Item = &'a str>) -> String {
    let projects = projects
        .map(jql_bare_or_string_literal)
        .collect::<Vec<_>>()
        .join(", ");
    format!("project IN ({projects})")
}

pub(crate) fn jql_string_literal(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for ch in value.chars() {
        if ch == '"' || ch == '\\' {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped.push('"');
    escaped
}

pub(crate) fn jql_bare_or_string_literal(value: &str) -> String {
    if is_safe_jql_bare_operand(value) {
        value.to_string()
    } else {
        jql_string_literal(value)
    }
}

pub(crate) fn capped_max_results(
    requested: Option<u32>,
    limits: &SearchLimitsConfig,
) -> Result<u32, ProviderError> {
    let requested = requested.unwrap_or(limits.max_results);
    if requested == 0 {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.search maxResults must be greater than zero",
        ));
    }
    Ok(requested.min(limits.max_results))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JqlToken {
    Word(String),
    String(String),
    Eq,
    NotEq,
    Lt,
    Lte,
    Gt,
    Gte,
    Tilde,
    NotTilde,
    Comma,
    LParen,
    RParen,
}

#[cfg(test)]
pub(crate) fn parse_jql_projects(jql: &str) -> Result<BTreeSet<String>, ProviderError> {
    parse_jql_expression(jql).map(|parsed| parsed.projects)
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedJqlExpression {
    pub(crate) expression: String,
    pub(crate) projects: BTreeSet<String>,
}

#[cfg(test)]
pub(crate) fn parse_jql_expression(jql: &str) -> Result<ParsedJqlExpression, ProviderError> {
    let ast = parse_jql_query(jql, CredentialMode::Service)?;
    Ok(ParsedJqlExpression {
        expression: ast.emit(),
        projects: ast.projects(),
    })
}

pub(crate) fn parse_jql_query(
    jql: &str,
    credential_mode: CredentialMode,
) -> Result<JqlQueryAst, ProviderError> {
    if jql.len() > MAX_JIRA_RAW_QUERY_BYTES {
        return Err(jql_input_invalid("JQL exceeded the byte cap"));
    }
    let jql = jql.trim();
    let tokens = tokenize_jql(jql).map_err(jql_input_invalid)?;
    if tokens.len() > MAX_JIRA_QUERY_TOKENS {
        return Err(jql_input_invalid("JQL exceeded the token cap"));
    }
    let mut parser = JqlParser {
        tokens,
        index: 0,
        credential_mode,
    };
    let ast = parser.parse_query().map_err(|message| {
        jql_input_invalid(format!("{message} (near token {})", parser.index.max(1)))
    })?;
    if parser.index != parser.tokens.len() {
        return Err(jql_input_invalid("JQL contains trailing tokens"));
    }
    Ok(ast)
}

pub(crate) fn jql_input_invalid(message: impl Into<String>) -> ProviderError {
    ProviderError::deny(ReasonCode::InputInvalid, message.into())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JqlQueryAst {
    pub(crate) filter: Option<JqlExpr>,
    pub(crate) order_by: Vec<JqlOrderTerm>,
}

impl JqlQueryAst {
    pub(crate) fn emit(&self) -> String {
        let mut emitted = self.filter.as_ref().map(JqlExpr::emit).unwrap_or_default();
        let order_by = self.emit_order_by();
        if !order_by.is_empty() {
            if !emitted.is_empty() {
                emitted.push(' ');
            }
            emitted.push_str(&order_by);
        }
        emitted
    }

    pub(crate) fn emit_order_by(&self) -> String {
        if self.order_by.is_empty() {
            return String::new();
        }
        let terms = self
            .order_by
            .iter()
            .map(JqlOrderTerm::emit)
            .collect::<Vec<_>>()
            .join(", ");
        format!("ORDER BY {terms}")
    }

    #[cfg(test)]
    pub(crate) fn projects(&self) -> BTreeSet<String> {
        let mut projects = BTreeSet::new();
        if let Some(filter) = &self.filter {
            filter.collect_projects(&mut projects);
        }
        projects
    }

    pub(crate) fn query_shape(&self) -> Value {
        json!({
            "filter": self.filter.as_ref().map(JqlExpr::shape),
            "orderBy": self.sort_fields(),
        })
    }

    pub(crate) fn text_operand_hashes(&self) -> Vec<String> {
        let mut hashes = Vec::new();
        if let Some(filter) = &self.filter {
            filter.collect_text_operand_hashes(&mut hashes);
        }
        hashes
    }

    pub(crate) fn sort_fields(&self) -> Vec<Value> {
        self.order_by
            .iter()
            .map(|term| {
                json!({
                    "field": term.field.canonical(),
                    "direction": term.direction.as_str(),
                })
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JqlExpr {
    Clause(JqlClause),
    And(Vec<JqlExpr>),
    Or(Vec<JqlExpr>),
}

impl JqlExpr {
    pub(crate) fn emit(&self) -> String {
        match self {
            Self::Clause(clause) => clause.emit(),
            Self::And(children) => children
                .iter()
                .map(|child| child.emit_for_parent())
                .collect::<Vec<_>>()
                .join(" AND "),
            Self::Or(children) => children
                .iter()
                .map(|child| child.emit_for_parent())
                .collect::<Vec<_>>()
                .join(" OR "),
        }
    }

    pub(crate) fn emit_for_parent(&self) -> String {
        match self {
            Self::Clause(_) => self.emit(),
            Self::And(_) | Self::Or(_) => format!("({})", self.emit()),
        }
    }

    #[cfg(test)]
    pub(crate) fn collect_projects(&self, projects: &mut BTreeSet<String>) {
        match self {
            Self::Clause(clause) => clause.collect_projects(projects),
            Self::And(children) | Self::Or(children) => {
                for child in children {
                    child.collect_projects(projects);
                }
            }
        }
    }

    pub(crate) fn collect_text_operand_hashes(&self, hashes: &mut Vec<String>) {
        match self {
            Self::Clause(clause) => clause.collect_text_operand_hashes(hashes),
            Self::And(children) | Self::Or(children) => {
                for child in children {
                    child.collect_text_operand_hashes(hashes);
                }
            }
        }
    }

    pub(crate) fn shape(&self) -> Value {
        match self {
            Self::Clause(clause) => clause.shape(),
            Self::And(children) => json!({
                "type": "and",
                "children": children.iter().map(JqlExpr::shape).collect::<Vec<_>>(),
            }),
            Self::Or(children) => json!({
                "type": "or",
                "children": children.iter().map(JqlExpr::shape).collect::<Vec<_>>(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JqlClause {
    pub(crate) field: JqlField,
    pub(crate) operator: JqlOperator,
    pub(crate) operand: JqlOperand,
}

impl JqlClause {
    pub(crate) fn emit(&self) -> String {
        match &self.operand {
            JqlOperand::Single(value) => {
                format!(
                    "{} {} {}",
                    self.field.canonical(),
                    self.operator.emit(),
                    value.emit_for_field(self.field)
                )
            }
            JqlOperand::List(values) => {
                let values = values
                    .iter()
                    .map(|value| value.emit_for_field(self.field))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    "{} {} ({values})",
                    self.field.canonical(),
                    self.operator.emit()
                )
            }
            JqlOperand::Empty => format!("{} {}", self.field.canonical(), self.operator.emit()),
        }
    }

    #[cfg(test)]
    pub(crate) fn collect_projects(&self, projects: &mut BTreeSet<String>) {
        match (&self.field, &self.operator, &self.operand) {
            (JqlField::Project, JqlOperator::Eq, JqlOperand::Single(value)) => {
                if let Some(project) = value.identifier() {
                    projects.insert(project.to_string());
                }
            }
            (JqlField::Project, JqlOperator::In, JqlOperand::List(values)) => {
                projects.extend(
                    values
                        .iter()
                        .filter_map(JqlValue::identifier)
                        .map(str::to_string),
                );
            }
            (JqlField::Key, JqlOperator::Eq, JqlOperand::Single(value)) => {
                if let Some(key) = value.identifier() {
                    projects.insert(issue_key_project(key));
                }
            }
            (JqlField::Key, JqlOperator::In, JqlOperand::List(values)) => {
                projects.extend(
                    values
                        .iter()
                        .filter_map(JqlValue::identifier)
                        .map(issue_key_project),
                );
            }
            _ => {}
        }
    }

    pub(crate) fn collect_text_operand_hashes(&self, hashes: &mut Vec<String>) {
        if self.operator == JqlOperator::Contains
            && let JqlOperand::Single(JqlValue::String(value)) = &self.operand
        {
            hashes.push(sha256_hex(value.as_bytes()));
        }
    }

    pub(crate) fn shape(&self) -> Value {
        json!({
            "type": "clause",
            "field": self.field.canonical(),
            "operator": self.operator.shape_name(),
            "operand": self.operand.shape(),
        })
    }
}

jql_inventory! {
    JqlField {
        Project,
        Key,
        Status,
        StatusCategory,
        IssueType,
        Priority,
        Resolution,
        Assignee,
        Reporter,
        Creator,
        Labels,
        Component,
        FixVersion,
        AffectedVersion,
        Created,
        Updated,
        ResolutionDate,
        DueDate,
        Summary,
        Description,
        Text,
    }
}

impl JqlField {
    pub(crate) fn from_input(value: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|field| {
            field.canonical().eq_ignore_ascii_case(value)
                || field
                    .aliases()
                    .iter()
                    .any(|alias| alias.eq_ignore_ascii_case(value))
        })
    }

    pub(crate) fn aliases(self) -> &'static [&'static str] {
        match self {
            Self::Project => &[],
            Self::Key => &["issuekey"],
            Self::Status => &[],
            Self::StatusCategory => &[],
            Self::IssueType => &["type"],
            Self::Priority => &[],
            Self::Resolution => &[],
            Self::Assignee => &[],
            Self::Reporter => &[],
            Self::Creator => &[],
            Self::Labels => &["label"],
            Self::Component => &["components"],
            Self::FixVersion => &["fixVersions"],
            Self::AffectedVersion => &["affectedVersions"],
            Self::Created => &[],
            Self::Updated => &[],
            Self::ResolutionDate => &[],
            Self::DueDate => &[],
            Self::Summary => &[],
            Self::Description => &[],
            Self::Text => &[],
        }
    }

    fn alias_documentation() -> Value {
        Value::Object(
            Self::ALL
                .iter()
                .flat_map(|field| {
                    field
                        .aliases()
                        .iter()
                        .map(|alias| ((*alias).to_string(), json!(field.canonical())))
                })
                .collect(),
        )
    }

    pub(crate) fn canonical(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::Key => "key",
            Self::Status => "status",
            Self::StatusCategory => "statusCategory",
            Self::IssueType => "issuetype",
            Self::Priority => "priority",
            Self::Resolution => "resolution",
            Self::Assignee => "assignee",
            Self::Reporter => "reporter",
            Self::Creator => "creator",
            Self::Labels => "labels",
            Self::Component => "component",
            Self::FixVersion => "fixVersion",
            Self::AffectedVersion => "affectedVersion",
            Self::Created => "created",
            Self::Updated => "updated",
            Self::ResolutionDate => "resolutiondate",
            Self::DueDate => "duedate",
            Self::Summary => "summary",
            Self::Description => "description",
            Self::Text => "text",
        }
    }

    pub(crate) fn allows_operator(self, operator: JqlOperator) -> bool {
        match self {
            Self::Project | Self::Key => matches!(operator, JqlOperator::Eq | JqlOperator::In),
            Self::Status | Self::StatusCategory | Self::IssueType | Self::Priority => matches!(
                operator,
                JqlOperator::Eq | JqlOperator::NotEq | JqlOperator::In | JqlOperator::NotIn
            ),
            Self::Resolution => matches!(
                operator,
                JqlOperator::Eq
                    | JqlOperator::NotEq
                    | JqlOperator::In
                    | JqlOperator::NotIn
                    | JqlOperator::IsEmpty
                    | JqlOperator::IsNotEmpty
            ),
            Self::Assignee => matches!(
                operator,
                JqlOperator::Eq
                    | JqlOperator::NotEq
                    | JqlOperator::In
                    | JqlOperator::NotIn
                    | JqlOperator::IsEmpty
                    | JqlOperator::IsNotEmpty
            ),
            Self::Reporter | Self::Creator => matches!(
                operator,
                JqlOperator::Eq | JqlOperator::NotEq | JqlOperator::In | JqlOperator::NotIn
            ),
            Self::Labels | Self::Component | Self::FixVersion | Self::AffectedVersion => matches!(
                operator,
                JqlOperator::Eq
                    | JqlOperator::NotEq
                    | JqlOperator::In
                    | JqlOperator::NotIn
                    | JqlOperator::IsEmpty
                    | JqlOperator::IsNotEmpty
            ),
            Self::Created | Self::Updated | Self::ResolutionDate | Self::DueDate => matches!(
                operator,
                JqlOperator::Eq
                    | JqlOperator::NotEq
                    | JqlOperator::Lt
                    | JqlOperator::Lte
                    | JqlOperator::Gt
                    | JqlOperator::Gte
            ),
            Self::Summary | Self::Description | Self::Text => operator == JqlOperator::Contains,
        }
    }

    pub(crate) fn operator_names(self) -> Vec<&'static str> {
        JqlOperator::ALL
            .iter()
            .copied()
            .filter(|operator| self.allows_operator(*operator))
            .map(JqlOperator::emit)
            .collect()
    }

    pub(crate) fn is_user(self) -> bool {
        matches!(self, Self::Assignee | Self::Reporter | Self::Creator)
    }

    pub(crate) fn is_date(self) -> bool {
        matches!(
            self,
            Self::Created | Self::Updated | Self::ResolutionDate | Self::DueDate
        )
    }

    pub(crate) fn is_text(self) -> bool {
        matches!(self, Self::Summary | Self::Description | Self::Text)
    }
}

jql_inventory! {
    JqlOperator {
        Eq,
        NotEq,
        Lt,
        Lte,
        Gt,
        Gte,
        In,
        NotIn,
        IsEmpty,
        IsNotEmpty,
        Contains,
    }
}

impl JqlOperator {
    pub(crate) fn emit(self) -> &'static str {
        match self {
            Self::Eq => "=",
            Self::NotEq => "!=",
            Self::Lt => "<",
            Self::Lte => "<=",
            Self::Gt => ">",
            Self::Gte => ">=",
            Self::In => "IN",
            Self::NotIn => "NOT IN",
            Self::IsEmpty => "IS EMPTY",
            Self::IsNotEmpty => "IS NOT EMPTY",
            Self::Contains => "~",
        }
    }

    pub(crate) fn shape_name(self) -> &'static str {
        self.emit()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JqlOperand {
    Single(JqlValue),
    List(Vec<JqlValue>),
    Empty,
}

impl JqlOperand {
    pub(crate) fn shape(&self) -> Value {
        match self {
            Self::Single(value) => json!({
                "type": "single",
                "value": value.shape(),
            }),
            Self::List(values) => json!({
                "type": "list",
                "count": values.len(),
                "values": values.iter().map(JqlValue::shape).collect::<Vec<_>>(),
            }),
            Self::Empty => json!({
                "type": "empty",
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JqlValue {
    Identifier(String),
    String(String),
    Date(String),
    Function(JqlFunction),
}

impl JqlValue {
    pub(crate) fn emit_for_field(&self, field: JqlField) -> String {
        match self {
            Self::Identifier(value) => jql_bare_or_string_literal(value),
            Self::Date(value) if is_safe_jql_bare_date(value) => value.clone(),
            Self::Date(value) => jql_string_literal(value),
            Self::String(value) if field.is_text() => jql_string_literal(value),
            Self::String(value) => jql_bare_or_string_literal(value),
            Self::Function(function) => function.emit(),
        }
    }

    #[cfg(test)]
    pub(crate) fn identifier(&self) -> Option<&str> {
        match self {
            Self::Identifier(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn shape(&self) -> Value {
        match self {
            Self::Identifier(_) => json!({ "type": "identifier" }),
            Self::String(_) => json!({ "type": "string" }),
            Self::Date(_) => json!({ "type": "date" }),
            Self::Function(function) => json!({
                "type": "function",
                "name": function.name.canonical(),
                "args": function.args.iter().map(JqlFunctionArg::shape).collect::<Vec<_>>(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JqlFunction {
    pub(crate) name: JqlFunctionName,
    pub(crate) args: Vec<JqlFunctionArg>,
}

impl JqlFunction {
    pub(crate) fn emit(&self) -> String {
        let args = self
            .args
            .iter()
            .map(JqlFunctionArg::emit)
            .collect::<Vec<_>>()
            .join(", ");
        format!("{}({args})", self.name.canonical())
    }
}

jql_inventory! {
    JqlFunctionName {
        CurrentUser,
        Now,
        StartOfDay,
        EndOfDay,
        StartOfWeek,
        EndOfWeek,
        StartOfMonth,
        EndOfMonth,
        StartOfYear,
        EndOfYear,
    }
}

impl JqlFunctionName {
    pub(crate) fn from_input(value: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|function| function.canonical().eq_ignore_ascii_case(value))
    }

    pub(crate) fn canonical(self) -> &'static str {
        match self {
            Self::CurrentUser => "currentUser",
            Self::Now => "now",
            Self::StartOfDay => "startOfDay",
            Self::EndOfDay => "endOfDay",
            Self::StartOfWeek => "startOfWeek",
            Self::EndOfWeek => "endOfWeek",
            Self::StartOfMonth => "startOfMonth",
            Self::EndOfMonth => "endOfMonth",
            Self::StartOfYear => "startOfYear",
            Self::EndOfYear => "endOfYear",
        }
    }

    pub(crate) fn is_date(self) -> bool {
        !matches!(self, Self::CurrentUser)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JqlFunctionArg {
    RelativeDate(String),
}

impl JqlFunctionArg {
    pub(crate) fn emit(&self) -> String {
        match self {
            Self::RelativeDate(value) => value.clone(),
        }
    }

    pub(crate) fn shape(&self) -> Value {
        match self {
            Self::RelativeDate(_) => json!({ "type": "relativeDate" }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JqlOrderTerm {
    pub(crate) field: JqlSortField,
    pub(crate) direction: SortDirection,
}

impl JqlOrderTerm {
    pub(crate) fn emit(&self) -> String {
        format!("{} {}", self.field.canonical(), self.direction.as_str())
    }
}

jql_inventory! {
    JqlSortField {
        Created,
        Updated,
        Priority,
        Status,
        IssueType,
        Key,
    }
}

impl JqlSortField {
    pub(crate) fn from_input(value: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|field| {
            field.canonical().eq_ignore_ascii_case(value)
                || field
                    .aliases()
                    .iter()
                    .any(|alias| alias.eq_ignore_ascii_case(value))
        })
    }

    pub(crate) fn aliases(self) -> &'static [&'static str] {
        match self {
            Self::Created => &[],
            Self::Updated => &[],
            Self::Priority => &[],
            Self::Status => &[],
            Self::IssueType => &["type"],
            Self::Key => &["issuekey"],
        }
    }

    fn alias_documentation() -> Value {
        Value::Object(
            Self::ALL
                .iter()
                .flat_map(|field| {
                    field
                        .aliases()
                        .iter()
                        .map(|alias| ((*alias).to_string(), json!(field.canonical())))
                })
                .collect(),
        )
    }

    pub(crate) fn canonical(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Updated => "updated",
            Self::Priority => "priority",
            Self::Status => "status",
            Self::IssueType => "issuetype",
            Self::Key => "key",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SortDirection {
    Asc,
    Desc,
}

impl SortDirection {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Asc => "ASC",
            Self::Desc => "DESC",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JqlBooleanOperator {
    And,
    Or,
}

pub(crate) struct JqlParser {
    pub(crate) tokens: Vec<JqlToken>,
    pub(crate) index: usize,
    pub(crate) credential_mode: CredentialMode,
}

impl JqlParser {
    pub(crate) fn parse_query(&mut self) -> Result<JqlQueryAst, String> {
        let filter = if self.tokens.is_empty() || self.peek_keyword("ORDER") {
            None
        } else {
            Some(self.parse_expr(0)?)
        };
        let order_by = if self.peek_keyword("ORDER") {
            self.parse_order_by()?
        } else {
            Vec::new()
        };
        Ok(JqlQueryAst { filter, order_by })
    }

    pub(crate) fn parse_expr(&mut self, depth: usize) -> Result<JqlExpr, String> {
        if depth > MAX_JIRA_QUERY_DEPTH {
            return Err("JQL nesting is too deep".to_string());
        }
        let first = self.parse_factor(depth)?;
        let mut children = vec![first];
        let mut operator: Option<JqlBooleanOperator> = None;
        while let Some(word) = self.peek_word() {
            if !word.eq_ignore_ascii_case("AND") && !word.eq_ignore_ascii_case("OR") {
                break;
            }
            let next_operator = if word.eq_ignore_ascii_case("AND") {
                JqlBooleanOperator::And
            } else {
                JqlBooleanOperator::Or
            };
            if let Some(previous) = &operator
                && previous != &next_operator
            {
                return Err("JQL mixes AND and OR without explicit grouping".to_string());
            }
            operator = Some(next_operator);
            self.index += 1;
            let rhs = self.parse_factor(depth)?;
            children.push(rhs);
        }
        match operator {
            None => Ok(children.remove(0)),
            Some(JqlBooleanOperator::And) => Ok(JqlExpr::And(children)),
            Some(JqlBooleanOperator::Or) => Ok(JqlExpr::Or(children)),
        }
    }

    pub(crate) fn parse_factor(&mut self, depth: usize) -> Result<JqlExpr, String> {
        if self.peek_keyword("NOT") {
            return Err("JQL prefix NOT is unsupported".to_string());
        }
        if self.consume(&JqlToken::LParen) {
            if depth >= MAX_JIRA_QUERY_DEPTH {
                return Err("JQL nesting is too deep".to_string());
            }
            let parsed = self.parse_expr(depth + 1)?;
            if !self.consume(&JqlToken::RParen) {
                return Err("JQL group is missing a closing parenthesis".to_string());
            }
            Ok(parsed)
        } else {
            self.parse_clause()
        }
    }

    pub(crate) fn parse_clause(&mut self) -> Result<JqlExpr, String> {
        let Some(field) = self.next_word() else {
            return Err("JQL clause is missing a field".to_string());
        };
        let field = JqlField::from_input(&field).ok_or_else(|| {
            format!(
                "JQL field is unsupported; supported fields: {}",
                JqlField::ALL
                    .iter()
                    .map(|field| field.canonical())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;
        let (operator, operand) = if self.consume(&JqlToken::Eq) {
            (JqlOperator::Eq, JqlOperand::Single(self.next_value(field)?))
        } else if self.consume(&JqlToken::NotEq) {
            (
                JqlOperator::NotEq,
                JqlOperand::Single(self.next_value(field)?),
            )
        } else if self.consume(&JqlToken::Lt) {
            (JqlOperator::Lt, JqlOperand::Single(self.next_value(field)?))
        } else if self.consume(&JqlToken::Lte) {
            (
                JqlOperator::Lte,
                JqlOperand::Single(self.next_value(field)?),
            )
        } else if self.consume(&JqlToken::Gt) {
            (JqlOperator::Gt, JqlOperand::Single(self.next_value(field)?))
        } else if self.consume(&JqlToken::Gte) {
            (
                JqlOperator::Gte,
                JqlOperand::Single(self.next_value(field)?),
            )
        } else if self.consume(&JqlToken::Tilde) {
            (
                JqlOperator::Contains,
                JqlOperand::Single(self.next_text_value()?),
            )
        } else if self.consume(&JqlToken::NotTilde) {
            return Err("JQL text negation is unsupported".to_string());
        } else {
            let Some(operator) = self.next_word() else {
                return Err("JQL clause is missing an operator".to_string());
            };
            if operator.eq_ignore_ascii_case("IN") {
                (
                    JqlOperator::In,
                    JqlOperand::List(self.next_value_list(field)?),
                )
            } else if operator.eq_ignore_ascii_case("NOT") {
                let Some(in_keyword) = self.next_word() else {
                    return Err("JQL NOT IN operator is invalid".to_string());
                };
                if !in_keyword.eq_ignore_ascii_case("IN") {
                    return Err("JQL prefix NOT is unsupported".to_string());
                }
                (
                    JqlOperator::NotIn,
                    JqlOperand::List(self.next_value_list(field)?),
                )
            } else if operator.eq_ignore_ascii_case("IS") {
                let is_not = if self.peek_keyword("NOT") {
                    self.index += 1;
                    true
                } else {
                    false
                };
                let Some(empty_keyword) = self.next_word() else {
                    return Err("JQL IS operator is invalid".to_string());
                };
                if !empty_keyword.eq_ignore_ascii_case("EMPTY") {
                    return Err("JQL IS operator supports only EMPTY".to_string());
                }
                (
                    if is_not {
                        JqlOperator::IsNotEmpty
                    } else {
                        JqlOperator::IsEmpty
                    },
                    JqlOperand::Empty,
                )
            } else {
                return Err(format!(
                    "JQL operator is unsupported for {}; supported operators: {}",
                    field.canonical(),
                    field.operator_names().join(", ")
                ));
            }
        };

        self.validate_clause(field, operator, &operand)?;
        Ok(JqlExpr::Clause(JqlClause {
            field,
            operator,
            operand,
        }))
    }

    pub(crate) fn next_value_list(&mut self, field: JqlField) -> Result<Vec<JqlValue>, String> {
        if !self.consume(&JqlToken::LParen) {
            return Err("JQL IN operator requires a parenthesized list".to_string());
        }
        let mut values = Vec::new();
        loop {
            if values.len() >= MAX_JIRA_IN_LIST_VALUES {
                return Err("JQL IN list exceeded the item cap".to_string());
            }
            values.push(self.next_value(field)?);
            if self.consume(&JqlToken::Comma) {
                continue;
            }
            if self.consume(&JqlToken::RParen) {
                break;
            }
            return Err("JQL IN list is invalid".to_string());
        }
        if values.is_empty() {
            return Err("JQL IN list must not be empty".to_string());
        }
        Ok(values)
    }

    pub(crate) fn next_value(&mut self, field: JqlField) -> Result<JqlValue, String> {
        match self.tokens.get(self.index).cloned() {
            Some(JqlToken::Word(_)) if self.peek_next_is_lparen() => self.next_function(field),
            Some(JqlToken::Word(value)) => {
                self.index += 1;
                self.value_from_word(field, value)
            }
            Some(JqlToken::String(value)) => {
                self.index += 1;
                self.value_from_string(field, value)
            }
            _ => Err("JQL value is missing".to_string()),
        }
    }

    pub(crate) fn next_text_value(&mut self) -> Result<JqlValue, String> {
        if let Some(JqlToken::String(value)) = self.tokens.get(self.index).cloned() {
            self.index += 1;
            Ok(JqlValue::String(value))
        } else {
            Err("JQL text search requires a quoted string".to_string())
        }
    }

    pub(crate) fn next_function(&mut self, field: JqlField) -> Result<JqlValue, String> {
        let Some(function_name) = self.next_word() else {
            return Err("JQL function name is missing".to_string());
        };
        let name = JqlFunctionName::from_input(&function_name).ok_or_else(|| {
            format!(
                "JQL function is unsupported; supported functions: {}",
                JqlFunctionName::ALL
                    .iter()
                    .map(|function| function.canonical())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;
        if !self.consume(&JqlToken::LParen) {
            return Err("JQL function call is invalid".to_string());
        }
        let mut args = Vec::new();
        if !self.consume(&JqlToken::RParen) {
            args.push(self.next_function_arg()?);
            if self.consume(&JqlToken::Comma) {
                return Err("JQL function arity is unsupported".to_string());
            }
            if !self.consume(&JqlToken::RParen) {
                return Err("JQL function arguments are invalid".to_string());
            }
        }
        match name {
            JqlFunctionName::CurrentUser => {
                if !args.is_empty() {
                    return Err("JQL currentUser function takes no arguments".to_string());
                }
                if !field.is_user() {
                    return Err(
                        "JQL currentUser function is unsupported for this field".to_string()
                    );
                }
                if self.credential_mode != CredentialMode::PerUser {
                    return Err(
                        "JQL currentUser function requires per_user credentials".to_string()
                    );
                }
            }
            _ => {
                if !field.is_date() {
                    return Err("JQL date function is unsupported for this field".to_string());
                }
                if !name.is_date() {
                    return Err("JQL function is unsupported for this field".to_string());
                }
                if matches!(name, JqlFunctionName::Now) && !args.is_empty() {
                    return Err("JQL now function takes no arguments".to_string());
                }
            }
        }
        Ok(JqlValue::Function(JqlFunction { name, args }))
    }

    pub(crate) fn next_function_arg(&mut self) -> Result<JqlFunctionArg, String> {
        match self.tokens.get(self.index).cloned() {
            Some(JqlToken::Word(value)) => {
                self.index += 1;
                if is_relative_date_literal(&value) {
                    Ok(JqlFunctionArg::RelativeDate(value))
                } else {
                    Err("JQL function offset is invalid".to_string())
                }
            }
            _ => Err("JQL function argument is missing".to_string()),
        }
    }

    pub(crate) fn value_from_word(
        &self,
        field: JqlField,
        value: String,
    ) -> Result<JqlValue, String> {
        match field {
            JqlField::Project => {
                if is_project_key(&value) {
                    Ok(JqlValue::Identifier(value))
                } else {
                    Err("JQL project value is invalid".to_string())
                }
            }
            JqlField::Key => {
                if is_issue_key(&value) {
                    Ok(JqlValue::Identifier(value))
                } else {
                    Err("JQL issue key value is invalid".to_string())
                }
            }
            field if field.is_date() => {
                if is_date_literal(&value) {
                    Ok(JqlValue::Date(value))
                } else {
                    Err("JQL date value is invalid".to_string())
                }
            }
            _ => {
                if is_safe_jql_identifier(&value) {
                    Ok(JqlValue::Identifier(value))
                } else {
                    Err("JQL identifier value is invalid".to_string())
                }
            }
        }
    }

    pub(crate) fn value_from_string(
        &self,
        field: JqlField,
        value: String,
    ) -> Result<JqlValue, String> {
        match field {
            JqlField::Project => {
                if is_project_key(&value) {
                    Ok(JqlValue::Identifier(value))
                } else {
                    Err("JQL project value is invalid".to_string())
                }
            }
            JqlField::Key => {
                if is_issue_key(&value) {
                    Ok(JqlValue::Identifier(value))
                } else {
                    Err("JQL issue key value is invalid".to_string())
                }
            }
            field if field.is_date() => {
                if is_date_literal(&value) {
                    Ok(JqlValue::Date(value))
                } else {
                    Err("JQL date value is invalid".to_string())
                }
            }
            _ => Ok(JqlValue::String(value)),
        }
    }

    pub(crate) fn validate_clause(
        &self,
        field: JqlField,
        operator: JqlOperator,
        operand: &JqlOperand,
    ) -> Result<(), String> {
        if !field.allows_operator(operator) {
            return Err(format!(
                "JQL operator {} is unsupported for {}; supported operators: {}",
                operator.emit(),
                field.canonical(),
                field.operator_names().join(", ")
            ));
        }
        match (operator, operand) {
            (
                JqlOperator::Eq
                | JqlOperator::NotEq
                | JqlOperator::Lt
                | JqlOperator::Lte
                | JqlOperator::Gt
                | JqlOperator::Gte
                | JqlOperator::Contains,
                JqlOperand::Single(_),
            )
            | (JqlOperator::In | JqlOperator::NotIn, JqlOperand::List(_))
            | (JqlOperator::IsEmpty | JqlOperator::IsNotEmpty, JqlOperand::Empty) => {}
            _ => return Err("JQL clause operand is invalid".to_string()),
        }
        if field.is_text() && operator != JqlOperator::Contains {
            return Err("JQL text field operator is unsupported".to_string());
        }
        Ok(())
    }

    pub(crate) fn parse_order_by(&mut self) -> Result<Vec<JqlOrderTerm>, String> {
        let Some(order_keyword) = self.next_word() else {
            return Err("JQL ORDER BY is invalid".to_string());
        };
        if !order_keyword.eq_ignore_ascii_case("ORDER") {
            return Err("JQL ORDER BY is invalid".to_string());
        }
        let Some(by_keyword) = self.next_word() else {
            return Err("JQL ORDER BY is invalid".to_string());
        };
        if !by_keyword.eq_ignore_ascii_case("BY") {
            return Err("JQL ORDER BY is invalid".to_string());
        }
        let mut terms = Vec::new();
        loop {
            if terms.len() >= MAX_JIRA_ORDER_TERMS {
                return Err("JQL ORDER BY exceeded the term cap".to_string());
            }
            let Some(field) = self.next_word() else {
                return Err("JQL ORDER BY field is missing".to_string());
            };
            let field = JqlSortField::from_input(&field).ok_or_else(|| {
                format!(
                    "JQL ORDER BY field is unsupported; supported sort fields: {}",
                    JqlSortField::ALL
                        .iter()
                        .map(|field| field.canonical())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?;
            if self.consume(&JqlToken::LParen) {
                return Err("JQL ORDER BY functions are unsupported".to_string());
            }
            let direction = if self.peek_keyword("ASC") {
                self.index += 1;
                SortDirection::Asc
            } else if self.peek_keyword("DESC") {
                self.index += 1;
                SortDirection::Desc
            } else {
                SortDirection::Asc
            };
            terms.push(JqlOrderTerm { field, direction });
            if self.consume(&JqlToken::Comma) {
                continue;
            }
            break;
        }
        Ok(terms)
    }

    pub(crate) fn next_word(&mut self) -> Option<String> {
        match self.tokens.get(self.index).cloned() {
            Some(JqlToken::Word(value)) => {
                self.index += 1;
                Some(value)
            }
            _ => None,
        }
    }

    pub(crate) fn peek_word(&self) -> Option<&str> {
        match self.tokens.get(self.index) {
            Some(JqlToken::Word(value)) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn peek_keyword(&self, keyword: &str) -> bool {
        self.peek_word()
            .is_some_and(|word| word.eq_ignore_ascii_case(keyword))
    }

    pub(crate) fn peek_next_is_lparen(&self) -> bool {
        self.tokens.get(self.index + 1) == Some(&JqlToken::LParen)
    }

    pub(crate) fn consume(&mut self, token: &JqlToken) -> bool {
        if self.tokens.get(self.index) == Some(token) {
            self.index += 1;
            true
        } else {
            false
        }
    }
}

pub(crate) fn tokenize_jql(jql: &str) -> Result<Vec<JqlToken>, String> {
    let mut chars = jql.char_indices().peekable();
    let mut tokens = Vec::new();
    while let Some((_, ch)) = chars.peek().copied() {
        if ch.is_whitespace() {
            chars.next();
            continue;
        }
        match ch {
            '=' => {
                chars.next();
                tokens.push(JqlToken::Eq);
            }
            '!' => {
                chars.next();
                match chars.peek().copied() {
                    Some((_, '=')) => {
                        chars.next();
                        tokens.push(JqlToken::NotEq);
                    }
                    Some((_, '~')) => {
                        chars.next();
                        tokens.push(JqlToken::NotTilde);
                    }
                    _ => return Err("JQL contains an unsupported operator".to_string()),
                }
            }
            '<' => {
                chars.next();
                if chars.peek().is_some_and(|(_, next)| *next == '=') {
                    chars.next();
                    tokens.push(JqlToken::Lte);
                } else {
                    tokens.push(JqlToken::Lt);
                }
            }
            '>' => {
                chars.next();
                if chars.peek().is_some_and(|(_, next)| *next == '=') {
                    chars.next();
                    tokens.push(JqlToken::Gte);
                } else {
                    tokens.push(JqlToken::Gt);
                }
            }
            '~' => {
                chars.next();
                tokens.push(JqlToken::Tilde);
            }
            ',' => {
                chars.next();
                tokens.push(JqlToken::Comma);
            }
            '(' => {
                chars.next();
                tokens.push(JqlToken::LParen);
            }
            ')' => {
                chars.next();
                tokens.push(JqlToken::RParen);
            }
            '"' | '\'' => tokens.push(JqlToken::String(read_quoted_jql(&mut chars, ch)?)),
            _ if is_jql_word_start(ch) => tokens.push(JqlToken::Word(read_jql_word(&mut chars))),
            _ => return Err("JQL contains an unsupported character".to_string()),
        }
    }
    Ok(tokens)
}

pub(crate) fn read_quoted_jql<I>(
    chars: &mut std::iter::Peekable<I>,
    quote: char,
) -> Result<String, String>
where
    I: Iterator<Item = (usize, char)>,
{
    chars.next();
    let mut value = String::new();
    while let Some((_, ch)) = chars.next() {
        if ch == quote {
            validate_jql_string_value(&value)?;
            return Ok(value);
        }
        if ch == '\\' {
            let Some((_, escaped)) = chars.next() else {
                return Err("JQL quoted value escape is unterminated".to_string());
            };
            if escaped == quote || escaped == '\\' {
                value.push(escaped);
            } else {
                return Err("JQL quoted value contains an unsupported escape".to_string());
            }
        } else {
            value.push(ch);
        }
    }
    Err("JQL quoted value is unterminated".to_string())
}

pub(crate) fn read_jql_word<I>(chars: &mut std::iter::Peekable<I>) -> String
where
    I: Iterator<Item = (usize, char)>,
{
    let mut value = String::new();
    while let Some((_, ch)) = chars.peek().copied() {
        if !is_jql_word_char(ch) {
            break;
        }
        value.push(ch);
        chars.next();
    }
    value
}

pub(crate) fn is_jql_word_start(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '+')
}

pub(crate) fn is_jql_word_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':' | '+')
}

pub(crate) fn is_safe_jql_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
}

pub(crate) fn is_safe_jql_bare_operand(value: &str) -> bool {
    value
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        && is_safe_jql_identifier(value)
        && !is_jql_reserved_word(value)
}

pub(crate) fn is_jql_reserved_word(value: &str) -> bool {
    const RESERVED_WORDS: &[&str] = &[
        "AFTER", "AND", "ASC", "BEFORE", "BY", "CF", "CHANGED", "DESC", "DURING", "EMPTY", "FROM",
        "IN", "IS", "NOT", "NULL", "ON", "OR", "ORDER", "TO", "WAS",
    ];

    RESERVED_WORDS
        .iter()
        .any(|reserved| value.eq_ignore_ascii_case(reserved))
}

pub(crate) fn validate_jql_string_value(value: &str) -> Result<(), String> {
    if value.len() > MAX_JIRA_STRING_LITERAL_BYTES {
        return Err("exceeded the string literal byte cap".to_string());
    }
    if value.chars().any(|ch| ch.is_control()) {
        return Err("contains a control character".to_string());
    }
    if !value.is_ascii() {
        return Err("contains a non-ASCII character".to_string());
    }
    Ok(())
}

pub(crate) fn is_relative_date_literal(value: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[+-][1-9][0-9]*[mhdw]$").expect("relative date regex"))
        .is_match(value)
}

pub(crate) fn is_safe_jql_bare_date(value: &str) -> bool {
    is_relative_date_literal(value) || is_jira_date_literal(value)
}

pub(crate) fn is_jira_date_literal(value: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[0-9]{4}[-/][0-9]{2}[-/][0-9]{2}$").expect("date regex"))
        .is_match(value)
}

pub(crate) fn is_jira_datetime_literal(value: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^[0-9]{4}[-/][0-9]{2}[-/][0-9]{2} [0-9]{2}:[0-9]{2}$").expect("datetime regex")
    })
    .is_match(value)
}

pub(crate) fn is_date_literal(value: &str) -> bool {
    is_relative_date_literal(value)
        || is_jira_date_literal(value)
        || is_jira_datetime_literal(value)
}
