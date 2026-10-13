//! Search inputs, scope-bounded query building, and the bounded CQL parser.
use super::*;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SearchInputs {
    pub(crate) query: ConfluenceSearchQueryInput,
    pub(crate) spaces: Option<Vec<String>>,
    pub(crate) max_results: Option<u32>,
    pub(crate) next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum ConfluenceSearchQueryInput {
    Cql { value: String },
    Text { value: String },
}

pub(crate) const MAX_CONFLUENCE_TEXT_QUERY_BYTES: usize = 512;
pub(crate) const MAX_CONFLUENCE_RAW_QUERY_BYTES: usize = 4096;
pub(crate) const MAX_CONFLUENCE_QUERY_DEPTH: usize = 32;
pub(crate) const MAX_CONFLUENCE_QUERY_TOKENS: usize = 512;
pub(crate) const MAX_CONFLUENCE_IN_LIST_VALUES: usize = 100;
pub(crate) const MAX_CONFLUENCE_STRING_LITERAL_BYTES: usize = 512;
pub(crate) const MAX_CONFLUENCE_ORDER_TERMS: usize = 5;
pub(crate) const CONFLUENCE_QUERY_AST_VERSION: u32 = 2;

fn cql_operator_names(field: CqlField) -> Vec<&'static str> {
    CqlOperator::ALL
        .into_iter()
        .filter(|operator| field.allows_operator(*operator))
        .map(CqlOperator::emit)
        .collect()
}

fn cql_field_names(kind: ConfluenceSearchContentKind) -> String {
    CqlField::ALL
        .into_iter()
        .filter(|field| kind.permits_field(*field))
        .map(CqlField::canonical)
        .collect::<Vec<_>>()
        .join(", ")
}

fn cql_sort_names() -> Vec<&'static str> {
    CqlField::ALL
        .into_iter()
        .filter_map(CqlSortField::from_field)
        .map(CqlSortField::canonical)
        .collect()
}

pub(crate) fn cql_documentation(kind: ConfluenceSearchContentKind) -> Value {
    let fields = CqlField::ALL.into_iter().filter(|field| kind.permits_field(*field))
        .map(|field| json!({
            "name": field.canonical(),
            "aliases": field.aliases(),
            "operators": cql_operator_names(field),
            "values": match field {
                CqlField::Type => kind.cql_type(),
                CqlField::Space => "space key",
                field if field.is_page_id() => "numeric content ID",
                field if field.is_date() => "valid YYYY-MM-DD or YYYY/MM/DD; optional HH:mm requires quoting",
                field if field.is_text() => "quoted text",
                field if field.is_user() => "account ID or identifier; quote values containing punctuation",
                _ => "identifier or quoted string",
            },
        })).collect::<Vec<_>>();
    json!({
        "cql": {
            "fields": fields,
            "booleanOperators": ["AND", "OR"],
            "grouping": "Parentheses are supported and required when mixing AND and OR at the same level. Prefix NOT is unsupported.",
            "functions": [],
            "literals": "Bare identifiers use ASCII letters, digits, underscore, hyphen and dot; quote other values. Single or double quotes delimit strings. Supported escapes are backslash, double quote, n, r and t. Control characters other than newline, carriage return and tab are rejected; punctuation outside supported grammar is rejected.",
            "unsupported": ["IS EMPTY", "IS NOT EMPTY", "!~", "prefix NOT"],
            "orderBy": {"fields": cql_sort_names(), "directions": ["ASC", "DESC"], "defaultDirection": "ASC", "maxTerms": MAX_CONFLUENCE_ORDER_TERMS},
            "emptyFilter": "Empty or whitespace-only CQL and ORDER BY alone search the effective authorized spaces; the broker always adds the action content type.",
            "scope": "Omit spaces to use effective broker authorization after grant, token and execution-context restrictions. Supply spaces only to narrow it. The broker groups caller filters and injects space inclusion/exclusion and content type predicates, then checks returned content.",
            "contentType": kind.cql_type(),
            "limits": {
                "queryBytes": MAX_CONFLUENCE_RAW_QUERY_BYTES,
                "tokens": MAX_CONFLUENCE_QUERY_TOKENS,
                "depth": MAX_CONFLUENCE_QUERY_DEPTH,
                "inListValues": MAX_CONFLUENCE_IN_LIST_VALUES,
                "stringLiteralBytes": MAX_CONFLUENCE_STRING_LITERAL_BYTES,
                "textQueryBytes": MAX_CONFLUENCE_TEXT_QUERY_BYTES
            },
            "textMode": "Nonempty text searches title with ~; use CQL text ~ for full text.",
            "errors": "Malformed or unsupported CQL returns input_invalid. Authorization and returned-content containment errors remain distinct.",
            "examples": [
                {"query": {"type": "cql", "value": "ORDER BY lastModified DESC"}},
                {"query": {"type": "cql", "value": ""}},
                {"query": {"type": "cql", "value": "title ~ \"runbook\" ORDER BY created DESC"}, "spaces": ["ENG"]},
                {"query": {"type": "text", "value": "runbook"}}
            ]
        }
    })
}

pub(crate) fn parse_search_inputs(inputs: &Value) -> Result<SearchInputs, ProviderError> {
    serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.search inputs are invalid",
        )
    })
}

pub(crate) fn requested_spaces(inputs: &SearchInputs) -> Result<BTreeSet<String>, ProviderError> {
    let mut spaces = BTreeSet::new();
    if let Some(values) = &inputs.spaces {
        if values.is_empty() {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "confluence.search spaces must not be empty",
            ));
        }
        for space in values {
            spaces.insert(validate_space_key(space)?);
        }
    }
    Ok(spaces)
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
pub(crate) struct BuiltConfluenceSearchQuery {
    pub(crate) cql: String,
    pub(crate) kind: &'static str,
    pub(crate) injected_space_predicate: &'static str,
    pub(crate) injected_type_predicate: &'static str,
    pub(crate) response_scope: EffectiveSearchScope,
    /// The caller's query, canonically re-emitted; continuations bind it.
    pub(crate) canonical_caller_cql: String,
    pub(crate) canonical_caller_cql_hash: String,
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

pub(crate) fn effective_search_scope(
    authorization: &SearchAuthorization,
    requested: &BTreeSet<String>,
) -> Result<EffectiveSearchScope, ProviderError> {
    if authorization.scope_type != "space" {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Confluence search authorization used an invalid scope type",
        ));
    }
    match &authorization.scope {
        SearchAuthorizationScope::Finite { values } => {
            let allowed = values.iter().cloned().collect::<BTreeSet<_>>();
            if allowed.is_empty() {
                return Err(ProviderError::deny(
                    ReasonCode::ServiceActionDenied,
                    "Confluence search policy scope is empty",
                ));
            }
            if requested.is_empty() {
                return Ok(EffectiveSearchScope::Finite(allowed));
            }
            if !requested.is_subset(&allowed) {
                return Err(ProviderError::deny(
                    ReasonCode::ServiceActionDenied,
                    "requested Confluence spaces are not authorized",
                ));
            }
            Ok(EffectiveSearchScope::Finite(requested.clone()))
        }
        SearchAuthorizationScope::AllExcept { excluded_values } => {
            let excluded = excluded_values.iter().cloned().collect::<BTreeSet<_>>();
            if !requested.is_disjoint(&excluded) {
                return Err(ProviderError::deny(
                    ReasonCode::ServiceActionDenied,
                    "requested Confluence spaces are not authorized",
                ));
            }
            if requested.is_empty() {
                Ok(EffectiveSearchScope::AllExcept(excluded))
            } else {
                Ok(EffectiveSearchScope::Finite(requested.clone()))
            }
        }
    }
}

pub(crate) fn build_confluence_search_query(
    query: &ConfluenceSearchQueryInput,
    effective_scope: &EffectiveSearchScope,
    limits: &SearchLimitsConfig,
) -> Result<BuiltConfluenceSearchQuery, ProviderError> {
    build_confluence_search_query_for_kind(
        query,
        effective_scope,
        limits,
        ConfluenceSearchContentKind::Page,
    )
}

pub(crate) fn build_confluence_blog_search_query(
    query: &ConfluenceSearchQueryInput,
    effective_scope: &EffectiveSearchScope,
    limits: &SearchLimitsConfig,
) -> Result<BuiltConfluenceSearchQuery, ProviderError> {
    build_confluence_search_query_for_kind(
        query,
        effective_scope,
        limits,
        ConfluenceSearchContentKind::BlogPost,
    )
}

pub(crate) fn build_confluence_search_query_for_kind(
    query: &ConfluenceSearchQueryInput,
    effective_scope: &EffectiveSearchScope,
    limits: &SearchLimitsConfig,
    content_kind: ConfluenceSearchContentKind,
) -> Result<BuiltConfluenceSearchQuery, ProviderError> {
    let (ast, kind) = match query {
        ConfluenceSearchQueryInput::Cql { value } => {
            (parse_cql_query_for_kind(value, content_kind)?, "cql")
        }
        ConfluenceSearchQueryInput::Text { value } => {
            (confluence_text_query(value, limits)?, "text")
        }
    };
    let caller_cql = ast.emit();
    let order_by_cql = ast.emit_order_by();
    let (space_predicate, injected_space_predicate) = match effective_scope {
        EffectiveSearchScope::Finite(spaces) => (
            Some(confluence_space_predicate(
                spaces.iter().map(String::as_str),
            )),
            "space_in",
        ),
        EffectiveSearchScope::AllExcept(excluded) if excluded.is_empty() => (None, "none"),
        EffectiveSearchScope::AllExcept(excluded) => (
            Some(
                confluence_space_predicate(excluded.iter().map(String::as_str)).replacen(
                    " IN (",
                    " NOT IN (",
                    1,
                ),
            ),
            "space_not_in",
        ),
    };
    let mut clauses = ast
        .filter
        .iter()
        .map(|filter| format!("({})", filter.emit()))
        .collect::<Vec<_>>();
    if let Some(predicate) = space_predicate {
        clauses.push(predicate);
    }
    clauses.push(format!("type = {}", content_kind.cql_type()));
    let mut cql = clauses.join(" AND ");
    if !order_by_cql.is_empty() {
        cql.push(' ');
        cql.push_str(&order_by_cql);
    }
    let query_shape = ast.query_shape();
    let text_operand_hashes = ast.text_operand_hashes();
    let sort_fields = ast.sort_fields();
    let response_scope = match effective_scope {
        EffectiveSearchScope::Finite(spaces) => EffectiveSearchScope::Finite(spaces.clone()),
        EffectiveSearchScope::AllExcept(excluded) => ast
            .space_scope()
            .map(|values| {
                EffectiveSearchScope::Finite(values.difference(excluded).cloned().collect())
            })
            .unwrap_or_else(|| EffectiveSearchScope::AllExcept(excluded.clone())),
    };
    Ok(BuiltConfluenceSearchQuery {
        cql,
        kind,
        injected_space_predicate,
        response_scope,
        canonical_caller_cql_hash: sha256_hex(caller_cql.as_bytes()),
        canonical_caller_cql: caller_cql,
        query_shape,
        text_operand_hashes,
        sort_fields,
        injected_type_predicate: content_kind.injected_type_predicate(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfluenceSearchContentKind {
    Page,
    BlogPost,
}

impl ConfluenceSearchContentKind {
    pub(crate) fn cql_type(self) -> &'static str {
        match self {
            Self::Page => "page",
            Self::BlogPost => "blogpost",
        }
    }

    pub(crate) fn injected_type_predicate(self) -> &'static str {
        match self {
            Self::Page => "type_page",
            Self::BlogPost => "type_blogpost",
        }
    }

    pub(crate) fn permits_field(self, field: CqlField) -> bool {
        match self {
            Self::Page => true,
            Self::BlogPost => !matches!(field, CqlField::Ancestor | CqlField::Parent),
        }
    }
}

pub(crate) fn confluence_text_query(
    raw: &str,
    _limits: &SearchLimitsConfig,
) -> Result<CqlQueryAst, ProviderError> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.search text query must not be empty",
        ));
    }
    if value.len() > MAX_CONFLUENCE_TEXT_QUERY_BYTES {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.search text query exceeded the byte cap",
        ));
    }
    validate_cql_string_value(value).map_err(|message| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            format!("confluence.search text query {message}"),
        )
    })?;
    Ok(CqlQueryAst {
        filter: Some(CqlExpr::Clause(CqlClause {
            field: CqlField::Title,
            operator: CqlOperator::Contains,
            operand: CqlOperand::Single(CqlValue::String(value.to_string())),
        })),
        order_by: Vec::new(),
    })
}

pub(crate) fn confluence_space_predicate<'a>(spaces: impl Iterator<Item = &'a str>) -> String {
    format!(
        "space IN ({})",
        spaces
            .map(cql_bare_or_string_literal)
            .collect::<Vec<_>>()
            .join(", ")
    )
}

pub(crate) fn cql_string_literal(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for ch in value.chars() {
        match ch {
            '"' | '\\' => {
                escaped.push('\\');
                escaped.push(ch);
            }
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            _ => escaped.push(ch),
        }
    }
    escaped.push('"');
    escaped
}

pub(crate) fn capped_max_results(
    requested: Option<u32>,
    limits: &SearchLimitsConfig,
) -> Result<u32, ProviderError> {
    let requested = requested.unwrap_or(limits.max_results);
    if requested == 0 {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "maxResults must be greater than zero",
        ));
    }
    Ok(requested.min(limits.max_results))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CqlQueryAst {
    pub(crate) filter: Option<CqlExpr>,
    pub(crate) order_by: Vec<CqlOrderTerm>,
}

impl CqlQueryAst {
    pub(crate) fn emit(&self) -> String {
        let mut emitted = self.filter.as_ref().map(CqlExpr::emit).unwrap_or_default();
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
            .map(CqlOrderTerm::emit)
            .collect::<Vec<_>>()
            .join(", ");
        format!("ORDER BY {terms}")
    }

    #[cfg(test)]
    pub(crate) fn spaces(&self) -> BTreeSet<String> {
        let mut spaces = BTreeSet::new();
        if let Some(filter) = &self.filter {
            filter.collect_spaces(&mut spaces);
        }
        spaces
    }

    pub(crate) fn space_scope(&self) -> Option<BTreeSet<String>> {
        self.filter.as_ref().and_then(CqlExpr::space_scope)
    }

    pub(crate) fn query_shape(&self) -> Value {
        json!({
            "filter": self.filter.as_ref().map(CqlExpr::shape),
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
pub(crate) enum CqlExpr {
    Clause(CqlClause),
    And(Vec<CqlExpr>),
    Or(Vec<CqlExpr>),
}

impl CqlExpr {
    pub(crate) fn emit(&self) -> String {
        match self {
            Self::Clause(clause) => clause.emit(),
            Self::And(children) => children
                .iter()
                .map(CqlExpr::emit_for_parent)
                .collect::<Vec<_>>()
                .join(" AND "),
            Self::Or(children) => children
                .iter()
                .map(CqlExpr::emit_for_parent)
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
    pub(crate) fn collect_spaces(&self, spaces: &mut BTreeSet<String>) {
        match self {
            Self::Clause(clause) => clause.collect_spaces(spaces),
            Self::And(children) | Self::Or(children) => {
                for child in children {
                    child.collect_spaces(spaces);
                }
            }
        }
    }

    pub(crate) fn space_scope(&self) -> Option<BTreeSet<String>> {
        match self {
            Self::Clause(clause) => clause.space_scope(),
            Self::And(children) => {
                let mut bounded: Option<BTreeSet<String>> = None;
                for child in children {
                    let Some(child_scope) = child.space_scope() else {
                        continue;
                    };
                    bounded = Some(match bounded {
                        Some(current) => current.intersection(&child_scope).cloned().collect(),
                        None => child_scope,
                    });
                }
                bounded
            }
            Self::Or(children) => {
                let mut bounded = BTreeSet::new();
                for child in children {
                    let child_scope = child.space_scope()?;
                    bounded.extend(child_scope);
                }
                Some(bounded)
            }
        }
    }

    pub(crate) fn shape(&self) -> Value {
        match self {
            Self::Clause(clause) => clause.shape(),
            Self::And(children) => json!({
                "type": "and",
                "children": children.iter().map(CqlExpr::shape).collect::<Vec<_>>(),
            }),
            Self::Or(children) => json!({
                "type": "or",
                "children": children.iter().map(CqlExpr::shape).collect::<Vec<_>>(),
            }),
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CqlClause {
    pub(crate) field: CqlField,
    pub(crate) operator: CqlOperator,
    pub(crate) operand: CqlOperand,
}

impl CqlClause {
    pub(crate) fn emit(&self) -> String {
        match &self.operand {
            CqlOperand::Single(value) => format!(
                "{} {} {}",
                self.field.canonical(),
                self.operator.emit(),
                value.emit_for_field(self.field)
            ),
            CqlOperand::List(values) => {
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
        }
    }

    #[cfg(test)]
    pub(crate) fn collect_spaces(&self, spaces: &mut BTreeSet<String>) {
        match (&self.field, &self.operator, &self.operand) {
            (CqlField::Space, CqlOperator::Eq, CqlOperand::Single(value)) => {
                if let Some(space) = value.identifier() {
                    spaces.insert(space.to_string());
                }
            }
            (CqlField::Space, CqlOperator::In, CqlOperand::List(values)) => {
                spaces.extend(
                    values
                        .iter()
                        .filter_map(CqlValue::identifier)
                        .map(str::to_string),
                );
            }
            _ => {}
        }
    }

    pub(crate) fn space_scope(&self) -> Option<BTreeSet<String>> {
        match (&self.field, &self.operator, &self.operand) {
            (CqlField::Space, CqlOperator::Eq, CqlOperand::Single(value)) => value
                .identifier()
                .map(|space| [space.to_string()].into_iter().collect()),
            (CqlField::Space, CqlOperator::In, CqlOperand::List(values)) => Some(
                values
                    .iter()
                    .filter_map(CqlValue::identifier)
                    .map(str::to_string)
                    .collect(),
            ),
            _ => None,
        }
    }

    pub(crate) fn shape(&self) -> Value {
        json!({
            "type": "clause",
            "field": self.field.canonical(),
            "operator": self.operator.emit(),
            "operand": self.operand.shape(),
        })
    }

    pub(crate) fn collect_text_operand_hashes(&self, hashes: &mut Vec<String>) {
        if !self.field.is_text() || self.operator != CqlOperator::Contains {
            return;
        }
        if let CqlOperand::Single(CqlValue::String(value)) = &self.operand {
            hashes.push(sha256_hex(value.as_bytes()));
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CqlField {
    Space,
    Type,
    Id,
    Title,
    Text,
    Label,
    Creator,
    Contributor,
    Mention,
    Ancestor,
    Parent,
    Created,
    LastModified,
}

impl CqlField {
    const ALL: [Self; 13] = [
        Self::Space,
        Self::Type,
        Self::Id,
        Self::Title,
        Self::Text,
        Self::Label,
        Self::Creator,
        Self::Contributor,
        Self::Mention,
        Self::Ancestor,
        Self::Parent,
        Self::Created,
        Self::LastModified,
    ];

    pub(crate) fn from_input(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|field| {
            value.eq_ignore_ascii_case(field.canonical())
                || field
                    .aliases()
                    .iter()
                    .any(|alias| value.eq_ignore_ascii_case(alias))
        })
    }

    fn aliases(self) -> &'static [&'static str] {
        match self {
            Self::Id => &["content.id"],
            Self::Label => &["labels"],
            _ => &[],
        }
    }

    pub(crate) fn canonical(self) -> &'static str {
        match self {
            Self::Space => "space",
            Self::Type => "type",
            Self::Id => "id",
            Self::Title => "title",
            Self::Text => "text",
            Self::Label => "label",
            Self::Creator => "creator",
            Self::Contributor => "contributor",
            Self::Mention => "mention",
            Self::Ancestor => "ancestor",
            Self::Parent => "parent",
            Self::Created => "created",
            Self::LastModified => "lastModified",
        }
    }

    pub(crate) fn is_text(self) -> bool {
        matches!(self, Self::Title | Self::Text)
    }

    pub(crate) fn is_date(self) -> bool {
        matches!(self, Self::Created | Self::LastModified)
    }

    pub(crate) fn is_page_id(self) -> bool {
        matches!(self, Self::Id | Self::Ancestor | Self::Parent)
    }

    pub(crate) fn is_user(self) -> bool {
        matches!(self, Self::Creator | Self::Contributor | Self::Mention)
    }

    pub(crate) fn allows_operator(self, operator: CqlOperator) -> bool {
        match self {
            Self::Space => matches!(operator, CqlOperator::Eq | CqlOperator::In),
            Self::Type => operator == CqlOperator::Eq,
            Self::Id | Self::Ancestor | Self::Parent => {
                matches!(operator, CqlOperator::Eq | CqlOperator::In)
            }
            Self::Title | Self::Text => operator == CqlOperator::Contains,
            Self::Label => matches!(
                operator,
                CqlOperator::Eq | CqlOperator::NotEq | CqlOperator::In | CqlOperator::NotIn
            ),
            Self::Creator | Self::Contributor => matches!(
                operator,
                CqlOperator::Eq | CqlOperator::NotEq | CqlOperator::In | CqlOperator::NotIn
            ),
            Self::Mention => matches!(operator, CqlOperator::Eq | CqlOperator::In),
            Self::Created | Self::LastModified => matches!(
                operator,
                CqlOperator::Eq
                    | CqlOperator::NotEq
                    | CqlOperator::Lt
                    | CqlOperator::Lte
                    | CqlOperator::Gt
                    | CqlOperator::Gte
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CqlOperator {
    Eq,
    NotEq,
    Lt,
    Lte,
    Gt,
    Gte,
    Contains,
    In,
    NotIn,
}

impl CqlOperator {
    const ALL: [Self; 9] = [
        Self::Eq,
        Self::NotEq,
        Self::Lt,
        Self::Lte,
        Self::Gt,
        Self::Gte,
        Self::Contains,
        Self::In,
        Self::NotIn,
    ];

    pub(crate) fn emit(self) -> &'static str {
        match self {
            Self::Eq => "=",
            Self::NotEq => "!=",
            Self::Lt => "<",
            Self::Lte => "<=",
            Self::Gt => ">",
            Self::Gte => ">=",
            Self::Contains => "~",
            Self::In => "IN",
            Self::NotIn => "NOT IN",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CqlOperand {
    Single(CqlValue),
    List(Vec<CqlValue>),
}

impl CqlOperand {
    pub(crate) fn shape(&self) -> Value {
        match self {
            Self::Single(value) => json!({
                "type": "single",
                "value": value.shape(),
            }),
            Self::List(values) => json!({
                "type": "list",
                "count": values.len(),
                "values": values.iter().map(CqlValue::shape).collect::<Vec<_>>(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CqlValue {
    Identifier(String),
    String(String),
    Number(String),
    Date(CqlDateLiteral),
}

impl CqlValue {
    pub(crate) fn emit_for_field(&self, field: CqlField) -> String {
        match self {
            Self::Identifier(value) if field.is_user() => cql_string_literal(value),
            Self::Identifier(value) => cql_bare_or_string_literal(value),
            Self::String(value) if field.is_text() => cql_string_literal(value),
            Self::String(value) if field.is_user() => cql_string_literal(value),
            Self::String(value) => cql_bare_or_string_literal(value),
            Self::Number(value) => value.clone(),
            Self::Date(value) => value.emit_quoted(),
        }
    }

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
            Self::Number(_) => json!({ "type": "number" }),
            Self::Date(_) => json!({ "type": "date" }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CqlDateLiteral {
    pub(crate) date: String,
    pub(crate) time: Option<String>,
}

impl CqlDateLiteral {
    pub(crate) fn emit(&self) -> String {
        match &self.time {
            Some(time) => format!("{} {time}", self.date),
            None => self.date.clone(),
        }
    }

    pub(crate) fn emit_quoted(&self) -> String {
        format!("\"{}\"", self.emit())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CqlOrderTerm {
    pub(crate) field: CqlSortField,
    pub(crate) direction: CqlSortDirection,
}

impl CqlOrderTerm {
    pub(crate) fn emit(&self) -> String {
        format!("{} {}", self.field.canonical(), self.direction.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CqlSortField {
    Created,
    LastModified,
    Title,
}

impl CqlSortField {
    pub(crate) fn from_field(field: CqlField) -> Option<Self> {
        match field {
            CqlField::Created => Some(Self::Created),
            CqlField::LastModified => Some(Self::LastModified),
            CqlField::Title => Some(Self::Title),
            _ => None,
        }
    }

    pub(crate) fn canonical(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::LastModified => "lastModified",
            Self::Title => "title",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CqlSortDirection {
    Asc,
    Desc,
}

impl CqlSortDirection {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Asc => "ASC",
            Self::Desc => "DESC",
        }
    }
}

#[cfg(test)]
pub(crate) fn parse_cql_query(cql: &str) -> Result<CqlQueryAst, ProviderError> {
    parse_cql_query_for_kind(cql, ConfluenceSearchContentKind::Page)
}

pub(crate) fn parse_cql_query_for_kind(
    cql: &str,
    content_kind: ConfluenceSearchContentKind,
) -> Result<CqlQueryAst, ProviderError> {
    if cql.len() > MAX_CONFLUENCE_RAW_QUERY_BYTES {
        return Err(cql_input_invalid("CQL exceeded the byte cap"));
    }
    let expression = cql.trim();
    let tokens = lex_cql(expression).map_err(cql_input_invalid)?;
    if tokens.len() > MAX_CONFLUENCE_QUERY_TOKENS {
        return Err(cql_input_invalid("CQL exceeded the token cap"));
    }
    let mut parser = CqlParser::new(tokens, content_kind);
    let filter = if parser.is_at_end() || parser.peek_keyword("ORDER") {
        None
    } else {
        Some(parser.parse_expr(0)?)
    };
    let order_by = if parser.peek_keyword("ORDER") {
        parser.parse_order_by()?
    } else {
        Vec::new()
    };
    if !parser.is_at_end() {
        return Err(cql_input_invalid("CQL contains trailing tokens"));
    }
    Ok(CqlQueryAst { filter, order_by })
}

#[cfg(test)]
pub(crate) fn canonical_cql(cql: &str) -> String {
    parse_cql_query(cql).unwrap().emit()
}

pub(crate) fn cql_input_invalid(message: impl Into<String>) -> ProviderError {
    ProviderError::deny(
        ReasonCode::InputInvalid,
        format!(
            "{}; call actions_describe for service confluence and action search or blog.search for supported CQL",
            message.into()
        ),
    )
}

pub(crate) struct CqlParser {
    pub(crate) tokens: Vec<CqlToken>,
    pub(crate) index: usize,
    pub(crate) content_kind: ConfluenceSearchContentKind,
}

impl CqlParser {
    pub(crate) fn new(tokens: Vec<CqlToken>, content_kind: ConfluenceSearchContentKind) -> Self {
        Self {
            tokens,
            index: 0,
            content_kind,
        }
    }

    pub(crate) fn is_at_end(&self) -> bool {
        self.index >= self.tokens.len()
    }

    pub(crate) fn parse_expr(&mut self, depth: usize) -> Result<CqlExpr, ProviderError> {
        if depth > MAX_CONFLUENCE_QUERY_DEPTH {
            return Err(cql_input_invalid("CQL nesting is too deep"));
        }
        let first = self.parse_term(depth)?;
        let mut children = vec![first];
        let mut operator: Option<&'static str> = None;
        loop {
            let next = if self.peek_keyword("AND") {
                Some("AND")
            } else if self.peek_keyword("OR") {
                Some("OR")
            } else {
                None
            };
            let Some(next_operator) = next else {
                break;
            };
            if let Some(current) = operator
                && current != next_operator
            {
                return Err(cql_input_invalid(
                    "mixed AND/OR CQL requires explicit parentheses",
                ));
            }
            operator = Some(next_operator);
            self.index += 1;
            children.push(self.parse_term(depth)?);
        }
        match operator {
            Some("AND") => Ok(CqlExpr::And(children)),
            Some("OR") => Ok(CqlExpr::Or(children)),
            _ => Ok(children.remove(0)),
        }
    }

    pub(crate) fn parse_term(&mut self, depth: usize) -> Result<CqlExpr, ProviderError> {
        if self.peek_keyword("NOT") {
            return Err(cql_input_invalid("CQL prefix NOT is unsupported"));
        }
        if self.consume(&CqlToken::LParen) {
            if depth >= MAX_CONFLUENCE_QUERY_DEPTH {
                return Err(cql_input_invalid("CQL nesting is too deep"));
            }
            let expr = self.parse_expr(depth + 1)?;
            if !self.consume(&CqlToken::RParen) {
                return Err(cql_input_invalid(
                    "CQL group is missing a closing parenthesis",
                ));
            }
            Ok(expr)
        } else {
            self.parse_clause()
        }
    }

    pub(crate) fn parse_clause(&mut self) -> Result<CqlExpr, ProviderError> {
        let Some(field) = self.next_word() else {
            return Err(cql_input_invalid("CQL clause is missing a field"));
        };
        let field = CqlField::from_input(&field).ok_or_else(|| {
            cql_input_invalid(format!(
                "CQL field at token {} is unsupported; supported fields: {}",
                self.index,
                cql_field_names(self.content_kind)
            ))
        })?;
        if !self.content_kind.permits_field(field) {
            return Err(cql_input_invalid(format!(
                "CQL field {} is unsupported for this content type; supported fields: {}",
                field.canonical(),
                cql_field_names(self.content_kind)
            )));
        }
        let (operator, operand) = if self.consume(&CqlToken::Eq) {
            (CqlOperator::Eq, CqlOperand::Single(self.next_value(field)?))
        } else if self.consume(&CqlToken::NotEq) {
            (
                CqlOperator::NotEq,
                CqlOperand::Single(self.next_value(field)?),
            )
        } else if self.consume(&CqlToken::Lt) {
            (CqlOperator::Lt, CqlOperand::Single(self.next_value(field)?))
        } else if self.consume(&CqlToken::Lte) {
            (
                CqlOperator::Lte,
                CqlOperand::Single(self.next_value(field)?),
            )
        } else if self.consume(&CqlToken::Gt) {
            (CqlOperator::Gt, CqlOperand::Single(self.next_value(field)?))
        } else if self.consume(&CqlToken::Gte) {
            (
                CqlOperator::Gte,
                CqlOperand::Single(self.next_value(field)?),
            )
        } else if self.consume(&CqlToken::Tilde) {
            (
                CqlOperator::Contains,
                CqlOperand::Single(self.next_text_value()?),
            )
        } else if self.consume(&CqlToken::NotTilde) {
            return Err(cql_input_invalid(format!(
                "CQL text negation is unsupported for field {}; supported operators: {}",
                field.canonical(),
                cql_operator_names(field).join(", ")
            )));
        } else {
            let Some(operator) = self.next_word() else {
                return Err(cql_input_invalid("CQL clause is missing an operator"));
            };
            if operator.eq_ignore_ascii_case("IN") {
                (
                    CqlOperator::In,
                    CqlOperand::List(self.next_value_list(field)?),
                )
            } else if operator.eq_ignore_ascii_case("NOT") {
                let Some(in_keyword) = self.next_word() else {
                    return Err(cql_input_invalid("CQL NOT IN operator is invalid"));
                };
                if !in_keyword.eq_ignore_ascii_case("IN") {
                    return Err(cql_input_invalid("CQL prefix NOT is unsupported"));
                }
                (
                    CqlOperator::NotIn,
                    CqlOperand::List(self.next_value_list(field)?),
                )
            } else if operator.eq_ignore_ascii_case("IS") {
                return Err(cql_input_invalid(format!(
                    "CQL IS operator is unsupported for field {}; supported operators: {}",
                    field.canonical(),
                    cql_operator_names(field).join(", ")
                )));
            } else {
                return Err(cql_input_invalid(format!(
                    "CQL operator is unsupported for field {}; supported operators: {}",
                    field.canonical(),
                    cql_operator_names(field).join(", ")
                )));
            }
        };
        self.validate_clause(field, operator, &operand)?;
        Ok(CqlExpr::Clause(CqlClause {
            field,
            operator,
            operand,
        }))
    }

    pub(crate) fn next_value_list(
        &mut self,
        field: CqlField,
    ) -> Result<Vec<CqlValue>, ProviderError> {
        if !self.consume(&CqlToken::LParen) {
            return Err(cql_input_invalid(
                "CQL IN operator requires a parenthesized list",
            ));
        }
        let mut values = Vec::new();
        loop {
            if values.len() >= MAX_CONFLUENCE_IN_LIST_VALUES {
                return Err(cql_input_invalid("CQL IN list exceeded the item cap"));
            }
            values.push(self.next_value(field)?);
            if self.consume(&CqlToken::Comma) {
                continue;
            }
            if self.consume(&CqlToken::RParen) {
                break;
            }
            return Err(cql_input_invalid("CQL IN list is invalid"));
        }
        if values.is_empty() {
            return Err(cql_input_invalid("CQL IN list must not be empty"));
        }
        Ok(values)
    }

    pub(crate) fn next_value(&mut self, field: CqlField) -> Result<CqlValue, ProviderError> {
        match self.tokens.get(self.index).cloned() {
            Some(CqlToken::Word(_)) if self.peek_next_is_lparen() => {
                Err(cql_input_invalid("CQL functions are unsupported"))
            }
            Some(CqlToken::Word(value)) => {
                self.index += 1;
                self.value_from_word(field, value)
            }
            Some(CqlToken::String(value)) => {
                self.index += 1;
                self.value_from_string(field, value)
            }
            _ => Err(cql_input_invalid("CQL value is missing")),
        }
    }

    pub(crate) fn next_text_value(&mut self) -> Result<CqlValue, ProviderError> {
        if let Some(CqlToken::String(value)) = self.tokens.get(self.index).cloned() {
            self.index += 1;
            Ok(CqlValue::String(value))
        } else {
            Err(cql_input_invalid(
                "CQL text search requires a quoted string",
            ))
        }
    }

    pub(crate) fn value_from_word(
        &self,
        field: CqlField,
        value: String,
    ) -> Result<CqlValue, ProviderError> {
        match field {
            CqlField::Space => Ok(CqlValue::Identifier(validate_space_key(&value).map_err(
                |_| cql_input_invalid("CQL space value is invalid; use a valid space key"),
            )?)),
            CqlField::Type => {
                if value.eq_ignore_ascii_case(self.content_kind.cql_type()) {
                    Ok(CqlValue::Identifier(
                        self.content_kind.cql_type().to_string(),
                    ))
                } else {
                    Err(cql_input_invalid(format!(
                        "CQL type must equal {} for this action",
                        self.content_kind.cql_type()
                    )))
                }
            }
            field if field.is_page_id() => {
                if is_page_id(&value) {
                    Ok(CqlValue::Number(value))
                } else {
                    Err(cql_input_invalid("CQL page ID is invalid"))
                }
            }
            field if field.is_date() => parse_cql_date_literal(&value).map(CqlValue::Date),
            _ => {
                if is_safe_cql_identifier(&value) {
                    Ok(CqlValue::Identifier(value))
                } else {
                    Err(cql_input_invalid("CQL identifier value is invalid"))
                }
            }
        }
    }

    pub(crate) fn value_from_string(
        &self,
        field: CqlField,
        value: String,
    ) -> Result<CqlValue, ProviderError> {
        match field {
            CqlField::Space => Ok(CqlValue::Identifier(validate_space_key(&value).map_err(
                |_| cql_input_invalid("CQL space value is invalid; use a valid space key"),
            )?)),
            CqlField::Type => {
                if value.eq_ignore_ascii_case(self.content_kind.cql_type()) {
                    Ok(CqlValue::Identifier(
                        self.content_kind.cql_type().to_string(),
                    ))
                } else {
                    Err(cql_input_invalid(format!(
                        "CQL type must equal {} for this action",
                        self.content_kind.cql_type()
                    )))
                }
            }
            field if field.is_page_id() => {
                if is_page_id(&value) {
                    Ok(CqlValue::Number(value))
                } else {
                    Err(cql_input_invalid("CQL page ID is invalid"))
                }
            }
            field if field.is_date() => parse_cql_date_literal(&value).map(CqlValue::Date),
            _ => Ok(CqlValue::String(value)),
        }
    }

    pub(crate) fn validate_clause(
        &self,
        field: CqlField,
        operator: CqlOperator,
        operand: &CqlOperand,
    ) -> Result<(), ProviderError> {
        if !field.allows_operator(operator) {
            return Err(cql_input_invalid(format!(
                "CQL operator {} is unsupported for field {}; supported operators: {}",
                operator.emit(),
                field.canonical(),
                cql_operator_names(field).join(", ")
            )));
        }
        match (operator, operand) {
            (
                CqlOperator::Eq
                | CqlOperator::NotEq
                | CqlOperator::Lt
                | CqlOperator::Lte
                | CqlOperator::Gt
                | CqlOperator::Gte
                | CqlOperator::Contains,
                CqlOperand::Single(_),
            )
            | (CqlOperator::In | CqlOperator::NotIn, CqlOperand::List(_)) => {}
            _ => return Err(cql_input_invalid("CQL clause operand is invalid")),
        }
        if matches!(field, CqlField::Type) {
            let CqlOperand::Single(CqlValue::Identifier(value)) = operand else {
                return Err(cql_input_invalid(format!(
                    "CQL type must equal {} for this action",
                    self.content_kind.cql_type()
                )));
            };
            if value != self.content_kind.cql_type() {
                return Err(cql_input_invalid(format!(
                    "CQL type must equal {} for this action",
                    self.content_kind.cql_type()
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn parse_order_by(&mut self) -> Result<Vec<CqlOrderTerm>, ProviderError> {
        let Some(order_keyword) = self.next_word() else {
            return Err(cql_input_invalid("CQL ORDER BY is invalid"));
        };
        if !order_keyword.eq_ignore_ascii_case("ORDER") {
            return Err(cql_input_invalid("CQL ORDER BY is invalid"));
        }
        let Some(by_keyword) = self.next_word() else {
            return Err(cql_input_invalid("CQL ORDER BY is invalid"));
        };
        if !by_keyword.eq_ignore_ascii_case("BY") {
            return Err(cql_input_invalid("CQL ORDER BY is invalid"));
        }
        let mut terms = Vec::new();
        loop {
            if terms.len() >= MAX_CONFLUENCE_ORDER_TERMS {
                return Err(cql_input_invalid("CQL ORDER BY exceeded the term cap"));
            }
            let Some(field_name) = self.next_word() else {
                return Err(cql_input_invalid("CQL ORDER BY field is missing"));
            };
            let field = CqlField::from_input(&field_name)
                .and_then(CqlSortField::from_field)
                .ok_or_else(|| {
                    cql_input_invalid(format!(
                        "CQL ORDER BY field at token {} is unsupported; supported sort fields: {}",
                        self.index,
                        cql_sort_names().join(", ")
                    ))
                })?;
            if self.consume(&CqlToken::LParen) {
                return Err(cql_input_invalid("CQL ORDER BY functions are unsupported"));
            }
            let direction = if self.peek_keyword("ASC") {
                self.index += 1;
                CqlSortDirection::Asc
            } else if self.peek_keyword("DESC") {
                self.index += 1;
                CqlSortDirection::Desc
            } else {
                CqlSortDirection::Asc
            };
            terms.push(CqlOrderTerm { field, direction });
            if self.consume(&CqlToken::Comma) {
                continue;
            }
            break;
        }
        if terms.is_empty() {
            return Err(cql_input_invalid("CQL ORDER BY is invalid"));
        }
        Ok(terms)
    }

    pub(crate) fn next_word(&mut self) -> Option<String> {
        if let Some(CqlToken::Word(value)) = self.tokens.get(self.index).cloned() {
            self.index += 1;
            Some(value)
        } else {
            None
        }
    }

    pub(crate) fn peek_keyword(&self, keyword: &str) -> bool {
        matches!(
            self.tokens.get(self.index),
            Some(CqlToken::Word(value)) if value.eq_ignore_ascii_case(keyword)
        )
    }

    pub(crate) fn peek_next_is_lparen(&self) -> bool {
        matches!(self.tokens.get(self.index + 1), Some(CqlToken::LParen))
    }

    pub(crate) fn consume(&mut self, token: &CqlToken) -> bool {
        if self.tokens.get(self.index) == Some(token) {
            self.index += 1;
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CqlToken {
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

pub(crate) fn lex_cql(input: &str) -> Result<Vec<CqlToken>, String> {
    let mut tokens = Vec::new();
    let mut chars = input.char_indices().peekable();
    while let Some((_, ch)) = chars.peek().copied() {
        match ch {
            ch if ch.is_whitespace() => {
                chars.next();
            }
            '(' => {
                chars.next();
                tokens.push(CqlToken::LParen);
            }
            ')' => {
                chars.next();
                tokens.push(CqlToken::RParen);
            }
            ',' => {
                chars.next();
                tokens.push(CqlToken::Comma);
            }
            '=' => {
                chars.next();
                tokens.push(CqlToken::Eq);
            }
            '!' => {
                chars.next();
                if consume_char(&mut chars, '=') {
                    tokens.push(CqlToken::NotEq);
                } else if consume_char(&mut chars, '~') {
                    tokens.push(CqlToken::NotTilde);
                } else {
                    return Err("CQL contains an unsupported operator".to_string());
                }
            }
            '<' => {
                chars.next();
                if consume_char(&mut chars, '=') {
                    tokens.push(CqlToken::Lte);
                } else {
                    tokens.push(CqlToken::Lt);
                }
            }
            '>' => {
                chars.next();
                if consume_char(&mut chars, '=') {
                    tokens.push(CqlToken::Gte);
                } else {
                    tokens.push(CqlToken::Gt);
                }
            }
            '~' => {
                chars.next();
                tokens.push(CqlToken::Tilde);
            }
            '"' | '\'' => tokens.push(CqlToken::String(read_cql_string(&mut chars, ch)?)),
            ch if is_cql_word_start(ch) => tokens.push(CqlToken::Word(read_cql_word(&mut chars))),
            ';' | '`' | '[' | ']' | '{' | '}' => {
                return Err("CQL contains an unsupported character".to_string());
            }
            _ => return Err("CQL contains an unsupported character".to_string()),
        }
        if tokens.len() > MAX_CONFLUENCE_QUERY_TOKENS {
            return Err("CQL exceeded the token cap".to_string());
        }
    }
    Ok(tokens)
}

pub(crate) fn consume_char<I>(chars: &mut std::iter::Peekable<I>, expected: char) -> bool
where
    I: Iterator<Item = (usize, char)>,
{
    if chars.peek().is_some_and(|(_, ch)| *ch == expected) {
        chars.next();
        true
    } else {
        false
    }
}

pub(crate) fn read_cql_string<I>(
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
            validate_cql_string_value(&value)?;
            return Ok(value);
        }
        if ch == '\\' {
            let Some((_, escaped)) = chars.next() else {
                return Err("CQL quoted value escape is unterminated".to_string());
            };
            match escaped {
                '"' => value.push('"'),
                '\\' => value.push('\\'),
                'n' => value.push('\n'),
                'r' => value.push('\r'),
                't' => value.push('\t'),
                _ => return Err("CQL quoted value contains an unsupported escape".to_string()),
            }
        } else {
            value.push(ch);
        }
    }
    Err("CQL quoted value is unterminated".to_string())
}

pub(crate) fn read_cql_word<I>(chars: &mut std::iter::Peekable<I>) -> String
where
    I: Iterator<Item = (usize, char)>,
{
    let mut value = String::new();
    while let Some((_, ch)) = chars.peek().copied() {
        if !is_cql_word_char(ch) {
            break;
        }
        value.push(ch);
        chars.next();
    }
    value
}

pub(crate) fn is_cql_word_start(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '+')
}

pub(crate) fn is_cql_word_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '/' | ':' | '+')
}

pub(crate) fn validate_cql_string_value(value: &str) -> Result<(), String> {
    if value.len() > MAX_CONFLUENCE_STRING_LITERAL_BYTES {
        return Err("exceeded the string literal byte cap".to_string());
    }
    if value
        .chars()
        .any(|ch| ch.is_control() && !matches!(ch, '\n' | '\r' | '\t'))
    {
        return Err("contains a control character".to_string());
    }
    Ok(())
}

pub(crate) fn is_safe_cql_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
}

pub(crate) fn is_safe_cql_bare_operand(value: &str) -> bool {
    is_safe_cql_identifier(value) && !is_cql_reserved_word(value)
}

pub(crate) fn is_cql_reserved_word(value: &str) -> bool {
    const RESERVED_WORDS: &[&str] = &[
        "AND", "ASC", "BY", "DESC", "EMPTY", "IN", "IS", "NOT", "OR", "ORDER",
    ];

    RESERVED_WORDS
        .iter()
        .any(|reserved| value.eq_ignore_ascii_case(reserved))
}

pub(crate) fn cql_bare_or_string_literal(value: &str) -> String {
    if is_safe_cql_bare_operand(value) {
        value.to_string()
    } else {
        cql_string_literal(value)
    }
}

pub(crate) fn parse_cql_date_literal(value: &str) -> Result<CqlDateLiteral, ProviderError> {
    let normalized = value.replace('/', "-");
    if cql_date_re().is_match(&normalized) {
        validate_cql_date(&normalized)?;
        return Ok(CqlDateLiteral {
            date: normalized,
            time: None,
        });
    }
    if let Some(captures) = cql_datetime_re().captures(&normalized) {
        validate_cql_date(&captures["date"])?;
        validate_cql_time(&captures["time"])?;
        return Ok(CqlDateLiteral {
            date: captures["date"].to_string(),
            time: Some(captures["time"].to_string()),
        });
    }
    Err(cql_input_invalid(
        "CQL date value is invalid; use YYYY-MM-DD or quoted YYYY-MM-DD HH:mm (slashes are also accepted)",
    ))
}

pub(crate) fn validate_cql_date(value: &str) -> Result<(), ProviderError> {
    NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .map(|_| ())
        .map_err(|_| cql_input_invalid("CQL date value is invalid; use YYYY-MM-DD or quoted YYYY-MM-DD HH:mm (slashes are also accepted)"))
}

pub(crate) fn validate_cql_time(value: &str) -> Result<(), ProviderError> {
    NaiveTime::parse_from_str(value, "%H:%M")
        .map(|_| ())
        .map_err(|_| cql_input_invalid("CQL date value is invalid; use YYYY-MM-DD or quoted YYYY-MM-DD HH:mm (slashes are also accepted)"))
}

#[cfg(test)]
pub(crate) fn parse_cql_spaces(cql: &str) -> Result<BTreeSet<String>, ProviderError> {
    Ok(parse_cql_query(cql)?.spaces())
}
