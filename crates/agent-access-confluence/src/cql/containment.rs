//! Compile host-selected content authority before adding the caller's query.
//!
//! This compiler is deliberately separate from the caller CQL parser: trusted
//! policy may require grouped negation, while caller grammar remains unchanged.
//! CQL is an indexed prefilter. Fresh provider evidence still authorizes results.
use super::*;
use crate::locations::{ContentLocationKind, parse_canonical_content_location};
use agent_access_provider::{
    ContainmentBoundary, ContainmentCollectionAuthorization, OfflineContainmentProof,
    ResourceContainer, ResourceSelector, ResourceType, TypedResourceSelector,
};

const MAX_AUTHORITY_SELECTOR_OCCURRENCES: usize = 4096;
// An allocation bound, NOT the HTTP request-size limit. The backend separately
// measures the encoded target and full URI, including fixed parameters/cursor.
const MAX_AUTHORITY_QUERY_BYTES: usize = 65_534;

fn authority_error() -> ProviderError {
    ProviderError::deny(
        ReasonCode::ScopeUnresolved,
        "Confluence content search authority could not be compiled within its limits",
    )
}

struct QueryWriter(String);

impl QueryWriter {
    fn new() -> Self {
        Self(String::new())
    }

    fn push(&mut self, value: &str) -> Result<(), ProviderError> {
        if self
            .0
            .len()
            .checked_add(value.len())
            .is_none_or(|len| len > MAX_AUTHORITY_QUERY_BYTES)
        {
            return Err(authority_error());
        }
        self.0.push_str(value);
        Ok(())
    }
}

fn authority_kind(
    authorization: &ContainmentCollectionAuthorization,
) -> Result<ConfluenceSearchContentKind, ProviderError> {
    match authorization.contract().domain.as_str() {
        "page" => Ok(ConfluenceSearchContentKind::Page),
        "blog" => Ok(ConfluenceSearchContentKind::BlogPost),
        _ => Err(authority_error()),
    }
}

fn count_authority(
    authorization: &ContainmentCollectionAuthorization,
) -> Result<(), ProviderError> {
    if authorization.grant_boundaries().len() > MAX_AUTHORITY_SELECTOR_OCCURRENCES {
        return Err(authority_error());
    }
    let mut count = 0usize;
    for boundary in authorization
        .grant_boundaries()
        .iter()
        .chain(authorization.token_boundary())
    {
        for amount in [boundary.included().len(), boundary.excluded().len()] {
            count = count.checked_add(amount).ok_or_else(authority_error)?;
            if count > MAX_AUTHORITY_SELECTOR_OCCURRENCES {
                return Err(authority_error());
            }
        }
    }
    Ok(())
}

fn write_false(out: &mut QueryWriter) -> Result<(), ProviderError> {
    // A contradiction uses only documented, nonnullable content-type fields.
    out.push("(type = page AND type = blogpost)")
}

fn write_selector(
    out: &mut QueryWriter,
    selector: &TypedResourceSelector,
    kind: ConfluenceSearchContentKind,
    site_origin: &str,
) -> Result<(), ProviderError> {
    match selector.resource_type().as_str() {
        "confluence_space" => match selector.selector() {
            ResourceSelector::All => {
                out.push("type = ")?;
                out.push(kind.cql_type())
            }
            ResourceSelector::Exact { value } if is_space_key(value) => {
                out.push("space = ")?;
                out.push(&cql_string_literal(value))
            }
            _ => Err(authority_error()),
        },
        "confluence_content" => {
            let (value, subtree) = match selector.selector() {
                ResourceSelector::Exact { value } => (value, false),
                ResourceSelector::Subtree { value } => (value, true),
                _ => return Err(authority_error()),
            };
            let location =
                parse_canonical_content_location(value).map_err(|_| authority_error())?;
            let projection = selector.projection().ok_or_else(authority_error)?;
            if projection.site_origin != location.site_origin
                || projection.root_kind != location.kind.as_str()
                || !projection.containers.iter().any(|container| {
                    container.resource_type.as_str() == "confluence_space"
                        && container.value == location.space_key
                })
            {
                return Err(authority_error());
            }
            if location.site_origin != site_origin {
                return write_false(out);
            }
            let applicable = matches!(
                (kind, location.kind, subtree),
                (
                    ConfluenceSearchContentKind::Page,
                    ContentLocationKind::Page,
                    _
                ) | (
                    ConfluenceSearchContentKind::Page,
                    ContentLocationKind::Folder,
                    true
                ) | (
                    ConfluenceSearchContentKind::BlogPost,
                    ContentLocationKind::Blog,
                    false
                )
            );
            if !applicable {
                return write_false(out);
            }
            let id = location.id.as_deref().ok_or_else(authority_error)?;
            out.push("(space = ")?;
            out.push(&cql_string_literal(&location.space_key))?;
            out.push(" AND ")?;
            if subtree {
                if location.kind == ContentLocationKind::Page {
                    out.push("(id = ")?;
                    out.push(id)?;
                    out.push(" OR ancestor = ")?;
                    out.push(id)?;
                    out.push(")")?;
                } else {
                    out.push("ancestor = ")?;
                    out.push(id)?;
                }
            } else {
                out.push("id = ")?;
                out.push(id)?;
            }
            out.push(")")
        }
        _ => Err(authority_error()),
    }
}

fn write_selector_union(
    out: &mut QueryWriter,
    selectors: &[TypedResourceSelector],
    kind: ConfluenceSearchContentKind,
    site_origin: &str,
) -> Result<(), ProviderError> {
    if selectors.is_empty() {
        return write_false(out);
    }
    out.push("(")?;
    for (index, selector) in selectors.iter().enumerate() {
        if index > 0 {
            out.push(" OR ")?;
        }
        write_selector(out, selector, kind, site_origin)?;
    }
    out.push(")")
}

fn write_boundary(
    out: &mut QueryWriter,
    boundary: &ContainmentBoundary,
    kind: ConfluenceSearchContentKind,
    site_origin: &str,
) -> Result<(), ProviderError> {
    out.push("(")?;
    write_selector_union(out, boundary.included(), kind, site_origin)?;
    if !boundary.excluded().is_empty() {
        out.push(" AND NOT ")?;
        write_selector_union(out, boundary.excluded(), kind, site_origin)?;
    }
    out.push(")")
}

/// Every winning boundary is preserved before union; the token stays a separate
/// conjunction. No DNF expansion, lower-band selection or space-only fallback.
pub(crate) fn compile_content_authority(
    authorization: &ContainmentCollectionAuthorization,
    site_origin: &str,
) -> Result<String, ProviderError> {
    if authorization.site_origin() != site_origin {
        return Err(authority_error());
    }
    count_authority(authorization)?;
    let kind = authority_kind(authorization)?;
    let mut out = QueryWriter::new();
    out.push("(")?;
    if authorization.grant_boundaries().is_empty() {
        write_false(&mut out)?;
    }
    for (index, boundary) in authorization.grant_boundaries().iter().enumerate() {
        if index > 0 {
            out.push(" OR ")?;
        }
        write_boundary(&mut out, boundary, kind, site_origin)?;
    }
    out.push(")")?;
    if let Some(token) = authorization.token_boundary() {
        out.push(" AND ")?;
        write_boundary(&mut out, token, kind, site_origin)?;
    }
    Ok(out.0)
}

pub(crate) fn requested_space_coverage(
    authorization: &ContainmentCollectionAuthorization,
    space: &str,
) -> Result<OfflineContainmentProof, ProviderError> {
    if !is_space_key(space) {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "Confluence search space key is invalid",
        ));
    }
    Ok(
        authorization.requested_container_coverage(&ResourceContainer::new(
            ResourceType::from_static("confluence_space"),
            space,
        )),
    )
}

pub(crate) fn build_containment_search_query(
    query: &ConfluenceSearchQueryInput,
    authorization: &ContainmentCollectionAuthorization,
    requested: &BTreeSet<String>,
    limits: &SearchLimitsConfig,
    content_kind: ConfluenceSearchContentKind,
    site_origin: &str,
) -> Result<BuiltConfluenceSearchQuery, ProviderError> {
    if authority_kind(authorization)? != content_kind {
        return Err(authority_error());
    }
    for space in requested {
        if matches!(
            requested_space_coverage(authorization, space)?,
            OfflineContainmentProof::Empty
        ) {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "requested Confluence spaces are not authorized",
            ));
        }
    }
    let (ast, kind) = match query {
        ConfluenceSearchQueryInput::Cql { value } => {
            (parse_cql_query_for_kind(value, content_kind)?, "cql")
        }
        ConfluenceSearchQueryInput::Text { value } => {
            (confluence_text_query(value, limits)?, "text")
        }
    };
    let authority = compile_content_authority(authorization, site_origin)?;
    let caller_cql = ast.emit();
    let mut out = QueryWriter::new();
    out.push("type = ")?;
    out.push(content_kind.cql_type())?;
    out.push(" AND (")?;
    out.push(&authority)?;
    out.push(")")?;
    if !requested.is_empty() {
        out.push(" AND (")?;
        for (index, space) in requested.iter().enumerate() {
            if index > 0 {
                out.push(" OR ")?;
            }
            out.push("space = ")?;
            out.push(&cql_string_literal(space))?;
        }
        out.push(")")?;
    }
    if let Some(filter) = &ast.filter {
        out.push(" AND (")?;
        out.push(&filter.emit())?;
        out.push(")")?;
    }
    let order_by = ast.emit_order_by();
    if !order_by.is_empty() {
        out.push(" ")?;
        out.push(&order_by)?;
    }
    Ok(BuiltConfluenceSearchQuery {
        cql: out.0,
        kind,
        injected_space_predicate: "content_authority",
        injected_type_predicate: content_kind.injected_type_predicate(),
        canonical_caller_cql_hash: sha256_hex(caller_cql.as_bytes()),
        canonical_caller_cql: caller_cql,
        query_shape: ast.query_shape(),
        text_operand_hashes: ast.text_operand_hashes(),
        sort_fields: ast.sort_fields(),
    })
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod grammar_tests;
