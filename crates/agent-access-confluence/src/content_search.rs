//! Collection authority is compiled upstream, then checked against current
//! evidence before any candidate metadata is released. Cursors contain only an
//! encrypted resume position and consistency commitment, never cached bodies.
use super::*;

const TOKENS: ContinuationFamily = ContinuationFamily::new(
    "confluence",
    "content-search",
    2,
    ContinuationLifetime::Generation,
    0,
)
.confidential()
.expires_after(Duration::from_secs(900));
const MAX_CURSOR_HISTORY: usize = 4096;
// Each complete pass can read 64 typed nodes and one space. The operation's
// actual HTTP counters additionally count the one shared delegated recovery.
const PROOF_PASS_REQUESTS: u32 = 65;

fn family(limits: &ProviderLimits) -> ContinuationFamily {
    let cap = usize::try_from(limits.max_upstream_response_bytes).unwrap_or(usize::MAX);
    TOKENS.with_max_payload_bytes(TOKENS.max_payload_bytes_within(cap))
}

fn invalid_cursor() -> ProviderError {
    ProviderError::deny(
        ReasonCode::InputInvalid,
        "Confluence search continuation is invalid or its authority changed; repeat the search without nextPageToken",
    )
}

fn protocol() -> ProviderError {
    ProviderError::error(
        ReasonCode::UpstreamProtocolFailed,
        "Confluence search returned invalid content or continuation metadata",
    )
}

fn budget_error() -> ProviderError {
    ProviderError::deny(
        ReasonCode::ScopeUnresolved,
        "Confluence search cannot complete current location checks within its work limits",
    )
}

fn token_error(error: ContinuationError) -> ProviderError {
    match error {
        ContinuationError::Invalid
        | ContinuationError::UnsupportedVersion
        | ContinuationError::Expired
        | ContinuationError::UpstreamQueryChanged
        | ContinuationError::TokenTooLarge { .. } => invalid_cursor(),
        _ => protocol(),
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Position {
    cursor: Option<String>,
    offset: usize,
    page_limit: u32,
    page_commitment: Option<String>,
    // Cursor digests, inside the confidential envelope. This detects cycles
    // across invocations without disclosing upstream cursor material.
    history: Vec<String>,
}

impl Position {
    fn first(page_limit: u32) -> Self {
        Self {
            cursor: None,
            offset: 0,
            page_limit,
            page_commitment: None,
            history: vec![],
        }
    }

    fn open(payload: &[u8], max_results: u32) -> Result<Self, ProviderError> {
        let position: Self = serde_json::from_slice(payload).map_err(|_| invalid_cursor())?;
        if position.page_limit == 0
            || position.page_limit > max_results
            || position.offset >= position.page_limit as usize
            || position.history.len() > MAX_CURSOR_HISTORY
            || position.cursor.as_ref().is_some_and(String::is_empty)
            || position.history.iter().any(|hash| !is_digest(hash))
            || position
                .page_commitment
                .as_ref()
                .is_some_and(|hash| !is_digest(hash))
            || ((position.offset > 0) != position.page_commitment.is_some())
            || (position.cursor.is_some() != !position.history.is_empty())
            || position.cursor.as_ref().is_some_and(|cursor| {
                position.history.last() != Some(&sha256_hex(cursor.as_bytes()))
            })
        {
            return Err(invalid_cursor());
        }
        let unique = position.history.iter().collect::<BTreeSet<_>>();
        if unique.len() != position.history.len() {
            return Err(invalid_cursor());
        }
        Ok(position)
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

enum Row {
    Page(ConfluencePage),
    Blog(ConfluenceBlogSummary),
}

impl Row {
    fn facts(&self) -> (&str, &str, Option<&str>, u64) {
        match self {
            Self::Page(page) => (&page.id, &page.space, page.status.as_deref(), page.version),
            Self::Blog(blog) => (&blog.id, &blog.space, blog.status.as_deref(), blog.version),
        }
    }
    fn id(&self) -> &str {
        self.facts().0
    }
    fn space(&self) -> &str {
        self.facts().1
    }

    fn location(&self, site: &str) -> Result<ContentLocation, ProviderError> {
        let (id, space, status, version) = self.facts();
        if !locations::is_canonical_content_id(id)
            || !is_space_key(space)
            || status != Some("current")
            || version == 0
        {
            return Err(protocol());
        }
        let (kind, segment) = match self {
            Self::Page(_) => ("page", "pages"),
            Self::Blog(_) => ("blog", "blog"),
        };
        Ok(ContentLocation::new(
            ContainmentIdentity::new(
                CONFLUENCE_CONTENT_RESOURCE.id().clone(),
                kind,
                format!("{site}/wiki/spaces/{space}/{segment}/{id}"),
            ),
            vec![ResourceContainer::new(
                CONFLUENCE_SPACE_RESOURCE.id().clone(),
                space,
            )],
            ContainmentEvidenceLevel::ContainerOnly,
        ))
    }
}

struct CandidatePage {
    rows: Vec<Row>,
    next: Option<String>,
}

impl CandidatePage {
    fn commitment(&self) -> Result<String, ProviderError> {
        let facts = self.rows.iter().map(Row::facts).collect::<Vec<_>>();
        let bytes = serde_json::to_vec(&(facts, &self.next)).map_err(|_| protocol())?;
        Ok(sha256_hex(&bytes))
    }
}

struct Retained {
    row: Row,
    proof: Option<SearchLocationProof>,
}

fn binding(
    provider: &ConfluenceProvider,
    request: &ProviderInvocation,
    authority: &ContainmentCollectionAuthorization,
    query: &BuiltConfluenceSearchQuery,
    requested: &BTreeSet<String>,
    max_results: u32,
) -> Result<ContinuationBinding, ProviderError> {
    let profile = serde_json::to_vec(&(
        provider.config.site().route_fingerprint(),
        &provider.config.content_access,
        &provider.config.content_search,
        provider.limits.max_upstream_response_bytes,
    ))
    .map_err(|_| protocol())?;
    let profile: [u8; 32] = Sha256::digest(profile).into();
    Ok(bind_atlassian_access(
        family(&provider.limits).bind(request.context(), profile),
        request.execution(),
        provider.config.cloud_id.as_deref(),
    )?
    .text("authority", authority.authority_digest())
    .text("domain", &authority.contract().domain)
    .text("queryType", query.kind)
    .text("callerQuery", &query.canonical_caller_cql)
    .text("upstreamQuery", &sha256_hex(query.cql.as_bytes()))
    .texts("spaces", requested.iter().map(String::as_str))
    .number("maxResults", u64::from(max_results)))
}

impl ConfluenceProvider {
    async fn fetch_content_candidates(
        &self,
        kind: ConfluenceSearchContentKind,
        query: &BuiltConfluenceSearchQuery,
        position: &Position,
        credential: &AtlassianCredential,
    ) -> Result<CandidatePage, ProviderError> {
        let request = ConfluenceSearchRequest {
            cql: query.cql.clone(),
            max_results: position.page_limit,
            next_page_token: position.cursor.clone(),
        };
        let page = match kind {
            ConfluenceSearchContentKind::Page => {
                let response = self
                    .backend
                    .search(request, credential)
                    .await
                    .map_err(confluence_backend_error)?;
                CandidatePage {
                    rows: response.value.pages.into_iter().map(Row::Page).collect(),
                    next: response.value.next_page_token,
                }
            }
            ConfluenceSearchContentKind::BlogPost => {
                let response = self
                    .backend
                    .search_blogs(request, credential)
                    .await
                    .map_err(confluence_backend_error)?;
                CandidatePage {
                    rows: response.value.blogs.into_iter().map(Row::Blog).collect(),
                    next: response.value.next_page_token,
                }
            }
        };
        if page.rows.len() > position.page_limit as usize
            || page.next.as_ref().is_some_and(String::is_empty)
            || page
                .next
                .as_ref()
                .is_some_and(|cursor| position.history.contains(&sha256_hex(cursor.as_bytes())))
        {
            return Err(protocol());
        }
        let mut ids = BTreeSet::new();
        for row in &page.rows {
            if !ids.insert(row.id()) {
                return Err(protocol());
            }
        }
        if position.offset > page.rows.len() {
            return Err(invalid_cursor());
        }
        if let Some(hash) = &position.page_commitment
            && page.commitment()? != *hash
        {
            return Err(invalid_cursor());
        }
        Ok(page)
    }

    pub(crate) async fn invoke_content_search(
        &self,
        request: ProviderInvocation,
        kind: ConfluenceSearchContentKind,
    ) -> Result<ProviderResult, ProviderError> {
        if !request.body_parts().is_empty() {
            return Err(protocol());
        }
        let started = Instant::now();
        let inputs = parse_search_inputs(request.inputs())?;
        let requested = requested_spaces(&inputs)?;
        let authority = request.containment_collection_authorization()?;
        let site = format!("https://{}", self.config.tenant_host);
        let query = build_containment_search_query(
            &inputs.query,
            authority,
            &requested,
            &self.config.search,
            kind,
            &site,
        )?;
        let max_results = capped_max_results(inputs.max_results, &self.config.search)?;
        let binding = binding(self, &request, authority, &query, &requested, max_results)?;
        let opened = inputs
            .next_page_token
            .as_deref()
            .map(|token| {
                self.listing_signer
                    .open_confidential(&binding, token)
                    .map_err(token_error)
            })
            .transpose()?;
        let expiry = self
            .listing_signer
            .deadline(&binding)
            .map_err(token_error)?;
        let limits = &self.config.content_search;
        let mut position = opened
            .as_ref()
            .map(|token| Position::open(token.payload(), max_results))
            .transpose()?
            .unwrap_or_else(|| Position::first(max_results.min(limits.max_candidates)));
        let scan = ConfluenceMetadataBudget::new(&ConfluenceContentAccessConfig {
            max_metadata_requests: limits.max_upstream_requests,
            max_metadata_bytes: limits.max_scan_bytes,
        });
        let metadata = ConfluenceMetadataBudget::with_parent(&self.config.content_access, &scan);
        let credential = self.execution_credential(request.admitted())?;
        let complete = authority.evidence_level() == ContainmentEvidenceLevel::CompleteLineage;
        let recovery = u32::from(matches!(request.execution(), ExecutionAccess::Delegated(_)));
        let reserve_one = PROOF_PASS_REQUESTS * 2 + recovery;
        // A fresh request that cannot possibly complete one candidate must not
        // return a token at the same position forever.
        if complete
            && (metadata
                .remaining_requests()
                .map_err(confluence_backend_error)?
                < reserve_one
                || scan
                    .remaining_requests()
                    .map_err(confluence_backend_error)?
                    < reserve_one + 1)
        {
            return Err(budget_error());
        }
        let (retained, next, scan_status) = scan
            .scope(async {
                let mut retained: Vec<Retained> = vec![];
                let mut scanned = 0u32;
                let mut pages = 0u32;
                let mut seen_ids = BTreeSet::new();
                loop {
                    if pages >= limits.max_candidate_pages
                        || scanned >= limits.max_candidates
                        || scan
                            .remaining_requests()
                            .map_err(confluence_backend_error)?
                            <= recovery
                    {
                        if pages == 0 {
                            return Err(budget_error());
                        }
                        break Ok((retained, Some(position), "scan_budget"));
                    }
                    if position.offset == 0 {
                        position.page_limit = max_results.min(limits.max_candidates - scanned);
                    }
                    let page = self
                        .fetch_content_candidates(kind, &query, &position, &credential)
                        .await?;
                    pages += 1;
                    let commitment = page.commitment()?;
                    let start_offset = position.offset;
                    let row_count = page.rows.len();
                    for (offset, row) in page.rows.into_iter().enumerate().skip(start_offset) {
                        // Validate the row independently even if current evidence
                        // later shows that an indexed result has moved outside scope.
                        let indexed = row.location(&site)?;
                        if !seen_ids.insert(row.id().to_owned()) {
                            return Err(protocol());
                        }
                        let reserved_final = u32::try_from(retained.len())
                            .map_err(|_| budget_error())?
                            .checked_mul(PROOF_PASS_REQUESTS)
                            .ok_or_else(budget_error)?;
                        if scanned >= limits.max_candidates
                            || (complete
                                && metadata
                                    .remaining_requests()
                                    .map_err(confluence_backend_error)?
                                    < reserve_one + reserved_final)
                        {
                            if scanned == 0 {
                                return Err(budget_error());
                            }
                            position.offset = offset;
                            position.page_commitment = (offset > 0).then_some(commitment);
                            return Ok((retained, Some(position), "scan_budget"));
                        }
                        scanned += 1;
                        if complete {
                            let proof = self
                                .search_location_proof(
                                    kind,
                                    row.id(),
                                    authority.evidence_level(),
                                    &credential,
                                    &metadata,
                                )
                                .await?;
                            if proof.location.target != indexed.target {
                                continue;
                            }
                            if authority
                                .matches_candidate(&proof.location)
                                .map_err(|_| protocol())?
                            {
                                retained.push(Retained {
                                    row,
                                    proof: Some(proof),
                                });
                            }
                        } else if authority
                            .matches_candidate(&indexed)
                            .map_err(|_| protocol())?
                        {
                            retained.push(Retained { row, proof: None });
                        }
                    }
                    if start_offset > 0 && start_offset == row_count {
                        return Err(invalid_cursor());
                    }
                    let Some(cursor) = page.next else {
                        break Ok((retained, None, "exhausted"));
                    };
                    if position.history.len() >= MAX_CURSOR_HISTORY {
                        return Err(protocol());
                    }
                    position.history.push(sha256_hex(cursor.as_bytes()));
                    position.cursor = Some(cursor);
                    position.offset = 0;
                    position.page_commitment = None;
                    position.page_limit = max_results.min(limits.max_candidates);
                    // A result page need not fill maxResults. Continue empty indexed
                    // pages within the budget; once there are rows, finish their final
                    // checks before any more candidate fetches.
                    if !retained.is_empty() {
                        break Ok((retained, Some(position), "more"));
                    }
                }
            })
            .await?;
        let mut released = vec![];
        let mut final_check = "not_run";
        for candidate in retained {
            if let Some(initial) = candidate.proof {
                let final_proof = self
                    .search_location_proof(
                        kind,
                        candidate.row.id(),
                        authority.evidence_level(),
                        &credential,
                        &metadata,
                    )
                    .await
                    .map_err(|mut error| {
                        error.audit.get_or_insert_with(|| Box::new(json!({})))["locationProof"] =
                            json!({"finalCheck":"unresolved"});
                        error
                    })?;
                if !initial.same_location(&final_proof)
                    || !authority
                        .matches_candidate(&final_proof.location)
                        .map_err(|_| protocol())?
                {
                    final_check = "changed";
                    continue;
                }
            }
            if final_check != "changed" {
                final_check = "matched";
            }
            released.push(candidate.row);
        }
        let next_page_token = next
            .map(|position| {
                let payload = serde_json::to_vec(&position).map_err(|_| protocol())?;
                if let Some(opened) = &opened {
                    self.listing_signer.seal_resumed(&binding, &payload, opened)
                } else {
                    self.listing_signer.seal_until(&binding, &payload, expiry)
                }
                .map_err(token_error)
            })
            .transpose()?;
        let observed_spaces = released
            .iter()
            .map(|row| row.space().to_owned())
            .collect::<BTreeSet<_>>();
        let object_ids = released
            .iter()
            .map(|row| row.id().to_owned())
            .collect::<Vec<_>>();
        let mut fallbacks = BrowserUrlFallbacks::default();
        let mut result = match kind {
            ConfluenceSearchContentKind::Page => search_result(
                &ConfluenceSearchPage {
                    pages: released
                        .into_iter()
                        .map(|row| match row {
                            Row::Page(page) => Ok(page),
                            _ => Err(protocol()),
                        })
                        .collect::<Result<_, _>>()?,
                    max_results,
                    next_page_token: None,
                },
                next_page_token.as_deref(),
                &self.config,
                &mut fallbacks,
            )?,
            ConfluenceSearchContentKind::BlogPost => blog_search_result(
                &ConfluenceSearchBlog {
                    blogs: released
                        .into_iter()
                        .map(|row| match row {
                            Row::Blog(blog) => Ok(blog),
                            _ => Err(protocol()),
                        })
                        .collect::<Result<_, _>>()?,
                    max_results,
                    next_page_token: None,
                },
                next_page_token.as_deref(),
                &self.config,
                &mut fallbacks,
            )?,
        };
        result["scanStatus"] = json!(scan_status);
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        let operation = if kind == ConfluenceSearchContentKind::Page {
            "search"
        } else {
            "blog.search"
        };
        Ok(ProviderResult::new(result).with_audit(fallbacks.into_audit(json!({
            "provider":"confluence", "operation":operation, "requestedSpaces":requested,
            "queryType":query.kind, "queryAstVersion":CONFLUENCE_QUERY_AST_VERSION,
            "canonicalCallerCqlHash":query.canonical_caller_cql_hash, "queryShape":query.query_shape,
            "textOperandHashes":query.text_operand_hashes, "injectedSpacePredicate":query.injected_space_predicate,
            "injectedTypePredicate":query.injected_type_predicate, "observedSpaces":observed_spaces,
            "returnedUrlFields":["webUrl","spaceUrl"], "sortFields":query.sort_fields,
            "maxResults":max_results, "resultCount":object_ids.len(), "scanStatus":scan_status,
            "locationProof":{"finalCheck":final_check},
            "credentialMode":request.credential_mode(), "egressProxy":self.backend.egress_proxy_audit(&credential),
        }))).with_upstream(Some(200), Some(elapsed_ms(started)))
            .with_object_ids(if kind == ConfluenceSearchContentKind::Page { json!({"pageIds":object_ids}) } else { json!({"blogIds":object_ids}) }))
    }
}

#[cfg(test)]
mod tests;
