//! Current content-location evidence and operation-local dispatch/release fences.
//! The host owns grants and precedence; this module supplies authenticated facts.
use super::*;

const MAX_LINEAGE_NODES: usize = 64;
const POINT_PASS_READS: u32 = 65;
const MOVE_PASS_READS: u32 = 256;
const MAX_MOVE_ROOTS: usize = 64;

#[derive(Clone, Debug)]
pub(crate) struct CreationParentLocator {
    pub(crate) parent: ConfluenceParent,
    pub(crate) url_space: Option<String>,
}

#[derive(Clone)]
enum ContentPlan {
    Page {
        id: String,
        url_space: Option<String>,
        regular: bool,
    },
    Blog {
        id: String,
        url_space: Option<String>,
    },
    Create {
        space: String,
        parent: Option<CreationParentLocator>,
    },
    Move(PageMoveInputs),
    Comment {
        action: ConfluenceCommentAction,
        owner_id: Option<String>,
        comment_id: Option<String>,
    },
    Draft(ConfluenceDraftHandle),
}

#[derive(Clone, PartialEq, Eq)]
struct NodeFact {
    id: String,
    kind: ConfluenceNodeKind,
    space_id: String,
    parent: Option<ConfluenceParent>,
    status: ConfluenceContentStatus,
}

impl NodeFact {
    fn of(node: &ConfluenceNode, level: ContainmentEvidenceLevel) -> Self {
        Self {
            id: node.id.clone(),
            kind: node.kind,
            space_id: node.space_id.clone(),
            parent: if level == ContainmentEvidenceLevel::CompleteLineage {
                node.parent.clone()
            } else {
                None
            },
            status: node.status,
        }
    }
}

#[derive(Clone)]
pub(crate) struct ContentProof {
    pub(crate) evidence: ContainmentEvidence,
    pub(crate) space: ConfluenceSpace,
    pub(crate) destination: Option<ConfluenceParent>,
    pub(crate) regular_page: Option<ConfluenceRegularPage>,
    graph: Vec<NodeFact>,
    blogs: Vec<(String, String, ConfluenceContentStatus)>,
    comment_chain: Vec<String>,
}

/// Kept unchanged through body spooling. Its shared counters never reset at a
/// file boundary or a final check, and the host never serializes its graph.
#[derive(Clone)]
pub(crate) struct ContentOperationState {
    plan: ContentPlan,
    initial: ContentProof,
    roots: Vec<TypedResourceSelector>,
    level: ContainmentEvidenceLevel,
    route: [u8; 32],
    pub(crate) budget: ConfluenceMetadataBudget,
    final_check: Arc<std::sync::atomic::AtomicU8>,
}

pub(crate) fn location_unresolved() -> ProviderError {
    ProviderError::deny(
        ReasonCode::ScopeUnresolved,
        "Confluence content location could not be confirmed",
    )
}

fn location_backend_error(error: ConfluenceBackendError) -> ProviderError {
    match error {
        ConfluenceBackendError::Forbidden
        | ConfluenceBackendError::NotFound
        | ConfluenceBackendError::ScopeUnresolved => location_unresolved(),
        other => confluence_backend_error(other),
    }
}

fn location_provider_error(error: ProviderError) -> ProviderError {
    if matches!(
        error.reason_code().standard(),
        Some(ReasonCode::UpstreamForbidden | ReasonCode::ScopeUnresolved)
    ) {
        location_unresolved()
    } else {
        error
    }
}

fn malformed_location() -> ProviderError {
    ProviderError::error(
        ReasonCode::UpstreamProtocolFailed,
        "Confluence returned invalid content-location metadata",
    )
}

fn content_identity(site: &str, space: &str, kind: &str, id: &str) -> ContainmentIdentity {
    let segment = match kind {
        "page" => "pages",
        "folder" => "folder",
        "blog" => "blog",
        _ => unreachable!("only selectable identities are projected"),
    };
    ContainmentIdentity::new(
        CONFLUENCE_CONTENT_RESOURCE.id().clone(),
        kind,
        format!("{site}/wiki/spaces/{space}/{segment}/{id}"),
    )
}

struct LocationPass<'a> {
    provider: &'a ConfluenceProvider,
    credential: &'a AtlassianCredential,
    budget: &'a ConfluenceMetadataBudget,
    level: ContainmentEvidenceLevel,
    site: String,
    logical_reads: u32,
    max_reads: u32,
    current_nodes: BTreeMap<(ConfluenceNodeKind, String), ConfluenceNode>,
    spaces: BTreeMap<String, ConfluenceSpace>,
    graph: Vec<NodeFact>,
    blogs: Vec<(String, String, ConfluenceContentStatus)>,
    regular_page: Option<ConfluenceRegularPage>,
}

impl<'a> LocationPass<'a> {
    fn new(
        provider: &'a ConfluenceProvider,
        credential: &'a AtlassianCredential,
        budget: &'a ConfluenceMetadataBudget,
        level: ContainmentEvidenceLevel,
        is_move: bool,
    ) -> Self {
        Self {
            provider,
            credential,
            budget,
            level,
            site: format!("https://{}", provider.config.tenant_host),
            logical_reads: 0,
            max_reads: if is_move {
                MOVE_PASS_READS
            } else {
                POINT_PASS_READS
            },
            current_nodes: BTreeMap::new(),
            spaces: BTreeMap::new(),
            graph: Vec::new(),
            blogs: Vec::new(),
            regular_page: None,
        }
    }

    fn charge(&mut self) -> Result<(), ProviderError> {
        if self.logical_reads >= self.max_reads {
            return Err(location_unresolved());
        }
        self.logical_reads += 1;
        Ok(())
    }

    async fn space(&mut self, id: &str) -> Result<ConfluenceSpace, ProviderError> {
        if let Some(space) = self.spaces.get(id) {
            return Ok(space.clone());
        }
        self.charge()?;
        let space = self
            .provider
            .backend
            .space_location_metadata(id, self.credential, self.budget)
            .await
            .map_err(location_backend_error)?
            .value;
        if space.id != id || !locations::is_canonical_content_id(id) || !is_space_key(&space.key) {
            return Err(malformed_location());
        }
        if space.status.as_deref() != Some("current") {
            return Err(location_unresolved());
        }
        self.spaces.insert(id.to_owned(), space.clone());
        Ok(space)
    }

    async fn node(
        &mut self,
        kind: ConfluenceNodeKind,
        id: &str,
        status: ConfluenceContentStatus,
        regular: bool,
    ) -> Result<ConfluenceNode, ProviderError> {
        if !regular
            && status == ConfluenceContentStatus::Current
            && let Some(node) = self.current_nodes.get(&(kind, id.to_owned()))
        {
            return Ok(node.clone());
        }
        self.charge()?;
        let node = if regular {
            let page = self
                .provider
                .backend
                .regular_page_metadata(
                    id,
                    self.level == ContainmentEvidenceLevel::CompleteLineage,
                    self.credential,
                    self.budget,
                )
                .await
                .map_err(location_backend_error)?
                .value;
            let node = page.node.clone();
            self.regular_page = Some(page);
            node
        } else {
            self.provider
                .backend
                .hierarchy_node(
                    kind,
                    id,
                    status,
                    self.level == ContainmentEvidenceLevel::CompleteLineage
                        || status == ConfluenceContentStatus::Draft,
                    self.credential,
                    self.budget,
                )
                .await
                .map_err(location_backend_error)?
                .value
        };
        if node.status != status {
            return Err(location_unresolved());
        }
        if node.id != id
            || node.kind != kind
            || !locations::is_canonical_content_id(id)
            || !locations::is_canonical_content_id(&node.space_id)
            || node.parent.as_ref().is_some_and(|parent| {
                !locations::is_canonical_content_id(&parent.id) || parent.id == id
            })
        {
            return Err(malformed_location());
        }
        if status == ConfluenceContentStatus::Current {
            self.current_nodes
                .insert((kind, id.to_owned()), node.clone());
        }
        Ok(node)
    }

    async fn location(
        &mut self,
        first: ConfluenceNode,
        provenance: ContainmentProvenance,
    ) -> Result<(ContentLocation, ConfluenceSpace), ProviderError> {
        let space = self.space(&first.space_id).await?;
        let target = content_identity(&self.site, &space.key, first.kind.as_str(), &first.id);
        let mut location = ContentLocation::new(
            target,
            vec![ResourceContainer::new(
                CONFLUENCE_SPACE_RESOURCE.id().clone(),
                &space.key,
            )],
            self.level,
        )
        .with_provenance(provenance);
        self.graph.push(NodeFact::of(&first, self.level));
        if self.level == ContainmentEvidenceLevel::CompleteLineage {
            let mut visited = BTreeSet::from([first.id.clone()]);
            let mut parent = first.parent;
            while let Some(reference) = parent {
                if visited.len() >= MAX_LINEAGE_NODES || !visited.insert(reference.id.clone()) {
                    return Err(location_unresolved());
                }
                let node = self
                    .node(
                        reference.kind,
                        &reference.id,
                        ConfluenceContentStatus::Current,
                        false,
                    )
                    .await?;
                if node.space_id != space.id {
                    return Err(location_unresolved());
                }
                if matches!(
                    node.kind,
                    ConfluenceNodeKind::Page | ConfluenceNodeKind::Folder
                ) {
                    location.ancestors.push(content_identity(
                        &self.site,
                        &space.key,
                        node.kind.as_str(),
                        &node.id,
                    ));
                }
                self.graph.push(NodeFact::of(&node, self.level));
                parent = node.parent;
            }
        }
        Ok((location, space))
    }

    async fn page(
        &mut self,
        id: &str,
        regular: bool,
    ) -> Result<(ContentLocation, ConfluenceSpace), ProviderError> {
        let node = self
            .node(
                ConfluenceNodeKind::Page,
                id,
                ConfluenceContentStatus::Current,
                regular,
            )
            .await?;
        self.location(node, ContainmentProvenance::Observed).await
    }

    async fn blog(
        &mut self,
        id: &str,
        status: ConfluenceContentStatus,
    ) -> Result<(ContentLocation, ConfluenceSpace), ProviderError> {
        self.charge()?;
        let blog = self
            .provider
            .backend
            .blog_location_metadata(id, status, self.credential, self.budget)
            .await
            .map_err(location_backend_error)?
            .value;
        if blog.status != status {
            return Err(location_unresolved());
        }
        if blog.id != id
            || !locations::is_canonical_content_id(id)
            || !locations::is_canonical_content_id(&blog.space_id)
        {
            return Err(malformed_location());
        }
        let space = self.space(&blog.space_id).await?;
        self.blogs
            .push((blog.id.clone(), blog.space_id.clone(), blog.status));
        Ok((
            ContentLocation::new(
                content_identity(&self.site, &space.key, "blog", id),
                vec![ResourceContainer::new(
                    CONFLUENCE_SPACE_RESOURCE.id().clone(),
                    &space.key,
                )],
                self.level,
            ),
            space,
        ))
    }
}

impl ConfluenceProvider {
    pub(crate) fn validate_content_locator(
        &self,
        request: LocalScopeRequest<'_>,
    ) -> Result<Option<ProviderState>, ProviderError> {
        let Some((kind, id, token)) = draft_handle_reference(request.action(), request.inputs())?
        else {
            return Ok(None);
        };
        let handle = self
            .continuations
            .open_draft_handle_for_local_scope(&request, kind, &id, &token)?;
        Ok(Some(ProviderState::new(handle)))
    }

    pub(crate) async fn resolve_content_scopes(
        &self,
        request: &ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        let credential = self
            .optional_lookup_credential(request.lookup_access())?
            .ok_or_else(location_unresolved)?;
        let level = request.containment_evidence_level();
        let handle = if consumes_draft_handle(request.action()) {
            Some(ProviderState::require::<ConfluenceDraftHandle>(request.locator_state())?.clone())
        } else {
            None
        };
        let plan = self.content_plan(request.action(), request.inputs(), handle)?;
        let roots = request.containment_roots().to_vec();
        let budget = ConfluenceMetadataBudget::new(&self.config.content_access);
        let initial = self
            .prove_content_plan(&plan, &roots, level, &credential, &budget, false)
            .await?;
        let evidence = initial.evidence.clone();
        Ok(
            ScopeResolution::containment(evidence).with_state(ProviderState::new(
                ContentOperationState {
                    plan,
                    initial,
                    roots,
                    level,
                    route: self.config.site().route_fingerprint(),
                    budget,
                    final_check: Arc::new(std::sync::atomic::AtomicU8::new(0)),
                },
            )),
        )
    }

    fn content_plan(
        &self,
        action: &str,
        inputs: &Value,
        handle: Option<ConfluenceDraftHandle>,
    ) -> Result<ContentPlan, ProviderError> {
        if let Some(handle) = handle {
            return Ok(ContentPlan::Draft(handle));
        }
        if let Some(comment_action) = confluence_comment_action(action) {
            let (owner_id, comment_id) = match comment_action.operation {
                ConfluenceCommentOperation::List => (
                    Some(parse_comment_list_inputs(comment_action, inputs)?.container_id),
                    None,
                ),
                ConfluenceCommentOperation::Add => (
                    Some(parse_comment_add_inputs(comment_action, inputs)?.container_id),
                    None,
                ),
                ConfluenceCommentOperation::View => {
                    (None, Some(parse_comment_id_inputs(inputs)?.comment_id))
                }
                ConfluenceCommentOperation::Update => {
                    (None, Some(parse_comment_update_inputs(inputs)?.comment_id))
                }
                ConfluenceCommentOperation::Delete => {
                    (None, Some(parse_comment_delete_inputs(inputs)?.comment_id))
                }
                ConfluenceCommentOperation::ReplyList => (
                    None,
                    Some(parse_comment_reply_list_inputs(inputs)?.comment_id),
                ),
                ConfluenceCommentOperation::ReplyAdd => (
                    None,
                    Some(parse_comment_reply_add_inputs(inputs)?.comment_id),
                ),
            };
            return Ok(ContentPlan::Comment {
                action: comment_action,
                owner_id,
                comment_id,
            });
        }
        let page = |id, url_space, regular| ContentPlan::Page {
            id,
            url_space,
            regular,
        };
        let blog = |id, url_space| ContentPlan::Blog { id, url_space };
        Ok(match action {
            "page.view" => {
                let value = page_locator_from_inputs(inputs, &self.config)?;
                page(value.page_id, value.url_space, false)
            }
            "page.update" => page(parse_page_update_inputs(inputs)?.page_id, None, true),
            "page.draft.stage" => page(parse_page_draft_stage_inputs(inputs)?.page_id, None, false),
            "attachment.add" => page(parse_attachment_add_inputs(inputs)?.page_id, None, false),
            "attachment.download" => page(
                parse_attachment_download_inputs(inputs)?.page_id,
                None,
                false,
            ),
            "attachment.list" => {
                let value = parse_attachment_list_inputs(inputs, &self.config)?.locator;
                page(value.page_id, value.url_space, false)
            }
            "verify" => page(parse_verify_inputs(inputs)?.page_id, None, false),
            "blog.view" => {
                let value = parse_blog_view_inputs(inputs, &self.config)?.locator;
                blog(value.blog_id, value.url_space)
            }
            "blog.update" => blog(parse_blog_update_inputs(inputs)?.blog_id, None),
            "blog.draft.stage" => blog(parse_blog_draft_stage_inputs(inputs)?.blog_id, None),
            "blog.attachment.add" => blog(parse_blog_attachment_add_inputs(inputs)?.blog_id, None),
            "blog.attachment.download" => {
                blog(parse_blog_attachment_download_inputs(inputs)?.blog_id, None)
            }
            "blog.attachment.list" => {
                let value = parse_blog_attachment_list_inputs(inputs, &self.config)?.locator;
                blog(value.blog_id, value.url_space)
            }
            "blog.verify" => blog(parse_blog_verify_inputs(inputs)?.blog_id, None),
            "page.create" => {
                let value = parse_page_create_inputs(inputs, &self.config)?;
                ContentPlan::Create {
                    space: value.space,
                    parent: value.parent,
                }
            }
            "page.draft.create" => {
                let value = parse_page_draft_create_inputs(inputs, &self.config)?;
                ContentPlan::Create {
                    space: value.space,
                    parent: value.parent,
                }
            }
            "page.move" => ContentPlan::Move(parse_page_move_inputs(inputs, &self.config)?),
            _ => return Err(ProviderStateError::TypeMismatch.into()),
        })
    }

    async fn prove_content_plan(
        &self,
        plan: &ContentPlan,
        roots: &[TypedResourceSelector],
        level: ContainmentEvidenceLevel,
        credential: &AtlassianCredential,
        budget: &ConfluenceMetadataBudget,
        execution: bool,
    ) -> Result<ContentProof, ProviderError> {
        let is_move = matches!(plan, ContentPlan::Move(_));
        if is_move && level != ContainmentEvidenceLevel::CompleteLineage {
            return Err(ProviderStateError::TypeMismatch.into());
        }
        let mut pass = LocationPass::new(self, credential, budget, level, is_move);
        let mut destination = None;
        let mut comment_chain = Vec::new();
        let (domain, obligations, space) = match plan {
            ContentPlan::Page {
                id,
                url_space,
                regular,
            } => {
                let (location, space) = pass.page(id, *regular).await?;
                validate_input_space(url_space.as_deref(), &space)?;
                (
                    "page",
                    vec![ContainmentObligation::Content(location)],
                    space,
                )
            }
            ContentPlan::Blog { id, url_space } => {
                let (location, space) = pass.blog(id, ConfluenceContentStatus::Current).await?;
                validate_input_space(url_space.as_deref(), &space)?;
                (
                    "blog",
                    vec![ContainmentObligation::Content(location)],
                    space,
                )
            }
            ContentPlan::Create {
                space: requested_space,
                parent,
            } => {
                pass.charge()?;
                let space = budget
                    .scope(self.backend.space_by_key(requested_space, credential))
                    .await
                    .map_err(location_backend_error)?
                    .value;
                if space.key != *requested_space
                    || space.status.as_deref() != Some("current")
                    || !locations::is_canonical_content_id(&space.id)
                {
                    return Err(location_unresolved());
                }
                pass.spaces.insert(space.id.clone(), space.clone());
                let selected = match parent {
                    Some(parent) => parent.parent.clone(),
                    None => ConfluenceParent {
                        kind: ConfluenceNodeKind::Page,
                        id: space
                            .homepage_id
                            .clone()
                            .filter(|id| locations::is_canonical_content_id(id))
                            .ok_or_else(location_unresolved)?,
                    },
                };
                let node = pass
                    .node(
                        selected.kind,
                        &selected.id,
                        ConfluenceContentStatus::Current,
                        false,
                    )
                    .await?;
                if !matches!(
                    node.kind,
                    ConfluenceNodeKind::Page | ConfluenceNodeKind::Folder
                ) || node.space_id != space.id
                {
                    return Err(location_unresolved());
                }
                if let Some(parent) = parent {
                    validate_input_space(parent.url_space.as_deref(), &space)?;
                }
                let (location, _) = pass.location(node, ContainmentProvenance::Observed).await?;
                destination = Some(selected);
                (
                    "page_destination",
                    vec![ContainmentObligation::ChildPlacement(location)],
                    space,
                )
            }
            ContentPlan::Comment {
                action,
                owner_id,
                comment_id,
            } => {
                let owner = if let Some(comment_id) = comment_id {
                    let evidence = budget
                        .scope(
                            self.comment_container_evidence(*action, comment_id, None, credential),
                        )
                        .await
                        .map_err(location_provider_error)?;
                    comment_chain = evidence.chain;
                    evidence.container.id().to_owned()
                } else {
                    owner_id.clone().ok_or(ProviderStateError::Missing)?
                };
                let (domain, location, space) = match action.container_type {
                    ConfluenceCommentContainerType::Page => {
                        let (location, space) = pass.page(&owner, false).await?;
                        ("page", location, space)
                    }
                    ConfluenceCommentContainerType::Blog => {
                        let (location, space) =
                            pass.blog(&owner, ConfluenceContentStatus::Current).await?;
                        ("blog", location, space)
                    }
                };
                (
                    domain,
                    vec![ContainmentObligation::Content(location)],
                    space,
                )
            }
            ContentPlan::Draft(handle) => {
                let space = pass.space(&handle.space_id).await?;
                if space.key != handle.space {
                    return Err(location_unresolved());
                }
                let location = if handle.content_type == ConfluenceDraftContentType::Blog {
                    if execution {
                        pass.blog(&handle.content_id, ConfluenceContentStatus::Draft)
                            .await?
                            .0
                    } else {
                        pass.blogs.push((
                            handle.content_id.clone(),
                            handle.space_id.clone(),
                            ConfluenceContentStatus::Draft,
                        ));
                        ContentLocation::new(
                            content_identity(&pass.site, &space.key, "blog", &handle.content_id),
                            vec![ResourceContainer::new(
                                CONFLUENCE_SPACE_RESOURCE.id().clone(),
                                &space.key,
                            )],
                            level,
                        )
                        .with_provenance(ContainmentProvenance::SignedLocator)
                    }
                } else {
                    let node = if execution {
                        let node = pass
                            .node(
                                ConfluenceNodeKind::Page,
                                &handle.content_id,
                                ConfluenceContentStatus::Draft,
                                false,
                            )
                            .await?;
                        if node.space_id != handle.space_id || node.parent != handle.parent {
                            return Err(location_unresolved());
                        }
                        node
                    } else {
                        ConfluenceNode {
                            id: handle.content_id.clone(),
                            kind: ConfluenceNodeKind::Page,
                            space_id: handle.space_id.clone(),
                            parent: handle.parent.clone(),
                            status: ConfluenceContentStatus::Draft,
                            version: None,
                        }
                    };
                    pass.location(
                        node,
                        if execution {
                            ContainmentProvenance::Observed
                        } else {
                            ContainmentProvenance::SignedLocator
                        },
                    )
                    .await?
                    .0
                };
                (
                    handle.content_type.as_str(),
                    vec![ContainmentObligation::Content(location)],
                    space,
                )
            }
            ContentPlan::Move(inputs) => {
                let source = pass
                    .node(
                        ConfluenceNodeKind::Page,
                        &inputs.page.page_id,
                        ConfluenceContentStatus::Current,
                        false,
                    )
                    .await?;
                let (current, space) = pass
                    .location(source.clone(), ContainmentProvenance::Observed)
                    .await?;
                validate_input_space(inputs.page.url_space.as_deref(), &space)?;
                let target_node = pass
                    .node(
                        ConfluenceNodeKind::Page,
                        &inputs.target.page_id,
                        ConfluenceContentStatus::Current,
                        false,
                    )
                    .await?;
                if source.id == target_node.id || target_node.space_id != space.id {
                    return Err(location_unresolved());
                }
                validate_input_space(inputs.target.url_space.as_deref(), &space)?;
                let selected = match inputs.position {
                    ConfluencePageMovePosition::Append => ConfluenceParent {
                        kind: ConfluenceNodeKind::Page,
                        id: target_node.id.clone(),
                    },
                    ConfluencePageMovePosition::Before | ConfluencePageMovePosition::After => {
                        target_node
                            .parent
                            .clone()
                            .filter(|parent| parent.kind == ConfluenceNodeKind::Page)
                            .ok_or_else(location_unresolved)?
                    }
                };
                let (anchor, _) = pass
                    .location(target_node, ContainmentProvenance::Observed)
                    .await?;
                let destination_node = pass
                    .node(
                        selected.kind,
                        &selected.id,
                        ConfluenceContentStatus::Current,
                        false,
                    )
                    .await?;
                let (placement, _) = pass
                    .location(destination_node, ContainmentProvenance::Observed)
                    .await?;
                if placement.target == current.target
                    || placement.ancestors.contains(&current.target)
                {
                    return Err(location_unresolved());
                }
                let mut proposed = current.clone();
                proposed.ancestors = std::iter::once(placement.target.clone())
                    .chain(placement.ancestors.iter().cloned())
                    .collect();
                proposed.provenance = ContainmentProvenance::Proposed;
                destination = Some(selected);
                (
                    "page_move",
                    vec![
                        ContainmentObligation::SubtreeImpact { current, proposed },
                        ContainmentObligation::ChildPlacement(placement),
                        ContainmentObligation::Content(anchor),
                    ],
                    space,
                )
            }
        };
        let mut related = Vec::new();
        if is_move {
            let mut seen = BTreeSet::new();
            for selector in roots {
                if selector.resource_type() != CONFLUENCE_CONTENT_RESOURCE.id() {
                    continue;
                }
                let value = match selector.selector() {
                    ResourceSelector::Exact { value } | ResourceSelector::Subtree { value } => {
                        value
                    }
                    _ => continue,
                };
                let root = locations::parse_canonical_content_location(value)
                    .map_err(|_| ProviderStateError::TypeMismatch)?;
                if root.site_origin != pass.site
                    || root.space_key != space.key
                    || root.kind == locations::ContentLocationKind::Blog
                {
                    continue;
                }
                if !seen.insert(value.clone()) {
                    continue;
                }
                if seen.len() > MAX_MOVE_ROOTS {
                    return Err(location_unresolved());
                }
                let kind = match root.kind {
                    locations::ContentLocationKind::Page => ConfluenceNodeKind::Page,
                    locations::ContentLocationKind::Folder => ConfluenceNodeKind::Folder,
                    _ => return Err(ProviderStateError::TypeMismatch.into()),
                };
                let node = pass
                    .node(
                        kind,
                        root.id.as_deref().ok_or(ProviderStateError::Missing)?,
                        ConfluenceContentStatus::Current,
                        false,
                    )
                    .await?;
                if node.space_id != space.id {
                    return Err(location_unresolved());
                }
                related.push(
                    pass.location(node, ContainmentProvenance::Observed)
                        .await?
                        .0,
                );
            }
        }
        Ok(ContentProof {
            evidence: ContainmentEvidence::new(domain, pass.site, obligations)
                .with_related_roots(related),
            space,
            destination,
            regular_page: pass.regular_page,
            graph: pass.graph,
            blogs: pass.blogs,
            comment_chain,
        })
    }

    pub(crate) async fn recheck_content_location(
        &self,
        request: &ProviderInvocation,
    ) -> Result<ContentProof, ProviderError> {
        self.recheck_admitted_content(request.admitted(), request.state())
            .await
    }

    pub(crate) async fn recheck_admitted_content(
        &self,
        request: &AdmittedRequest,
        state: Option<&ProviderState>,
    ) -> Result<ContentProof, ProviderError> {
        let state = ProviderState::require::<ContentOperationState>(state)?;
        if state.route != self.config.site().route_fingerprint() {
            return Err(ProviderStateError::TypeMismatch.into());
        }
        let credential = self.execution_credential(request)?;
        if let ContentPlan::Draft(expected) = &state.plan {
            let (kind, id, token) = draft_handle_reference(request.action(), request.inputs())?
                .ok_or(ProviderStateError::Missing)?;
            let actual = self.continuations.open_draft_handle(
                request.context(),
                request.execution(),
                kind,
                &id,
                &token,
            )?;
            if &actual != expected {
                return Err(invalid_draft_handle_error());
            }
        }
        state
            .final_check
            .store(3, std::sync::atomic::Ordering::Relaxed);
        let fresh = self
            .prove_content_plan(
                &state.plan,
                &state.roots,
                state.level,
                &credential,
                &state.budget,
                true,
            )
            .await
            .map_err(|error| state.with_failure_audit(error))?;
        if request
            .containment_authorization()?
            .check_same_location(&fresh.evidence)
            .is_err()
            || fresh.space.id != state.initial.space.id
            || fresh.space.key != state.initial.space.key
            || fresh.graph != state.initial.graph
            || fresh.blogs != state.initial.blogs
            || fresh.comment_chain != state.initial.comment_chain
        {
            state
                .final_check
                .store(2, std::sync::atomic::Ordering::Relaxed);
            return Err(state.with_failure_audit(location_unresolved()));
        }
        state
            .final_check
            .store(1, std::sync::atomic::Ordering::Relaxed);
        Ok(fresh)
    }
}

fn validate_input_space(claim: Option<&str>, space: &ConfluenceSpace) -> Result<(), ProviderError> {
    if claim.is_some_and(|claim| claim != space.key && space.alias.as_deref() != Some(claim)) {
        return Err(location_unresolved());
    }
    Ok(())
}

/// Reads the admitted container coordinate without manufacturing a scalar scope
/// alias. Only the two independent-blog create actions retain scalar space scope.
pub(crate) fn admitted_space(request: &AdmittedRequest) -> Result<&str, ProviderError> {
    if matches!(request.action(), "blog.create" | "blog.draft.create") {
        return authorized_single_scope(request.resource_scopes()?, "space");
    }
    let evidence = request.containment_authorization()?.evidence();
    let location = match evidence
        .obligations()
        .first()
        .ok_or(ProviderStateError::Missing)?
    {
        ContainmentObligation::Content(location)
        | ContainmentObligation::ChildPlacement(location) => location,
        ContainmentObligation::SubtreeImpact { current, .. } => current,
        _ => return Err(ProviderStateError::TypeMismatch.into()),
    };
    location
        .containers
        .iter()
        .find(|container| container.resource_type == *CONFLUENCE_SPACE_RESOURCE.id())
        .map(|container| container.value.as_str())
        .ok_or_else(|| ProviderStateError::Missing.into())
}

impl ContentOperationState {
    fn with_failure_audit(&self, mut error: ProviderError) -> ProviderError {
        error.audit.get_or_insert_with(|| Box::new(json!({})))["locationProof"] = self.audit();
        error
    }
    pub(crate) fn audit(&self) -> Value {
        let (requests, bytes) = self.budget.usage().unwrap_or_default();
        let state = match self.final_check.load(std::sync::atomic::Ordering::Relaxed) {
            1 => "matched",
            2 => "changed",
            3 => "unresolved",
            _ => "not_run",
        };
        json!({"finalCheck":state,"space":self.initial.space.key,"spaceId":self.initial.space.id,
            "metadataRequests":requests,"metadataBytes":bytes,
            "publicNodeCount":self.initial.graph.iter().filter(|node| matches!(node.kind, ConfluenceNodeKind::Page | ConfluenceNodeKind::Folder)).count() + self.initial.blogs.len()})
    }
}

#[derive(Clone)]
pub(crate) struct SearchLocationProof {
    pub(crate) location: ContentLocation,
    pub(crate) space: ConfluenceSpace,
    graph: Vec<NodeFact>,
    blogs: Vec<(String, String, ConfluenceContentStatus)>,
}
impl SearchLocationProof {
    pub(crate) fn same_location(&self, other: &Self) -> bool {
        self.location == other.location
            && self.space.id == other.space.id
            && self.space.key == other.space.key
            && self.graph == other.graph
            && self.blogs == other.blogs
    }
}
impl ConfluenceProvider {
    pub(crate) async fn search_location_proof(
        &self,
        kind: ConfluenceSearchContentKind,
        id: &str,
        level: ContainmentEvidenceLevel,
        credential: &AtlassianCredential,
        budget: &ConfluenceMetadataBudget,
    ) -> Result<SearchLocationProof, ProviderError> {
        let mut pass = LocationPass::new(self, credential, budget, level, false);
        let (location, space) = match kind {
            ConfluenceSearchContentKind::Page => pass.page(id, false).await?,
            ConfluenceSearchContentKind::BlogPost => {
                pass.blog(id, ConfluenceContentStatus::Current).await?
            }
        };
        Ok(SearchLocationProof {
            location,
            space,
            graph: pass.graph,
            blogs: pass.blogs,
        })
    }

    pub(crate) async fn content_metadata<F: std::future::Future>(
        &self,
        request: &ProviderInvocation,
        future: F,
    ) -> F::Output {
        match ProviderState::optional::<ContentOperationState>(request.state()) {
            Ok(Some(state)) => state.budget.scope(future).await,
            _ => future.await,
        }
    }
}

#[cfg(test)]
impl ConfluenceProvider {
    /// Tests of locator normalization project only their confirmed space. The
    /// production resolver returns the full containment evidence and state.
    pub(crate) async fn fixture_space_lookup(
        &self,
        action: &str,
        inputs: &Value,
        credential: Option<&AtlassianCredential>,
    ) -> Result<ResourceScopes, ProviderError> {
        if confluence_scope_name(action) == "space" || matches!(action, "search" | "blog.search") {
            return self.local_scopes(action, inputs);
        }
        let plan = self.content_plan(action, inputs, None)?;
        let budget = ConfluenceMetadataBudget::new(&self.config.content_access);
        let proof = self
            .prove_content_plan(
                &plan,
                &[],
                if action == "page.move" {
                    ContainmentEvidenceLevel::CompleteLineage
                } else {
                    ContainmentEvidenceLevel::ContainerOnly
                },
                credential.ok_or_else(location_unresolved)?,
                &budget,
                false,
            )
            .await?;
        Ok(BTreeMap::from([("space".into(), vec![proof.space.key])]))
    }
}

#[cfg(test)]
mod tests;
