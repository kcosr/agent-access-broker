//! Host-style admission for provider tests. It performs the same local locator,
//! authenticated metadata, contract validation and operation-state handoff as
//! the production host; fixtures still control their selected space authority.
use super::*;
use agent_access_provider::test_support::{InvocationBuilder, ScopeRequestFixture};

impl ConfluenceProvider {
    pub(crate) async fn admit_fixture(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderInvocation, ProviderError> {
        if matches!(request.action(), "search" | "blog.search") {
            if request.containment_collection_authorization().is_ok() {
                return Ok(request);
            }
            let selected = request.search_authorization()?;
            if selected.scope_type != "space" {
                return Err(ProviderStateError::TypeMismatch.into());
            }
            let registry = ResourceTypeRegistry::new([
                &CONFLUENCE_SPACE_RESOURCE,
                &CONFLUENCE_CONTENT_RESOURCE,
            ])
            .unwrap();
            let boundaries = selected
                .scope
                .clauses()
                .iter()
                .map(|clause| {
                    let typed = |values: &[ScalarResourceSelector]| {
                        values
                            .iter()
                            .map(|value| {
                                registry
                                    .typed_selector(CONFLUENCE_SPACE_RESOURCE.id(), &value.into())
                            })
                            .collect::<Result<Vec<_>, _>>()
                    };
                    Ok::<_, ContainmentError>(ContainmentBoundary::new(
                        typed(clause.included())?,
                        typed(clause.excluded())?,
                    ))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let contract = confluence_resource_scopes()[confluence_scope_name(request.action())]
                .as_containment()
                .unwrap()
                .clone();
            let digest = sha256_hex(&serde_json::to_vec(&boundaries).unwrap());
            let authorization = agent_access_provider::host::containment_collection_authorization(
                &format!("https://{}", self.config.tenant_host),
                contract,
                boundaries,
                None,
                &registry,
                ContainmentEvidenceLevel::ContainerOnly,
                digest,
            )?;
            return Ok(InvocationBuilder::from(request)
                .containment_collection(authorization)
                .build());
        }
        if confluence_scope_name(request.action()) == "space" {
            return Ok(request);
        }
        if request.containment_authorization().is_ok() && request.state().is_some() {
            return Ok(request);
        }
        let spaces = request
            .resource_scopes()?
            .get("space")
            .cloned()
            .unwrap_or_default();
        let level = if request.action() == "page.move" {
            ContainmentEvidenceLevel::CompleteLineage
        } else {
            ContainmentEvidenceLevel::ContainerOnly
        };
        let mut fixture =
            ScopeRequestFixture::new("confluence", request.action(), request.inputs().clone())
                .identity(request.identity().clone())
                .execution_context(request.execution_context())
                .lookup_access(request.lookup_access().cloned())
                .containment_evidence_level(level);
        if let Some(state) = self.validate_scope_locator(fixture.local_request())? {
            fixture = fixture.locator_state(state);
        }
        let resolved = self.resolve_scopes(fixture.request()).await?;
        let (ScopeEvidence::Containment(evidence), Some(state)) = resolved.into_parts() else {
            return Err(ProviderStateError::Missing.into());
        };
        for obligation in evidence.obligations() {
            let location = match obligation {
                ContainmentObligation::Content(location)
                | ContainmentObligation::ChildPlacement(location) => location,
                ContainmentObligation::SubtreeImpact { current, .. } => current,
                _ => return Err(ProviderStateError::TypeMismatch.into()),
            };
            if !location.containers.iter().any(|container| {
                container.resource_type == *CONFLUENCE_SPACE_RESOURCE.id()
                    && spaces.contains(&container.value)
            }) {
                return Err(location_unresolved());
            }
        }
        let contract = confluence_resource_scopes()[confluence_scope_name(request.action())]
            .as_containment()
            .unwrap()
            .clone();
        let registry =
            ResourceTypeRegistry::new([&CONFLUENCE_SPACE_RESOURCE, &CONFLUENCE_CONTENT_RESOURCE])
                .unwrap();
        let authorization = agent_access_provider::host::containment_authorization(
            &format!("https://{}", self.config.tenant_host),
            contract,
            evidence,
            &registry,
            level,
            "a".repeat(64),
        )?;
        Ok(InvocationBuilder::from(request)
            .containment(authorization)
            .state(state)
            .build())
    }

    pub(crate) async fn invoke_fixture(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let request = self.admit_fixture(request).await?;
        self.invoke_checked(request).await
    }
}
