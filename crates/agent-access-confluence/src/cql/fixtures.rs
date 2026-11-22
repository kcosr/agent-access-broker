//! Space selections for parser tests, admitted through the real containment
//! constructor and compiled by the same path as page/folder policies.
use super::*;
use agent_access_provider::{
    ContainmentBoundary, ContainmentCollectionAuthorization, ContainmentEvidenceLevel,
    OfflineContainmentProof, ResourceTypeRegistry, host,
};

#[derive(Debug)]
pub(crate) enum FixtureSpaces {
    Finite(BTreeSet<String>),
    AllExcept(BTreeSet<String>),
}

impl FixtureSpaces {
    pub(crate) fn authority(
        &self,
        kind: ConfluenceSearchContentKind,
    ) -> ContainmentCollectionAuthorization {
        let registry =
            ResourceTypeRegistry::new([&CONFLUENCE_SPACE_RESOURCE, &CONFLUENCE_CONTENT_RESOURCE])
                .unwrap();
        let typed = |selector| {
            registry
                .typed_selector(CONFLUENCE_SPACE_RESOURCE.id(), &selector)
                .unwrap()
        };
        let exact = |values: &BTreeSet<String>| {
            values
                .iter()
                .map(|value| {
                    typed(ResourceSelector::Exact {
                        value: value.clone(),
                    })
                })
                .collect()
        };
        let boundary = match self {
            Self::Finite(values) => ContainmentBoundary::new(exact(values), vec![]),
            Self::AllExcept(values) => {
                ContainmentBoundary::new(vec![typed(ResourceSelector::All)], exact(values))
            }
        };
        let scope = match kind {
            ConfluenceSearchContentKind::Page => "page_location",
            ConfluenceSearchContentKind::BlogPost => "blog_location",
        };
        let contract = confluence_resource_scopes()[scope]
            .as_containment()
            .unwrap()
            .clone();
        host::containment_collection_authorization(
            "https://example.atlassian.net",
            contract,
            vec![boundary],
            None,
            &registry,
            ContainmentEvidenceLevel::ContainerOnly,
            "a".repeat(64),
        )
        .unwrap()
    }

    pub(crate) fn authorizes_value(&self, value: &str) -> bool {
        matches!(
            requested_space_coverage(&self.authority(ConfluenceSearchContentKind::Page), value)
                .unwrap(),
            OfflineContainmentProof::Covered
        )
    }
}

pub(crate) fn build_fixture_search_query(
    query: &ConfluenceSearchQueryInput,
    spaces: &FixtureSpaces,
    limits: &SearchLimitsConfig,
    kind: ConfluenceSearchContentKind,
) -> Result<BuiltConfluenceSearchQuery, ProviderError> {
    build_containment_search_query(
        query,
        &spaces.authority(kind),
        &BTreeSet::new(),
        limits,
        kind,
        "https://example.atlassian.net",
    )
}

pub(crate) fn build_fixture_page_query(
    query: &ConfluenceSearchQueryInput,
    spaces: &FixtureSpaces,
    limits: &SearchLimitsConfig,
) -> Result<BuiltConfluenceSearchQuery, ProviderError> {
    build_fixture_search_query(query, spaces, limits, ConfluenceSearchContentKind::Page)
}

pub(crate) fn build_fixture_blog_query(
    query: &ConfluenceSearchQueryInput,
    spaces: &FixtureSpaces,
    limits: &SearchLimitsConfig,
) -> Result<BuiltConfluenceSearchQuery, ProviderError> {
    build_fixture_search_query(query, spaces, limits, ConfluenceSearchContentKind::BlogPost)
}
