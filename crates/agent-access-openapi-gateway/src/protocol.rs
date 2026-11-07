use agent_access_openapi_common::{
    GATEWAY_MAX_PATHS, GatewayPlanV1, GatewayRouteManifestV1, validate_endpoint,
};
use agent_access_provider::{
    GatewayClassification, GatewayManagedInput, GatewayProtocol, GatewayRequestHead,
    GatewayServiceContext, ProviderBuildError, ProviderError, ReasonCode, ResourceScopes,
    is_action_name,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

#[derive(Debug, Clone)]
pub(crate) struct Operation {
    pub action: String,
    pub accepted_hash: String,
    pub plan: GatewayPlanV1,
}

#[derive(Debug)]
pub(crate) struct Protocol {
    pub manifest: GatewayRouteManifestV1,
    pub operations: BTreeMap<(String, String), Arc<Operation>>,
    pub upstream_base: String,
    pub manifest_generation: u64,
}

pub(crate) fn build(
    context: &GatewayServiceContext,
    input: &GatewayManagedInput,
) -> Result<Arc<dyn GatewayProtocol>, ProviderBuildError> {
    if input.manifest.version != 1
        || input.manifest_generation == 0
        || !valid_hash(&input.manifest_hash)
        || input.actions.len() > GATEWAY_MAX_PATHS * 7
    {
        return Err(invalid(
            "gateway manifest envelope is invalid or unsupported",
        ));
    }
    let manifest: GatewayRouteManifestV1 = serde_json::from_value(input.manifest.data.clone())
        .map_err(|_| invalid("gateway route manifest has an invalid shape"))?;
    manifest.validate().map_err(invalid)?;
    let endpoint = validate_endpoint(&context.upstream_base_url).map_err(invalid)?;
    let mut operations = BTreeMap::new();
    let mut actions = BTreeSet::new();
    let mut active_security = None;
    for action in &input.actions {
        if action.plan.version != 1
            || action.version == 0
            || !valid_hash(&action.accepted_hash)
            || !is_action_name(&action.action)
            || !actions.insert(action.action.clone())
        {
            return Err(invalid("gateway action envelope is invalid or unsupported"));
        }
        let plan: GatewayPlanV1 = serde_json::from_value(action.plan.data.clone())
            .map_err(|_| invalid("gateway operation plan has an invalid shape"))?;
        plan.validate().map_err(invalid)?;
        if !action.dispatchable {
            // Retained/quarantined plans remain valid historical records. They
            // cannot become an executable route through this runtime map.
            continue;
        }
        manifest.validate_plan(&plan).map_err(invalid)?;
        if let Some(security) = &active_security {
            if security != &plan.security {
                return Err(invalid(
                    "gateway operations disagree on upstream authentication",
                ));
            }
        } else {
            active_security = Some(plan.security.clone());
        }
        let key = (plan.method.clone(), plan.path.clone());
        let operation = Arc::new(Operation {
            action: action.action.clone(),
            accepted_hash: action.accepted_hash.clone(),
            plan,
        });
        if operations.insert(key, operation).is_some() {
            return Err(invalid("gateway operations have duplicate route ownership"));
        }
    }
    Ok(Arc::new(Protocol {
        manifest,
        operations,
        upstream_base: endpoint.to_string(),
        manifest_generation: input.manifest_generation,
    }))
}

fn invalid(message: impl Into<String>) -> ProviderBuildError {
    ProviderBuildError::invalid(message)
}

fn valid_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn missing() -> ProviderError {
    ProviderError::deny(
        ReasonCode::GatewayRuleNotFound,
        "gateway route was not found",
    )
}

impl GatewayProtocol for Protocol {
    fn classify(
        &self,
        head: GatewayRequestHead<'_>,
    ) -> Result<GatewayClassification, ProviderError> {
        let (path, raw_query) = head
            .path_and_query()
            .split_once('?')
            .unwrap_or((head.path_and_query(), ""));
        let selected = self
            .manifest
            .select(head.method().as_str(), path)
            .map_err(|_| {
                ProviderError::deny(
                    ReasonCode::InputInvalid,
                    "gateway request target is invalid",
                )
            })?
            .ok_or_else(missing)?;
        let route = selected.route.ok_or_else(missing)?;
        if !route.current || !route.supported {
            return Err(missing());
        }
        let operation = self
            .operations
            .get(&(
                head.method().as_str().to_owned(),
                selected.template.to_owned(),
            ))
            .ok_or_else(missing)?
            .clone();
        let request = crate::request::Request {
            operation: operation.clone(),
            path: selected.canonical_path,
            parameters: selected.parameters,
            raw_query: raw_query.to_owned(),
            headers: head.headers().clone(),
            upstream_base: self.upstream_base.clone(),
            manifest_generation: self.manifest_generation,
        };
        Ok(GatewayClassification::new(
            operation.action.clone(),
            ResourceScopes::new(),
            "request",
            Box::new(request),
        ))
    }
}
