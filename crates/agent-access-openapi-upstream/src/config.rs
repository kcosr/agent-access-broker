use agent_access_core::imports::*;
use url::Url;

pub(crate) struct Settings {
    pub source: DefinitionSource,
    /// Relative/default source destinations resolve against this fixed base.
    /// Uploads use the approved API endpoint, never a local filename or URL.
    pub document_base: Url,
    pub scheme: Option<String>,
    pub document_delivery: Option<ImportedCredentialDelivery>,
}
pub(crate) enum DefinitionSource {
    Url(Url),
    Upload,
}
impl Settings {
    pub fn parse(definition: &ImportedServiceDefinition) -> Result<Self, String> {
        definition.validate()?;
        if definition.adapter_kind != "openapi_http" || definition.transport_auth {
            return Err(
                "OpenAPI imports require openapi_http without transport authentication".into(),
            );
        }
        for binding in &definition.execution_bindings {
            if !matches!(
                binding.delivery,
                ImportedCredentialDelivery::Basic
                    | ImportedCredentialDelivery::Bearer
                    | ImportedCredentialDelivery::RawHeader { .. }
            ) {
                return Err("unsupported OpenAPI credential delivery".into());
            }
            if let ImportedCredentialDelivery::RawHeader { name } = &binding.delivery {
                parameter_header(name)?;
            }
            if binding.mechanism != ImportedAuthMechanism::StaticToken {
                return Err("OpenAPI imports currently require static Basic, bearer or header API-key execution credentials".into());
            }
        }
        let settings = &definition.connection_settings;
        if settings.keys().any(|key| {
            !matches!(
                key.as_str(),
                "definitionSource"
                    | "definitionUrl"
                    | "securityScheme"
                    | "definitionAuthKind"
                    | "definitionAuthHeader"
            )
        }) {
            return Err("unknown OpenAPI connection setting".into());
        }
        let api_endpoint = endpoint(&definition.endpoint)?;
        let source = match settings.get("definitionSource").map(String::as_str) {
            None => DefinitionSource::Url(endpoint(
                settings
                    .get("definitionUrl")
                    .ok_or("definitionUrl is required")?,
            )?),
            Some("upload") => {
                if [
                    "definitionUrl",
                    "definitionAuthKind",
                    "definitionAuthHeader",
                ]
                .iter()
                .any(|key| settings.contains_key(*key))
                    || definition.discovery != ImportedDiscoveryCredential::Anonymous
                {
                    return Err("uploaded definitions require anonymous discovery without a document URL or authentication settings".into());
                }
                DefinitionSource::Upload
            }
            Some(_) => return Err("unsupported definitionSource".into()),
        };
        let document_base = match &source {
            DefinitionSource::Url(url) => url.clone(),
            DefinitionSource::Upload => api_endpoint,
        };
        let kind = settings
            .get("definitionAuthKind")
            .map(String::as_str)
            .unwrap_or("none");
        let document_delivery = match kind {
            "none" if definition.discovery == ImportedDiscoveryCredential::Anonymous => None,
            "basic" if definition.discovery == ImportedDiscoveryCredential::Slot => Some(ImportedCredentialDelivery::Basic),
            "bearer" if definition.discovery == ImportedDiscoveryCredential::Slot => Some(ImportedCredentialDelivery::Bearer),
            "raw_header" if definition.discovery == ImportedDiscoveryCredential::Slot => {
                let delivery = ImportedCredentialDelivery::RawHeader { name: settings.get("definitionAuthHeader").ok_or("definitionAuthHeader is required")?.clone() };
                parameter_header(settings.get("definitionAuthHeader").expect("required header"))?;
                Some(delivery)
            }
            _ => return Err("public definitions use anonymous discovery; private definitions require a dedicated discovery slot and basic, bearer or raw_header authentication".into()),
        };
        if kind != "raw_header" && settings.contains_key("definitionAuthHeader") {
            return Err("definitionAuthHeader is only valid for raw_header authentication".into());
        }
        let scheme = settings
            .get("securityScheme")
            .filter(|name| !name.is_empty())
            .cloned();
        if scheme.as_ref().is_some_and(|name| !bounded(name, 256)) {
            return Err("securityScheme must be a bounded component name".into());
        }
        Ok(Self {
            source,
            document_base,
            scheme,
            document_delivery,
        })
    }
}

pub(crate) fn bounded(text: &str, max: usize) -> bool {
    !text.is_empty() && text.len() <= max && !text.chars().any(char::is_control)
}
pub(crate) fn endpoint(raw: &str) -> Result<Url, String> {
    let url = Url::parse(raw).map_err(|_| "invalid OpenAPI URL")?;
    if !matches!(url.scheme(), "https" | "http")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !bounded(raw, 4096)
        || raw.contains(['*', '\\'])
    {
        return Err("OpenAPI URLs must be fixed HTTP(S) URLs without credentials, query, fragment or wildcards".into());
    }
    Ok(url)
}

pub(crate) fn parameter_header(name: &str) -> Result<(), String> {
    ImportedCredentialDelivery::RawHeader { name: name.into() }.validate()?;
    let lower = name.to_ascii_lowercase();
    if lower.starts_with("x-forwarded-")
        || matches!(
            lower.as_str(),
            "forwarded"
                | "x-http-method-override"
                | "x-method-override"
                | "x-http-method"
                | "x-original-url"
                | "x-rewrite-url"
        )
    {
        return Err("routing and method override headers are unsupported".into());
    }
    Ok(())
}
