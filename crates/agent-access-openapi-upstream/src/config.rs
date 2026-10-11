use agent_access_provider::*;
use url::Url;

pub(crate) struct Settings {
    pub document: Url,
    pub scheme: Option<String>,
    pub document_delivery: Option<ImportedCredentialDelivery>,
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
            if let ImportedCredentialDelivery::RawHeader { name } = &binding.delivery {
                parameter_header(name)?;
            }
            if binding.mechanism != ImportedAuthMechanism::StaticToken {
                return Err("OpenAPI imports currently require static bearer or header API-key execution credentials".into());
            }
        }
        let settings = &definition.connection_settings;
        if settings.keys().any(|key| {
            !matches!(
                key.as_str(),
                "definitionUrl" | "securityScheme" | "definitionAuthKind" | "definitionAuthHeader"
            )
        }) {
            return Err("unknown OpenAPI connection setting".into());
        }
        let document = endpoint(
            settings
                .get("definitionUrl")
                .ok_or("definitionUrl is required")?,
        )?;
        endpoint(&definition.endpoint)?;
        let kind = settings
            .get("definitionAuthKind")
            .map(String::as_str)
            .unwrap_or("none");
        let document_delivery = match kind {
            "none" if definition.discovery == ImportedDiscoveryCredential::Anonymous => None,
            "bearer" if definition.discovery == ImportedDiscoveryCredential::Slot => Some(ImportedCredentialDelivery::Bearer),
            "raw_header" if definition.discovery == ImportedDiscoveryCredential::Slot => {
                let delivery = ImportedCredentialDelivery::RawHeader { name: settings.get("definitionAuthHeader").ok_or("definitionAuthHeader is required")?.clone() };
                parameter_header(settings.get("definitionAuthHeader").expect("required header"))?;
                Some(delivery)
            }
            _ => return Err("public definitions use anonymous discovery; private definitions require a dedicated discovery slot and bearer or raw_header authentication".into()),
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
            document,
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
