//! Source-neutral operation contracts and the single durable HTTP plan.
use agent_access_core::imports::ImportedCredentialDelivery;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use url::Url;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dialect {
    OpenApi31,
    Swagger2,
}

pub(crate) struct Operation {
    pub destinations: Option<Vec<Url>>,
    pub security_schemes: Vec<Security>,
    pub security_requirements: Value,
    pub parameters: Vec<Value>,
    pub body: Body,
    pub responses: BTreeMap<String, Response>,
}
pub(crate) enum Body {
    None,
    Json {
        schema: Value,
        required: bool,
    },
    FormUrlEncoded {
        schema: Value,
        required: bool,
        encoding: Option<Value>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Security {
    pub scheme: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
}
impl Security {
    pub fn delivery(&self) -> Result<ImportedCredentialDelivery, String> {
        match (self.kind.as_str(), self.header.as_ref()) {
            ("basic", None) => Ok(ImportedCredentialDelivery::Basic),
            ("bearer", None) => Ok(ImportedCredentialDelivery::Bearer),
            ("raw_header", Some(name)) => {
                let delivery = ImportedCredentialDelivery::RawHeader { name: name.clone() };
                crate::config::parameter_header(name)?;
                Ok(delivery)
            }
            _ => Err("unsupported OpenAPI security mapping".into()),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Parameter {
    pub name: String,
    pub location: String,
    pub style: String,
    pub explode: bool,
    pub required: bool,
    pub value_type: String,
    pub array: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Response {
    pub content_type: Option<String>,
    pub schema: Option<Value>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Plan {
    pub method: String,
    pub path: String,
    pub security: Security,
    pub parameters: Vec<Parameter>,
    pub request_body: bool,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_form"
    )]
    pub form_body: Option<FormBody>,
    pub responses: BTreeMap<String, Response>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FormField {
    pub name: String,
    pub value_type: String,
    pub required: bool,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FormBody {
    pub fields: Vec<FormField>,
}
fn present_form<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<FormBody>, D::Error> {
    // A present null is invalid; absence alone retains the permanent JSON meaning.
    FormBody::deserialize(deserializer).map(Some)
}
