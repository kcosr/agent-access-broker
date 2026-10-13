use crate::{CorrelationContext, DelegatedCredential, ResourceScopes};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerBodyPart {
    pub name: String,
    pub file_name: Option<String>,
    pub content_type: Option<String>,
    pub bytes: Vec<u8>,
    pub temp_file: Option<Arc<BrokerBodyPartFile>>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct BrokerBodyPartFile {
    path: PathBuf,
    size: u64,
    sha256: String,
}

impl BrokerBodyPartFile {
    pub fn new(path: PathBuf, size: u64, sha256: String) -> Self {
        Self { path, size, sha256 }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

impl Drop for BrokerBodyPartFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

impl BrokerBodyPart {
    pub fn from_temp_file(
        name: String,
        file_name: Option<String>,
        content_type: Option<String>,
        path: PathBuf,
        size: u64,
        sha256: String,
    ) -> Self {
        Self {
            name,
            file_name,
            content_type,
            bytes: Vec::new(),
            temp_file: Some(Arc::new(BrokerBodyPartFile::new(path, size, sha256))),
        }
    }

    pub fn size(&self) -> u64 {
        if let Some(file) = &self.temp_file {
            file.size()
        } else {
            self.bytes.len() as u64
        }
    }

    pub fn sha256_hex(&self) -> String {
        if let Some(file) = &self.temp_file {
            return file.sha256().to_string();
        }
        let mut digest = Sha256::new();
        digest.update(&self.bytes);
        digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    pub fn temp_file_path(&self) -> Option<&Path> {
        self.temp_file.as_ref().map(|file| file.path())
    }

    pub fn temp_file(&self) -> Option<Arc<BrokerBodyPartFile>> {
        self.temp_file.clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerBodyPartSpec {
    pub name: String,
    pub file_name: String,
    pub content_type: String,
    pub size: u64,
    pub sha256: String,
}

/// The caller an invocation runs for. Backends see only the principal and
/// whether it authenticated, never the broker's full identity context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InvocationIdentity {
    pub principal: String,
    pub authenticated: bool,
}

impl InvocationIdentity {
    pub fn anonymous() -> Self {
        Self {
            principal: "anonymous".to_string(),
            authenticated: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderInvocation {
    /// Execution context selected and authorized by the host, never a tool input.
    pub execution_context: String,
    pub identity: InvocationIdentity,
    pub service: String,
    pub action: String,
    #[serde(skip)]
    pub correlation: CorrelationContext,
    pub inputs: Value,
    #[serde(skip)]
    pub body_parts: Vec<BrokerBodyPart>,
    pub resource_scopes: ResourceScopes,
    /// Only the admitted exact resource's private attributes, resolved by the host.
    #[serde(skip)]
    pub resource_attributes: crate::ResourceAttributes,
    pub credential_mode: String,
    #[serde(skip)]
    pub credential: Option<ExecutionCredential>,
    #[serde(skip)]
    pub lookup_credential: Option<ExecutionCredential>,
    /// The delegated credential the runtime acquired for this invocation,
    /// for services whose descriptor accepts one.
    #[serde(skip)]
    pub delegated_credential: Option<DelegatedCredential>,
    /// Provider-owned state carried from scope resolution or body-part
    /// admission to dispatch. The host never inspects or changes it.
    #[serde(skip)]
    pub state: Option<crate::ProviderState>,
    /// Broker-admitted search boundary for search-contained actions.
    #[serde(skip)]
    pub search_authorization: Option<SearchAuthorization>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ExecutionCredential {
    pub kind: String,
    pub username: Option<String>,
    pub token: Option<String>,
}

impl std::fmt::Debug for ExecutionCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecutionCredential")
            .field("kind", &self.kind)
            .field("username", &self.username.as_ref().map(|_| "<redacted>"))
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Search boundary handed to a provider for a search-contained action. The
/// provider must constrain its upstream query and check every result against
/// this scope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SearchAuthorization {
    pub scope_type: String,
    pub scope: SearchAuthorizationScope,
    pub credential_mode: String,
}

impl SearchAuthorization {
    pub fn resource_scopes(&self) -> ResourceScopes {
        let values = match &self.scope {
            SearchAuthorizationScope::Finite { values } => values.clone(),
            SearchAuthorizationScope::AllExcept { .. } => vec!["*".to_string()],
        };
        BTreeMap::from([(self.scope_type.clone(), values)])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum SearchAuthorizationScope {
    Finite { values: Vec<String> },
    AllExcept { excluded_values: Vec<String> },
}

impl SearchAuthorizationScope {
    pub fn matches(&self, value: &str) -> bool {
        match self {
            Self::Finite { values } => values.iter().any(|allowed| allowed == value),
            Self::AllExcept { excluded_values } => {
                !excluded_values.iter().any(|excluded| excluded == value)
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Finite { values } if values.is_empty())
    }

    pub fn is_universe(&self) -> bool {
        matches!(self, Self::AllExcept { excluded_values } if excluded_values.is_empty())
    }

    pub fn union(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Finite { values: left }, Self::Finite { values: right }) => Self::Finite {
                values: left
                    .iter()
                    .chain(right)
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
            },
            (
                Self::AllExcept {
                    excluded_values: left,
                },
                Self::AllExcept {
                    excluded_values: right,
                },
            ) => Self::AllExcept {
                excluded_values: left
                    .iter()
                    .filter(|value| right.contains(value))
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
            },
            (Self::AllExcept { excluded_values }, Self::Finite { values })
            | (Self::Finite { values }, Self::AllExcept { excluded_values }) => Self::AllExcept {
                excluded_values: excluded_values
                    .iter()
                    .filter(|value| !values.contains(value))
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
            },
        }
    }

    pub fn intersection(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Finite { values: left }, Self::Finite { values: right }) => Self::Finite {
                values: left
                    .iter()
                    .filter(|value| right.contains(value))
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
            },
            (
                Self::AllExcept {
                    excluded_values: left,
                },
                Self::AllExcept {
                    excluded_values: right,
                },
            ) => Self::AllExcept {
                excluded_values: left
                    .iter()
                    .chain(right)
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
            },
            (Self::AllExcept { excluded_values }, Self::Finite { values })
            | (Self::Finite { values }, Self::AllExcept { excluded_values }) => Self::Finite {
                values: values
                    .iter()
                    .filter(|value| !excluded_values.contains(value))
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
            },
        }
    }
}
