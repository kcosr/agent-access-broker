//! Configuration loading failures and host secret-reference resolution.
use std::fs;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("configuration validation failed")]
    Invalid { errors: Vec<String> },
}

impl ConfigError {
    pub fn errors(&self) -> &[String] {
        match self {
            Self::Invalid { errors } => errors,
            _ => &[],
        }
    }
}

/// Failure preparing a host service from configuration: an invalid setting,
/// or a secret reference that cannot be resolved.
#[derive(Debug, Error)]
pub enum HostConfigError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("{label} references missing environment variable {name}")]
    MissingEnv { label: String, name: String },
    #[error("failed to read secret reference for {label}: {source}")]
    SecretFile {
        label: String,
        #[source]
        source: std::io::Error,
    },
}

impl HostConfigError {
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::Config(ConfigError::Invalid {
            errors: vec![message.into()],
        })
    }
}

/// Resolves an `env:NAME` or `file:/absolute/path` secret reference, trimmed.
pub fn load_secret_ref_value(label: &str, reference: &str) -> Result<String, HostConfigError> {
    if let Some(name) = reference.strip_prefix("env:") {
        return std::env::var(name)
            .map(|value| value.trim().to_string())
            .map_err(|_| HostConfigError::MissingEnv {
                label: label.to_string(),
                name: name.to_string(),
            });
    }
    if let Some(path) = reference.strip_prefix("file:") {
        return fs::read_to_string(path)
            .map(|value| value.trim().to_string())
            .map_err(|source| HostConfigError::SecretFile {
                label: label.to_string(),
                source,
            });
    }
    Err(HostConfigError::invalid(format!(
        "{label} must use env:NAME or file:/absolute/path"
    )))
}
