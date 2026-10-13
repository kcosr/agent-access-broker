use crate::host::UpstreamClientFactoryError;
use std::error::Error;
use std::fmt;

/// Why a provider could not be built for a runtime generation.
///
/// Its diagnostics are safe configuration messages: they name configuration
/// fields, such as `providers.<kind>.base_url`, and never contain secret
/// values. When the host's own network construction failed, the host's cause
/// travels with it as the error source, so the host keeps its diagnostics.
pub struct ProviderBuildError {
    diagnostics: Vec<String>,
    host_cause: Option<Box<dyn Error + Send + Sync>>,
}

impl ProviderBuildError {
    /// A configuration problem found while building, described without
    /// secrets.
    pub fn invalid(message: impl Into<String>) -> Self {
        Self {
            diagnostics: vec![message.into()],
            host_cause: None,
        }
    }

    /// The host could not construct the client labeled `label`.
    pub(crate) fn client(label: &str, error: UpstreamClientFactoryError) -> Self {
        Self {
            diagnostics: vec![format!("{label} HTTP client could not be constructed")],
            host_cause: Some(error.into_cause()),
        }
    }

    pub fn diagnostics(&self) -> &[String] {
        &self.diagnostics
    }

    /// The diagnostics and, when the host's network construction failed, the
    /// host's own cause.
    pub fn into_parts(self) -> (Vec<String>, Option<Box<dyn Error + Send + Sync>>) {
        (self.diagnostics, self.host_cause)
    }
}

impl fmt::Debug for ProviderBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderBuildError")
            .field("diagnostics", &self.diagnostics)
            .field("host_cause", &self.host_cause)
            .finish()
    }
}

impl fmt::Display for ProviderBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.diagnostics.join("; "))
    }
}

impl Error for ProviderBuildError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.host_cause
            .as_deref()
            .map(|cause| cause as &(dyn Error + 'static))
    }
}
