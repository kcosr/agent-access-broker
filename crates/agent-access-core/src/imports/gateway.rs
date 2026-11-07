//! Generic persisted routing data for managed gateway adapters.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const IMPORT_MAX_GATEWAY_ROUTE_BYTES: usize = 4 * 1024 * 1024;
pub const IMPORT_GATEWAY_ENVELOPE_VERSION: u32 = 1;

/// Versioned opaque protocol data. The registered gateway builder validates
/// protocol semantics; core validates the envelope and its storage bounds.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportedGatewayRouteCandidate {
    pub version: u32,
    pub data: Value,
}

impl std::fmt::Debug for ImportedGatewayRouteCandidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportedGatewayRouteCandidate")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl ImportedGatewayRouteCandidate {
    pub fn new(data: Value) -> Result<Self, String> {
        let candidate = Self {
            version: IMPORT_GATEWAY_ENVELOPE_VERSION,
            data,
        };
        candidate.encoded()?;
        Ok(candidate)
    }

    pub fn encoded(&self) -> Result<Vec<u8>, String> {
        if self.version == 0 || !self.data.is_object() {
            return Err("gateway route envelope is invalid".into());
        }
        let bytes = serde_json::to_vec(self).map_err(|_| "gateway route envelope is invalid")?;
        if bytes.len() > IMPORT_MAX_GATEWAY_ROUTE_BYTES {
            return Err("gateway route manifest exceeds its byte limit".into());
        }
        Ok(bytes)
    }

    pub fn content_hash(&self) -> Result<String, String> {
        Ok(format!("{:x}", Sha256::digest(self.encoded()?)))
    }

    pub fn is_supported(&self) -> bool {
        self.version == IMPORT_GATEWAY_ENVELOPE_VERSION
    }
}

/// A retained routing generation, independent of expiring import previews.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportedGatewayRouteRecord {
    pub manifest: ImportedGatewayRouteCandidate,
    pub content_hash: String,
    pub generation: u64,
}

impl ImportedGatewayRouteRecord {
    pub fn next(
        previous: Option<&Self>,
        manifest: ImportedGatewayRouteCandidate,
    ) -> Result<Self, String> {
        let generation = previous
            .map_or(Some(1), |old| old.generation.checked_add(1))
            .filter(|generation| *generation <= i64::MAX as u64)
            .ok_or("gateway route generation is exhausted")?;
        let content_hash = manifest.content_hash()?;
        Ok(Self {
            manifest,
            content_hash,
            generation,
        })
    }
}
