mod connection_credentials;
mod secret_reference_identity;
mod secret_references;
pub(crate) use secret_reference_identity::AttestedSecretReferencePin;
pub use secret_references::{SecretCredentialWriteResult, SecretReferenceUse};
pub(crate) use secret_references::{
    SecretOutputCapture, SecretOutputReservation, SecretOutputReservationBatch,
    SecretReferenceLimits, SecretReservationOutcome, SecretReservationRequest,
};
mod identity_access;
mod identity_tokens;
pub use identity_access::{
    AttestedIdentityProof, IdentityAccessRecord, ResolvedAttestedIdentity, UsernameBindingRecord,
};
mod principal_access;
pub use principal_access::*;
use principal_access::{
    management_authority_conn, require_self_service, validate_principal_access,
};
#[path = "imported_store.rs"]
mod imported_store;
pub use imported_store::*;
mod imported_resource_types;
pub use imported_resource_types::{
    DeletedResourceAttributes, ImportedTypeEffects, ImportedTypeTransaction,
};
mod local_password_failures;
pub(crate) mod oauth;
pub(crate) mod oauth_revocation;
mod principal_service_limits;
mod resource_attributes;
pub(crate) use resource_attributes::{AdmittedResourceEntry, CommandResourceAttributes};
mod resources;
use crate::fs_permissions;
use crate::load_secret_ref_value;
#[cfg(test)]
use crate::sqlite_support::ValidatedLedger;
use crate::sqlite_support::{self, SqliteAdmissionError, SqliteMigration, SqliteStoreLabel};
use crate::{
    AgentInvokeTokenCaveats, BrokerTokensConfig, CredentialEncryptionConfig,
    CredentialEncryptionKeyConfig, EXECUTION_CONTEXT_MAX_VALUES, ManagedStoreConfig,
    POLICY_GRANT_MAX_SUBJECTS, ResourceSelection, is_safe_identifier, is_safe_principal,
    is_valid_execution_context_value,
};
use crate::{ResourceCatalog, ResourceDefinition, ResourceGroupDefinition};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use agent_access_provider::{
    ExecutionCredential, ReasonCode, ResourceSelector, ResourceType, is_service_name,
};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use hmac::{Hmac, Mac};
pub use identity_tokens::IdentityTokenMetadata;
pub use principal_service_limits::{
    PrincipalServiceLimitRecord, PrincipalServiceLimitWriteRequest,
};
use rand::RngCore;
use rand::rngs::OsRng;
pub use resources::*;
use rusqlite::types::Type;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

pub const MANAGED_STORE_SCHEMA_VERSION: &str = MANAGED_STORE_SECRET_REFERENCES_VERSION;
const MANAGED_STORE_SECRET_REFERENCES_VERSION: &str = "029_secret_references";
const MANAGED_STORE_OAUTH_REVOCATIONS_VERSION: &str = "028_oauth_revocations";
const MANAGED_STORE_COMMAND_IMPORTS_VERSION: &str = "027_command_imports";
const MANAGED_STORE_TRUSTED_USER_IDENTITY_VERSION: &str = "026_trusted_user_identity";
const MANAGED_STORE_PRINCIPAL_ACCESS_VERSION: &str = "025_principal_access";
const MANAGED_STORE_OAUTH_DISCOVERY_REVISION_VERSION: &str = "024_oauth_discovery_revision";
const MANAGED_STORE_IMPORTED_SERVICES_VERSION: &str = "023_imported_services";
const MANAGED_STORE_PRINCIPAL_SERVICE_LIMITS_VERSION: &str = "022_principal_service_limits";
const MANAGED_STORE_LOCAL_PASSWORD_FAILURES_VERSION: &str = "021_local_password_failures";
const MANAGED_STORE_RESOURCE_ATTRIBUTES_VERSION: &str = "020_resource_attributes";
const MANAGED_STORE_REGISTERED_RESOURCE_TYPES_VERSION: &str = "019_registered_resource_types";
const MANAGED_STORE_OAUTH_VERSION: &str = "018_oauth_foundation";
const MANAGED_STORE_REMOVE_SHELL_APPROVAL_VERSION: &str = "017_remove_shell_approval";
const MANAGED_STORE_CLOUDBEES_CI_VERSION: &str = "016_cloudbees_ci_job_namespace";
const MANAGED_STORE_BASELINE_SCHEMA_VERSION: &str = "014_resource_policy_baseline";
const MANAGED_STORE_IDENTITY_TOKENS_VERSION: &str = "015_identity_tokens";
// Credential ciphertext authentication is independent of the database schema version.
const CREDENTIAL_AAD_SCHEMA_VERSION: &str = "002_credential_secret_material";
const MANAGED_STORE_BASELINE_CHECKSUM: &str =
    "c190f63348e29074c8ddf1e9003c9ed8f7ee1636228916320568308efdc13572";
const LOCAL_PASSWORD_ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const LOCAL_PASSWORD_ARGON2_ITERATIONS: u32 = 3;
const LOCAL_PASSWORD_ARGON2_PARALLELISM: u32 = 1;
const LOCAL_PASSWORD_MAX_CONCURRENT: usize = 2;
const LOCAL_PASSWORD_MAX_ADMIN_CONCURRENT: usize = 1;
static DUMMY_LOCAL_PASSWORD_HASH_PHC: OnceLock<String> = OnceLock::new();

const SQLITE_ENCRYPTED_BACKEND: &str = "sqlite_encrypted";

const MANAGED_STORE_LABEL: SqliteStoreLabel = SqliteStoreLabel {
    name: "managed store",
    incompatible_message: "managed store schema is not supported by this broker; preserve the database and use a compatible broker binary or restore a matching backup. For unsupported older schemas, follow docs/operator-guide.md#upgrade-and-rollback to create a fresh store at a new path and reconstruct managed state.",
};

const MANAGED_STORE_BASELINE_SQL: &str = include_str!("managed_store/schema.sql");

type ManagedStoreMigration = SqliteMigration<ManagedStoreError>;

#[derive(Clone, Copy)]
struct ManagedStoreMigrationCatalog<'a> {
    migrations: &'a [ManagedStoreMigration],
}

const IDENTITY_TOKENS_SQL: &str = include_str!("managed_store/identity_tokens.sql");
const CLOUDBEES_CI_JOB_NAMESPACE_SQL: &str =
    include_str!("managed_store/cloudbees_ci_job_namespace.sql");
const REMOVE_SHELL_APPROVAL_SQL: &str = include_str!("managed_store/remove_shell_approval.sql");
const OAUTH_SQL: &str = include_str!("managed_store/oauth.sql");
const REGISTERED_RESOURCE_TYPES_SQL: &str =
    include_str!("managed_store/registered_resource_types.sql");
const RESOURCE_ATTRIBUTES_SQL: &str = include_str!("managed_store/resource_attributes.sql");
const LOCAL_PASSWORD_FAILURES_SQL: &str = include_str!("managed_store/local_password_failures.sql");
const PRINCIPAL_SERVICE_LIMITS_SQL: &str =
    include_str!("managed_store/principal_service_limits.sql");
const IMPORTED_SERVICES_SQL: &str = include_str!("managed_store/imported_services.sql");
const MANAGED_STORE_MIGRATIONS: &[ManagedStoreMigration] = &[
    ManagedStoreMigration {
        version: MANAGED_STORE_BASELINE_SCHEMA_VERSION,
        checksum: MANAGED_STORE_BASELINE_CHECKSUM,
        sql: MANAGED_STORE_BASELINE_SQL,
        seed: None,
        structural_validation: validate_baseline_structure,
    },
    ManagedStoreMigration {
        version: MANAGED_STORE_IDENTITY_TOKENS_VERSION,
        checksum: "9feebd41cf9925fc2c8f6bf02e095fb567cb9bcfb4f97993d36c285f002b1b22",
        sql: IDENTITY_TOKENS_SQL,
        seed: None,
        structural_validation: validate_identity_tokens_structure,
    },
    ManagedStoreMigration {
        version: MANAGED_STORE_CLOUDBEES_CI_VERSION,
        checksum: "d63e5de34e082eac7b263732d0d4d669669880a86894a8126940ca37a757f5d4",
        sql: CLOUDBEES_CI_JOB_NAMESPACE_SQL,
        seed: None,
        structural_validation: validate_cloudbees_ci_structure,
    },
    ManagedStoreMigration {
        version: MANAGED_STORE_REMOVE_SHELL_APPROVAL_VERSION,
        checksum: "2d945372e95a4d7545f88ee4463f3b742b903a533a08611eead4845d2fc102c7",
        sql: REMOVE_SHELL_APPROVAL_SQL,
        seed: None,
        structural_validation: validate_managed_store_latest_structure,
    },
    ManagedStoreMigration {
        version: MANAGED_STORE_OAUTH_VERSION,
        checksum: "67887d31c33e4deb9e9df0c84e6c40502737b6d90999ef3d8d86c1a7fea06bcb",
        sql: OAUTH_SQL,
        seed: None,
        structural_validation: validate_oauth_structure,
    },
    ManagedStoreMigration {
        version: MANAGED_STORE_REGISTERED_RESOURCE_TYPES_VERSION,
        checksum: "99a8b782344fe2db9ab810e485fce6f878145a7f5ad6881814ebe8e7560bd390",
        sql: REGISTERED_RESOURCE_TYPES_SQL,
        seed: None,
        structural_validation: validate_registered_resource_types_structure,
    },
    ManagedStoreMigration {
        version: MANAGED_STORE_RESOURCE_ATTRIBUTES_VERSION,
        checksum: "24774c4a9dd2283208eb38e44820ea35b4748c0864ef822e1aaeac878a26f287",
        sql: RESOURCE_ATTRIBUTES_SQL,
        seed: None,
        structural_validation: validate_resource_attributes_structure,
    },
    ManagedStoreMigration {
        version: MANAGED_STORE_LOCAL_PASSWORD_FAILURES_VERSION,
        checksum: "b7ef7390a7be50006b83e3ab27e885adf8874c645afa366a98fd301f7fbb71b5",
        sql: LOCAL_PASSWORD_FAILURES_SQL,
        seed: None,
        structural_validation: local_password_failures::validate_structure,
    },
    ManagedStoreMigration {
        version: MANAGED_STORE_PRINCIPAL_SERVICE_LIMITS_VERSION,
        checksum: "3948a1529cdec3d7764ac705da99c766f04fdab292094e1d6a7544e76ba818d2",
        sql: PRINCIPAL_SERVICE_LIMITS_SQL,
        seed: None,
        structural_validation: validate_principal_service_limits_structure,
    },
    ManagedStoreMigration {
        version: MANAGED_STORE_IMPORTED_SERVICES_VERSION,
        checksum: "07145c88d41cbaeabfc04fe1d257e497a72f74bd3ae5aed808a6fd4d02a91409",
        sql: IMPORTED_SERVICES_SQL,
        seed: None,
        structural_validation: imported_store::validate_structure,
    },
    ManagedStoreMigration {
        version: MANAGED_STORE_OAUTH_DISCOVERY_REVISION_VERSION,
        checksum: "5a5b0235b9955b4e56c729602f88aed03cc0fbd5844b14bf61249c555fb4ff38",
        sql: include_str!("managed_store/oauth_discovery_revision.sql"),
        seed: None,
        structural_validation: oauth::validate_discovery_revision_structure,
    },
    ManagedStoreMigration {
        version: MANAGED_STORE_PRINCIPAL_ACCESS_VERSION,
        checksum: "6c95f3934ab95b1b13fdeeedce16aa25f1b2467a40258689205d835462881aed",
        sql: include_str!("managed_store/principal_access.sql"),
        seed: None,
        structural_validation: principal_access::validate_structure,
    },
    ManagedStoreMigration {
        version: MANAGED_STORE_TRUSTED_USER_IDENTITY_VERSION,
        checksum: "7e5d839306c3c8d2497f4cbbaf39d4036eb71f15074f0f00ffeb937534a57280",
        sql: include_str!("managed_store/trusted_user_identity.sql"),
        seed: None,
        structural_validation: identity_access::validate_structure,
    },
    ManagedStoreMigration {
        version: MANAGED_STORE_COMMAND_IMPORTS_VERSION,
        checksum: "680c67854a4a81c21660162c6215a5ef51fcf431e8d9eaff54cee0247137ac9a",
        sql: include_str!("managed_store/command_imports.sql"),
        seed: None,
        structural_validation: imported_store::validate_command_imports_structure,
    },
    ManagedStoreMigration {
        version: MANAGED_STORE_OAUTH_REVOCATIONS_VERSION,
        checksum: "54ad925a25730925cd410d948b0691cdaecc2ba791681023f639be89fd1bf986",
        sql: include_str!("managed_store/oauth_revocations.sql"),
        seed: None,
        structural_validation: imported_store::validate_oauth_revocations_structure,
    },
    ManagedStoreMigration {
        version: MANAGED_STORE_SECRET_REFERENCES_VERSION,
        checksum: "4c3fd69f149da35c06fabd9874cc980ac9b3386f5e85895313596e98d25657a7",
        sql: include_str!("managed_store/secret_references.sql"),
        seed: None,
        structural_validation: secret_references::validate_structure,
    },
];

fn production_migration_catalog() -> ManagedStoreMigrationCatalog<'static> {
    ManagedStoreMigrationCatalog {
        migrations: MANAGED_STORE_MIGRATIONS,
    }
}

impl ManagedStoreMigrationCatalog<'_> {
    fn latest(&self) -> Result<&ManagedStoreMigration, ManagedStoreError> {
        self.migrations.last().ok_or_else(|| {
            ManagedStoreError::SchemaInvalid("migration catalog is empty".to_string())
        })
    }

    fn validate(&self) -> Result<(), ManagedStoreError> {
        if self.migrations.is_empty() {
            return Err(ManagedStoreError::SchemaInvalid(
                "managed store requires one fresh schema baseline".to_string(),
            ));
        }
        for migration in self.migrations {
            if migration.checksum != sha256_hex(migration.sql.as_bytes()) {
                return Err(ManagedStoreError::SchemaInvalid(
                    "managed store migration checksum is invalid".into(),
                ));
            }
        }
        if self
            .migrations
            .windows(2)
            .any(|pair| pair[0].version >= pair[1].version)
        {
            return Err(ManagedStoreError::SchemaInvalid(
                "managed store migration order is invalid".into(),
            ));
        }
        let baseline = &self.migrations[0];
        if baseline.version != MANAGED_STORE_BASELINE_SCHEMA_VERSION
            || baseline.checksum != MANAGED_STORE_BASELINE_CHECKSUM
            || baseline.sql != MANAGED_STORE_BASELINE_SQL
            || baseline.checksum != sha256_hex(baseline.sql.as_bytes())
        {
            return Err(ManagedStoreError::SchemaInvalid(
                "managed store baseline is invalid".to_string(),
            ));
        }
        Ok(())
    }

    fn current_schema_checksum(&self) -> String {
        sqlite_support::catalog_checksum(self.migrations)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedStoreOpenMode {
    Startup,
    Reload,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyValidationIssue {
    pub field: String,
    pub code: String,
    pub message: String,
}

/// An import change refused because stored resources or retained grants
/// would not stay valid under it. The message names them for people; the
/// lists name them for clients, which management reports as
/// `target.affectedGrants` and `target.resources`.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImportChangeBlocked {
    pub message: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub affected_grants: Vec<ImportBlockingGrant>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<ImportBlockingResource>,
}

/// A retained grant the change would leave invalid, with the policy
/// validation issue's code and message.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImportBlockingGrant {
    pub id: String,
    pub reason_code: String,
    pub reason: String,
}

/// A stored resource that prevents the change, by Broker type and ID.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ImportBlockingResource {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub id: String,
}

#[derive(Debug, Error)]
pub enum ManagedStoreError {
    #[error("managed store is unavailable: {0}")]
    Unavailable(String),
    #[error("managed store migration is required")]
    MigrationRequired,
    #[error("managed store schema is invalid: {0}")]
    SchemaInvalid(String),
    #[error("encryption key is missing: {0}")]
    EncryptionKeyMissing(String),
    #[error("encryption key is invalid: {0}")]
    EncryptionKeyInvalid(String),
    #[error("credential encryption failed")]
    CredentialEncryptFailed,
    #[error("credential decryption failed")]
    CredentialDecryptFailed,
    #[error("principal is required")]
    PrincipalRequired,
    #[error("principal was not found")]
    PrincipalNotFound,
    #[error("principal is disabled")]
    PrincipalDisabled,
    #[error("self-service is disabled")]
    SelfServiceDisabled,
    #[error("group was not found")]
    GroupNotFound,
    #[error("resource was not found")]
    ResourceNotFound,
    #[error(
        "Resource \"{0}\" already exists with this resource type and coverage. Open the existing resource to edit it."
    )]
    ResourceConflict(Box<CatalogAuditEntity>),
    #[error("resource group was not found")]
    ResourceGroupNotFound,
    #[error("resource or resource group is in use; remove references before deletion")]
    ResourceInUse,
    #[error("policy grant was not found")]
    PolicyGrantNotFound,
    #[error("scoped policy managers cannot move grants between services")]
    PolicyManagementServiceMoveDenied,
    #[error("policy authority is unavailable: {0}")]
    PolicyAuthorityUnavailable(String),
    #[error("policy validation failed: {0}")]
    PolicyValidationFailed(String),
    #[error("policy validation failed")]
    PolicyValidationIssues(Vec<PolicyValidationIssue>),
    #[error("reload or policy mutation is already in progress")]
    ReloadInProgress,
    #[error("principal already exists")]
    PrincipalAlreadyExists,
    #[error("version conflict")]
    VersionConflict,
    #[error("identity binding conflicts with an existing identity")]
    IdentityBindingConflict,
    #[error("identity version conflict")]
    IdentityVersionConflict,
    #[error("identity binding was not found")]
    IdentityBindingNotFound,
    #[error("attested identity is denied")]
    AttestedIdentityDenied,
    #[error("broker token was not found")]
    BrokerTokenNotFound,
    #[error("broker token is expired")]
    BrokerTokenExpired,
    #[error("broker token is revoked")]
    BrokerTokenRevoked,
    #[error("broker token is paused")]
    BrokerTokenPaused,
    #[error("broker token cannot be changed in its current state")]
    BrokerTokenStateConflict,
    #[error("broker token class is denied")]
    BrokerTokenClassDenied,
    #[error("local login failed")]
    LocalLoginFailed,
    #[error("local password work capacity is exhausted")]
    LocalPasswordBusy,
    #[error("local login is locked")]
    LocalLoginLocked,
    #[error("local password sign-in is not enabled")]
    LocalPasswordNotEnabled,
    #[error("local password sign-in is already enabled")]
    LocalPasswordAlreadyEnabled,
    #[error("OIDC provider state is unavailable")]
    OidcProviderUnavailable,
    #[error("OIDC authorization flow was not found or is no longer valid")]
    OidcFlowInvalid,
    #[error("OIDC authorization flow is expired")]
    OidcFlowExpired,
    #[error("OIDC authorization flow capacity is exhausted")]
    OidcFlowCapacity,
    #[error("OIDC callback is stale")]
    OidcCallbackStale,
    #[error("OIDC login method conflicts with an existing binding")]
    OidcLoginMethodConflict,
    #[error("external group binding was not found")]
    ExternalGroupBindingNotFound,
    #[error("external group binding conflicts with an existing mapping")]
    ExternalGroupBindingConflict,
    #[error("OIDC admission was denied")]
    OidcAdmissionDenied,
    #[error("credential was not found")]
    CredentialNotFound,
    #[error("credential is expired")]
    CredentialExpired,
    #[error("secret reference was not found")]
    SecretReferenceNotFound,
    #[error("secret reference expired; the upstream operation must not be repeated automatically")]
    SecretReferenceExpired,
    #[error("secret reference use is denied")]
    SecretReferenceDenied,
    #[error("temporary secret capacity is exhausted")]
    SecretReferenceCapacity,
    #[error("secret reservation is no longer writable")]
    SecretReferenceStateConflict,
    #[error("input is invalid: {0}")]
    InputInvalid(String),
    #[error("input is invalid: {}", .0.message)]
    ImportChangeBlocked(Box<ImportChangeBlocked>),
    #[error("credential is invalid: {0}")]
    CredentialInvalid(String),
    #[error("right is missing")]
    RightMissing,
}

impl ManagedStoreError {
    pub fn reason_code(&self) -> ReasonCode {
        match self {
            Self::Unavailable(_) => ReasonCode::ManagedStoreUnavailable,
            Self::MigrationRequired | Self::SchemaInvalid(_) => {
                ReasonCode::ManagedStoreMigrationRequired
            }
            Self::EncryptionKeyMissing(_) => ReasonCode::EncryptionKeyMissing,
            Self::EncryptionKeyInvalid(_) => ReasonCode::EncryptionKeyInvalid,
            Self::CredentialEncryptFailed => ReasonCode::CredentialEncryptFailed,
            Self::CredentialDecryptFailed => ReasonCode::CredentialDecryptFailed,
            Self::PrincipalRequired => ReasonCode::PrincipalRequired,
            Self::PrincipalNotFound => ReasonCode::PrincipalNotFound,
            Self::PrincipalDisabled => ReasonCode::PrincipalDisabled,
            Self::SelfServiceDisabled => ReasonCode::SelfServiceDisabled,
            Self::GroupNotFound => ReasonCode::GroupNotFound,
            Self::ResourceNotFound => ReasonCode::ResourceNotFound,
            Self::ResourceGroupNotFound => ReasonCode::ResourceGroupNotFound,
            Self::ResourceInUse => ReasonCode::ResourceInUse,
            Self::PolicyGrantNotFound => ReasonCode::PolicyGrantNotFound,
            Self::PolicyManagementServiceMoveDenied => ReasonCode::ManagementDenied,
            Self::PolicyAuthorityUnavailable(_) => ReasonCode::PolicyAuthorityUnavailable,
            Self::PolicyValidationFailed(_) | Self::PolicyValidationIssues(_) => {
                ReasonCode::PolicyValidationFailed
            }
            Self::ReloadInProgress => ReasonCode::ReloadInProgress,
            Self::PrincipalAlreadyExists | Self::VersionConflict => ReasonCode::VersionConflict,
            Self::IdentityBindingConflict => ReasonCode::IdentityBindingConflict,
            Self::IdentityVersionConflict => ReasonCode::IdentityVersionConflict,
            Self::IdentityBindingNotFound => ReasonCode::IdentityBindingNotFound,
            Self::AttestedIdentityDenied => ReasonCode::IdentityAssertionDenied,
            Self::BrokerTokenNotFound => ReasonCode::BrokerTokenNotFound,
            Self::BrokerTokenExpired => ReasonCode::BrokerTokenExpired,
            Self::BrokerTokenRevoked => ReasonCode::BrokerTokenRevoked,
            Self::BrokerTokenPaused => ReasonCode::BrokerTokenPaused,
            Self::BrokerTokenStateConflict => ReasonCode::BrokerTokenStateConflict,
            Self::BrokerTokenClassDenied => ReasonCode::BrokerTokenClassDenied,
            Self::LocalLoginFailed => ReasonCode::LocalLoginFailed,
            Self::LocalLoginLocked => ReasonCode::LocalLoginLocked,
            Self::LocalPasswordBusy => ReasonCode::ConcurrencyLimited,
            Self::LocalPasswordNotEnabled => ReasonCode::LocalPasswordNotEnabled,
            Self::LocalPasswordAlreadyEnabled => ReasonCode::LocalPasswordAlreadyEnabled,
            Self::OidcProviderUnavailable => ReasonCode::OidcUnavailable,
            Self::OidcFlowInvalid | Self::OidcCallbackStale => ReasonCode::OidcFlowInvalid,
            Self::OidcFlowExpired => ReasonCode::OidcFlowExpired,
            Self::OidcFlowCapacity => ReasonCode::OidcUnavailable,
            Self::OidcLoginMethodConflict => ReasonCode::OidcLoginMethodConflict,
            Self::ExternalGroupBindingConflict => ReasonCode::ExternalGroupBindingConflict,
            Self::ExternalGroupBindingNotFound => ReasonCode::ExternalGroupBindingNotFound,
            Self::OidcAdmissionDenied => ReasonCode::OidcAdmissionDenied,
            Self::CredentialNotFound => ReasonCode::CredentialNotFound,
            Self::CredentialExpired => ReasonCode::CredentialExpired,
            Self::SecretReferenceNotFound => ReasonCode::SecretReferenceNotFound,
            Self::SecretReferenceExpired => ReasonCode::SecretReferenceExpired,
            Self::SecretReferenceDenied => ReasonCode::SecretReferenceDenied,
            Self::SecretReferenceCapacity => ReasonCode::SecretReferenceCapacity,
            Self::SecretReferenceStateConflict => ReasonCode::VersionConflict,
            Self::InputInvalid(_) | Self::ResourceConflict(_) | Self::ImportChangeBlocked(_) => {
                ReasonCode::InputInvalid
            }
            Self::CredentialInvalid(_) => ReasonCode::CredentialInvalid,
            Self::RightMissing => ReasonCode::RightMissing,
        }
    }
}

// Reload opens a new connection, but must share admission with hash jobs still
// running against the old snapshot. Weak entries do not retain retired stores.
struct LocalPasswordWork {
    hashes: Arc<tokio::sync::Semaphore>,
    admin_hashes: Arc<tokio::sync::Semaphore>,
    requests: Arc<tokio::sync::Semaphore>,
}

fn local_password_work_for_store(path: &Path) -> Result<Arc<LocalPasswordWork>, ManagedStoreError> {
    static STORES: OnceLock<Mutex<BTreeMap<PathBuf, Weak<LocalPasswordWork>>>> = OnceLock::new();
    let path = fs::canonicalize(path)
        .map_err(|error| ManagedStoreError::Unavailable(error.to_string()))?;
    let mut stores = STORES.get_or_init(Mutex::default).lock().unwrap();
    stores.retain(|_, work| work.strong_count() > 0);
    if let Some(work) = stores.get(&path).and_then(Weak::upgrade) {
        return Ok(work);
    }
    let work = Arc::new(LocalPasswordWork {
        hashes: Arc::new(tokio::sync::Semaphore::new(LOCAL_PASSWORD_MAX_CONCURRENT)),
        admin_hashes: Arc::new(tokio::sync::Semaphore::new(
            LOCAL_PASSWORD_MAX_ADMIN_CONCURRENT,
        )),
        requests: Arc::new(tokio::sync::Semaphore::new(LOCAL_PASSWORD_MAX_CONCURRENT)),
    });
    stores.insert(path, Arc::downgrade(&work));
    Ok(work)
}

#[derive(Clone)]
pub struct ManagedStore {
    path: PathBuf,
    connection: Arc<Mutex<Connection>>,
    identity_key_ring: Arc<Mutex<Option<CredentialKeyRing>>>,
    /// How principal disablement keeps revoking registrations' OAuth
    /// families: set by the active OAuth configuration.
    oauth_revocation: Arc<Mutex<Option<oauth_revocation::RevocationCapture>>>,
    local_password_work: Arc<LocalPasswordWork>,
    schema_version: String,
    schema_checksum: String,
    latest_migration_checksum: String,
    applied_migrations_this_open: Arc<BTreeSet<String>>,
}

impl std::fmt::Debug for ManagedStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl ManagedStore {
    pub fn open(
        config: &ManagedStoreConfig,
        mode: ManagedStoreOpenMode,
    ) -> Result<Self, ManagedStoreError> {
        Self::open_with_catalog(config, mode, production_migration_catalog())
    }

    fn open_with_catalog(
        config: &ManagedStoreConfig,
        mode: ManagedStoreOpenMode,
        catalog: ManagedStoreMigrationCatalog<'_>,
    ) -> Result<Self, ManagedStoreError> {
        catalog.validate()?;
        let latest = catalog.latest()?;
        let schema_version = latest.version.to_string();
        let schema_checksum = catalog.current_schema_checksum();
        let latest_migration_checksum = latest.checksum.to_string();
        let path = PathBuf::from(&config.path);
        let allow_create = matches!(mode, ManagedStoreOpenMode::Startup) && config.auto_migrate;
        if allow_create {
            if let Some(parent) = path.parent() {
                fs_permissions::ensure_private_dir(parent).map_err(|error| {
                    ManagedStoreError::Unavailable(format!(
                        "failed to create managed store directory {}: {error}",
                        parent.display()
                    ))
                })?;
            }
            fs_permissions::ensure_private_file_by_path(&path).map_err(|error| {
                ManagedStoreError::Unavailable(format!(
                    "failed to create managed store file {}: {error}",
                    path.display()
                ))
            })?;
        } else {
            fs_permissions::validate_private_parent(&path).map_err(|error| {
                ManagedStoreError::Unavailable(format!(
                    "failed to validate managed store directory for {}: {error}",
                    path.display()
                ))
            })?;
        }
        restrict_sqlite_files(&path)?;
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_FULL_MUTEX;
        let connection = Connection::open_with_flags(&path, flags).map_err(|error| {
            ManagedStoreError::Unavailable(format!(
                "failed to open managed store {}: {error}",
                path.display()
            ))
        })?;
        connection
            .execute_batch("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;")
            .map_err(|error| {
                ManagedStoreError::Unavailable(format!(
                    "failed to initialize managed store connection: {error}"
                ))
            })?;
        restrict_sqlite_files(&path)?;
        let connection = Arc::new(Mutex::new(connection));
        let applied_migrations_this_open = {
            let conn = connection.lock().unwrap();
            let applied = admit_schema(
                &conn,
                catalog,
                matches!(mode, ManagedStoreOpenMode::Startup) && config.auto_migrate,
            )?;
            conn.execute_batch("PRAGMA journal_mode = WAL;")
                .map_err(sql_unavailable)?;
            applied
        };
        let store = Self {
            local_password_work: local_password_work_for_store(&path)?,
            path,
            connection,
            identity_key_ring: Arc::new(Mutex::new(None)),
            oauth_revocation: Arc::new(Mutex::new(None)),
            schema_version,
            schema_checksum,
            latest_migration_checksum,
            applied_migrations_this_open: Arc::new(applied_migrations_this_open),
        };
        restrict_sqlite_files(store.path())?;
        Ok(store)
    }

    /// Reserve a password request before scheduling a blocking task. The permit
    /// must stay with that task, including after its HTTP future is cancelled.
    pub fn try_admit_local_password_request(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, ManagedStoreError> {
        self.local_password_work
            .requests
            .clone()
            .try_acquire_owned()
            .map_err(|_| ManagedStoreError::LocalPasswordBusy)
    }

    fn try_acquire_work(&self) -> Result<tokio::sync::OwnedSemaphorePermit, ManagedStoreError> {
        self.local_password_work
            .hashes
            .clone()
            .try_acquire_owned()
            .map_err(|_| ManagedStoreError::LocalPasswordBusy)
    }

    // Keep administrative recovery available when login/password-change work
    // is saturated, while bounding total Argon2 memory to three hash jobs.
    fn try_acquire_admin_password_work(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, ManagedStoreError> {
        self.local_password_work
            .admin_hashes
            .clone()
            .try_acquire_owned()
            .map_err(|_| ManagedStoreError::LocalPasswordBusy)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn schema_checksum() -> String {
        production_migration_catalog().current_schema_checksum()
    }

    pub fn migration_applied_this_open(&self, version: &str) -> bool {
        self.applied_migrations_this_open.contains(version)
    }

    pub fn check_ready(
        &self,
        key_ring: Option<&CredentialKeyRing>,
    ) -> Result<(), ManagedStoreError> {
        self.check_schema_ready()?;
        let conn = self.connection.lock().unwrap();
        identity_access::check_integrity(&conn)?;
        check_secret_material_ready(&conn, key_ring)?;
        identity_tokens::check_ready(&conn, key_ring)?;
        oauth::check_ready(&conn, key_ring)?;
        oauth_revocation::check_ready(&conn, key_ring)?;
        resource_attributes::check_ready(&conn, key_ring)?;
        imported_store::check_ready(&conn, key_ring)?;
        secret_references::check_ready(&conn, key_ring)?;
        let key_ids = active_credential_key_ids(&conn)?;
        match key_ring {
            Some(key_ring) => {
                for key_id in key_ids {
                    if !key_ring.has_key(&key_id) {
                        return Err(ManagedStoreError::EncryptionKeyMissing(key_id));
                    }
                }
            }
            None if !key_ids.is_empty() => {
                return Err(ManagedStoreError::EncryptionKeyMissing(
                    "credential key ring".to_string(),
                ));
            }
            None => {}
        }
        Ok(())
    }

    pub fn check_schema_ready(&self) -> Result<(), ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        check_schema_ready(&conn, &self.schema_version, &self.latest_migration_checksum)?;
        conn.query_row("SELECT 1", [], |_| Ok(()))
            .map_err(sql_unavailable)?;
        Ok(())
    }

    pub fn active_credential_key_ids(&self) -> Result<Vec<String>, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        active_credential_key_ids(&conn)
    }

    pub fn active_credential_count(&self) -> Result<u64, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(1) FROM credentials WHERE status = 'active'",
                [],
                |row| row.get(0),
            )
            .map_err(sql_unavailable)?;
        Ok(count as u64)
    }

    pub fn active_credentials_need_key_ring(&self) -> Result<bool, ManagedStoreError> {
        Ok(self.active_credential_count()? > 0 || !self.active_credential_key_ids()?.is_empty())
    }

    pub fn check_active_credential_keys(
        &self,
        key_ring: &CredentialKeyRing,
    ) -> Result<(), ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        for key_id in active_credential_key_ids(&conn)? {
            if !key_ring.has_key(&key_id) {
                return Err(ManagedStoreError::EncryptionKeyMissing(key_id));
            }
        }
        Ok(())
    }

    pub fn status(&self) -> Result<ManagedStoreStatus, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        Ok(ManagedStoreStatus {
            path: self.path.display().to_string(),
            schema_version: self.schema_version.clone(),
            schema_checksum: self.schema_checksum.clone(),
            principals: count_table(&conn, "principals")?,
            groups: count_table_if_exists(&conn, "groups")?,
            broker_tokens: count_table(&conn, "broker_tokens")?,
            rights: count_table(&conn, "rights")?,
            credentials: count_table(&conn, "credentials")?,
            key_ids_in_use: active_credential_key_ids(&conn)?,
        })
    }

    pub fn policy_revision(&self) -> Result<ManagedPolicyRevision, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        policy_revision(&conn)
    }

    /// Capture retained grant references and their generation atomically before
    /// entering a mutation callback (which already owns the connection lock).
    pub fn policy_validation_baseline(
        &self,
    ) -> Result<(ManagedPolicyRevision, Vec<ManagedPolicyGrantRecord>), ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        Ok((policy_revision(&conn)?, policy_grants(&conn, None)?))
    }

    pub fn policy_grants(&self) -> Result<Vec<ManagedPolicyGrantRecord>, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        policy_grants(&conn, None)
    }

    pub fn policy_grant(
        &self,
        grant_id: &str,
    ) -> Result<ManagedPolicyGrantRecord, ManagedStoreError> {
        validate_policy_grant_id(grant_id)?;
        let conn = self.connection.lock().unwrap();
        policy_grant_by_id(&conn, grant_id)
    }

    pub fn active_policy_grants(&self) -> Result<Vec<ManagedPolicyGrantRecord>, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        policy_grants(&conn, Some("active"))
    }

    pub fn validate_policy_grant_create<F>(
        &self,
        request: ManagedPolicyGrantCreateRequest,
        mut validate_candidate: F,
    ) -> Result<(), ManagedStoreError>
    where
        F: FnMut(
            &[ManagedPolicyGrantRecord],
            &ManagedPolicyRevision,
            &ManagedPolicySubjectCatalog,
            &ManagedResourceCatalog,
        ) -> Result<(), ManagedStoreError>,
    {
        validate_policy_grant_create_request(&request)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        let grant_id = request
            .grant_id
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        if policy_grant_exists(&tx, &grant_id)? {
            return Err(ManagedStoreError::VersionConflict);
        }
        let now = normalized_now_string();
        let status = request.status.unwrap_or_else(|| "active".to_string());
        let actor = request.created_by.clone();
        let grant = ManagedPolicyGrantRecord {
            grant_id,
            grant_order: next_policy_grant_order(&tx)?,
            subjects: request.subjects,
            execution_contexts: request.execution_contexts,
            service: request.service,
            actions: request.actions,
            resources: request.resources,
            credential_mode: request.credential_mode,
            priority: request.priority,
            status: status.clone(),
            description: normalize_optional_text(request.description),
            version: 1,
            created_at: now.clone(),
            created_by: actor.clone(),
            updated_at: now.clone(),
            updated_by: actor.clone(),
            disabled_at: (status == "disabled").then_some(now.clone()),
            deleted_at: None,
        };
        let mut active_grants = policy_grants(&tx, Some("active"))?;
        if grant.status == "active" {
            active_grants.push(grant.clone());
        }
        active_grants.sort_by_key(|grant| grant.grant_order);
        let previous_revision = policy_revision(&tx)?;
        let revision = next_policy_revision(&previous_revision, &now, &actor)?;
        let subjects = policy_subject_catalog(&tx)?;
        let catalog = resource_catalog(&tx)?;
        validate_grant_resource_references(&active_grants, &catalog)?;
        validate_candidate(&active_grants, &revision, &subjects, &catalog)?;
        if grant.status != "active" {
            validate_grant_resource_references(std::slice::from_ref(&grant), &catalog)?;
            validate_candidate(std::slice::from_ref(&grant), &revision, &subjects, &catalog)?;
        }
        Ok(())
    }

    pub fn validate_policy_grant_patch<F>(
        &self,
        request: ManagedPolicyGrantPatchRequest,
        validate_candidate: F,
    ) -> Result<(), ManagedStoreError>
    where
        F: FnMut(
            &[ManagedPolicyGrantRecord],
            &ManagedPolicyRevision,
            &ManagedPolicySubjectCatalog,
            &ManagedResourceCatalog,
        ) -> Result<(), ManagedStoreError>,
    {
        self.validate_policy_grant_patch_authorized(
            request,
            &PolicyReadScope::Global,
            validate_candidate,
        )
    }

    pub fn validate_policy_grant_patch_authorized<F>(
        &self,
        request: ManagedPolicyGrantPatchRequest,
        scope: &PolicyReadScope,
        mut validate_candidate: F,
    ) -> Result<(), ManagedStoreError>
    where
        F: FnMut(
            &[ManagedPolicyGrantRecord],
            &ManagedPolicyRevision,
            &ManagedPolicySubjectCatalog,
            &ManagedResourceCatalog,
        ) -> Result<(), ManagedStoreError>,
    {
        validate_policy_grant_patch_request(&request)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        let current = policy_grant_by_id(&tx, &request.grant_id)?;
        if !scope.authorizes_service(&current.service) {
            return Err(ManagedStoreError::PolicyGrantNotFound);
        }
        if matches!(scope, PolicyReadScope::Services { .. })
            && request
                .service
                .as_deref()
                .is_some_and(|service| service != current.service)
        {
            return Err(ManagedStoreError::PolicyManagementServiceMoveDenied);
        }
        ensure_policy_grant_version(&current, request.expected_version)?;
        if current.status == "deleted" {
            return Err(input_invalid("deleted policy grants cannot be edited"));
        }
        let now = normalized_now_string();
        let authorization_changed = request.subjects.is_some()
            || request.execution_contexts.is_some()
            || request.service.is_some()
            || request.actions.is_some()
            || request.resources.is_some()
            || request.credential_mode.is_some()
            || request.priority.is_some();
        let mut updated = current.clone();
        if let Some(subjects) = request.subjects {
            updated.subjects = subjects;
        }
        if let Some(execution_contexts) = request.execution_contexts {
            updated.execution_contexts = execution_contexts;
        }
        if let Some(service) = request.service {
            updated.service = service;
        }
        if let Some(actions) = request.actions {
            updated.actions = actions;
        }
        if let Some(resources) = request.resources {
            updated.resources = resources;
        }
        if let Some(credential_mode) = request.credential_mode {
            updated.credential_mode = credential_mode;
        }
        if let Some(priority) = request.priority {
            updated.priority = priority;
        }
        if let Some(description) = request.description {
            updated.description = normalize_optional_text(description);
        }
        if let Some(status) = request.status {
            updated.status = status.clone();
            match status.as_str() {
                "active" => {
                    updated.disabled_at = None;
                    updated.deleted_at = None;
                }
                "disabled" => {
                    updated.disabled_at = Some(now.clone());
                    updated.deleted_at = None;
                }
                _ => {}
            }
        }
        updated.version += 1;
        updated.updated_at = now.clone();
        updated.updated_by = request.updated_by;
        let active_grants =
            active_policy_grants_with_replacement(&tx, Some(updated.clone()), None)?;
        let previous_revision = policy_revision(&tx)?;
        let revision = next_policy_revision(&previous_revision, &now, &updated.updated_by)?;
        let subjects = policy_subject_catalog(&tx)?;
        let catalog = resource_catalog(&tx)?;
        validate_grant_resource_references(&active_grants, &catalog)?;
        validate_candidate(&active_grants, &revision, &subjects, &catalog)?;
        if updated.status != "active" && authorization_changed {
            validate_grant_resource_references(std::slice::from_ref(&updated), &catalog)?;
            validate_candidate(
                std::slice::from_ref(&updated),
                &revision,
                &subjects,
                &catalog,
            )?;
        }
        Ok(())
    }

    pub fn policy_subject_catalog(&self) -> Result<ManagedPolicySubjectCatalog, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        policy_subject_catalog(&conn)
    }

    pub fn create_policy_grant<F>(
        &self,
        request: ManagedPolicyGrantCreateRequest,
        validate_candidate: F,
    ) -> Result<ManagedPolicyMutationResult, ManagedStoreError>
    where
        F: FnMut(
            &[ManagedPolicyGrantRecord],
            &ManagedPolicyRevision,
            &ManagedPolicySubjectCatalog,
            &ManagedResourceCatalog,
        ) -> Result<(), ManagedStoreError>,
    {
        validate_policy_grant_create_request(&request)?;
        let grant_id = match request.grant_id {
            Some(grant_id) => {
                validate_policy_grant_id(&grant_id)?;
                grant_id
            }
            None => Uuid::new_v4().to_string(),
        };
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        if policy_grant_exists(&tx, &grant_id)? {
            return Err(ManagedStoreError::VersionConflict);
        }
        let now = normalized_now_string();
        let status = request.status.unwrap_or_else(|| "active".to_string());
        let grant = ManagedPolicyGrantRecord {
            grant_id,
            grant_order: next_policy_grant_order(&tx)?,
            subjects: request.subjects,
            execution_contexts: request.execution_contexts,
            service: request.service,
            actions: request.actions,
            resources: request.resources,
            credential_mode: request.credential_mode,
            priority: request.priority,
            status: status.clone(),
            description: normalize_optional_text(request.description),
            version: 1,
            created_at: now.clone(),
            created_by: request.created_by.clone(),
            updated_at: now.clone(),
            updated_by: request.created_by,
            disabled_at: (status == "disabled").then_some(now.clone()),
            deleted_at: None,
        };
        let mut active_grants = policy_grants(&tx, Some("active"))?;
        if grant.status == "active" {
            active_grants.push(grant.clone());
        }
        active_grants.sort_by_key(|grant| grant.grant_order);
        let previous_revision = policy_revision(&tx)?;
        let revision = next_policy_revision(&previous_revision, &now, &grant.updated_by)?;
        finalize_policy_mutation(
            tx,
            previous_revision,
            revision,
            active_grants,
            (grant.status != "active").then_some(grant.clone()),
            validate_candidate,
            |tx, revision| {
                insert_policy_grant(tx, &grant)?;
                update_policy_revision(tx, revision)?;
                Ok(grant.clone())
            },
        )
    }

    pub fn patch_policy_grant<F>(
        &self,
        request: ManagedPolicyGrantPatchRequest,
        validate_candidate: F,
    ) -> Result<ManagedPolicyMutationResult, ManagedStoreError>
    where
        F: FnMut(
            &[ManagedPolicyGrantRecord],
            &ManagedPolicyRevision,
            &ManagedPolicySubjectCatalog,
            &ManagedResourceCatalog,
        ) -> Result<(), ManagedStoreError>,
    {
        self.patch_policy_grant_authorized(request, &PolicyWriteScope::Global, validate_candidate)
    }

    pub fn patch_policy_grant_authorized<F>(
        &self,
        request: ManagedPolicyGrantPatchRequest,
        scope: &PolicyWriteScope,
        validate_candidate: F,
    ) -> Result<ManagedPolicyMutationResult, ManagedStoreError>
    where
        F: FnMut(
            &[ManagedPolicyGrantRecord],
            &ManagedPolicyRevision,
            &ManagedPolicySubjectCatalog,
            &ManagedResourceCatalog,
        ) -> Result<(), ManagedStoreError>,
    {
        validate_policy_grant_patch_request(&request)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        let current = policy_grant_by_id(&tx, &request.grant_id)?;
        ensure_policy_management_scope(scope, &current.service)?;
        ensure_policy_management_service_unchanged(
            scope,
            &current.service,
            request.service.as_deref(),
        )?;
        ensure_policy_grant_version(&current, request.expected_version)?;
        if current.status == "deleted" {
            return Err(input_invalid("deleted policy grants cannot be edited"));
        }
        let now = normalized_now_string();
        let authorization_changed = request.subjects.is_some()
            || request.execution_contexts.is_some()
            || request.service.is_some()
            || request.actions.is_some()
            || request.resources.is_some()
            || request.credential_mode.is_some()
            || request.priority.is_some();
        let mut updated = current.clone();
        if let Some(subjects) = request.subjects {
            updated.subjects = subjects;
        }
        if let Some(execution_contexts) = request.execution_contexts {
            updated.execution_contexts = execution_contexts;
        }
        if let Some(service) = request.service {
            updated.service = service;
        }
        if let Some(actions) = request.actions {
            updated.actions = actions;
        }
        if let Some(resources) = request.resources {
            updated.resources = resources;
        }
        if let Some(credential_mode) = request.credential_mode {
            updated.credential_mode = credential_mode;
        }
        if let Some(priority) = request.priority {
            updated.priority = priority;
        }
        if let Some(description) = request.description {
            updated.description = normalize_optional_text(description);
        }
        if let Some(status) = request.status {
            updated.status = status.clone();
            match status.as_str() {
                "active" => {
                    updated.disabled_at = None;
                    updated.deleted_at = None;
                }
                "disabled" => {
                    updated.disabled_at = Some(now.clone());
                    updated.deleted_at = None;
                }
                _ => {}
            }
        }
        updated.version += 1;
        updated.updated_at = now.clone();
        updated.updated_by = request.updated_by;
        let active_grants =
            active_policy_grants_with_replacement(&tx, Some(updated.clone()), None)?;
        let previous_revision = policy_revision(&tx)?;
        let revision = next_policy_revision(&previous_revision, &now, &updated.updated_by)?;
        let inactive_validation_grant =
            (updated.status != "active" && authorization_changed).then_some(updated.clone());
        finalize_policy_mutation(
            tx,
            previous_revision,
            revision,
            active_grants,
            inactive_validation_grant,
            validate_candidate,
            |tx, revision| {
                update_policy_grant_record(tx, &updated)?;
                update_policy_revision(tx, revision)?;
                Ok(updated.clone())
            },
        )
    }

    pub fn add_policy_grant_subject<F>(
        &self,
        request: ManagedPolicyGrantSubjectAddRequest,
        validate_candidate: F,
    ) -> Result<ManagedPolicyMutationResult, ManagedStoreError>
    where
        F: FnMut(
            &[ManagedPolicyGrantRecord],
            &ManagedPolicyRevision,
            &ManagedPolicySubjectCatalog,
            &ManagedResourceCatalog,
        ) -> Result<(), ManagedStoreError>,
    {
        self.add_policy_grant_subject_authorized(
            request,
            &PolicyWriteScope::Global,
            validate_candidate,
        )
    }

    pub fn add_policy_grant_subject_authorized<F>(
        &self,
        request: ManagedPolicyGrantSubjectAddRequest,
        scope: &PolicyWriteScope,
        validate_candidate: F,
    ) -> Result<ManagedPolicyMutationResult, ManagedStoreError>
    where
        F: FnMut(
            &[ManagedPolicyGrantRecord],
            &ManagedPolicyRevision,
            &ManagedPolicySubjectCatalog,
            &ManagedResourceCatalog,
        ) -> Result<(), ManagedStoreError>,
    {
        validate_policy_grant_subject_add_request(&request)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        let current = policy_grant_by_id(&tx, &request.grant_id)?;
        ensure_policy_management_scope(scope, &current.service)?;
        ensure_policy_grant_version(&current, request.expected_version)?;
        if current.status == "deleted" {
            return Err(input_invalid(
                "deleted policy grants cannot have subjects changed",
            ));
        }
        if current
            .subjects
            .iter()
            .any(|subject| subject == &request.subject)
        {
            return Err(input_invalid("subject is already attached to policy grant"));
        }

        let now = normalized_now_string();
        let mut updated = current.clone();
        updated.subjects.push(request.subject);
        updated.version += 1;
        updated.updated_at = now.clone();
        updated.updated_by = request.updated_by;

        let active_grants =
            active_policy_grants_with_replacement(&tx, Some(updated.clone()), None)?;
        let previous_revision = policy_revision(&tx)?;
        let revision = next_policy_revision(&previous_revision, &now, &updated.updated_by)?;
        let inactive_validation_grant = (updated.status != "active").then_some(updated.clone());
        finalize_policy_mutation(
            tx,
            previous_revision,
            revision,
            active_grants,
            inactive_validation_grant,
            validate_candidate,
            |tx, revision| {
                update_policy_grant_record(tx, &updated)?;
                update_policy_revision(tx, revision)?;
                Ok(updated.clone())
            },
        )
    }

    pub fn remove_policy_grant_subject<F>(
        &self,
        request: ManagedPolicyGrantSubjectRemoveRequest,
        validate_candidate: F,
    ) -> Result<ManagedPolicyMutationResult, ManagedStoreError>
    where
        F: FnMut(
            &[ManagedPolicyGrantRecord],
            &ManagedPolicyRevision,
            &ManagedPolicySubjectCatalog,
            &ManagedResourceCatalog,
        ) -> Result<(), ManagedStoreError>,
    {
        self.remove_policy_grant_subject_authorized(
            request,
            &PolicyWriteScope::Global,
            validate_candidate,
        )
    }

    pub fn remove_policy_grant_subject_authorized<F>(
        &self,
        request: ManagedPolicyGrantSubjectRemoveRequest,
        scope: &PolicyWriteScope,
        validate_candidate: F,
    ) -> Result<ManagedPolicyMutationResult, ManagedStoreError>
    where
        F: FnMut(
            &[ManagedPolicyGrantRecord],
            &ManagedPolicyRevision,
            &ManagedPolicySubjectCatalog,
            &ManagedResourceCatalog,
        ) -> Result<(), ManagedStoreError>,
    {
        validate_policy_grant_subject_remove_request(&request)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        let current = policy_grant_by_id(&tx, &request.grant_id)?;
        ensure_policy_management_scope(scope, &current.service)?;
        ensure_policy_grant_version(&current, request.expected_version)?;
        if current.status == "deleted" {
            return Err(input_invalid(
                "deleted policy grants cannot have subjects changed",
            ));
        }
        if !current
            .subjects
            .iter()
            .any(|subject| subject == &request.subject)
        {
            return Err(input_invalid("subject is not attached to policy grant"));
        }

        let now = normalized_now_string();
        let mut updated = current.clone();
        updated
            .subjects
            .retain(|subject| subject != &request.subject);
        if updated.subjects.is_empty() && updated.status == "active" {
            if request.last_subject_behavior == "disable_grant" {
                updated.status = "disabled".to_string();
                updated.disabled_at = Some(now.clone());
                updated.deleted_at = None;
            } else {
                return Err(ManagedStoreError::PolicyValidationIssues(vec![
                    PolicyValidationIssue {
                        field: "subjects".to_string(),
                        code: "empty".to_string(),
                        message: "active policy grants must have at least one subject; use lastSubjectBehavior=disable_grant to remove the final subject".to_string(),
                    },
                ]));
            }
        }
        updated.version += 1;
        updated.updated_at = now.clone();
        updated.updated_by = request.updated_by;

        let active_grants =
            active_policy_grants_with_replacement(&tx, Some(updated.clone()), None)?;
        let previous_revision = policy_revision(&tx)?;
        let revision = next_policy_revision(&previous_revision, &now, &updated.updated_by)?;
        let inactive_validation_grant = (updated.status != "active").then_some(updated.clone());
        finalize_policy_mutation(
            tx,
            previous_revision,
            revision,
            active_grants,
            inactive_validation_grant,
            validate_candidate,
            |tx, revision| {
                update_policy_grant_record(tx, &updated)?;
                update_policy_revision(tx, revision)?;
                Ok(updated.clone())
            },
        )
    }

    pub fn enable_policy_grant<F>(
        &self,
        request: ManagedPolicyGrantStatusRequest,
        validate_candidate: F,
    ) -> Result<ManagedPolicyMutationResult, ManagedStoreError>
    where
        F: FnMut(
            &[ManagedPolicyGrantRecord],
            &ManagedPolicyRevision,
            &ManagedPolicySubjectCatalog,
            &ManagedResourceCatalog,
        ) -> Result<(), ManagedStoreError>,
    {
        self.set_policy_grant_status(
            request,
            "active",
            &PolicyWriteScope::Global,
            validate_candidate,
        )
    }

    pub fn enable_policy_grant_authorized<F>(
        &self,
        request: ManagedPolicyGrantStatusRequest,
        scope: &PolicyWriteScope,
        validate_candidate: F,
    ) -> Result<ManagedPolicyMutationResult, ManagedStoreError>
    where
        F: FnMut(
            &[ManagedPolicyGrantRecord],
            &ManagedPolicyRevision,
            &ManagedPolicySubjectCatalog,
            &ManagedResourceCatalog,
        ) -> Result<(), ManagedStoreError>,
    {
        self.set_policy_grant_status(request, "active", scope, validate_candidate)
    }

    pub fn disable_policy_grant<F>(
        &self,
        request: ManagedPolicyGrantStatusRequest,
        validate_candidate: F,
    ) -> Result<ManagedPolicyMutationResult, ManagedStoreError>
    where
        F: FnMut(
            &[ManagedPolicyGrantRecord],
            &ManagedPolicyRevision,
            &ManagedPolicySubjectCatalog,
            &ManagedResourceCatalog,
        ) -> Result<(), ManagedStoreError>,
    {
        self.set_policy_grant_status(
            request,
            "disabled",
            &PolicyWriteScope::Global,
            validate_candidate,
        )
    }

    pub fn disable_policy_grant_authorized<F>(
        &self,
        request: ManagedPolicyGrantStatusRequest,
        scope: &PolicyWriteScope,
        validate_candidate: F,
    ) -> Result<ManagedPolicyMutationResult, ManagedStoreError>
    where
        F: FnMut(
            &[ManagedPolicyGrantRecord],
            &ManagedPolicyRevision,
            &ManagedPolicySubjectCatalog,
            &ManagedResourceCatalog,
        ) -> Result<(), ManagedStoreError>,
    {
        self.set_policy_grant_status(request, "disabled", scope, validate_candidate)
    }

    pub fn delete_policy_grant<F>(
        &self,
        request: ManagedPolicyGrantStatusRequest,
        validate_candidate: F,
    ) -> Result<ManagedPolicyMutationResult, ManagedStoreError>
    where
        F: FnMut(
            &[ManagedPolicyGrantRecord],
            &ManagedPolicyRevision,
            &ManagedPolicySubjectCatalog,
            &ManagedResourceCatalog,
        ) -> Result<(), ManagedStoreError>,
    {
        self.set_policy_grant_status(
            request,
            "deleted",
            &PolicyWriteScope::Global,
            validate_candidate,
        )
    }

    pub fn delete_policy_grant_authorized<F>(
        &self,
        request: ManagedPolicyGrantStatusRequest,
        scope: &PolicyWriteScope,
        validate_candidate: F,
    ) -> Result<ManagedPolicyMutationResult, ManagedStoreError>
    where
        F: FnMut(
            &[ManagedPolicyGrantRecord],
            &ManagedPolicyRevision,
            &ManagedPolicySubjectCatalog,
            &ManagedResourceCatalog,
        ) -> Result<(), ManagedStoreError>,
    {
        self.set_policy_grant_status(request, "deleted", scope, validate_candidate)
    }

    fn set_policy_grant_status<F>(
        &self,
        request: ManagedPolicyGrantStatusRequest,
        status: &str,
        scope: &PolicyWriteScope,
        validate_candidate: F,
    ) -> Result<ManagedPolicyMutationResult, ManagedStoreError>
    where
        F: FnMut(
            &[ManagedPolicyGrantRecord],
            &ManagedPolicyRevision,
            &ManagedPolicySubjectCatalog,
            &ManagedResourceCatalog,
        ) -> Result<(), ManagedStoreError>,
    {
        validate_policy_grant_status_request(&request)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        let current = policy_grant_by_id(&tx, &request.grant_id)?;
        ensure_policy_management_scope(scope, &current.service)?;
        ensure_policy_grant_version(&current, request.expected_version)?;
        if current.status == "deleted" {
            return Err(input_invalid("deleted policy grants cannot change status"));
        }
        let now = normalized_now_string();
        let mut updated = current.clone();
        updated.status = status.to_string();
        updated.version += 1;
        updated.updated_at = now.clone();
        updated.updated_by = request.updated_by;
        match status {
            "active" => {
                updated.disabled_at = None;
                updated.deleted_at = None;
            }
            "disabled" => {
                updated.disabled_at = Some(now.clone());
                updated.deleted_at = None;
            }
            "deleted" => {
                updated.resources = ResourceSelection::default();
                updated.deleted_at = Some(now.clone());
            }
            _ => {}
        }
        let active_grants = active_policy_grants_with_replacement(
            &tx,
            (status == "active").then_some(updated.clone()),
            Some(&updated.grant_id),
        )?;
        let previous_revision = policy_revision(&tx)?;
        let revision = next_policy_revision(&previous_revision, &now, &updated.updated_by)?;
        finalize_policy_mutation(
            tx,
            previous_revision,
            revision,
            active_grants,
            None,
            validate_candidate,
            |tx, revision| {
                update_policy_grant_record(tx, &updated)?;
                update_policy_revision(tx, revision)?;
                Ok(updated.clone())
            },
        )
    }

    pub fn principal_count(&self) -> Result<u64, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        count_table(&conn, "principals")
    }

    pub fn active_admin_principal_count(&self) -> Result<u64, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        active_admin_principal_count(&conn)
    }

    pub fn bootstrap_initial_admin(
        &self,
        hasher: &LocalPasswordHasher,
        request: InitialAdminBootstrapRequest,
    ) -> Result<PrincipalRecord, ManagedStoreError> {
        validate_initial_admin_bootstrap_request(&request)?;
        if request.password.len() < request.min_password_length {
            return Err(input_invalid(format!(
                "password must be at least {} bytes",
                request.min_password_length
            )));
        }
        let _work = self.try_acquire_admin_password_work()?;
        let password_hash_phc = hasher.hash_password(&request.password)?;
        let login_method_id = Uuid::new_v4().to_string();
        let now = normalized_now_string();
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let principal_count: i64 = tx
            .query_row("SELECT COUNT(1) FROM principals", [], |row| row.get(0))
            .map_err(sql_unavailable)?;
        if principal_count != 0 {
            return Err(input_invalid(
                "initial admin bootstrap requires an empty principal table",
            ));
        }
        tx.execute(
            "INSERT INTO principals
             (principal_id, kind, display_name, email, external_subject, status,
              created_at, updated_at, disabled_at, created_by, role, self_service_enabled)
             VALUES (?1, 'user', ?1, NULL, NULL, 'active', ?2, ?2, NULL, 'system:initial_admin', 'admin', 1)",
            params![request.principal_id, now],
        )
        .map_err(sql_unavailable)?;
        tx.execute(
            "INSERT INTO principal_login_methods
             (login_method_id, principal_id, method, external_provider, external_subject,
              status, password_hash_phc, password_set_at, must_change_password, created_at,
              updated_at, created_by, updated_by)
             VALUES (?1, ?2, 'local_password', NULL, NULL, 'active', ?3, ?4, 1, ?4, ?4,
                     'system:initial_admin', 'system:initial_admin')",
            params![
                login_method_id,
                request.principal_id,
                password_hash_phc,
                now
            ],
        )
        .map_err(sql_unavailable)?;
        self.initialize_identity_token(&tx, &request.principal_id, "user")?;
        let principal = principal_by_id(&tx, &request.principal_id)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(principal)
    }

    pub fn create_or_update_principal(
        &self,
        request: PrincipalWriteRequest,
    ) -> Result<PrincipalRecord, ManagedStoreError> {
        validate_principal_write_request(&request)?;
        let self_service_enabled = request
            .self_service_enabled
            .unwrap_or(request.kind != "service_account");
        validate_principal_access(&request.kind, request.role, self_service_enabled)?;
        let display_name = normalized_optional_profile_value(request.display_name.as_deref());
        let email = normalized_optional_profile_value(request.email.as_deref());
        let now = now_string();
        let mut connection = self.connection.lock().unwrap();
        let conn = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let existing: Option<String> = conn
            .query_row(
                "SELECT principal_id FROM principals WHERE principal_id = ?1",
                params![request.principal_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_unavailable)?;
        if existing.is_some() {
            let current = principal_by_id(&conn, &request.principal_id)?;
            if current.kind != request.kind && (current.kind == "user" || request.kind == "user") {
                return Err(input_invalid("human principal kind cannot be changed"));
            }
            validate_principal_access(&request.kind, current.role, current.self_service_enabled)?;
            if current.kind != request.kind
                && principal_is_active_admin(&conn, &request.principal_id)?
                && active_admin_principal_count(&conn)? <= 1
            {
                return Err(input_invalid(
                    "last active admin cannot change principal kind",
                ));
            }
            conn.execute(
                "UPDATE principals
                 SET kind = ?2, display_name = ?3, email = ?4, external_subject = ?5,
                     status = 'active', updated_at = ?6, disabled_at = NULL
                 WHERE principal_id = ?1",
                params![
                    request.principal_id,
                    request.kind,
                    display_name,
                    email,
                    request.external_subject,
                    now
                ],
            )
            .map_err(sql_unavailable)?;
        } else {
            conn.execute(
                "INSERT INTO principals
                 (principal_id, kind, display_name, email, external_subject, status,
                  created_at, updated_at, disabled_at, created_by, role, self_service_enabled)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'active', ?6, ?6, NULL, ?7, ?8, ?9)",
                params![
                    request.principal_id,
                    request.kind,
                    display_name,
                    email,
                    request.external_subject,
                    now,
                    request.created_by,
                    request.role.as_str(),
                    self_service_enabled
                ],
            )
            .map_err(sql_unavailable)?;
            self.initialize_identity_token(&conn, &request.principal_id, &request.kind)?;
        }
        let principal = principal_by_id(&conn, &request.principal_id)?;
        conn.commit().map_err(sql_unavailable)?;
        Ok(principal)
    }

    pub fn create_principal(
        &self,
        request: PrincipalWriteRequest,
    ) -> Result<PrincipalRecord, ManagedStoreError> {
        validate_principal_write_request(&request)?;
        let self_service_enabled = request
            .self_service_enabled
            .unwrap_or(request.kind != "service_account");
        validate_principal_access(&request.kind, request.role, self_service_enabled)?;
        let display_name = normalized_optional_profile_value(request.display_name.as_deref());
        let email = normalized_optional_profile_value(request.email.as_deref());
        let now = now_string();
        let mut connection = self.connection.lock().unwrap();
        let conn = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let exists: Option<String> = conn
            .query_row(
                "SELECT principal_id FROM principals WHERE principal_id = ?1",
                params![request.principal_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_unavailable)?;
        if exists.is_some() {
            return Err(ManagedStoreError::PrincipalAlreadyExists);
        }
        conn.execute(
            "INSERT INTO principals
             (principal_id, kind, display_name, email, external_subject, status,
              created_at, updated_at, disabled_at, created_by, role, self_service_enabled)
             VALUES (?1, ?2, ?3, ?4, ?5, 'active', ?6, ?6, NULL, ?7, ?8, ?9)",
            params![
                request.principal_id,
                request.kind,
                display_name,
                email,
                request.external_subject,
                now,
                request.created_by,
                request.role.as_str(),
                self_service_enabled
            ],
        )
        .map_err(sql_unavailable)?;
        self.initialize_identity_token(&conn, &request.principal_id, &request.kind)?;
        let principal = principal_by_id(&conn, &request.principal_id)?;
        conn.commit().map_err(sql_unavailable)?;
        Ok(principal)
    }

    pub fn set_principal_enabled(
        &self,
        principal_id: &str,
        enabled: bool,
    ) -> Result<PrincipalRecord, ManagedStoreError> {
        validate_principal_id(principal_id)?;
        let now = now_string();
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        principal_by_id(&tx, principal_id)?;
        if !enabled
            && principal_is_active_admin(&tx, principal_id)?
            && active_admin_principal_count(&tx)? <= 1
        {
            return Err(input_invalid("last active admin cannot be disabled"));
        }
        let changed = if enabled {
            tx.execute(
                "UPDATE principals
                 SET status = 'active', updated_at = ?2, disabled_at = NULL
                 WHERE principal_id = ?1",
                params![principal_id, now],
            )
        } else {
            tx.execute(
                "UPDATE principals
                 SET status = 'disabled', updated_at = ?2, disabled_at = ?2
                 WHERE principal_id = ?1",
                params![principal_id, now],
            )
        }
        .map_err(sql_unavailable)?;
        if changed == 0 {
            return Err(ManagedStoreError::PrincipalNotFound);
        }
        // Disablement ends the owner's OAuth connections and keeps their
        // families for remote revocation in this transaction.
        let kept = if enabled {
            0
        } else {
            oauth_revocation::end_owner_slots(
                &tx,
                self.oauth_revocation_capture().as_ref(),
                principal_id,
            )?
        };
        let principal = principal_by_id(&tx, principal_id)?;
        tx.commit().map_err(sql_unavailable)?;
        if kept > 0 {
            crate::oauth::revocation::wake();
        }
        Ok(principal)
    }

    pub fn patch_principal(
        &self,
        request: PrincipalPatchRequest,
    ) -> Result<PrincipalRecord, ManagedStoreError> {
        validate_principal_patch_request(&request)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        principal_by_id(&tx, &request.principal_id)?;
        if request.status.as_deref() == Some("disabled")
            && principal_is_active_admin(&tx, &request.principal_id)?
            && active_admin_principal_count(&tx)? <= 1
        {
            return Err(input_invalid("last active admin cannot be disabled"));
        }
        if let Some(display_name) = &request.display_name {
            let display_name = display_name
                .as_deref()
                .map(|value| value.trim().to_string());
            tx.execute(
                "UPDATE principals SET display_name = ?2, updated_at = ?3 WHERE principal_id = ?1",
                params![request.principal_id, display_name, now_string()],
            )
            .map_err(sql_unavailable)?;
        }
        if let Some(email) = &request.email {
            let email = email.as_deref().map(|value| value.trim().to_string());
            tx.execute(
                "UPDATE principals SET email = ?2, updated_at = ?3 WHERE principal_id = ?1",
                params![request.principal_id, email, now_string()],
            )
            .map_err(sql_unavailable)?;
        }
        if let Some(status) = &request.status {
            if status == "active" {
                tx.execute(
                    "UPDATE principals
                     SET status = 'active', updated_at = ?2, disabled_at = NULL
                     WHERE principal_id = ?1",
                    params![request.principal_id, now_string()],
                )
            } else {
                tx.execute(
                    "UPDATE principals
                     SET status = 'disabled', updated_at = ?2, disabled_at = ?2
                     WHERE principal_id = ?1",
                    params![request.principal_id, now_string()],
                )
            }
            .map_err(sql_unavailable)?;
        }
        // Disablement ends the owner's OAuth connections and keeps their
        // families for remote revocation in this transaction.
        let kept = if request.status.as_deref() == Some("disabled") {
            oauth_revocation::end_owner_slots(
                &tx,
                self.oauth_revocation_capture().as_ref(),
                &request.principal_id,
            )?
        } else {
            0
        };
        let principal = principal_by_id(&tx, &request.principal_id)?;
        tx.commit().map_err(sql_unavailable)?;
        if kept > 0 {
            crate::oauth::revocation::wake();
        }
        Ok(principal)
    }

    pub fn principal(&self, principal_id: &str) -> Result<PrincipalRecord, ManagedStoreError> {
        validate_principal_id(principal_id)?;
        let conn = self.connection.lock().unwrap();
        principal_by_id(&conn, principal_id)
    }

    pub fn active_principal(
        &self,
        principal_id: &str,
    ) -> Result<PrincipalRecord, ManagedStoreError> {
        let principal = self.principal(principal_id)?;
        if principal.status == "disabled" {
            return Err(ManagedStoreError::PrincipalDisabled);
        }
        Ok(principal)
    }

    pub fn list_principals(&self) -> Result<Vec<PrincipalRecord>, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        let mut statement = conn
            .prepare(
                "SELECT principal_id, kind, display_name, email, external_subject, status,
                        created_at, updated_at, disabled_at, created_by, role, self_service_enabled
                 FROM principals
                 ORDER BY principal_id",
            )
            .map_err(sql_unavailable)?;
        let rows = statement
            .query_map([], principal_from_row)
            .map_err(sql_unavailable)?;
        let mut principals = collect_rows(rows)?;
        let mut sign_in_methods = sign_in_methods_by_principal(&conn, None)?;
        for principal in &mut principals {
            principal.sign_in_methods = sign_in_methods
                .remove(&principal.principal_id)
                .unwrap_or_default();
            principal.groups = principal_groups(&conn, &principal.principal_id)?;
        }
        Ok(principals)
    }

    pub fn create_group(
        &self,
        request: GroupWriteRequest,
    ) -> Result<GroupRecord, ManagedStoreError> {
        validate_group_write_request(&request)?;
        let group_id = request.group_id.clone();
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        if group_exists(&tx, &group_id)? {
            return Err(ManagedStoreError::VersionConflict);
        }
        let now = normalized_now_string();
        tx.execute(
            "INSERT INTO groups
             (group_id, display_name, description, status, created_at, created_by, updated_at,
              updated_by, disabled_at)
             VALUES (?1, ?2, ?3, 'active', ?4, ?5, ?4, ?5, NULL)",
            params![
                group_id,
                normalize_optional_text(request.display_name),
                normalize_optional_text(request.description),
                now,
                request.created_by
            ],
        )
        .map_err(sql_unavailable)?;
        let group = group_by_id(&tx, &group_id)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(group)
    }

    pub fn patch_group(
        &self,
        request: GroupPatchRequest,
    ) -> Result<GroupRecord, ManagedStoreError> {
        validate_group_patch_request(&request)?;
        let group_id = request.group_id.clone();
        let updated_by = request.updated_by.clone();
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        group_by_id(&tx, &group_id)?;
        let now = normalized_now_string();
        if let Some(display_name) = request.display_name {
            tx.execute(
                "UPDATE groups
                 SET display_name = ?2, updated_at = ?3, updated_by = ?4
                 WHERE group_id = ?1",
                params![
                    group_id,
                    normalize_optional_text(display_name),
                    now,
                    updated_by
                ],
            )
            .map_err(sql_unavailable)?;
        }
        if let Some(description) = request.description {
            tx.execute(
                "UPDATE groups
                 SET description = ?2, updated_at = ?3, updated_by = ?4
                 WHERE group_id = ?1",
                params![
                    group_id,
                    normalize_optional_text(description),
                    now,
                    updated_by
                ],
            )
            .map_err(sql_unavailable)?;
        }
        if let Some(status) = request.status {
            let disabled_at = (status == "disabled").then_some(now.clone());
            tx.execute(
                "UPDATE groups
                 SET status = ?2, disabled_at = ?3, updated_at = ?4, updated_by = ?5
                 WHERE group_id = ?1",
                params![group_id, status, disabled_at, now, updated_by],
            )
            .map_err(sql_unavailable)?;
        }
        let group = group_by_id(&tx, &group_id)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(group)
    }

    pub fn group(&self, group_id: &str) -> Result<GroupRecord, ManagedStoreError> {
        validate_group_name(group_id)?;
        let conn = self.connection.lock().unwrap();
        group_by_id(&conn, group_id)
    }

    pub fn list_groups(&self) -> Result<Vec<GroupRecord>, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        let resolved_at = normalized_now_string();
        let mut statement = conn
            .prepare(
                "WITH effective(principal_id, group_id) AS (
                   SELECT principal_id, group_id FROM principal_groups
                   UNION
                   SELECT lm.principal_id, b.group_id
                   FROM principal_login_methods lm
                   JOIN oidc_membership_refresh_state rs ON rs.login_method_id = lm.login_method_id
                   JOIN external_principal_groups epg ON epg.login_method_id = lm.login_method_id
                   JOIN external_group_bindings b ON b.binding_id = epg.binding_id
                   JOIN oidc_provider_state ps ON ps.provider_id = 'microsoft'
                   WHERE lm.method = 'oidc' AND lm.external_provider = 'microsoft'
                     AND lm.status = 'active' AND ps.enabled = 1 AND b.status = 'active'
                     AND rs.valid_until > ?1 AND epg.valid_until > ?1
                 )
                 SELECT g.group_id, g.display_name, g.description, g.status, g.created_at,
                        g.created_by, g.updated_at, g.updated_by, g.disabled_at,
                        COUNT(e.principal_id) AS member_count
                 FROM groups g
                 LEFT JOIN effective e ON e.group_id = g.group_id
                 GROUP BY g.group_id, g.display_name, g.description, g.status, g.created_at,
                          g.created_by, g.updated_at, g.updated_by, g.disabled_at
                 ORDER BY g.group_id",
            )
            .map_err(sql_unavailable)?;
        let rows = statement
            .query_map(params![resolved_at], group_from_row)
            .map_err(sql_unavailable)?;
        collect_rows(rows)
    }

    pub fn group_members(
        &self,
        group_id: &str,
    ) -> Result<Vec<GroupMemberRecord>, ManagedStoreError> {
        validate_group_name(group_id)?;
        let conn = self.connection.lock().unwrap();
        group_by_id(&conn, group_id)?;
        group_members(&conn, group_id)
    }

    pub fn add_group(
        &self,
        principal_id: &str,
        group: &str,
        actor: &str,
    ) -> Result<(), ManagedStoreError> {
        validate_principal_id(principal_id)?;
        validate_group_name(group)?;
        validate_actor(actor)?;
        let conn = self.connection.lock().unwrap();
        principal_by_id_for_membership(&conn, principal_id)?;
        group_by_id(&conn, group)?;
        conn.execute(
            "INSERT OR IGNORE INTO principal_groups
             (principal_id, group_id, created_at, created_by)
             VALUES (?1, ?2, ?3, ?4)",
            params![principal_id, group, now_string(), actor],
        )
        .map_err(sql_unavailable)?;
        Ok(())
    }

    pub fn remove_group(&self, principal_id: &str, group: &str) -> Result<(), ManagedStoreError> {
        self.remove_local_group_with_effect(principal_id, group)?;
        Ok(())
    }

    pub fn remove_local_group_with_effect(
        &self,
        principal_id: &str,
        group: &str,
    ) -> Result<LocalGroupRemovalResult, ManagedStoreError> {
        validate_principal_id(principal_id)?;
        validate_group_name(group)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        principal_by_id_for_membership(&tx, principal_id)?;
        group_by_id(&tx, group)?;
        let removed = tx
            .execute(
                "DELETE FROM principal_groups WHERE principal_id = ?1 AND group_id = ?2",
                params![principal_id, group],
            )
            .map_err(sql_unavailable)?;
        let membership = effective_membership_at_conn(&tx, principal_id, &normalized_now_string())?;
        let still_effective = membership.groups.iter().any(|candidate| candidate == group);
        tx.commit().map_err(sql_unavailable)?;
        Ok(LocalGroupRemovalResult {
            removed: removed != 0,
            still_effective,
        })
    }

    pub fn groups(&self, principal_id: &str) -> Result<Vec<String>, ManagedStoreError> {
        validate_principal_id(principal_id)?;
        let conn = self.connection.lock().unwrap();
        principal_groups(&conn, principal_id)
    }

    pub fn policy_groups(&self, principal_id: &str) -> Result<Vec<String>, ManagedStoreError> {
        validate_principal_id(principal_id)?;
        let conn = self.connection.lock().unwrap();
        principal_policy_groups(&conn, principal_id)
    }

    pub fn effective_membership_at(
        &self,
        principal_id: &str,
        resolved_at: &str,
    ) -> Result<EffectiveMembershipRecord, ManagedStoreError> {
        validate_principal_id(principal_id)?;
        let resolved_at = normalize_optional_timestamp(Some(resolved_at), "resolvedAt")?
            .expect("present timestamp normalizes to a value");
        let conn = self.connection.lock().unwrap();
        principal_by_id_without_groups(&conn, principal_id)?;
        effective_membership_at_conn(&conn, principal_id, &resolved_at)
    }

    pub fn issue_broker_token(
        &self,
        hasher: &BrokerTokenHasher,
        request: BrokerTokenIssueRequest,
    ) -> Result<IssuedBrokerToken, ManagedStoreError> {
        self.issue_broker_token_inner(hasher, request, false, None)
    }

    fn issue_broker_token_inner(
        &self,
        hasher: &BrokerTokenHasher,
        request: BrokerTokenIssueRequest,
        personal: bool,
        catalog: Option<&ManagedResourceCatalog>,
    ) -> Result<IssuedBrokerToken, ManagedStoreError> {
        validate_broker_token_issue_request(&request)?;
        let expires_at = normalize_optional_timestamp(request.expires_at.as_deref(), "expiresAt")?;
        let raw_token = generate_broker_token(&request.token_class);
        let token_hash = hasher.hash(&raw_token)?;
        let now = now_string();
        let token_id = Uuid::new_v4().to_string();
        let scopes_json = serde_json::to_string(&request.scopes)
            .map_err(|_| input_invalid("token scopes must be JSON serializable"))?;
        let mut connection = self.connection.lock().unwrap();
        let conn = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        if request.token_class == BrokerTokenClass::AgentInvoke {
            validate_token_resource_references(&conn, &request.scopes, catalog)?;
        }
        let principal = principal_by_id(&conn, &request.principal_id)?;
        if principal.status == "disabled" {
            return Err(ManagedStoreError::PrincipalDisabled);
        }
        if principal.kind == "service_account"
            && request.token_class != BrokerTokenClass::AgentInvoke
        {
            return Err(input_invalid(
                "service accounts may only receive agent_invoke tokens",
            ));
        }
        if personal {
            require_self_service(&conn, &request.principal_id)?;
        }
        if request.token_class == BrokerTokenClass::Admin
            && (principal.kind != "user" || !principal.role.can_read_admin())
        {
            return Err(input_invalid(
                "admin tokens require an Administrator or Auditor user",
            ));
        }
        conn.execute(
            "INSERT INTO broker_tokens
             (token_id, token_hash, principal_id, name, token_class, scopes_json, created_at,
              expires_at, revoked_at, revoked_by, last_used_at, created_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, NULL, NULL, ?9)",
            params![
                token_id,
                token_hash,
                request.principal_id,
                request.name,
                request.token_class.as_str(),
                scopes_json,
                now,
                expires_at,
                request.created_by
            ],
        )
        .map_err(sql_unavailable)?;
        let record = broker_token_by_id(&conn, &token_id)?;
        conn.commit().map_err(sql_unavailable)?;
        Ok(IssuedBrokerToken {
            token: raw_token,
            record,
        })
    }

    /// The kind of the managed principal a configured static principal's ID
    /// names, which selects its credential connections' methods. `None` when
    /// no managed principal has the ID, or it is disabled, so a static
    /// principal without an active managed row selects no personal method.
    pub fn static_principal_kind(
        &self,
        principal_id: &str,
    ) -> Result<Option<crate::PrincipalKind>, ManagedStoreError> {
        if validate_principal_id(principal_id).is_err() {
            return Ok(None);
        }
        let conn = self.connection.lock().unwrap();
        let row: Option<(String, String)> = conn
            .query_row(
                "SELECT kind, status FROM principals WHERE principal_id = ?1",
                params![principal_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sql_unavailable)?;
        Ok(row
            .filter(|(_, status)| status == "active")
            .and_then(|(kind, _)| crate::PrincipalKind::from_stored(&kind)))
    }

    pub fn resolve_broker_token(
        &self,
        hasher: &BrokerTokenHasher,
        raw_token: &str,
    ) -> Result<BrokerTokenIdentity, ManagedStoreError> {
        let token_hash = hasher.hash(raw_token)?;
        let conn = self.connection.lock().unwrap();
        let Some(record) = broker_token_by_hash(&conn, &token_hash)? else {
            return Err(ManagedStoreError::BrokerTokenNotFound);
        };
        if !constant_time_eq(record.token_hash.as_bytes(), token_hash.as_bytes()) {
            return Err(ManagedStoreError::BrokerTokenNotFound);
        }
        if record.revoked_at.is_some() {
            return Err(ManagedStoreError::BrokerTokenRevoked);
        }
        if timestamp_is_past(record.expires_at.as_deref()) {
            return Err(ManagedStoreError::BrokerTokenExpired);
        }
        if record.paused_at.is_some() {
            return Err(ManagedStoreError::BrokerTokenPaused);
        }
        let principal = principal_by_id(&conn, &record.principal_id)?;
        if principal.status == "disabled" {
            return Err(ManagedStoreError::PrincipalDisabled);
        }
        if principal.kind == "service_account"
            && record.token_class != BrokerTokenClass::AgentInvoke
        {
            return Err(ManagedStoreError::BrokerTokenClassDenied);
        }
        if record.token_class == BrokerTokenClass::Admin
            && (principal.kind != "user" || !principal.role.can_read_admin())
        {
            return Err(ManagedStoreError::BrokerTokenClassDenied);
        }
        conn.execute(
            "UPDATE broker_tokens SET last_used_at = ?2 WHERE token_id = ?1",
            params![record.token_id, now_string()],
        )
        .map_err(sql_unavailable)?;
        Ok(BrokerTokenIdentity {
            principal_id: record.principal_id.clone(),
            principal_kind: principal.principal_kind(),
            policy_groups: principal_policy_groups(&conn, &record.principal_id)?,
            groups: principal.groups,
            role: principal.role,
            self_service_enabled: principal.self_service_enabled,
            token_class: record.token_class,
            token_id: record.token_id,
            scopes: record.scopes,
            expires_at: record.expires_at,
        })
    }

    pub fn list_broker_tokens(&self) -> Result<Vec<BrokerTokenRecord>, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        let mut statement = conn
            .prepare(
                "SELECT token_id, token_hash, principal_id, name, token_class, scopes_json,
                        created_at, expires_at, revoked_at, revoked_by, paused_at, paused_by,
                        last_used_at, created_by
                 FROM broker_tokens
                 ORDER BY created_at DESC, token_id",
            )
            .map_err(sql_unavailable)?;
        let rows = statement
            .query_map([], broker_token_from_row)
            .map_err(sql_unavailable)?;
        collect_rows(rows)
    }

    pub fn list_broker_tokens_for_principal(
        &self,
        principal_id: &str,
    ) -> Result<Vec<BrokerTokenRecord>, ManagedStoreError> {
        validate_principal_id(principal_id)?;
        let conn = self.connection.lock().unwrap();
        principal_by_id(&conn, principal_id)?;
        let mut statement = conn
            .prepare(
                "SELECT token_id, token_hash, principal_id, name, token_class, scopes_json,
                        created_at, expires_at, revoked_at, revoked_by, paused_at, paused_by,
                        last_used_at, created_by
                 FROM broker_tokens
                 WHERE principal_id = ?1
                 ORDER BY created_at DESC, token_id",
            )
            .map_err(sql_unavailable)?;
        let rows = statement
            .query_map(params![principal_id], broker_token_from_row)
            .map_err(sql_unavailable)?;
        collect_rows(rows)
    }

    pub fn broker_token(&self, token_id: &str) -> Result<BrokerTokenRecord, ManagedStoreError> {
        validate_uuid_id(token_id, "tokenId")?;
        let conn = self.connection.lock().unwrap();
        broker_token_by_id(&conn, token_id)
    }

    pub fn broker_token_is_browser_session(
        &self,
        token_id: &str,
    ) -> Result<bool, ManagedStoreError> {
        validate_uuid_id(token_id, "tokenId")?;
        let conn = self.connection.lock().unwrap();
        browser_session_token_exists(&conn, token_id)
    }

    pub fn revoke_broker_token(
        &self,
        token_id: &str,
        actor: &str,
    ) -> Result<BrokerTokenRecord, ManagedStoreError> {
        validate_uuid_id(token_id, "tokenId")?;
        validate_actor(actor)?;
        let now = now_string();
        let conn = self.connection.lock().unwrap();
        let changed = conn
            .execute(
                "UPDATE broker_tokens
                 SET revoked_at = COALESCE(revoked_at, ?2), revoked_by = COALESCE(revoked_by, ?3)
                 WHERE token_id = ?1",
                params![token_id, now, actor],
            )
            .map_err(sql_unavailable)?;
        if changed == 0 {
            return Err(ManagedStoreError::BrokerTokenNotFound);
        }
        broker_token_by_id(&conn, token_id)
    }

    pub fn pause_broker_token(
        &self,
        token_id: &str,
        actor: &str,
    ) -> Result<BrokerTokenRecord, ManagedStoreError> {
        self.transition_agent_token_pause(
            token_id,
            None,
            actor,
            TokenPauseTransition::Pause,
            None,
            AgentTokenManagementPurpose::Administrative,
        )
    }

    pub fn resume_broker_token(
        &self,
        token_id: &str,
        actor: &str,
    ) -> Result<BrokerTokenRecord, ManagedStoreError> {
        self.resume_broker_token_with_catalog(token_id, actor, None)
    }

    pub fn list_login_methods(
        &self,
        principal_id: &str,
    ) -> Result<Vec<LoginMethodRecord>, ManagedStoreError> {
        validate_principal_id(principal_id)?;
        self.principal(principal_id)?;
        let conn = self.connection.lock().unwrap();
        let mut statement = conn
            .prepare(
                "SELECT login_method_id, principal_id, method, external_provider,
                        external_subject, status, password_set_at, must_change_password,
                        created_at, updated_at, created_by, updated_by
                 FROM principal_login_methods
                 WHERE principal_id = ?1
                 ORDER BY method, created_at",
            )
            .map_err(sql_unavailable)?;
        let rows = statement
            .query_map(params![principal_id], login_method_from_row)
            .map_err(sql_unavailable)?;
        let mut methods = collect_rows(rows)?;
        for method in &mut methods {
            local_password_failures::attach_lockout(&conn, method)?;
        }
        Ok(methods)
    }

    pub fn oidc_provider_state(
        &self,
    ) -> Result<Option<OidcProviderStateRecord>, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        oidc_provider_state(&conn)
    }

    pub fn reconcile_oidc_provider_state(
        &self,
        request: OidcProviderStateReconcileRequest,
    ) -> Result<OidcProviderStateRecord, ManagedStoreError> {
        validate_actor(&request.actor)?;
        validate_canonical_uuid(&request.tenant_id, "tenantId")?;
        validate_canonical_uuid(&request.client_id, "clientId")?;
        if request.config_fingerprint.is_empty() || request.config_fingerprint.len() > 256 {
            return Err(input_invalid("OIDC config fingerprint is invalid"));
        }
        if !(900..=86_400).contains(&request.external_membership_ttl_seconds) {
            return Err(input_invalid("OIDC external membership TTL is invalid"));
        }
        let now = normalized_now_string();
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let existing = oidc_provider_state(&tx)?;
        if let Some(state) = existing.as_ref()
            && state.tenant_id != request.tenant_id
        {
            let durable_oidc_objects: i64 = tx
                .query_row(
                    "SELECT
                       (SELECT COUNT(1) FROM principal_login_methods WHERE method = 'oidc') +
                       (SELECT COUNT(1) FROM external_group_bindings)",
                    [],
                    |row| row.get(0),
                )
                .map_err(sql_unavailable)?;
            if durable_oidc_objects != 0 {
                return Err(ManagedStoreError::OidcLoginMethodConflict);
            }
        }
        let generation = match existing.as_ref() {
            Some(state)
                if state.config_fingerprint == request.config_fingerprint
                    && state.enabled == request.enabled
                    && state.tenant_id == request.tenant_id
                    && state.client_id == request.client_id =>
            {
                state.config_generation
            }
            Some(state) => state
                .config_generation
                .checked_add(1)
                .ok_or_else(|| input_invalid("OIDC config generation is exhausted"))?,
            None => 1,
        };
        if let Some(state) = existing.as_ref()
            && request.external_membership_ttl_seconds < state.external_membership_ttl_seconds
        {
            clamp_oidc_membership_ttl_tx(&tx, request.external_membership_ttl_seconds, &now)?;
        }
        let client_changed = existing
            .as_ref()
            .is_some_and(|state| state.client_id != request.client_id);
        if !request.enabled || request.invalidate_existing_evidence || client_changed {
            expire_all_oidc_membership_tx(&tx, &request.actor, &now)?;
        }
        tx.execute(
            "INSERT INTO oidc_provider_state
             (provider_id, tenant_id, client_id, enabled, config_generation, config_fingerprint,
              external_membership_ttl_s, updated_at)
             VALUES ('microsoft', ?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(provider_id) DO UPDATE SET
               tenant_id = excluded.tenant_id,
               client_id = excluded.client_id,
               enabled = excluded.enabled,
               config_generation = excluded.config_generation,
               config_fingerprint = excluded.config_fingerprint,
               external_membership_ttl_s = excluded.external_membership_ttl_s,
               updated_at = excluded.updated_at",
            params![
                request.tenant_id,
                request.client_id,
                request.enabled,
                generation as i64,
                request.config_fingerprint,
                request.external_membership_ttl_seconds as i64,
                now
            ],
        )
        .map_err(sql_unavailable)?;
        let state = oidc_provider_state(&tx)?.ok_or(ManagedStoreError::OidcProviderUnavailable)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(state)
    }

    pub fn create_oidc_flow(
        &self,
        request: OidcFlowCreateRequest,
    ) -> Result<OidcFlowRecord, ManagedStoreError> {
        validate_oidc_flow_create_request(&request)?;
        let expires_at = normalize_optional_timestamp(Some(&request.expires_at), "expiresAt")?
            .expect("present timestamp normalizes to a value");
        let now = normalized_now_string();
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        require_oidc_provider_generation(&tx, request.provider_generation)?;
        tx.execute(
            "DELETE FROM oidc_authorization_flows
             WHERE expires_at <= ?1",
            params![now],
        )
        .map_err(sql_unavailable)?;
        let pending: i64 = tx
            .query_row(
                "SELECT COUNT(1) FROM oidc_authorization_flows WHERE consumed_at IS NULL",
                [],
                |row| row.get(0),
            )
            .map_err(sql_unavailable)?;
        if pending as u64 >= request.max_pending_flows {
            tx.commit().map_err(sql_unavailable)?;
            return Err(ManagedStoreError::OidcFlowCapacity);
        }
        tx.execute(
            "INSERT INTO oidc_authorization_flows
             (state_hash, browser_binding_hash, provider_generation, encrypted_payload,
              encryption_nonce, return_path, created_at, expires_at, consumed_at, outcome_code)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, NULL)",
            params![
                request.state_hash,
                request.browser_binding_hash,
                request.provider_generation as i64,
                request.encrypted_payload,
                request.encryption_nonce,
                request.return_path,
                now,
                expires_at
            ],
        )
        .map_err(map_oidc_flow_insert_error)?;
        let sequence = tx.last_insert_rowid();
        let record = oidc_flow_by_sequence(&tx, sequence)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(record)
    }

    pub fn claim_oidc_flow(
        &self,
        request: OidcFlowClaimRequest,
    ) -> Result<OidcFlowRecord, ManagedStoreError> {
        if request.state_hash.len() != 32 || request.browser_binding_hash.len() != 32 {
            return Err(ManagedStoreError::OidcFlowInvalid);
        }
        let now = normalized_now_string();
        let conn = self.connection.lock().unwrap();
        let sequence: Option<i64> = conn
            .query_row(
                "UPDATE oidc_authorization_flows
                 SET consumed_at = ?4, outcome_code = ?5
                 WHERE state_hash = ?1 AND browser_binding_hash = ?2
                   AND provider_generation = ?3 AND consumed_at IS NULL AND expires_at > ?4
                   AND EXISTS (
                     SELECT 1 FROM oidc_provider_state ps
                     WHERE ps.provider_id = 'microsoft' AND ps.enabled = 1
                       AND ps.config_generation = ?3
                   )
                 RETURNING flow_sequence",
                params![
                    request.state_hash,
                    request.browser_binding_hash,
                    request.provider_generation as i64,
                    now,
                    request.outcome_code
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_unavailable)?;
        let Some(sequence) = sequence else {
            let expired: bool = conn
                .query_row(
                    "SELECT EXISTS (
                       SELECT 1 FROM oidc_authorization_flows
                       WHERE state_hash = ?1 AND browser_binding_hash = ?2
                         AND provider_generation = ?3 AND consumed_at IS NULL
                         AND expires_at <= ?4
                     )",
                    params![
                        request.state_hash,
                        request.browser_binding_hash,
                        request.provider_generation as i64,
                        now
                    ],
                    |row| row.get(0),
                )
                .map_err(sql_unavailable)?;
            return Err(if expired {
                ManagedStoreError::OidcFlowExpired
            } else {
                ManagedStoreError::OidcFlowInvalid
            });
        };
        oidc_flow_by_sequence(&conn, sequence)
    }

    pub fn create_external_group_binding(
        &self,
        request: ExternalGroupBindingCreateRequest,
    ) -> Result<ExternalGroupBindingRecord, ManagedStoreError> {
        validate_external_group_id(&request.external_group_id)?;
        validate_group_name(&request.group_id)?;
        validate_actor(&request.actor)?;
        let binding_id = Uuid::new_v4().to_string();
        let now = normalized_now_string();
        let conn = self.connection.lock().unwrap();
        group_by_id(&conn, &request.group_id)?;
        conn.execute(
            "INSERT INTO external_group_bindings
             (binding_id, external_group_id, group_id, status, created_at, created_by,
              updated_at, updated_by)
             VALUES (?1, ?2, ?3, 'active', ?4, ?5, ?4, ?5)",
            params![
                binding_id,
                request.external_group_id,
                request.group_id,
                now,
                request.actor
            ],
        )
        .map_err(map_external_binding_insert_error)?;
        external_group_binding_by_id(&conn, &binding_id)
    }

    pub fn list_external_group_bindings(
        &self,
        group_id: Option<&str>,
    ) -> Result<Vec<ExternalGroupBindingRecord>, ManagedStoreError> {
        if let Some(group_id) = group_id {
            validate_group_name(group_id)?;
        }
        let conn = self.connection.lock().unwrap();
        external_group_bindings(&conn, group_id)
    }

    pub fn external_group_binding(
        &self,
        binding_id: &str,
    ) -> Result<ExternalGroupBindingRecord, ManagedStoreError> {
        validate_uuid_id(binding_id, "bindingId")?;
        let conn = self.connection.lock().unwrap();
        external_group_binding_by_id(&conn, binding_id)
    }

    pub fn set_external_group_binding_enabled(
        &self,
        binding_id: &str,
        enabled: bool,
        actor: &str,
    ) -> Result<ExternalGroupBindingRecord, ManagedStoreError> {
        validate_uuid_id(binding_id, "bindingId")?;
        validate_actor(actor)?;
        let now = normalized_now_string();
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        external_group_binding_by_id(&tx, binding_id)?;
        if !enabled {
            tx.execute(
                "DELETE FROM external_principal_groups WHERE binding_id = ?1",
                params![binding_id],
            )
            .map_err(sql_unavailable)?;
        }
        tx.execute(
            "UPDATE external_group_bindings SET status = ?2, updated_at = ?3, updated_by = ?4
             WHERE binding_id = ?1",
            params![
                binding_id,
                if enabled { "active" } else { "disabled" },
                now,
                actor
            ],
        )
        .map_err(sql_unavailable)?;
        let record = external_group_binding_by_id(&tx, binding_id)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(record)
    }

    pub fn delete_external_group_binding(&self, binding_id: &str) -> Result<(), ManagedStoreError> {
        validate_uuid_id(binding_id, "bindingId")?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let binding = external_group_binding_by_id(&tx, binding_id)?;
        if binding.status != "disabled" {
            return Err(ManagedStoreError::ExternalGroupBindingConflict);
        }
        tx.execute(
            "DELETE FROM external_principal_groups WHERE binding_id = ?1",
            params![binding_id],
        )
        .map_err(sql_unavailable)?;
        tx.execute(
            "DELETE FROM external_group_bindings WHERE binding_id = ?1",
            params![binding_id],
        )
        .map_err(sql_unavailable)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(())
    }

    pub fn link_oidc_login_method(
        &self,
        request: OidcLoginMethodLinkRequest,
    ) -> Result<LoginMethodRecord, ManagedStoreError> {
        validate_principal_id(&request.principal_id)?;
        validate_canonical_uuid(&request.user_object_id, "userObjectId")?;
        validate_actor(&request.actor)?;
        let now = normalized_now_string();
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let principal = principal_by_id(&tx, &request.principal_id)?;
        require_interactive_principal(&principal)?;
        let provider =
            oidc_provider_state(&tx)?.ok_or(ManagedStoreError::OidcProviderUnavailable)?;
        let external_subject =
            format!("entra:v1:{}:{}", provider.tenant_id, request.user_object_id);
        let existing = oidc_login_method_for_principal(&tx, &request.principal_id)?;
        if let Some(existing) = existing {
            if existing.external_subject.as_deref() != Some(&external_subject) {
                return Err(ManagedStoreError::OidcLoginMethodConflict);
            }
            tx.execute(
                "UPDATE principal_login_methods SET status = 'active', updated_at = ?2,
                 updated_by = ?3 WHERE login_method_id = ?1",
                params![existing.login_method_id, now, request.actor],
            )
            .map_err(sql_unavailable)?;
            let record = login_method_by_id(&tx, &existing.login_method_id)?;
            tx.commit().map_err(sql_unavailable)?;
            return Ok(record);
        }
        let login_method_id = Uuid::new_v4().to_string();
        tx.execute(
            "INSERT INTO principal_login_methods
             (login_method_id, principal_id, method, external_provider, external_subject,
              status, password_hash_phc, password_set_at, must_change_password, created_at,
              updated_at, created_by, updated_by)
             VALUES (?1, ?2, 'oidc', 'microsoft', ?3, 'active', NULL, NULL, 0, ?4, ?4, ?5, ?5)",
            params![
                login_method_id,
                request.principal_id,
                external_subject,
                now,
                request.actor
            ],
        )
        .map_err(map_oidc_method_insert_error)?;
        let record = login_method_by_id(&tx, &login_method_id)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(record)
    }

    pub fn unlink_oidc_login_method(
        &self,
        principal_id: &str,
        actor: &str,
    ) -> Result<(), ManagedStoreError> {
        validate_principal_id(principal_id)?;
        validate_actor(actor)?;
        let now = normalized_now_string();
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let method = oidc_login_method_for_principal(&tx, principal_id)?
            .ok_or(ManagedStoreError::OidcLoginMethodConflict)?;
        revoke_browser_sessions_by_login_method_id_tx(&tx, &method.login_method_id, actor, &now)?;
        tx.execute(
            "DELETE FROM external_principal_groups WHERE login_method_id = ?1",
            params![method.login_method_id],
        )
        .map_err(sql_unavailable)?;
        tx.execute(
            "DELETE FROM oidc_membership_refresh_state WHERE login_method_id = ?1",
            params![method.login_method_id],
        )
        .map_err(sql_unavailable)?;
        tx.execute(
            "DELETE FROM principal_login_methods WHERE login_method_id = ?1",
            params![method.login_method_id],
        )
        .map_err(sql_unavailable)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(())
    }

    pub fn record_trusted_incomplete_oidc_callback(
        &self,
        external_subject: &str,
        flow_sequence: u64,
        provider_generation: u64,
        observed_at: &str,
    ) -> Result<bool, ManagedStoreError> {
        validate_oidc_external_subject(external_subject)?;
        let observed_at = normalize_optional_timestamp(Some(observed_at), "observedAt")?
            .expect("present timestamp normalizes to a value");
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        require_oidc_provider_generation(&tx, provider_generation)?;
        let advanced =
            advance_oidc_subject_watermark_tx(&tx, external_subject, flow_sequence, &observed_at)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(advanced)
    }

    pub fn complete_oidc_login(
        &self,
        hasher: &BrokerTokenHasher,
        request: OidcCompleteLoginRequest,
    ) -> Result<OidcCompletionOutcome, ManagedStoreError> {
        validate_oidc_external_subject(&request.external_subject)?;
        validate_principal_id(&request.jit_principal_id)?;
        validate_actor(&request.created_by)?;
        let evidence_at = normalize_optional_timestamp(Some(&request.evidence_at), "evidenceAt")?
            .expect("present timestamp normalizes to a value");
        let callback_now =
            normalize_optional_timestamp(Some(&request.callback_now), "callbackNow")?
                .expect("present timestamp normalizes to a value");
        for group_id in &request.external_group_ids {
            validate_external_group_id(group_id)?;
        }
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let provider = require_oidc_provider_generation(&tx, request.provider_generation)?;
        if !advance_oidc_subject_watermark_tx(
            &tx,
            &request.external_subject,
            request.flow_sequence,
            &callback_now,
        )? {
            tx.commit().map_err(sql_unavailable)?;
            return Ok(OidcCompletionOutcome::Superseded);
        }
        let evidence_at_value = DateTime::parse_from_rfc3339(&evidence_at)
            .map_err(|_| input_invalid("OIDC evidence time is invalid"))?
            .with_timezone(&Utc);
        let valid_until = normalized_timestamp(
            evidence_at_value + Duration::seconds(provider.external_membership_ttl_seconds as i64),
        );
        if valid_until <= callback_now {
            tx.commit().map_err(sql_unavailable)?;
            return Ok(OidcCompletionOutcome::Denied {
                reason: "evidence_expired".to_string(),
            });
        }
        let mut method = oidc_login_method_for_subject(&tx, &request.external_subject)?;
        if let Some(existing) = method.as_ref() {
            let principal = principal_by_id_without_groups(&tx, &existing.principal_id)?;
            if principal.kind != "user" {
                tx.commit().map_err(sql_unavailable)?;
                return Ok(OidcCompletionOutcome::Denied {
                    reason: "principal_not_interactive".to_string(),
                });
            }
            if existing.status != "active" || principal.status != "active" {
                tx.commit().map_err(sql_unavailable)?;
                return Ok(OidcCompletionOutcome::Denied {
                    reason: "login_method_disabled".to_string(),
                });
            }
        }
        let mut statement = tx
            .prepare(
                "SELECT b.binding_id, b.external_group_id
                 FROM external_group_bindings b JOIN groups g ON g.group_id = b.group_id
                 WHERE b.status = 'active' AND g.status = 'active'
                 ORDER BY b.binding_id",
            )
            .map_err(sql_unavailable)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sql_unavailable)?;
        let matched = collect_rows(rows)?
            .into_iter()
            .filter(|(_, external_group_id)| request.external_group_ids.contains(external_group_id))
            .collect::<Vec<_>>();
        drop(statement);
        let jit_created = method.is_none();
        if jit_created && (!request.jit_provisioning || matched.is_empty()) {
            tx.commit().map_err(sql_unavailable)?;
            return Ok(OidcCompletionOutcome::Denied {
                reason: if request.jit_provisioning {
                    "no_mapped_group"
                } else {
                    "jit_disabled"
                }
                .to_string(),
            });
        }
        if method.is_none() {
            tx.execute(
                "INSERT INTO principals
                 (principal_id, kind, display_name, email, external_subject, status,
                  created_at, updated_at, disabled_at, created_by, role, self_service_enabled)
                 VALUES (?1, 'user', ?2, ?3, NULL, 'active', ?4, ?4, NULL, ?5, 'user', 1)",
                params![
                    request.jit_principal_id,
                    normalized_optional_profile_value(request.display_name.as_deref()),
                    normalized_optional_profile_value(request.email.as_deref()),
                    callback_now,
                    request.created_by
                ],
            )
            .map_err(sql_unavailable)?;
            self.initialize_identity_token(&tx, &request.jit_principal_id, "user")?;
            let login_method_id = Uuid::new_v4().to_string();
            tx.execute(
                "INSERT INTO principal_login_methods
                 (login_method_id, principal_id, method, external_provider, external_subject,
                  status, password_hash_phc, password_set_at, must_change_password, created_at,
                  updated_at, created_by, updated_by)
                 VALUES (?1, ?2, 'oidc', 'microsoft', ?3, 'active', NULL, NULL, 0, ?4, ?4, ?5,
                         ?5)",
                params![
                    login_method_id,
                    request.jit_principal_id,
                    request.external_subject,
                    callback_now,
                    request.created_by
                ],
            )
            .map_err(map_oidc_method_insert_error)?;
            method = Some(login_method_by_id(&tx, &login_method_id)?);
        }
        let method = method.expect("OIDC method resolved or created");
        tx.execute(
            "DELETE FROM external_principal_groups WHERE login_method_id = ?1",
            params![method.login_method_id],
        )
        .map_err(sql_unavailable)?;
        for (binding_id, _) in &matched {
            tx.execute(
                "INSERT INTO external_principal_groups
                 (login_method_id, binding_id, observed_at, evidence_at, valid_until, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?3)",
                params![
                    method.login_method_id,
                    binding_id,
                    callback_now,
                    evidence_at,
                    valid_until
                ],
            )
            .map_err(sql_unavailable)?;
        }
        tx.execute(
            "INSERT INTO oidc_membership_refresh_state
             (login_method_id, observed_at, evidence_at, valid_until, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?2)
             ON CONFLICT(login_method_id) DO UPDATE SET
               observed_at = excluded.observed_at, evidence_at = excluded.evidence_at,
               valid_until = excluded.valid_until, updated_at = excluded.updated_at",
            params![
                method.login_method_id,
                callback_now,
                evidence_at,
                valid_until
            ],
        )
        .map_err(sql_unavailable)?;
        let session_request = BrowserSessionIssueRequest {
            principal_id: method.principal_id.clone(),
            login_method: "oidc".to_string(),
            login_method_id: Some(method.login_method_id.clone()),
            ttl_seconds: request.session_ttl_seconds,
            password_change_required: false,
            created_by: request.created_by,
        };
        validate_browser_session_issue_request(&session_request)?;
        let session = issue_browser_session_tx(&tx, hasher, &session_request, &callback_now)?;
        let membership = effective_membership_at_conn(&tx, &method.principal_id, &callback_now)?;
        let mut principal = principal_by_id_without_groups(&tx, &method.principal_id)?;
        principal.groups = membership.groups.clone();
        let result = OidcCompleteLoginResult {
            principal,
            login_method: method,
            session,
            membership,
        };
        tx.commit().map_err(sql_unavailable)?;
        Ok(OidcCompletionOutcome::Succeeded {
            result: Box::new(result),
            jit_created,
        })
    }

    /// Enroll or replace a disabled local method. Never resets an active method.
    /// The admin HTTP boundary also requires explicit separate-sign-in consent.
    pub fn enable_local_password(
        &self,
        hasher: &LocalPasswordHasher,
        request: LocalPasswordWriteRequest,
    ) -> Result<EnabledLocalPassword, ManagedStoreError> {
        validate_local_password_write(&request)?;
        let _work = self.try_acquire_admin_password_work()?;
        let password_hash = hasher.hash_password(&request.password)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        require_interactive_principal(&principal_by_id_without_groups(
            &tx,
            &request.principal_id,
        )?)?;
        let existing = local_password_login_method(&tx, &request.principal_id)?;
        if existing
            .as_ref()
            .is_some_and(|method| method.status == "active")
        {
            return Err(ManagedStoreError::LocalPasswordAlreadyEnabled);
        }
        let previous_status = if existing.is_some() {
            SignInMethodStatus::Disabled
        } else {
            SignInMethodStatus::Absent
        };
        let method = write_local_password_tx(&tx, &request, &password_hash, existing.as_ref())?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(EnabledLocalPassword {
            method,
            previous_status,
        })
    }

    /// Replace only an active credential; cannot enroll or re-enable.
    pub fn reset_local_password(
        &self,
        hasher: &LocalPasswordHasher,
        request: LocalPasswordWriteRequest,
    ) -> Result<LoginMethodRecord, ManagedStoreError> {
        validate_local_password_write(&request)?;
        let _work = self.try_acquire_admin_password_work()?;
        let password_hash = hasher.hash_password(&request.password)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        require_interactive_principal(&principal_by_id_without_groups(
            &tx,
            &request.principal_id,
        )?)?;
        let existing = local_password_login_method(&tx, &request.principal_id)?
            .filter(|method| method.status == "active")
            .ok_or(ManagedStoreError::LocalPasswordNotEnabled)?;
        let method = write_local_password_tx(&tx, &request, &password_hash, Some(&existing))?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(method)
    }

    /// After hashing outside the store lock, credential recheck, mutation and
    /// any replacement local session share one write transaction. A concurrent
    /// reset/disable cannot resurrect stale authority.
    /// An OIDC caller keeps its original session and authentication provenance.
    pub fn change_local_password(
        &self,
        password_hasher: &LocalPasswordHasher,
        token_hasher: &BrokerTokenHasher,
        request: LocalPasswordChangeRequest,
    ) -> Result<ChangedLocalPassword, ManagedStoreError> {
        let verify = &request.verification;
        validate_local_password_verify_request(verify)?;
        let write = LocalPasswordWriteRequest {
            principal_id: verify.principal_id.clone(),
            password: request.new_password,
            min_password_length: request.min_password_length,
            password_change_required: false,
            actor: verify.principal_id.clone(),
        };
        validate_local_password_write(&write)?;
        // Hashing the replacement does not depend on store state. Keep it out
        // of the global connection lock and SQLite's write transaction.
        let _work = self.try_acquire_work()?;
        let password_hash = password_hasher.hash_password(&write.password)?;
        let candidate = self.verify_local_password_outside_store(password_hasher, verify)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        if local_password_failures::source_locked(
            &tx,
            &verify.principal_id,
            &verify.source,
            verify.lockout_ttl_seconds,
            Utc::now(),
        )? {
            return Err(ManagedStoreError::LocalLoginLocked);
        }
        let Some(mut verified) = recheck_local_password_candidate(&tx, candidate.as_ref(), verify)?
        else {
            // Failed password changes must retain failure accounting. Drop this
            // transaction before the failure counter's own write transaction.
            drop(tx);
            let locked = local_password_failures::record_failure(
                &mut conn,
                &verify.principal_id,
                &verify.source,
                verify.max_failed_attempts,
                verify.lockout_ttl_seconds,
                Utc::now(),
            )?;
            return Err(if locked {
                ManagedStoreError::LocalLoginLocked
            } else {
                ManagedStoreError::LocalLoginFailed
            });
        };
        let existing = local_password_login_method(&tx, &verified.principal_id)?
            .ok_or(ManagedStoreError::LocalLoginFailed)?;
        let method = write_local_password_tx(&tx, &write, &password_hash, Some(&existing))?;
        let replacement_session = if request.replace_local_session {
            Some(issue_browser_session_tx(
                &tx,
                token_hasher,
                &BrowserSessionIssueRequest {
                    principal_id: verified.principal_id.clone(),
                    login_method: "local_password".to_string(),
                    login_method_id: Some(method.login_method_id),
                    ttl_seconds: request.session_ttl_seconds,
                    password_change_required: false,
                    created_by: verified.principal_id.clone(),
                },
                &normalized_now_string(),
            )?)
        } else {
            None
        };
        verified.password_change_required = false;
        tx.commit().map_err(sql_unavailable)?;
        Ok(ChangedLocalPassword {
            verified,
            replacement_session,
        })
    }

    pub fn disable_local_password(
        &self,
        principal_id: &str,
        actor: &str,
    ) -> Result<LoginMethodRecord, ManagedStoreError> {
        validate_principal_id(principal_id)?;
        validate_actor(actor)?;
        let principal = self.principal(principal_id)?;
        require_interactive_principal(&principal)?;
        let now = normalized_now_string();
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        if principal_is_active_admin(&tx, principal_id)? && active_admin_principal_count(&tx)? <= 1
        {
            return Err(input_invalid(
                "last active admin local password cannot be disabled",
            ));
        }
        let login_method_id: Option<String> = tx
            .query_row(
                "SELECT login_method_id
                 FROM principal_login_methods
                 WHERE principal_id = ?1 AND method = 'local_password'",
                params![principal_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_unavailable)?;
        let Some(login_method_id) = login_method_id else {
            return Err(input_invalid(
                "local password login method is not configured",
            ));
        };
        tx.execute(
            "UPDATE principal_login_methods
             SET status = 'disabled',
                 updated_at = ?3,
                 updated_by = ?2
             WHERE principal_id = ?1 AND method = 'local_password'",
            params![principal_id, actor, now],
        )
        .map_err(sql_unavailable)?;
        local_password_failures::clear_principal(&tx, principal_id)?;
        revoke_browser_sessions_by_method_tx(&tx, principal_id, "local_password", actor, &now)?;
        let record = login_method_by_id(&tx, &login_method_id)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(record)
    }

    pub fn unlock_local_password(
        &self,
        principal_id: &str,
        actor: &str,
    ) -> Result<LoginMethodRecord, ManagedStoreError> {
        validate_principal_id(principal_id)?;
        validate_actor(actor)?;
        let principal = self.principal(principal_id)?;
        require_interactive_principal(&principal)?;
        let now = normalized_now_string();
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        let login_method_id: Option<String> = tx
            .query_row(
                "SELECT login_method_id
                 FROM principal_login_methods
                 WHERE principal_id = ?1 AND method = 'local_password'",
                params![principal_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_unavailable)?;
        let Some(login_method_id) = login_method_id else {
            return Err(input_invalid(
                "local password login method is not configured",
            ));
        };
        // Unlock clears the failure state of every source.
        local_password_failures::clear_principal(&tx, principal_id)?;
        tx.execute(
            "UPDATE principal_login_methods
             SET updated_at = ?3,
                 updated_by = ?2
             WHERE login_method_id = ?1",
            params![login_method_id, actor, now],
        )
        .map_err(sql_unavailable)?;
        let record = login_method_by_id(&tx, &login_method_id)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(record)
    }

    fn verify_local_password_outside_store(
        &self,
        hasher: &LocalPasswordHasher,
        request: &LocalPasswordVerifyRequest,
    ) -> Result<Option<LocalPasswordCandidate>, ManagedStoreError> {
        let candidate = {
            let conn = self.connection.lock().unwrap();
            if local_password_failures::source_locked(
                &conn,
                &request.principal_id,
                &request.source,
                request.lockout_ttl_seconds,
                Utc::now(),
            )? {
                return Err(ManagedStoreError::LocalLoginLocked);
            }
            local_password_candidate(&conn, request)?
        };
        let hash = candidate
            .as_ref()
            .map(|candidate| candidate.password_hash_phc.as_str())
            .unwrap_or_else(|| dummy_local_password_hash_phc());
        if hasher.verify_password(&request.password, hash)? {
            Ok(candidate)
        } else {
            Ok(None)
        }
    }

    /// Verifies a local password, counting failures per `(principal, source)`.
    ///
    /// A locked source is rejected before any lookup or hashing; a source
    /// without its own failure row is locked while the principal's overflow
    /// row is. Every other failure, including unknown, disabled, or non-user
    /// principals, counts against the submitted principal ID and source (or
    /// the principal's overflow row once it has the maximum number of
    /// per-source rows), so a lockout response does not reveal whether the
    /// principal exists. Success clears only the verifying source's counter.
    pub fn verify_local_password(
        &self,
        hasher: &LocalPasswordHasher,
        request: LocalPasswordVerifyRequest,
    ) -> Result<VerifiedLocalPassword, ManagedStoreError> {
        validate_local_password_verify_request(&request)?;
        let _work = self.try_acquire_work()?;
        let candidate = self.verify_local_password_outside_store(hasher, &request)?;
        let mut conn = self.connection.lock().unwrap();
        if local_password_failures::source_locked(
            &conn,
            &request.principal_id,
            &request.source,
            request.lockout_ttl_seconds,
            Utc::now(),
        )? {
            return Err(ManagedStoreError::LocalLoginLocked);
        }
        if let Some(verified) =
            recheck_local_password_candidate(&conn, candidate.as_ref(), &request)?
        {
            local_password_failures::clear_source(&conn, &request.principal_id, &request.source)?;
            return Ok(verified);
        }
        let locked = local_password_failures::record_failure(
            &mut conn,
            &request.principal_id,
            &request.source,
            request.max_failed_attempts,
            request.lockout_ttl_seconds,
            Utc::now(),
        )?;
        if locked {
            Err(ManagedStoreError::LocalLoginLocked)
        } else {
            Err(ManagedStoreError::LocalLoginFailed)
        }
    }

    /// Hash outside the connection lock, then recheck the credential and issue
    /// its session in one immediate transaction. Reset/disable invalidates an
    /// in-progress verification; a later reset revokes the issued session.
    pub fn authenticate_local_password_session(
        &self,
        password_hasher: &LocalPasswordHasher,
        token_hasher: &BrokerTokenHasher,
        request: LocalPasswordVerifyRequest,
        session_ttl_seconds: u64,
    ) -> Result<AuthenticatedLocalPassword, ManagedStoreError> {
        validate_local_password_verify_request(&request)?;
        let _work = self.try_acquire_work()?;
        let candidate = self.verify_local_password_outside_store(password_hasher, &request)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        if local_password_failures::source_locked(
            &tx,
            &request.principal_id,
            &request.source,
            request.lockout_ttl_seconds,
            Utc::now(),
        )? {
            return Err(ManagedStoreError::LocalLoginLocked);
        }
        let Some(verified) = recheck_local_password_candidate(&tx, candidate.as_ref(), &request)?
        else {
            // Failure accounting owns its own immediate transaction.
            drop(tx);
            let locked = local_password_failures::record_failure(
                &mut conn,
                &request.principal_id,
                &request.source,
                request.max_failed_attempts,
                request.lockout_ttl_seconds,
                Utc::now(),
            )?;
            return Err(if locked {
                ManagedStoreError::LocalLoginLocked
            } else {
                ManagedStoreError::LocalLoginFailed
            });
        };
        local_password_failures::clear_source(&tx, &request.principal_id, &request.source)?;
        let session = issue_browser_session_tx(
            &tx,
            token_hasher,
            &BrowserSessionIssueRequest {
                principal_id: verified.principal_id.clone(),
                login_method: "local_password".into(),
                login_method_id: Some(verified.login_method_id.clone()),
                ttl_seconds: session_ttl_seconds,
                password_change_required: verified.password_change_required,
                created_by: verified.principal_id.clone(),
            },
            &normalized_now_string(),
        )?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(AuthenticatedLocalPassword { verified, session })
    }

    pub fn issue_browser_session(
        &self,
        hasher: &BrokerTokenHasher,
        request: BrowserSessionIssueRequest,
    ) -> Result<IssuedBrowserSession, ManagedStoreError> {
        validate_browser_session_issue_request(&request)?;
        let now = normalized_now_string();
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let issued = issue_browser_session_tx(&tx, hasher, &request, &now)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(issued)
    }

    pub fn resolve_browser_session(
        &self,
        hasher: &BrokerTokenHasher,
        raw_token: &str,
    ) -> Result<BrowserSessionIdentity, ManagedStoreError> {
        let token_identity = self.resolve_broker_token(hasher, raw_token)?;
        if token_identity.token_class != BrokerTokenClass::UserManage {
            return Err(ManagedStoreError::BrokerTokenClassDenied);
        }
        let conn = self.connection.lock().unwrap();
        let session = browser_session_by_token_id(&conn, &token_identity.token_id)?;
        if session.principal_id != token_identity.principal_id {
            return Err(ManagedStoreError::BrokerTokenRevoked);
        }
        let login_method_id = session
            .login_method_id
            .as_deref()
            .ok_or(ManagedStoreError::BrokerTokenRevoked)?;
        let method = login_method_by_id(&conn, login_method_id)?;
        if method.principal_id != session.principal_id || method.method != session.login_method {
            return Err(ManagedStoreError::BrokerTokenRevoked);
        }
        if method.status != "active" {
            return Err(ManagedStoreError::BrokerTokenRevoked);
        }
        if let Some(password_set_at) = method.password_set_at.as_deref()
            && password_set_at > session.auth_time.as_str()
        {
            return Err(ManagedStoreError::BrokerTokenRevoked);
        }
        let principal = principal_by_id_without_groups(&conn, &session.principal_id)?;
        if principal.kind != "user" {
            return Err(ManagedStoreError::BrokerTokenRevoked);
        }
        Ok(BrowserSessionIdentity {
            sign_in_methods: principal.sign_in_methods,
            principal_id: token_identity.principal_id,
            display_name: principal.display_name,
            email: principal.email,
            groups: token_identity.groups,
            policy_groups: token_identity.policy_groups,
            role: token_identity.role,
            self_service_enabled: token_identity.self_service_enabled,
            token_id: token_identity.token_id,
            scopes: token_identity.scopes,
            expires_at: token_identity.expires_at,
            login_method: session.login_method,
            login_method_id: session.login_method_id,
            auth_time: session.auth_time,
            password_change_required: session.password_change_required
                || method.must_change_password,
        })
    }

    pub fn revoke_browser_session(
        &self,
        token_id: &str,
        actor: &str,
    ) -> Result<BrokerTokenRecord, ManagedStoreError> {
        validate_uuid_id(token_id, "tokenId")?;
        validate_actor(actor)?;
        let now = normalized_now_string();
        let conn = self.connection.lock().unwrap();
        let exists: Option<String> = conn
            .query_row(
                "SELECT token_id FROM browser_sessions WHERE token_id = ?1",
                params![token_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_unavailable)?;
        if exists.is_none() {
            return Err(ManagedStoreError::BrokerTokenNotFound);
        }
        conn.execute(
            "UPDATE broker_tokens
             SET revoked_at = COALESCE(revoked_at, ?2), revoked_by = COALESCE(revoked_by, ?3)
             WHERE token_id = ?1",
            params![token_id, now, actor],
        )
        .map_err(sql_unavailable)?;
        broker_token_by_id(&conn, token_id)
    }

    pub fn issue_self_agent_token(
        &self,
        hasher: &BrokerTokenHasher,
        request: SelfAgentTokenIssueRequest,
    ) -> Result<IssuedBrokerToken, ManagedStoreError> {
        self.issue_self_agent_token_with_catalog(hasher, request, None)
    }

    pub fn issue_self_agent_token_with_catalog(
        &self,
        hasher: &BrokerTokenHasher,
        request: SelfAgentTokenIssueRequest,
        catalog: Option<&ManagedResourceCatalog>,
    ) -> Result<IssuedBrokerToken, ManagedStoreError> {
        validate_self_agent_token_issue_request(&request)?;
        self.issue_broker_token_inner(
            hasher,
            BrokerTokenIssueRequest {
                principal_id: request.principal_id,
                name: request.name,
                token_class: BrokerTokenClass::AgentInvoke,
                scopes: request.scopes,
                expires_at: request.expires_at,
                created_by: request.created_by,
            },
            true,
            catalog,
        )
    }

    pub fn issue_broker_token_with_catalog(
        &self,
        hasher: &BrokerTokenHasher,
        request: BrokerTokenIssueRequest,
        catalog: Option<&ManagedResourceCatalog>,
    ) -> Result<IssuedBrokerToken, ManagedStoreError> {
        self.issue_broker_token_inner(hasher, request, false, catalog)
    }

    pub fn list_self_agent_tokens(
        &self,
        principal_id: &str,
        include_revoked: bool,
        include_expired: bool,
    ) -> Result<Vec<BrokerTokenRecord>, ManagedStoreError> {
        validate_principal_id(principal_id)?;
        let now = normalized_now_string();
        let conn = self.connection.lock().unwrap();
        let mut statement = conn
            .prepare(
                "SELECT token_id, token_hash, principal_id, name, token_class, scopes_json,
                        created_at, expires_at, revoked_at, revoked_by, paused_at, paused_by,
                        last_used_at, created_by
                 FROM broker_tokens
                 WHERE principal_id = ?1
                   AND token_class = 'agent_invoke'
                   AND (?2 OR revoked_at IS NULL)
                   AND (?3 OR expires_at IS NULL OR expires_at > ?4)
                 ORDER BY created_at DESC, token_id",
            )
            .map_err(sql_unavailable)?;
        let rows = statement
            .query_map(
                params![principal_id, include_revoked, include_expired, now],
                broker_token_from_row,
            )
            .map_err(sql_unavailable)?;
        collect_rows(rows)
    }

    pub fn self_agent_token(
        &self,
        principal_id: &str,
        token_id: &str,
    ) -> Result<BrokerTokenRecord, ManagedStoreError> {
        validate_principal_id(principal_id)?;
        validate_uuid_id(token_id, "tokenId")?;
        let conn = self.connection.lock().unwrap();
        broker_token_by_id_principal_class(
            &conn,
            token_id,
            principal_id,
            BrokerTokenClass::AgentInvoke,
        )
    }

    pub fn revoke_self_agent_token(
        &self,
        principal_id: &str,
        token_id: &str,
        actor: &str,
    ) -> Result<BrokerTokenRecord, ManagedStoreError> {
        validate_principal_id(principal_id)?;
        validate_uuid_id(token_id, "tokenId")?;
        validate_actor(actor)?;
        let now = now_string();
        let conn = self.connection.lock().unwrap();
        let changed = conn
            .execute(
                "UPDATE broker_tokens
                 SET revoked_at = COALESCE(revoked_at, ?3), revoked_by = COALESCE(revoked_by, ?4)
                 WHERE token_id = ?1
                   AND principal_id = ?2
                   AND token_class = 'agent_invoke'",
                params![token_id, principal_id, now, actor],
            )
            .map_err(sql_unavailable)?;
        if changed == 0 {
            return Err(ManagedStoreError::BrokerTokenNotFound);
        }
        broker_token_by_id_principal_class(
            &conn,
            token_id,
            principal_id,
            BrokerTokenClass::AgentInvoke,
        )
    }

    pub fn pause_principal_agent_token(
        &self,
        principal_id: &str,
        token_id: &str,
        actor: &str,
        purpose: AgentTokenManagementPurpose,
    ) -> Result<BrokerTokenRecord, ManagedStoreError> {
        validate_principal_id(principal_id)?;
        self.transition_agent_token_pause(
            token_id,
            Some(principal_id),
            actor,
            TokenPauseTransition::Pause,
            None,
            purpose,
        )
    }

    pub fn resume_principal_agent_token(
        &self,
        principal_id: &str,
        token_id: &str,
        actor: &str,
        purpose: AgentTokenManagementPurpose,
    ) -> Result<BrokerTokenRecord, ManagedStoreError> {
        self.resume_principal_agent_token_with_catalog(principal_id, token_id, actor, None, purpose)
    }

    pub fn resume_broker_token_with_catalog(
        &self,
        token_id: &str,
        actor: &str,
        catalog: Option<&ManagedResourceCatalog>,
    ) -> Result<BrokerTokenRecord, ManagedStoreError> {
        self.transition_agent_token_pause(
            token_id,
            None,
            actor,
            TokenPauseTransition::Resume,
            catalog,
            AgentTokenManagementPurpose::Administrative,
        )
    }

    pub fn resume_principal_agent_token_with_catalog(
        &self,
        principal_id: &str,
        token_id: &str,
        actor: &str,
        catalog: Option<&ManagedResourceCatalog>,
        purpose: AgentTokenManagementPurpose,
    ) -> Result<BrokerTokenRecord, ManagedStoreError> {
        validate_principal_id(principal_id)?;
        self.transition_agent_token_pause(
            token_id,
            Some(principal_id),
            actor,
            TokenPauseTransition::Resume,
            catalog,
            purpose,
        )
    }

    fn transition_agent_token_pause(
        &self,
        token_id: &str,
        principal_id: Option<&str>,
        actor: &str,
        transition: TokenPauseTransition,
        catalog: Option<&ManagedResourceCatalog>,
        purpose: AgentTokenManagementPurpose,
    ) -> Result<BrokerTokenRecord, ManagedStoreError> {
        validate_uuid_id(token_id, "tokenId")?;
        validate_actor(actor)?;
        let now = normalized_now_string();
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        if purpose == AgentTokenManagementPurpose::Personal {
            let record = broker_token_by_id(&tx, token_id)?;
            ensure_agent_token_transition_scope(&record, principal_id)?;
            require_self_service(&tx, &record.principal_id)?;
        }
        let record = transition_agent_token_pause_tx(
            &tx,
            token_id,
            principal_id,
            actor,
            &now,
            transition,
            catalog,
        )?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(record)
    }

    pub fn grant_right(
        &self,
        request: RightGrantRequest,
    ) -> Result<RightRecord, ManagedStoreError> {
        validate_right_grant_request(&request)?;
        self.active_principal(&request.principal_id)?;
        if request.resource_scope_json.is_some() {
            return Err(input_invalid("resource_scope_json is reserved in V1"));
        }
        let right_id = Uuid::new_v4().to_string();
        let expires_at = normalize_optional_timestamp(request.expires_at.as_deref(), "expiresAt")?;
        let conn = self.connection.lock().unwrap();
        conn.execute(
            "INSERT INTO rights
             (right_id, principal_id, right_name, service, credential_name, resource_scope_json,
              created_by, created_at, expires_at, revoked_at, revoked_by, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7, ?8, NULL, NULL, ?9)",
            params![
                right_id,
                request.principal_id,
                request.right,
                request.service,
                request.credential_name,
                request.created_by,
                now_string(),
                expires_at,
                request.reason
            ],
        )
        .map_err(sql_unavailable)?;
        right_by_id(&conn, &right_id)
    }

    pub fn revoke_right(
        &self,
        right_id: &str,
        actor: &str,
    ) -> Result<RightRecord, ManagedStoreError> {
        validate_uuid_id(right_id, "rightId")?;
        validate_actor(actor)?;
        let now = now_string();
        let conn = self.connection.lock().unwrap();
        let changed = conn
            .execute(
                "UPDATE rights
                 SET revoked_at = COALESCE(revoked_at, ?2), revoked_by = COALESCE(revoked_by, ?3)
                 WHERE right_id = ?1",
                params![right_id, now, actor],
            )
            .map_err(sql_unavailable)?;
        if changed == 0 {
            return Err(ManagedStoreError::RightMissing);
        }
        right_by_id(&conn, right_id)
    }

    pub fn list_rights(
        &self,
        principal_id: Option<&str>,
    ) -> Result<Vec<RightRecord>, ManagedStoreError> {
        if let Some(principal_id) = principal_id {
            validate_principal_id(principal_id)?;
        }
        let conn = self.connection.lock().unwrap();
        if let Some(principal_id) = principal_id {
            let mut statement = conn
                .prepare(
                    "SELECT right_id, principal_id, right_name, service, credential_name,
                            resource_scope_json, created_by, created_at, expires_at, revoked_at,
                            revoked_by, reason
                     FROM rights
                     WHERE principal_id = ?1
                     ORDER BY created_at DESC, right_id",
                )
                .map_err(sql_unavailable)?;
            let rows = statement
                .query_map(params![principal_id], right_from_row)
                .map_err(sql_unavailable)?;
            return collect_rows(rows);
        }
        let mut statement = conn
            .prepare(
                "SELECT right_id, principal_id, right_name, service, credential_name,
                        resource_scope_json, created_by, created_at, expires_at, revoked_at,
                        revoked_by, reason
                 FROM rights
                 ORDER BY created_at DESC, right_id",
            )
            .map_err(sql_unavailable)?;
        let rows = statement
            .query_map([], right_from_row)
            .map_err(sql_unavailable)?;
        collect_rows(rows)
    }

    pub fn has_credential_right(
        &self,
        principal_id: &str,
        right: &str,
        service: &str,
        credential_name: &str,
    ) -> Result<bool, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        has_credential_right_conn(&conn, principal_id, right, service, credential_name)
    }

    pub fn require_credential_right(
        &self,
        principal_id: &str,
        right: &str,
        service: &str,
        credential_name: &str,
    ) -> Result<(), ManagedStoreError> {
        if self.has_credential_right(principal_id, right, service, credential_name)? {
            Ok(())
        } else {
            Err(ManagedStoreError::RightMissing)
        }
    }

    pub fn upsert_user_credential(
        &self,
        key_ring: &CredentialKeyRing,
        request: CredentialWriteRequest,
        purpose: CredentialManagementPurpose,
    ) -> Result<CredentialMetadata, ManagedStoreError> {
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let metadata = upsert_user_credential_conn(&tx, key_ring, request, purpose)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(metadata)
    }

    pub fn credential_by_tuple(
        &self,
        owner_principal_id: &str,
        service: &str,
        name: &str,
    ) -> Result<CredentialMetadata, ManagedStoreError> {
        validate_principal_id(owner_principal_id)?;
        validate_service_and_name(service, name)?;
        let conn = self.connection.lock().unwrap();
        credential_metadata_by_tuple(&conn, owner_principal_id, service, name)
    }

    pub fn credential_by_id(
        &self,
        credential_id: &str,
    ) -> Result<CredentialMetadata, ManagedStoreError> {
        validate_uuid_id(credential_id, "credentialId")?;
        let conn = self.connection.lock().unwrap();
        credential_metadata_by_id(&conn, credential_id)
    }

    pub fn credential_tuple_by_id(
        &self,
        credential_id: &str,
    ) -> Result<(String, String, String), ManagedStoreError> {
        validate_uuid_id(credential_id, "credentialId")?;
        let conn = self.connection.lock().unwrap();
        let credential = credential_metadata_by_id(&conn, credential_id)?;
        Ok((
            credential.owner_principal,
            credential.service,
            credential.name,
        ))
    }

    pub fn list_credentials(
        &self,
        owner_principal_id: Option<&str>,
    ) -> Result<Vec<CredentialMetadata>, ManagedStoreError> {
        if let Some(owner_principal_id) = owner_principal_id {
            validate_principal_id(owner_principal_id)?;
        }
        let conn = self.connection.lock().unwrap();
        if let Some(owner_principal_id) = owner_principal_id {
            let mut statement = conn
                .prepare(
                    "SELECT credential_id, owner_principal_id, owner_kind, service, name,
                            profile, credential_kind, metadata_json, secret_backend, secret_ref,
                            material_version, status, created_at, updated_at, created_by,
                            updated_by, last_used_at, last_verified_at, verification_status,
                            last_verification_attempt_at, last_verification_error_code
                     FROM credentials
                     WHERE owner_kind = 'user' AND owner_principal_id = ?1
                     ORDER BY service, name",
                )
                .map_err(sql_unavailable)?;
            let rows = statement
                .query_map(params![owner_principal_id], credential_metadata_from_row)
                .map_err(sql_unavailable)?;
            return collect_rows(rows);
        }
        let mut statement = conn
            .prepare(
                "SELECT credential_id, owner_principal_id, owner_kind, service, name,
                        profile, credential_kind, metadata_json, secret_backend, secret_ref,
                        material_version, status, created_at, updated_at, created_by,
                        updated_by, last_used_at, last_verified_at, verification_status,
                        last_verification_attempt_at, last_verification_error_code
                 FROM credentials
                 ORDER BY owner_principal_id, service, name",
            )
            .map_err(sql_unavailable)?;
        let rows = statement
            .query_map([], credential_metadata_from_row)
            .map_err(sql_unavailable)?;
        collect_rows(rows)
    }

    pub fn list_credentials_readable_by(
        &self,
        principal_id: &str,
    ) -> Result<Vec<CredentialMetadata>, ManagedStoreError> {
        let credentials = self.list_credentials(Some(principal_id))?;
        let mut readable = Vec::new();
        for credential in credentials {
            if self.has_credential_right(
                principal_id,
                "credentials:self:read_metadata",
                &credential.service,
                &credential.name,
            )? {
                readable.push(credential);
            }
        }
        Ok(readable)
    }

    pub fn delete_user_credential(
        &self,
        owner_principal_id: &str,
        service: &str,
        name: &str,
        purpose: CredentialManagementPurpose,
    ) -> Result<CredentialMetadata, ManagedStoreError> {
        validate_principal_id(owner_principal_id)?;
        validate_service_and_name(service, name)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        if purpose == CredentialManagementPurpose::Personal {
            require_self_service(&tx, owner_principal_id)?;
        }
        let metadata = credential_metadata_by_tuple(&tx, owner_principal_id, service, name)?;
        tx.execute(
            "DELETE FROM credentials WHERE credential_id = ?1",
            params![metadata.credential_id],
        )
        .map_err(sql_unavailable)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(metadata)
    }

    pub fn delete_user_credential_by_id(
        &self,
        credential_id: &str,
        purpose: CredentialManagementPurpose,
    ) -> Result<CredentialMetadata, ManagedStoreError> {
        validate_uuid_id(credential_id, "credentialId")?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let metadata = credential_metadata_by_id(&tx, credential_id)?;
        if purpose == CredentialManagementPurpose::Personal {
            require_self_service(&tx, &metadata.owner_principal)?;
        }
        if metadata.owner_kind != "user" {
            return Err(ManagedStoreError::CredentialInvalid(
                "only user credentials are supported in V1".to_string(),
            ));
        }
        tx.execute(
            "DELETE FROM credentials WHERE credential_id = ?1",
            params![metadata.credential_id],
        )
        .map_err(sql_unavailable)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(metadata)
    }

    pub fn resolve_user_credential(
        &self,
        key_ring: &CredentialKeyRing,
        owner_principal_id: &str,
        service: &str,
        name: &str,
        expected_profile: &str,
    ) -> Result<ExecutionCredential, ManagedStoreError> {
        validate_principal_id(owner_principal_id)?;
        validate_service_and_name(service, name)?;
        validate_profile(expected_profile)?;
        let conn = self.connection.lock().unwrap();
        let row = encrypted_credential_by_tuple(&conn, owner_principal_id, service, name)?;
        let credential = execution_credential_from_encrypted_row(key_ring, &row, expected_profile)?;
        conn.execute(
            "UPDATE credentials SET last_used_at = ?2 WHERE credential_id = ?1",
            params![row.credential_id, now_string()],
        )
        .map_err(sql_unavailable)?;
        Ok(credential)
    }

    /// Check the same stored material as execution, without recording use or
    /// applying management permissions. Discovery is not a verification attempt.
    pub(crate) fn check_user_credential(
        &self,
        key_ring: &CredentialKeyRing,
        owner_principal_id: &str,
        service: &str,
        name: &str,
        expected_profile: &str,
    ) -> Result<(), ManagedStoreError> {
        validate_principal_id(owner_principal_id)?;
        validate_service_and_name(service, name)?;
        validate_profile(expected_profile)?;
        let conn = self.connection.lock().unwrap();
        let row = encrypted_credential_by_tuple(&conn, owner_principal_id, service, name)?;
        execution_credential_from_encrypted_row(key_ring, &row, expected_profile).map(drop)
    }

    /// The caller's personal credential as a command import receives it,
    /// read and checked as [`Self::resolve_user_credential`] reads it for
    /// execution, which it records as a use.
    pub(crate) fn resolve_user_command_credential(
        &self,
        key_ring: &CredentialKeyRing,
        owner_principal_id: &str,
        service: &str,
        name: &str,
        expected_profile: &str,
    ) -> Result<crate::imports::CommandCredential, ManagedStoreError> {
        validate_principal_id(owner_principal_id)?;
        validate_service_and_name(service, name)?;
        validate_profile(expected_profile)?;
        let conn = self.connection.lock().unwrap();
        let row = encrypted_credential_by_tuple(&conn, owner_principal_id, service, name)?;
        let credential = command_credential_from_encrypted_row(key_ring, &row, expected_profile)?;
        conn.execute(
            "UPDATE credentials SET last_used_at = ?2 WHERE credential_id = ?1",
            params![row.credential_id, now_string()],
        )
        .map_err(sql_unavailable)?;
        Ok(credential)
    }

    /// The personal credential a verification resolved as `target`, as a
    /// command import's `verify` receives it. A credential replaced or
    /// rotated since then fails `VersionConflict`; nothing records a use.
    pub(crate) fn resolve_user_command_credential_for_verification(
        &self,
        key_ring: &CredentialKeyRing,
        owner_principal_id: &str,
        service: &str,
        name: &str,
        expected_profile: &str,
        target: &CredentialVerificationTarget,
    ) -> Result<crate::imports::CommandCredential, ManagedStoreError> {
        validate_principal_id(owner_principal_id)?;
        validate_service_and_name(service, name)?;
        validate_profile(expected_profile)?;
        let conn = self.connection.lock().unwrap();
        let row = encrypted_credential_by_tuple(&conn, owner_principal_id, service, name)?;
        if row.credential_id != target.credential_id
            || row.material_version != target.material_version
        {
            return Err(ManagedStoreError::VersionConflict);
        }
        command_credential_from_encrypted_row(key_ring, &row, expected_profile)
    }

    pub fn resolve_user_credential_for_verification(
        &self,
        key_ring: &CredentialKeyRing,
        owner_principal_id: &str,
        service: &str,
        name: &str,
        expected_profile: &str,
        purpose: CredentialManagementPurpose,
    ) -> Result<CredentialVerificationCandidate, ManagedStoreError> {
        validate_principal_id(owner_principal_id)?;
        validate_service_and_name(service, name)?;
        validate_profile(expected_profile)?;
        let mut connection = self.connection.lock().unwrap();
        let conn = connection.transaction().map_err(sql_unavailable)?;
        purpose.check_active_owner(&conn, owner_principal_id)?;
        let row = encrypted_credential_by_tuple(&conn, owner_principal_id, service, name)?;
        let credential = execution_credential_from_encrypted_row(key_ring, &row, expected_profile)?;
        Ok(CredentialVerificationCandidate {
            credential,
            target: CredentialVerificationTarget {
                credential_id: row.credential_id,
                material_version: row.material_version,
            },
        })
    }

    pub fn verify_user_credential(
        &self,
        key_ring: &CredentialKeyRing,
        owner_principal_id: &str,
        service: &str,
        name: &str,
        expected_profile: &str,
        purpose: CredentialManagementPurpose,
    ) -> Result<CredentialMetadata, ManagedStoreError> {
        let candidate = self.resolve_user_credential_for_verification(
            key_ring,
            owner_principal_id,
            service,
            name,
            expected_profile,
            purpose,
        )?;
        self.mark_user_credential_verified_if_current(&candidate.target, "local_verified", purpose)
    }

    pub fn mark_user_credential_verified_if_current(
        &self,
        target: &CredentialVerificationTarget,
        verification_status: &str,
        purpose: CredentialManagementPurpose,
    ) -> Result<CredentialMetadata, ManagedStoreError> {
        validate_uuid_id(&target.credential_id, "credentialId")?;
        validate_uuid_id(&target.material_version, "materialVersion")?;
        validate_credential_verification_status(verification_status)?;
        let now = now_string();
        let mut connection = self.connection.lock().unwrap();
        let conn = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        if purpose == CredentialManagementPurpose::Personal {
            let owner = credential_metadata_by_id(&conn, &target.credential_id)?.owner_principal;
            require_self_service(&conn, &owner)?;
        }
        let updated = conn
            .execute(
                "UPDATE credentials
                 SET last_verified_at = ?3,
                     last_verification_attempt_at = ?3,
                     verification_status = ?4,
                     last_verification_error_code = NULL
                 WHERE credential_id = ?1
                   AND material_version = ?2
                   AND status = 'active'",
                params![
                    &target.credential_id,
                    &target.material_version,
                    now,
                    verification_status
                ],
            )
            .map_err(sql_unavailable)?;
        if updated == 0 {
            return Err(ManagedStoreError::VersionConflict);
        }
        let result = credential_metadata_by_id(&conn, &target.credential_id)?;
        conn.commit().map_err(sql_unavailable)?;
        Ok(result)
    }

    pub fn mark_user_credential_verification_failed_if_current(
        &self,
        target: &CredentialVerificationTarget,
        error_code: &str,
        purpose: CredentialManagementPurpose,
    ) -> Result<CredentialMetadata, ManagedStoreError> {
        validate_uuid_id(&target.credential_id, "credentialId")?;
        validate_uuid_id(&target.material_version, "materialVersion")?;
        validate_credential_verification_error_code(error_code)?;
        let now = now_string();
        let mut connection = self.connection.lock().unwrap();
        let conn = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        if purpose == CredentialManagementPurpose::Personal {
            let owner = credential_metadata_by_id(&conn, &target.credential_id)?.owner_principal;
            require_self_service(&conn, &owner)?;
        }
        let updated = conn
            .execute(
                "UPDATE credentials
                 SET last_verification_attempt_at = ?3,
                     verification_status = 'verification_failed',
                     last_verification_error_code = ?4
                 WHERE credential_id = ?1
                   AND material_version = ?2
                   AND status = 'active'",
                params![
                    &target.credential_id,
                    &target.material_version,
                    now,
                    error_code
                ],
            )
            .map_err(sql_unavailable)?;
        if updated == 0 {
            return Err(ManagedStoreError::VersionConflict);
        }
        let result = credential_metadata_by_id(&conn, &target.credential_id)?;
        conn.commit().map_err(sql_unavailable)?;
        Ok(result)
    }

    pub fn rewrap_credentials(
        &self,
        key_ring: &CredentialKeyRing,
        from_key: &str,
        to_key: &str,
        actor: &str,
    ) -> Result<RewrapSummary, ManagedStoreError> {
        validate_safe_key_id(from_key)?;
        validate_safe_key_id(to_key)?;
        validate_actor(actor)?;
        if !key_ring.has_key(from_key) {
            return Err(ManagedStoreError::EncryptionKeyMissing(
                from_key.to_string(),
            ));
        }
        if !key_ring.has_key(to_key) {
            return Err(ManagedStoreError::EncryptionKeyMissing(to_key.to_string()));
        }
        let mut conn = self.connection.lock().unwrap();
        let secret_refs = credential_secret_refs_by_key(&conn, from_key)?;
        let mut rewrapped = 0_u64;
        let mut conflicts = 0_u64;
        for secret_ref in secret_refs {
            let tx = conn.transaction().map_err(sql_unavailable)?;
            let Some(row) = encrypted_credential_by_secret_ref_and_key(&tx, &secret_ref, from_key)?
            else {
                conflicts += 1;
                tx.commit().map_err(sql_unavailable)?;
                continue;
            };
            let old_aad = CredentialAad {
                credential_id: row.credential_id.clone(),
                owner_kind: row.owner_kind.clone(),
                owner_principal_id: row.owner_principal_id.clone(),
                service: row.service.clone(),
                name: row.name.clone(),
                profile: row.profile.clone(),
                credential_kind: row.credential_kind.clone(),
                secret_backend: row.secret_backend.clone(),
                secret_ref: row.secret_ref.clone(),
                material_version: row.material_version.clone(),
                key_id: row.key_id.clone(),
            };
            let secret = key_ring.decrypt(
                &row.key_id,
                &row.secret_nonce,
                &row.secret_ciphertext,
                &old_aad,
            )?;
            let new_aad = CredentialAad {
                key_id: to_key.to_string(),
                ..old_aad
            };
            let encrypted = key_ring.encrypt_with_key(to_key, &secret, &new_aad)?;
            let updated = tx
                .execute(
                    "UPDATE credential_secret_material
                     SET secret_ciphertext = ?5, secret_nonce = ?6, key_id = ?7, updated_at = ?8
                     WHERE secret_ref = ?1
                       AND credential_id = ?2
                       AND key_id = ?3
                       AND secret_nonce = ?4",
                    params![
                        row.secret_ref,
                        row.credential_id,
                        row.key_id,
                        row.secret_nonce,
                        encrypted.ciphertext,
                        encrypted.nonce,
                        encrypted.key_id,
                        now_string()
                    ],
                )
                .map_err(sql_unavailable)?;
            if updated == 0 {
                conflicts += 1;
                tx.commit().map_err(sql_unavailable)?;
                continue;
            }
            rewrapped += 1;
            tx.commit().map_err(sql_unavailable)?;
        }
        rewrapped += identity_tokens::rewrap(&mut conn, key_ring, from_key, to_key)?;
        rewrapped += oauth::rewrap(&mut conn, key_ring, from_key, to_key)?;
        rewrapped += oauth_revocation::rewrap(&mut conn, key_ring, from_key, to_key)?;
        rewrapped += resource_attributes::rewrap(&mut conn, key_ring, from_key, to_key)?;
        rewrapped += imported_store::rewrap(&mut conn, key_ring, from_key, to_key)?;
        rewrapped += secret_references::rewrap(&mut conn, key_ring, from_key, to_key)?;
        Ok(RewrapSummary {
            from_key: from_key.to_string(),
            to_key: to_key.to_string(),
            rewrapped,
            conflicts,
        })
    }
}

impl From<SqliteAdmissionError> for ManagedStoreError {
    fn from(error: SqliteAdmissionError) -> Self {
        match error {
            SqliteAdmissionError::Unavailable(message) => Self::Unavailable(message),
            SqliteAdmissionError::MigrationRequired => Self::MigrationRequired,
            SqliteAdmissionError::SchemaInvalid(message) => Self::SchemaInvalid(message),
        }
    }
}

fn admit_schema(
    conn: &Connection,
    catalog: ManagedStoreMigrationCatalog<'_>,
    allow_migration: bool,
) -> Result<BTreeSet<String>, ManagedStoreError> {
    sqlite_support::admit_schema(
        conn,
        catalog.migrations,
        MANAGED_STORE_LABEL,
        allow_migration,
    )
}

#[cfg(test)]
fn read_validated_ledger(
    conn: &Connection,
    catalog: ManagedStoreMigrationCatalog<'_>,
) -> Result<ValidatedLedger, ManagedStoreError> {
    sqlite_support::read_validated_ledger(conn, catalog.migrations, MANAGED_STORE_LABEL)
}

fn check_schema_ready(
    conn: &Connection,
    schema_version: &str,
    latest_migration_checksum: &str,
) -> Result<(), ManagedStoreError> {
    if !migrations_table_exists(conn)? {
        return Err(ManagedStoreError::MigrationRequired);
    }
    let migration: Option<(String, String)> = conn
        .query_row(
            "SELECT version, checksum FROM schema_migrations ORDER BY version DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sql_unavailable)?;
    match migration {
        Some((version, checksum))
            if version == schema_version && checksum == latest_migration_checksum =>
        {
            Ok(())
        }
        Some(_) | None => Err(ManagedStoreError::MigrationRequired),
    }
}

fn migrations_table_exists(conn: &Connection) -> Result<bool, ManagedStoreError> {
    Ok(sqlite_support::migrations_table_exists(conn)?)
}

fn sqlite_object_exists(
    conn: &Connection,
    object_type: &str,
    name: &str,
) -> Result<bool, ManagedStoreError> {
    Ok(sqlite_support::sqlite_object_exists(
        conn,
        object_type,
        name,
    )?)
}

fn validate_baseline_structure(conn: &Connection) -> Result<(), ManagedStoreError> {
    let expected = Connection::open_in_memory().map_err(sql_unavailable)?;
    expected
        .execute_batch(MANAGED_STORE_BASELINE_SQL)
        .map_err(sql_unavailable)?;
    compare_schema(conn, &expected)?;
    run_foreign_key_check(conn)?;
    run_quick_check(conn)?;
    check_policy_revision_ready(conn)
}
fn validate_principal_service_limits_structure(conn: &Connection) -> Result<(), ManagedStoreError> {
    let expected = expected_schema_connection(true, true)?;
    for sql in [
        OAUTH_SQL,
        REGISTERED_RESOURCE_TYPES_SQL,
        RESOURCE_ATTRIBUTES_SQL,
        LOCAL_PASSWORD_FAILURES_SQL,
        PRINCIPAL_SERVICE_LIMITS_SQL,
    ] {
        expected.execute_batch(sql).map_err(sql_unavailable)?;
    }
    compare_schema(conn, &expected)?;
    run_foreign_key_check(conn)?;
    run_quick_check(conn)?;
    check_secret_material_ready(conn, None)?;
    check_policy_revision_ready(conn)
}

fn validate_resource_attributes_structure(conn: &Connection) -> Result<(), ManagedStoreError> {
    let expected = expected_schema_connection(true, true)?;
    expected.execute_batch(OAUTH_SQL).map_err(sql_unavailable)?;
    expected
        .execute_batch(REGISTERED_RESOURCE_TYPES_SQL)
        .map_err(sql_unavailable)?;
    expected
        .execute_batch(RESOURCE_ATTRIBUTES_SQL)
        .map_err(sql_unavailable)?;
    compare_schema(conn, &expected)?;
    run_foreign_key_check(conn)?;
    run_quick_check(conn)?;
    check_secret_material_ready(conn, None)?;
    check_policy_revision_ready(conn)
}

fn validate_registered_resource_types_structure(
    conn: &Connection,
) -> Result<(), ManagedStoreError> {
    let expected = expected_schema_connection(true, true)?;
    expected.execute_batch(OAUTH_SQL).map_err(sql_unavailable)?;
    expected
        .execute_batch(REGISTERED_RESOURCE_TYPES_SQL)
        .map_err(sql_unavailable)?;
    compare_schema(conn, &expected)?;
    run_foreign_key_check(conn)?;
    run_quick_check(conn)?;
    check_secret_material_ready(conn, None)?;
    check_policy_revision_ready(conn)
}

fn validate_oauth_structure(conn: &Connection) -> Result<(), ManagedStoreError> {
    let expected = expected_schema_connection(true, true)?;
    expected.execute_batch(OAUTH_SQL).map_err(sql_unavailable)?;
    compare_schema(conn, &expected)?;
    run_foreign_key_check(conn)?;
    run_quick_check(conn)?;
    check_secret_material_ready(conn, None)?;
    check_policy_revision_ready(conn)
}
fn validate_managed_store_latest_structure(conn: &Connection) -> Result<(), ManagedStoreError> {
    validate_managed_store_structure(conn, true, true)?;
    check_policy_revision_ready(conn)
}
fn validate_cloudbees_ci_structure(conn: &Connection) -> Result<(), ManagedStoreError> {
    validate_managed_store_structure(conn, true, false)?;
    check_policy_revision_ready(conn)
}
fn validate_identity_tokens_structure(conn: &Connection) -> Result<(), ManagedStoreError> {
    validate_managed_store_structure(conn, false, false)?;
    check_policy_revision_ready(conn)
}

fn check_policy_revision_ready(conn: &Connection) -> Result<(), ManagedStoreError> {
    let (row_count, minimum_id, maximum_id): (i64, Option<i64>, Option<i64>) = conn
        .query_row(
            "SELECT COUNT(1), MIN(id), MAX(id) FROM policy_revisions",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(sql_unavailable)?;
    if row_count != 1 || minimum_id != Some(1) || maximum_id != Some(1) {
        return Err(ManagedStoreError::SchemaInvalid(
            "policy revision singleton row is missing".to_string(),
        ));
    }
    let generation: i64 = conn
        .query_row(
            "SELECT generation FROM policy_revisions WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .map_err(sql_unavailable)?;
    if generation < 0 {
        return Err(ManagedStoreError::SchemaInvalid(
            "policy revision generation is invalid".to_string(),
        ));
    }
    Ok(())
}

fn validate_managed_store_structure(
    conn: &Connection,
    include_cloudbees_ci: bool,
    remove_shell_approval: bool,
) -> Result<(), ManagedStoreError> {
    let expected = expected_schema_connection(include_cloudbees_ci, remove_shell_approval)?;
    compare_schema(conn, &expected)?;
    run_foreign_key_check(conn)?;
    run_quick_check(conn)?;
    check_secret_material_ready(conn, None)?;
    Ok(())
}

fn expected_schema_connection(
    include_cloudbees_ci: bool,
    remove_shell_approval: bool,
) -> Result<Connection, ManagedStoreError> {
    let expected = Connection::open_in_memory().map_err(sql_unavailable)?;
    expected
        .execute_batch(MANAGED_STORE_BASELINE_SQL)
        .map_err(sql_unavailable)?;
    expected
        .execute_batch(IDENTITY_TOKENS_SQL)
        .map_err(sql_unavailable)?;
    if include_cloudbees_ci {
        expected
            .execute_batch(CLOUDBEES_CI_JOB_NAMESPACE_SQL)
            .map_err(sql_unavailable)?;
    }
    if remove_shell_approval {
        expected
            .execute_batch(REMOVE_SHELL_APPROVAL_SQL)
            .map_err(sql_unavailable)?;
    }
    Ok(expected)
}

fn compare_schema(actual: &Connection, expected: &Connection) -> Result<(), ManagedStoreError> {
    Ok(sqlite_support::compare_schema(
        actual,
        expected,
        MANAGED_STORE_LABEL,
    )?)
}

#[cfg(test)]
fn table_info(
    conn: &Connection,
    table: &str,
) -> Result<Vec<sqlite_support::ColumnInfo>, ManagedStoreError> {
    Ok(sqlite_support::table_info(conn, table)?)
}

fn run_foreign_key_check(conn: &Connection) -> Result<(), ManagedStoreError> {
    Ok(sqlite_support::run_foreign_key_check(
        conn,
        MANAGED_STORE_LABEL,
    )?)
}

fn run_quick_check(conn: &Connection) -> Result<(), ManagedStoreError> {
    Ok(sqlite_support::run_quick_check(conn, MANAGED_STORE_LABEL)?)
}

fn count_table(conn: &Connection, table: &str) -> Result<u64, ManagedStoreError> {
    let sql = format!("SELECT COUNT(1) FROM {table}");
    let count: i64 = conn
        .query_row(&sql, [], |row| row.get(0))
        .map_err(sql_unavailable)?;
    Ok(count as u64)
}

fn count_table_if_exists(conn: &Connection, table: &str) -> Result<u64, ManagedStoreError> {
    if sqlite_object_exists(conn, "table", table)? {
        count_table(conn, table)
    } else {
        Ok(0)
    }
}

fn active_credential_key_ids(conn: &Connection) -> Result<Vec<String>, ManagedStoreError> {
    let mut statement = conn
        .prepare(
            "SELECT DISTINCT m.key_id
             FROM credential_secret_material m
             INNER JOIN credentials c ON c.credential_id = m.credential_id
             WHERE c.status = 'active'
             UNION SELECT key_id FROM principal_identity_tokens WHERE key_id IS NOT NULL
             UNION SELECT key_id FROM oauth_slots
             UNION SELECT key_id FROM oauth_revocations WHERE key_id IS NOT NULL
             UNION SELECT key_id FROM resource_secret_material
             UNION SELECT key_id FROM imported_secret_material
             UNION SELECT origin_key_id FROM secret_reference_receipts
             UNION SELECT key_id FROM secret_reference_material WHERE key_id IS NOT NULL
             UNION SELECT key_id FROM secret_reference_caller_generations
             ORDER BY key_id",
        )
        .map_err(sql_unavailable)?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sql_unavailable)?;
    collect_rows(rows)
}

fn check_secret_material_ready(
    conn: &Connection,
    key_ring: Option<&CredentialKeyRing>,
) -> Result<(), ManagedStoreError> {
    let mut credentials = conn
        .prepare(
            "SELECT credential_id, metadata_json, secret_backend, secret_ref, material_version,
                    profile, credential_kind
             FROM credentials
             WHERE status = 'active'
             ORDER BY credential_id",
        )
        .map_err(sql_unavailable)?;
    let rows = credentials
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })
        .map_err(sql_unavailable)?;
    for row in rows {
        let (
            credential_id,
            metadata_json,
            secret_backend,
            secret_ref,
            material_version,
            profile,
            credential_kind,
        ) = row.map_err(sql_unavailable)?;
        serde_json::from_str::<Value>(&metadata_json).map_err(|_| {
            ManagedStoreError::SchemaInvalid("credential metadata is malformed".to_string())
        })?;
        if !is_safe_identifier(&profile) {
            return Err(ManagedStoreError::SchemaInvalid(
                "credential profile is malformed".to_string(),
            ));
        }
        if !matches!(credential_kind.as_str(), "basic_api_token" | "bearer_token") {
            return Err(ManagedStoreError::SchemaInvalid(
                "credential kind is unsupported".to_string(),
            ));
        }
        if secret_backend != SQLITE_ENCRYPTED_BACKEND {
            return Err(ManagedStoreError::SchemaInvalid(
                "credential secret backend is unsupported".to_string(),
            ));
        }
        validate_sqlite_secret_ref_for_schema(&secret_ref)?;
        validate_uuid_for_schema(&material_version, "credential material version")?;
        let material = conn
            .query_row(
                "SELECT credential_id, backend, key_id, secret_nonce, secret_ciphertext
                 FROM credential_secret_material
                 WHERE secret_ref = ?1",
                params![secret_ref],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(sql_unavailable)?;
        let Some((material_credential_id, material_backend, key_id, nonce, ciphertext)) = material
        else {
            return Err(ManagedStoreError::SchemaInvalid(
                "credential secret material is missing".to_string(),
            ));
        };
        if material_credential_id != credential_id {
            return Err(ManagedStoreError::SchemaInvalid(
                "credential secret material does not match credential".to_string(),
            ));
        }
        if material_backend != SQLITE_ENCRYPTED_BACKEND {
            return Err(ManagedStoreError::SchemaInvalid(
                "credential secret material backend is unsupported".to_string(),
            ));
        }
        validate_safe_key_id(&key_id)?;
        if nonce.len() != 12 || ciphertext.len() < 16 {
            return Err(ManagedStoreError::SchemaInvalid(
                "credential secret material is malformed".to_string(),
            ));
        }
        if let Some(key_ring) = key_ring {
            let encrypted = encrypted_credential_by_secret_ref_and_key(conn, &secret_ref, &key_id)?
                .ok_or_else(|| {
                    ManagedStoreError::SchemaInvalid(
                        "credential secret material does not match credential".to_string(),
                    )
                })?;
            // Readiness checks retained material integrity, independently of
            // expiry or the provider's configured credential profile.
            decrypt_execution_credential(key_ring, &encrypted)?;
        }
    }

    let invalid_material: Option<String> = conn
        .query_row(
            "SELECT m.secret_ref
             FROM credential_secret_material m
             LEFT JOIN credentials c ON c.credential_id = m.credential_id
             WHERE c.credential_id IS NULL
                OR c.secret_ref <> m.secret_ref
                OR m.backend <> 'sqlite_encrypted'
             LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql_unavailable)?;
    if invalid_material.is_some() {
        return Err(ManagedStoreError::SchemaInvalid(
            "credential secret material is orphaned or inconsistent".to_string(),
        ));
    }
    Ok(())
}

#[derive(Clone)]
pub struct CredentialKeyRing {
    active_key: String,
    keys: Arc<BTreeMap<String, [u8; 32]>>,
}

impl std::fmt::Debug for CredentialKeyRing {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialKeyRing")
            .field("active_key", &self.active_key)
            .field("key_count", &self.keys.len())
            .finish()
    }
}

impl CredentialKeyRing {
    pub fn load(config: &CredentialEncryptionConfig) -> Result<Self, ManagedStoreError> {
        let mut keys = BTreeMap::new();
        for key in &config.keys {
            let material = load_key_material(key)?;
            if keys.insert(key.id.clone(), material).is_some() {
                return Err(ManagedStoreError::EncryptionKeyInvalid(format!(
                    "duplicate key id {}",
                    key.id
                )));
            }
        }
        if !keys.contains_key(&config.active_key) {
            return Err(ManagedStoreError::EncryptionKeyMissing(
                config.active_key.clone(),
            ));
        }
        Ok(Self {
            active_key: config.active_key.clone(),
            keys: Arc::new(keys),
        })
    }

    pub fn active_key_id(&self) -> &str {
        &self.active_key
    }

    pub fn key_ids(&self) -> Vec<String> {
        self.keys.keys().cloned().collect()
    }

    pub fn has_key(&self, key_id: &str) -> bool {
        self.keys.contains_key(key_id)
    }

    fn encrypt(
        &self,
        secret: &Value,
        aad: &CredentialAad,
    ) -> Result<EncryptedSecret, ManagedStoreError> {
        self.encrypt_with_key(&self.active_key, secret, aad)
    }

    fn encrypt_with_key(
        &self,
        key_id: &str,
        secret: &Value,
        aad: &CredentialAad,
    ) -> Result<EncryptedSecret, ManagedStoreError> {
        let key = self
            .keys
            .get(key_id)
            .ok_or_else(|| ManagedStoreError::EncryptionKeyMissing(key_id.to_string()))?;
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| ManagedStoreError::EncryptionKeyInvalid(key_id.to_string()))?;
        let mut nonce = [0_u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let plaintext =
            serde_json::to_vec(secret).map_err(|_| ManagedStoreError::CredentialEncryptFailed)?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: aad.bytes().as_bytes(),
                },
            )
            .map_err(|_| ManagedStoreError::CredentialEncryptFailed)?;
        Ok(EncryptedSecret {
            key_id: key_id.to_string(),
            nonce: nonce.to_vec(),
            ciphertext,
        })
    }

    fn decrypt(
        &self,
        key_id: &str,
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &CredentialAad,
    ) -> Result<Value, ManagedStoreError> {
        let key = self
            .keys
            .get(key_id)
            .ok_or_else(|| ManagedStoreError::EncryptionKeyMissing(key_id.to_string()))?;
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| ManagedStoreError::EncryptionKeyInvalid(key_id.to_string()))?;
        let nonce: [u8; 12] = nonce
            .try_into()
            .map_err(|_| ManagedStoreError::CredentialDecryptFailed)?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad: aad.bytes().as_bytes(),
                },
            )
            .map_err(|_| ManagedStoreError::CredentialDecryptFailed)?;
        serde_json::from_slice(&plaintext).map_err(|_| ManagedStoreError::CredentialDecryptFailed)
    }
}

fn load_key_material(
    config: &CredentialEncryptionKeyConfig,
) -> Result<[u8; 32], ManagedStoreError> {
    let raw = match config.provider.as_str() {
        "env" => {
            let name = config.env.as_deref().ok_or_else(|| {
                ManagedStoreError::EncryptionKeyInvalid(format!("key {} missing env", config.id))
            })?;
            std::env::var(name).map_err(|_| {
                ManagedStoreError::EncryptionKeyMissing(format!("env key {}", config.id))
            })?
        }
        "file" => {
            let path = config.path.as_deref().ok_or_else(|| {
                ManagedStoreError::EncryptionKeyInvalid(format!("key {} missing path", config.id))
            })?;
            fs::read_to_string(path).map_err(|_| {
                ManagedStoreError::EncryptionKeyMissing(format!("file key {}", config.id))
            })?
        }
        _ => {
            return Err(ManagedStoreError::EncryptionKeyInvalid(format!(
                "key {} has unsupported provider",
                config.id
            )));
        }
    };
    let trimmed = raw.strip_suffix('\n').unwrap_or(&raw);
    let bytes = URL_SAFE_NO_PAD.decode(trimmed).map_err(|_| {
        ManagedStoreError::EncryptionKeyInvalid(format!("key {} is not base64url", config.id))
    })?;
    bytes.try_into().map_err(|_| {
        ManagedStoreError::EncryptionKeyInvalid(format!(
            "key {} must decode to 32 bytes",
            config.id
        ))
    })
}

#[derive(Clone)]
struct EncryptedSecret {
    key_id: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(Debug, Clone)]
struct CredentialAad {
    credential_id: String,
    owner_kind: String,
    owner_principal_id: String,
    service: String,
    name: String,
    profile: String,
    credential_kind: String,
    secret_backend: String,
    secret_ref: String,
    material_version: String,
    key_id: String,
}

impl CredentialAad {
    fn bytes(&self) -> String {
        format!(
            "schema_version={};credential_id={};owner_kind={};owner_principal={};service={};name={};credential_profile={};credential_kind={};secret_backend={};secret_ref={};material_version={};key_id={}",
            CREDENTIAL_AAD_SCHEMA_VERSION,
            self.credential_id,
            self.owner_kind,
            self.owner_principal_id,
            self.service,
            self.name,
            self.profile,
            self.credential_kind,
            self.secret_backend,
            self.secret_ref,
            self.material_version,
            self.key_id
        )
    }
}

#[derive(Clone)]
pub struct BrokerTokenHasher {
    key: Arc<[u8; 32]>,
}

impl std::fmt::Debug for BrokerTokenHasher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerTokenHasher")
            .field("key", &"<redacted>")
            .finish()
    }
}

impl BrokerTokenHasher {
    pub fn load(config: &BrokerTokensConfig) -> Result<Self, ManagedStoreError> {
        Ok(Self {
            key: Arc::new(load_base64url_32_byte_secret(
                "broker_tokens.hash_key_ref",
                &config.hash_key_ref,
                "broker token hash key",
            )?),
        })
    }

    pub fn hash(&self, raw_token: &str) -> Result<String, ManagedStoreError> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(self.key.as_ref()).map_err(|_| {
            ManagedStoreError::EncryptionKeyInvalid("broker token hash key".to_string())
        })?;
        mac.update(raw_token.as_bytes());
        Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
    }

    pub fn hmac_base64url(
        &self,
        context: &[u8],
        payload: &[u8],
    ) -> Result<String, ManagedStoreError> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(self.key.as_ref()).map_err(|_| {
            ManagedStoreError::EncryptionKeyInvalid("broker token hash key".to_string())
        })?;
        mac.update(context);
        mac.update(payload);
        Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
    }
}

impl agent_access_provider::StableSigningKey for BrokerTokenHasher {
    fn hmac_base64url(
        &self,
        context: &[u8],
        payload: &[u8],
    ) -> Result<String, agent_access_provider::SigningError> {
        BrokerTokenHasher::hmac_base64url(self, context, payload)
            .map_err(|_| agent_access_provider::SigningError)
    }
}

#[derive(Clone)]
pub struct LocalPasswordHasher {
    key: Arc<[u8; 32]>,
    #[cfg(test)]
    verification_hook: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl std::fmt::Debug for LocalPasswordHasher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalPasswordHasher")
            .field("key", &"<redacted>")
            .finish()
    }
}

impl LocalPasswordHasher {
    pub fn load(label: &str, secret_ref: &str) -> Result<Self, ManagedStoreError> {
        Ok(Self {
            #[cfg(test)]
            verification_hook: None,
            key: Arc::new(load_base64url_32_byte_secret(
                label,
                secret_ref,
                "local password pepper",
            )?),
        })
    }

    pub fn hash_password(&self, password: &str) -> Result<String, ManagedStoreError> {
        let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
        let digest = self.password_digest(password)?;
        local_password_argon2()
            .hash_password(&digest, &salt)
            .map(|hash| hash.to_string())
            .map_err(|_| {
                ManagedStoreError::EncryptionKeyInvalid("local password hasher".to_string())
            })
    }

    fn verify_password(
        &self,
        password: &str,
        password_hash_phc: &str,
    ) -> Result<bool, ManagedStoreError> {
        #[cfg(test)]
        if let Some(hook) = &self.verification_hook {
            hook();
        }
        let digest = self.password_digest(password)?;
        let parsed = PasswordHash::new(password_hash_phc).map_err(|_| {
            ManagedStoreError::SchemaInvalid("local password hash is malformed".to_string())
        })?;
        Ok(Argon2::default().verify_password(&digest, &parsed).is_ok())
    }

    fn password_digest(&self, password: &str) -> Result<[u8; 32], ManagedStoreError> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(self.key.as_ref()).map_err(|_| {
            ManagedStoreError::EncryptionKeyInvalid("local password pepper".to_string())
        })?;
        mac.update(b"aab-local-password-v1:");
        mac.update(password.as_bytes());
        let bytes = mac.finalize().into_bytes();
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&bytes);
        Ok(digest)
    }
}

fn local_password_argon2() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            LOCAL_PASSWORD_ARGON2_MEMORY_KIB,
            LOCAL_PASSWORD_ARGON2_ITERATIONS,
            LOCAL_PASSWORD_ARGON2_PARALLELISM,
            None,
        )
        .expect("local password Argon2id parameters must be valid"),
    )
}

fn dummy_local_password_hash_phc() -> &'static str {
    DUMMY_LOCAL_PASSWORD_HASH_PHC
        .get_or_init(|| {
            let salt = SaltString::from_b64("YWFiLWxvY2FsLXBhc3N3b3JkLWR1bW15")
                .expect("dummy local password salt must be valid PHC base64");
            local_password_argon2()
                .hash_password(&[0_u8; 32], &salt)
                .expect("dummy local password hash must be computable")
                .to_string()
        })
        .as_str()
}

#[derive(Clone)]
pub struct BrowserCsrfKey {
    key: Arc<[u8; 32]>,
}

impl std::fmt::Debug for BrowserCsrfKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrowserCsrfKey")
            .field("key", &"<redacted>")
            .finish()
    }
}

impl BrowserCsrfKey {
    pub fn load(label: &str, secret_ref: &str) -> Result<Self, ManagedStoreError> {
        Ok(Self {
            key: Arc::new(load_base64url_32_byte_secret(
                label,
                secret_ref,
                "browser CSRF key",
            )?),
        })
    }

    pub fn token_for_session(&self, token_id: &str) -> Result<String, ManagedStoreError> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(self.key.as_ref())
            .map_err(|_| ManagedStoreError::EncryptionKeyInvalid("browser CSRF key".to_string()))?;
        mac.update(b"aab-browser-csrf-v1:");
        mac.update(token_id.as_bytes());
        Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
    }
}

fn load_base64url_32_byte_secret(
    label: &str,
    secret_ref: &str,
    public_name: &str,
) -> Result<[u8; 32], ManagedStoreError> {
    let raw = load_secret_ref_value(label, secret_ref)
        .map_err(|_| ManagedStoreError::EncryptionKeyMissing(public_name.to_string()))?;
    let trimmed = raw.strip_suffix('\n').unwrap_or(&raw);
    let key = URL_SAFE_NO_PAD.decode(trimmed).map_err(|_| {
        ManagedStoreError::EncryptionKeyInvalid(format!("{public_name} is not base64url"))
    })?;
    key.try_into().map_err(|_| {
        ManagedStoreError::EncryptionKeyInvalid(format!("{public_name} must decode to 32 bytes"))
    })
}

fn generate_broker_token(token_class: &BrokerTokenClass) -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    format!(
        "aab_{}_{}",
        token_class.prefix(),
        URL_SAFE_NO_PAD.encode(bytes)
    )
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.ct_eq(right).into()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BrokerTokenClass {
    AgentInvoke,
    UserManage,
    Admin,
}

impl BrokerTokenClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AgentInvoke => "agent_invoke",
            Self::UserManage => "user_manage",
            Self::Admin => "admin",
        }
    }

    pub fn prefix(&self) -> &'static str {
        match self {
            Self::AgentInvoke => "ai",
            Self::UserManage => "um",
            Self::Admin => "ad",
        }
    }
}

impl std::str::FromStr for BrokerTokenClass {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "agent_invoke" => Ok(Self::AgentInvoke),
            "user_manage" => Ok(Self::UserManage),
            "admin" => Ok(Self::Admin),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ManagedStoreStatus {
    pub path: String,
    pub schema_version: String,
    pub schema_checksum: String,
    pub principals: u64,
    pub groups: u64,
    pub broker_tokens: u64,
    pub rights: u64,
    pub credentials: u64,
    pub key_ids_in_use: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ManagedPolicyRevision {
    pub generation: u64,
    pub updated_at: String,
    pub updated_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ManagedPolicyGrantRecord {
    pub grant_id: String,
    pub grant_order: i64,
    pub subjects: Vec<String>,
    pub execution_contexts: Vec<String>,
    pub service: String,
    pub actions: Vec<String>,
    pub resources: ResourceSelection,
    pub credential_mode: String,
    pub priority: Option<i32>,
    pub status: String,
    pub description: Option<String>,
    pub version: i64,
    pub created_at: String,
    pub created_by: String,
    pub updated_at: String,
    pub updated_by: String,
    pub disabled_at: Option<String>,
    pub deleted_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ManagedPolicyGrantCreateRequest {
    pub grant_id: Option<String>,
    pub subjects: Vec<String>,
    pub execution_contexts: Vec<String>,
    pub service: String,
    pub actions: Vec<String>,
    pub resources: ResourceSelection,
    pub credential_mode: String,
    pub priority: Option<i32>,
    pub status: Option<String>,
    pub description: Option<String>,
    pub created_by: String,
}

#[derive(Debug, Clone)]
pub struct ManagedPolicyGrantPatchRequest {
    pub grant_id: String,
    pub expected_version: i64,
    pub subjects: Option<Vec<String>>,
    pub execution_contexts: Option<Vec<String>>,
    pub service: Option<String>,
    pub actions: Option<Vec<String>>,
    pub resources: Option<ResourceSelection>,
    pub credential_mode: Option<String>,
    pub priority: Option<Option<i32>>,
    pub status: Option<String>,
    pub description: Option<Option<String>>,
    pub updated_by: String,
}

#[derive(Debug, Clone)]
pub struct ManagedPolicyGrantStatusRequest {
    pub grant_id: String,
    pub expected_version: i64,
    pub updated_by: String,
}

#[derive(Debug, Clone)]
pub struct ManagedPolicyGrantSubjectAddRequest {
    pub grant_id: String,
    pub expected_version: i64,
    pub subject: String,
    pub updated_by: String,
}

#[derive(Debug, Clone)]
pub struct ManagedPolicyGrantSubjectRemoveRequest {
    pub grant_id: String,
    pub expected_version: i64,
    pub subject: String,
    pub last_subject_behavior: String,
    pub updated_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ManagedPolicyMutationResult {
    pub catalog: ManagedResourceCatalog,
    pub previous_revision: ManagedPolicyRevision,
    pub revision: ManagedPolicyRevision,
    pub grant: ManagedPolicyGrantRecord,
    pub active_grants: Vec<ManagedPolicyGrantRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ManagedPolicySubjectCatalog {
    pub principals: BTreeSet<String>,
    pub groups: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PrincipalRecord {
    pub sign_in_methods: SignInMethods,
    pub principal_id: String,
    pub kind: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub external_subject: Option<String>,
    pub status: String,
    pub groups: Vec<String>,
    pub role: PrincipalRole,
    pub self_service_enabled: bool,
    pub created_at: String,
    pub updated_at: String,
    pub disabled_at: Option<String>,
    pub created_by: String,
}

impl PrincipalRecord {
    /// The principal's kind, which selects its credential connections'
    /// methods; `None` for a stored value no kind names.
    pub fn principal_kind(&self) -> Option<crate::PrincipalKind> {
        crate::PrincipalKind::from_stored(&self.kind)
    }
}

/// Enrollment state, independent of provider health, principal status or lockout.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignInMethodStatus {
    #[default]
    Absent,
    Active,
    Disabled,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignInMethods {
    pub local_password: SignInMethodStatus,
    pub microsoft: SignInMethodStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GroupRecord {
    pub group_id: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub status: String,
    pub created_at: Option<String>,
    pub created_by: Option<String>,
    pub updated_at: Option<String>,
    pub updated_by: Option<String>,
    pub disabled_at: Option<String>,
    pub member_count: u64,
}

#[derive(Debug, Clone)]
pub struct GroupWriteRequest {
    pub group_id: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub created_by: String,
}

#[derive(Debug, Clone)]
pub struct GroupPatchRequest {
    pub group_id: String,
    pub display_name: Option<Option<String>>,
    pub description: Option<Option<String>>,
    pub status: Option<String>,
    pub updated_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GroupMemberRecord {
    pub principal_id: String,
    pub kind: Option<String>,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub status: Option<String>,
    pub created_at: Option<String>,
    pub created_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub membership: Option<EffectiveGroupMembershipRecord>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrincipalWriteRequest {
    #[serde(default)]
    pub role: PrincipalRole,
    pub self_service_enabled: Option<bool>,
    pub principal_id: String,
    pub kind: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub external_subject: Option<String>,
    pub created_by: String,
}

#[derive(Debug, Clone)]
pub struct PrincipalPatchRequest {
    pub principal_id: String,
    pub display_name: Option<Option<String>>,
    pub email: Option<Option<String>>,
    pub status: Option<String>,
}

#[derive(Debug, Clone)]
pub struct InitialAdminBootstrapRequest {
    pub principal_id: String,
    pub password: String,
    pub min_password_length: usize,
}

#[derive(Debug, Clone)]
pub struct BrokerTokenIssueRequest {
    pub principal_id: String,
    pub name: String,
    pub token_class: BrokerTokenClass,
    pub scopes: Value,
    pub expires_at: Option<String>,
    pub created_by: String,
}

impl BrokerTokenIssueRequest {
    pub fn expires_after(mut self, ttl_seconds: u64) -> Self {
        self.expires_at = Some(normalized_timestamp(
            Utc::now() + Duration::seconds(ttl_seconds as i64),
        ));
        self
    }
}

#[derive(Debug, Clone)]
pub struct SelfAgentTokenIssueRequest {
    pub principal_id: String,
    pub name: String,
    pub scopes: Value,
    pub expires_at: Option<String>,
    pub created_by: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IssuedBrokerToken {
    pub token: String,
    pub record: BrokerTokenRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BrokerTokenRecord {
    pub token_id: String,
    #[serde(skip_serializing)]
    pub token_hash: String,
    pub principal_id: String,
    pub name: String,
    pub token_class: BrokerTokenClass,
    pub scopes: Value,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
    pub revoked_by: Option<String>,
    pub paused_at: Option<String>,
    pub paused_by: Option<String>,
    pub last_used_at: Option<String>,
    pub created_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerTokenIdentity {
    pub principal_id: String,
    pub principal_kind: Option<crate::PrincipalKind>,
    pub groups: Vec<String>,
    pub policy_groups: Vec<String>,
    pub role: PrincipalRole,
    pub self_service_enabled: bool,
    pub token_class: BrokerTokenClass,
    pub token_id: String,
    pub scopes: Value,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LocalPasswordWriteRequest {
    pub principal_id: String,
    pub password: String,
    pub min_password_length: usize,
    pub password_change_required: bool,
    pub actor: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnabledLocalPassword {
    #[serde(flatten)]
    pub method: LoginMethodRecord,
    pub previous_status: SignInMethodStatus,
}

pub struct LocalPasswordChangeRequest {
    pub verification: LocalPasswordVerifyRequest,
    pub new_password: String,
    pub min_password_length: usize,
    pub replace_local_session: bool,
    pub session_ttl_seconds: u64,
}

pub struct ChangedLocalPassword {
    pub verified: VerifiedLocalPassword,
    pub replacement_session: Option<IssuedBrowserSession>,
}

pub struct AuthenticatedLocalPassword {
    pub verified: VerifiedLocalPassword,
    pub session: IssuedBrowserSession,
}

#[derive(Debug, Clone)]
pub struct LocalPasswordVerifyRequest {
    pub principal_id: String,
    pub password: String,
    /// Grouped client source (full IPv4 address or IPv6 /64 prefix). Failed
    /// attempts and lockouts are counted per principal and source.
    pub source: String,
    pub max_failed_attempts: u32,
    pub lockout_ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LoginMethodRecord {
    pub login_method_id: String,
    pub principal_id: String,
    pub method: String,
    pub external_provider: Option<String>,
    pub external_subject: Option<String>,
    pub status: String,
    pub password_set_at: Option<String>,
    pub must_change_password: bool,
    /// Whether any source is currently locked out of this local password.
    pub locked: bool,
    /// Latest active lockout expiry across sources.
    pub locked_until: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub created_by: String,
    pub updated_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLocalPassword {
    pub sign_in_methods: SignInMethods,
    pub principal_id: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub policy_groups: Vec<String>,
    pub role: PrincipalRole,
    pub self_service_enabled: bool,
    pub login_method_id: String,
    pub password_change_required: bool,
}

#[derive(Debug, Clone)]
pub struct BrowserSessionIssueRequest {
    pub principal_id: String,
    pub login_method: String,
    pub login_method_id: Option<String>,
    pub ttl_seconds: u64,
    pub password_change_required: bool,
    pub created_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BrowserSessionRecord {
    pub token_id: String,
    pub principal_id: String,
    pub login_method: String,
    pub login_method_id: Option<String>,
    pub auth_time: String,
    pub created_at: String,
    pub password_change_required: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IssuedBrowserSession {
    pub token: String,
    pub record: BrokerTokenRecord,
    pub session: BrowserSessionRecord,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BrowserSessionIdentity {
    pub sign_in_methods: SignInMethods,
    pub principal_id: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub policy_groups: Vec<String>,
    pub role: PrincipalRole,
    pub self_service_enabled: bool,
    pub token_id: String,
    pub scopes: Value,
    pub expires_at: Option<String>,
    pub login_method: String,
    pub login_method_id: Option<String>,
    pub auth_time: String,
    pub password_change_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OidcProviderStateRecord {
    pub provider_id: String,
    pub tenant_id: String,
    pub client_id: String,
    pub enabled: bool,
    pub config_generation: u64,
    pub config_fingerprint: String,
    pub external_membership_ttl_seconds: u64,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct OidcProviderStateReconcileRequest {
    pub tenant_id: String,
    pub client_id: String,
    pub enabled: bool,
    pub config_fingerprint: String,
    pub external_membership_ttl_seconds: u64,
    pub invalidate_existing_evidence: bool,
    pub actor: String,
}

#[derive(Debug, Clone)]
pub struct OidcFlowCreateRequest {
    pub state_hash: Vec<u8>,
    pub browser_binding_hash: Vec<u8>,
    pub provider_generation: u64,
    pub encrypted_payload: Vec<u8>,
    pub encryption_nonce: Vec<u8>,
    pub return_path: String,
    pub expires_at: String,
    pub max_pending_flows: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OidcFlowRecord {
    pub flow_sequence: u64,
    #[serde(skip_serializing)]
    pub state_hash: Vec<u8>,
    #[serde(skip_serializing)]
    pub browser_binding_hash: Vec<u8>,
    pub provider_generation: u64,
    #[serde(skip_serializing)]
    pub encrypted_payload: Vec<u8>,
    #[serde(skip_serializing)]
    pub encryption_nonce: Vec<u8>,
    pub return_path: String,
    pub created_at: String,
    pub expires_at: String,
    pub consumed_at: Option<String>,
    pub outcome_code: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OidcFlowClaimRequest {
    pub state_hash: Vec<u8>,
    pub browser_binding_hash: Vec<u8>,
    pub provider_generation: u64,
    pub outcome_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExternalGroupBindingRecord {
    pub binding_id: String,
    pub external_group_id: String,
    pub group_id: String,
    pub status: String,
    pub created_at: String,
    pub created_by: String,
    pub updated_at: String,
    pub updated_by: String,
}

#[derive(Debug, Clone)]
pub struct ExternalGroupBindingCreateRequest {
    pub external_group_id: String,
    pub group_id: String,
    pub actor: String,
}

#[derive(Debug, Clone)]
pub struct OidcLoginMethodLinkRequest {
    pub principal_id: String,
    pub user_object_id: String,
    pub actor: String,
}

#[derive(Debug, Clone)]
pub struct OidcCompleteLoginRequest {
    pub flow_sequence: u64,
    pub provider_generation: u64,
    pub external_subject: String,
    pub external_group_ids: BTreeSet<String>,
    pub jit_provisioning: bool,
    pub jit_principal_id: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub evidence_at: String,
    pub callback_now: String,
    pub session_ttl_seconds: u64,
    pub created_by: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OidcCompleteLoginResult {
    pub principal: PrincipalRecord,
    pub login_method: LoginMethodRecord,
    pub session: IssuedBrowserSession,
    pub membership: EffectiveMembershipRecord,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", tag = "outcome")]
pub enum OidcCompletionOutcome {
    Succeeded {
        result: Box<OidcCompleteLoginResult>,
        jit_created: bool,
    },
    Denied {
        reason: String,
    },
    Superseded,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveMembershipRecord {
    pub groups: Vec<String>,
    pub policy_groups: Vec<String>,
    pub details: Vec<EffectiveGroupMembershipRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveGroupMembershipRecord {
    pub group_id: String,
    pub effective: bool,
    pub source: String,
    pub local: Option<LocalMembershipContributionRecord>,
    pub microsoft: Vec<MicrosoftMembershipContributionRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LocalMembershipContributionRecord {
    pub added_at: String,
    pub added_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MicrosoftMembershipContributionRecord {
    pub binding_id: String,
    pub external_group_id: String,
    pub observed_at: String,
    pub valid_until: String,
    pub current: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LocalGroupRemovalResult {
    pub removed: bool,
    pub still_effective: bool,
}

#[derive(Debug, Clone)]
pub struct RightGrantRequest {
    pub principal_id: String,
    pub right: String,
    pub service: Option<String>,
    pub credential_name: Option<String>,
    pub resource_scope_json: Option<String>,
    pub created_by: String,
    pub expires_at: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RightRecord {
    pub right_id: String,
    pub principal_id: String,
    pub right: String,
    pub service: Option<String>,
    pub credential_name: Option<String>,
    pub resource_scope_json: Option<String>,
    pub created_by: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
    pub revoked_by: Option<String>,
    pub reason: Option<String>,
}

#[derive(Clone)]
pub struct CredentialWriteRequest {
    pub owner_principal_id: String,
    pub service: String,
    pub name: String,
    pub profile: String,
    pub credential_kind: String,
    pub secret: Value,
    pub metadata: Value,
    pub actor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CredentialMetadata {
    pub credential_id: String,
    pub owner_principal: String,
    pub owner_kind: String,
    pub service: String,
    pub name: String,
    pub profile: String,
    pub credential_kind: String,
    pub metadata: Value,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
    pub created_by: String,
    pub updated_by: String,
    pub last_used_at: Option<String>,
    pub last_verified_at: Option<String>,
    pub verification_status: Option<String>,
    pub last_verification_attempt_at: Option<String>,
    pub last_verification_error_code: Option<String>,
    #[serde(skip)]
    pub secret_backend: String,
    #[serde(skip)]
    pub secret_ref: String,
    #[serde(skip)]
    pub material_version: String,
}

#[derive(Debug, Clone)]
pub struct CredentialVerificationCandidate {
    pub credential: ExecutionCredential,
    pub target: CredentialVerificationTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialVerificationTarget {
    pub credential_id: String,
    pub material_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RewrapSummary {
    pub from_key: String,
    pub to_key: String,
    pub rewrapped: u64,
    pub conflicts: u64,
}

#[derive(Clone)]
struct EncryptedCredentialRow {
    credential_id: String,
    owner_principal_id: String,
    owner_kind: String,
    service: String,
    name: String,
    profile: String,
    credential_kind: String,
    metadata: Value,
    secret_backend: String,
    secret_ref: String,
    material_version: String,
    secret_ciphertext: Vec<u8>,
    secret_nonce: Vec<u8>,
    key_id: String,
    status: String,
}

fn validate_principal_write_request(
    request: &PrincipalWriteRequest,
) -> Result<(), ManagedStoreError> {
    validate_principal_id(&request.principal_id)?;
    validate_actor(&request.created_by)?;
    if !matches!(request.kind.as_str(), "user" | "service_account" | "system") {
        return Err(input_invalid(
            "principal kind must be user, service_account, or system",
        ));
    }
    if let Some(display_name) = request.display_name.as_deref() {
        validate_principal_display_name(display_name)?;
    }
    if let Some(email) = request.email.as_deref() {
        validate_principal_email(email)?;
    }
    Ok(())
}

fn require_interactive_principal(principal: &PrincipalRecord) -> Result<(), ManagedStoreError> {
    if principal.kind != "user" {
        return Err(input_invalid(
            "operation is only available to interactive user principals",
        ));
    }
    Ok(())
}

fn validate_principal_patch_request(
    request: &PrincipalPatchRequest,
) -> Result<(), ManagedStoreError> {
    validate_principal_id(&request.principal_id)?;
    if request.display_name.is_none() && request.email.is_none() && request.status.is_none() {
        return Err(input_invalid(
            "at least one of displayName, email, or status is required",
        ));
    }
    if let Some(Some(display_name)) = &request.display_name {
        validate_principal_display_name(display_name)?;
    }
    if let Some(Some(email)) = &request.email {
        validate_principal_email(email)?;
    }
    if let Some(status) = request.status.as_deref()
        && !matches!(status, "active" | "disabled")
    {
        return Err(input_invalid("status must be active or disabled"));
    }
    Ok(())
}

fn validate_group_write_request(request: &GroupWriteRequest) -> Result<(), ManagedStoreError> {
    validate_group_name(&request.group_id)?;
    validate_actor(&request.created_by)?;
    validate_group_metadata(
        request.display_name.as_deref(),
        request.description.as_deref(),
    )?;
    Ok(())
}

fn validate_group_patch_request(request: &GroupPatchRequest) -> Result<(), ManagedStoreError> {
    validate_group_name(&request.group_id)?;
    validate_actor(&request.updated_by)?;
    if request.display_name.is_none() && request.description.is_none() && request.status.is_none() {
        return Err(input_invalid(
            "at least one of displayName, description, or status is required",
        ));
    }
    validate_group_metadata(
        request
            .display_name
            .as_ref()
            .and_then(|value| value.as_deref()),
        request
            .description
            .as_ref()
            .and_then(|value| value.as_deref()),
    )?;
    if let Some(status) = request.status.as_deref()
        && !matches!(status, "active" | "disabled")
    {
        return Err(input_invalid("status must be active or disabled"));
    }
    Ok(())
}

fn validate_group_metadata(
    display_name: Option<&str>,
    description: Option<&str>,
) -> Result<(), ManagedStoreError> {
    if let Some(display_name) = display_name {
        validate_display_name(display_name, "displayName")?;
    }
    if let Some(description) = description {
        validate_description(description, "description")?;
    }
    Ok(())
}

fn validate_policy_grant_create_request(
    request: &ManagedPolicyGrantCreateRequest,
) -> Result<(), ManagedStoreError> {
    if let Some(grant_id) = request.grant_id.as_deref() {
        validate_policy_grant_id(grant_id)?;
    }
    validate_policy_grant_subjects_field(&request.subjects)?;
    validate_policy_grant_execution_contexts_field(&request.execution_contexts)?;
    validate_policy_grant_service_field(&request.service)?;
    validate_policy_grant_actions_field(&request.actions)?;
    validate_policy_grant_credential_mode(&request.credential_mode)?;
    if let Some(status) = request.status.as_deref() {
        validate_policy_grant_status_field(status)?;
    }
    validate_policy_grant_metadata(request.description.as_deref())?;
    validate_actor(&request.created_by)?;
    Ok(())
}

fn validate_policy_grant_patch_request(
    request: &ManagedPolicyGrantPatchRequest,
) -> Result<(), ManagedStoreError> {
    validate_policy_grant_id(&request.grant_id)?;
    validate_policy_grant_expected_version(request.expected_version)?;
    validate_actor(&request.updated_by)?;
    if request.subjects.is_none()
        && request.execution_contexts.is_none()
        && request.service.is_none()
        && request.actions.is_none()
        && request.resources.is_none()
        && request.credential_mode.is_none()
        && request.priority.is_none()
        && request.status.is_none()
        && request.description.is_none()
    {
        return Err(input_invalid("at least one policy grant field is required"));
    }
    if let Some(subjects) = request.subjects.as_ref() {
        validate_policy_grant_subjects_field(subjects)?;
    }
    if let Some(execution_contexts) = request.execution_contexts.as_ref() {
        validate_policy_grant_execution_contexts_field(execution_contexts)?;
    }
    if let Some(service) = request.service.as_deref() {
        validate_policy_grant_service_field(service)?;
    }
    if let Some(actions) = request.actions.as_ref() {
        validate_policy_grant_actions_field(actions)?;
    }
    if let Some(credential_mode) = request.credential_mode.as_deref() {
        validate_policy_grant_credential_mode(credential_mode)?;
    }
    if let Some(status) = request.status.as_deref() {
        validate_policy_grant_status_field(status)?;
    }
    validate_policy_grant_metadata(
        request
            .description
            .as_ref()
            .and_then(|value| value.as_deref()),
    )?;
    Ok(())
}

fn validate_policy_grant_status_request(
    request: &ManagedPolicyGrantStatusRequest,
) -> Result<(), ManagedStoreError> {
    validate_policy_grant_id(&request.grant_id)?;
    validate_policy_grant_expected_version(request.expected_version)?;
    validate_actor(&request.updated_by)?;
    Ok(())
}

fn validate_policy_grant_subject_add_request(
    request: &ManagedPolicyGrantSubjectAddRequest,
) -> Result<(), ManagedStoreError> {
    validate_policy_grant_id(&request.grant_id)?;
    validate_policy_grant_expected_version(request.expected_version)?;
    validate_policy_grant_subject_value(&request.subject, "subject")?;
    validate_actor(&request.updated_by)?;
    Ok(())
}

fn validate_policy_grant_subject_remove_request(
    request: &ManagedPolicyGrantSubjectRemoveRequest,
) -> Result<(), ManagedStoreError> {
    validate_policy_grant_id(&request.grant_id)?;
    validate_policy_grant_expected_version(request.expected_version)?;
    validate_policy_grant_subject_value(&request.subject, "subject")?;
    if !matches!(
        request.last_subject_behavior.as_str(),
        "reject" | "disable_grant"
    ) {
        return Err(input_invalid(
            "lastSubjectBehavior must be reject or disable_grant",
        ));
    }
    validate_actor(&request.updated_by)?;
    Ok(())
}

fn validate_policy_grant_id(grant_id: &str) -> Result<(), ManagedStoreError> {
    if is_safe_identifier(grant_id) && !is_reserved_policy_grant_id(grant_id) {
        Ok(())
    } else {
        Err(input_invalid(
            "grantId must be 1-128 characters using letters, numbers, dots, underscores, or hyphens, and must not be '.', '..', 'export', or 'validate'",
        ))
    }
}

fn is_reserved_policy_grant_id(grant_id: &str) -> bool {
    matches!(grant_id, "." | "..")
        || grant_id.eq_ignore_ascii_case("export")
        || grant_id.eq_ignore_ascii_case("validate")
}

fn validate_policy_grant_expected_version(version: i64) -> Result<(), ManagedStoreError> {
    if version < 1 {
        return Err(input_invalid(
            "expectedVersion must be greater than or equal to 1",
        ));
    }
    Ok(())
}

fn ensure_policy_management_scope(
    scope: &PolicyWriteScope,
    service: &str,
) -> Result<(), ManagedStoreError> {
    if scope.authorizes_service(service) {
        Ok(())
    } else {
        Err(ManagedStoreError::PolicyGrantNotFound)
    }
}

fn ensure_policy_management_service_unchanged(
    scope: &PolicyWriteScope,
    current_service: &str,
    proposed_service: Option<&str>,
) -> Result<(), ManagedStoreError> {
    if matches!(scope, PolicyWriteScope::Global)
        || proposed_service.is_none_or(|service| service == current_service)
    {
        Ok(())
    } else {
        Err(ManagedStoreError::PolicyManagementServiceMoveDenied)
    }
}

fn validate_policy_grant_subjects_field(subjects: &[String]) -> Result<(), ManagedStoreError> {
    if subjects.len() > POLICY_GRANT_MAX_SUBJECTS {
        return Err(input_invalid(format!(
            "subjects must contain at most {POLICY_GRANT_MAX_SUBJECTS} entries"
        )));
    }
    let mut seen = BTreeSet::new();
    for (index, subject) in subjects.iter().enumerate() {
        validate_policy_grant_subject_value(subject, &format!("subjects[{index}]"))?;
        if !seen.insert(subject) {
            return Err(input_invalid(format!(
                "subjects[{index}] duplicates an earlier subject"
            )));
        }
    }
    Ok(())
}

fn validate_policy_grant_subject_value(
    subject: &str,
    field: &str,
) -> Result<(), ManagedStoreError> {
    if subject.trim().is_empty() || subject.chars().any(char::is_control) {
        return Err(input_invalid(format!(
            "{field} must be a non-empty non-control string"
        )));
    }
    Ok(())
}

fn validate_policy_grant_execution_contexts_field(
    execution_contexts: &[String],
) -> Result<(), ManagedStoreError> {
    if execution_contexts.is_empty() {
        return Err(input_invalid("executionContexts must not be empty"));
    }
    if execution_contexts.len() > EXECUTION_CONTEXT_MAX_VALUES {
        return Err(input_invalid(format!(
            "executionContexts must contain at most {EXECUTION_CONTEXT_MAX_VALUES} entries"
        )));
    }
    let mut seen = BTreeSet::new();
    for (index, execution_context) in execution_contexts.iter().enumerate() {
        if !is_valid_execution_context_value(execution_context) {
            return Err(input_invalid(format!(
                "executionContexts[{index}] must match [a-z][a-z0-9_-]{{0,63}}"
            )));
        }
        if !seen.insert(execution_context) {
            return Err(input_invalid(format!(
                "executionContexts[{index}] duplicates an earlier execution context"
            )));
        }
    }
    Ok(())
}

fn validate_policy_grant_service_field(service: &str) -> Result<(), ManagedStoreError> {
    if !is_service_name(service) {
        return Err(input_invalid("service must be a safe service name"));
    }
    Ok(())
}

fn validate_policy_grant_actions_field(actions: &[String]) -> Result<(), ManagedStoreError> {
    if actions.is_empty() {
        return Err(input_invalid("actions must not be empty"));
    }
    if actions
        .iter()
        .any(|action| action.trim().is_empty() || action.chars().any(char::is_control))
    {
        return Err(input_invalid(
            "actions must be non-empty non-control strings",
        ));
    }
    Ok(())
}

fn validate_policy_grant_credential_mode(mode: &str) -> Result<(), ManagedStoreError> {
    if !matches!(mode, "service" | "per_user") {
        return Err(input_invalid("credentialMode must be service or per_user"));
    }
    Ok(())
}

fn validate_policy_grant_status_field(status: &str) -> Result<(), ManagedStoreError> {
    if !matches!(status, "active" | "disabled") {
        return Err(input_invalid("status must be active or disabled"));
    }
    Ok(())
}

fn validate_policy_grant_metadata(description: Option<&str>) -> Result<(), ManagedStoreError> {
    if let Some(description) = description {
        validate_description(description, "description")?;
    }
    Ok(())
}

fn validate_initial_admin_bootstrap_request(
    request: &InitialAdminBootstrapRequest,
) -> Result<(), ManagedStoreError> {
    validate_principal_id(&request.principal_id)?;
    if request.password.is_empty() {
        return Err(input_invalid("password must not be empty"));
    }
    if request.password.len() > 1024 {
        return Err(input_invalid("password must be at most 1024 bytes"));
    }
    if request.password.eq_ignore_ascii_case(&request.principal_id) {
        return Err(input_invalid("password must not equal the principal id"));
    }
    if request.min_password_length == 0 {
        return Err(input_invalid(
            "minimum password length must be greater than zero",
        ));
    }
    Ok(())
}

fn validate_broker_token_issue_request(
    request: &BrokerTokenIssueRequest,
) -> Result<(), ManagedStoreError> {
    validate_principal_id(&request.principal_id)?;
    validate_actor(&request.created_by)?;
    validate_display_name(&request.name, "token name")?;
    normalize_optional_timestamp(request.expires_at.as_deref(), "expiresAt")?;
    if request.token_class == BrokerTokenClass::AgentInvoke {
        AgentInvokeTokenCaveats::parse_issuance_structure(&request.scopes)
            .map_err(|error| input_invalid(error.to_string()))?;
    }
    Ok(())
}

fn validate_self_agent_token_issue_request(
    request: &SelfAgentTokenIssueRequest,
) -> Result<(), ManagedStoreError> {
    validate_principal_id(&request.principal_id)?;
    validate_actor(&request.created_by)?;
    validate_display_name(&request.name, "token name")?;
    normalize_optional_timestamp(request.expires_at.as_deref(), "expiresAt")?;
    AgentInvokeTokenCaveats::parse_issuance_structure(&request.scopes)
        .map_err(|error| input_invalid(error.to_string()))?;
    Ok(())
}

fn validate_local_password_set_request(
    request: &LocalPasswordWriteRequest,
) -> Result<(), ManagedStoreError> {
    validate_principal_id(&request.principal_id)?;
    validate_actor(&request.actor)?;
    if request.password.is_empty() {
        return Err(input_invalid("password must not be empty"));
    }
    if request.password.len() > 1024 {
        return Err(input_invalid("password must be at most 1024 bytes"));
    }
    if request.password.eq_ignore_ascii_case(&request.principal_id) {
        return Err(input_invalid("password must not equal the principal id"));
    }
    if request.min_password_length == 0 {
        return Err(input_invalid(
            "minimum password length must be greater than zero",
        ));
    }
    Ok(())
}

fn validate_local_password_verify_request(
    request: &LocalPasswordVerifyRequest,
) -> Result<(), ManagedStoreError> {
    validate_principal_id(&request.principal_id)?;
    local_password_failures::validate_source(&request.source)?;
    if request.password.is_empty() {
        return Err(ManagedStoreError::LocalLoginFailed);
    }
    if request.max_failed_attempts == 0 || request.lockout_ttl_seconds == 0 {
        return Err(input_invalid("local password lockout settings are invalid"));
    }
    Ok(())
}

fn validate_browser_session_issue_request(
    request: &BrowserSessionIssueRequest,
) -> Result<(), ManagedStoreError> {
    validate_principal_id(&request.principal_id)?;
    validate_actor(&request.created_by)?;
    if !matches!(request.login_method.as_str(), "local_password" | "oidc") {
        return Err(input_invalid("login method is invalid"));
    }
    if let Some(login_method_id) = request.login_method_id.as_deref() {
        validate_uuid_id(login_method_id, "loginMethodId")?;
    }
    if request.ttl_seconds == 0 {
        return Err(input_invalid(
            "browser session ttl must be greater than zero",
        ));
    }
    Ok(())
}

fn validate_right_grant_request(request: &RightGrantRequest) -> Result<(), ManagedStoreError> {
    validate_principal_id(&request.principal_id)?;
    validate_actor(&request.created_by)?;
    validate_right_name(&request.right)?;
    if let Some(service) = request.service.as_deref()
        && !is_service_name(service)
    {
        return Err(input_invalid("right service is invalid"));
    }
    if let Some(name) = request.credential_name.as_deref() {
        validate_credential_name(name)?;
    }
    normalize_optional_timestamp(request.expires_at.as_deref(), "expiresAt")?;
    Ok(())
}

fn validate_credential_write_request(
    request: &CredentialWriteRequest,
) -> Result<(), ManagedStoreError> {
    validate_principal_id(&request.owner_principal_id)?;
    validate_service_and_name(&request.service, &request.name)?;
    validate_profile(&request.profile)?;
    validate_actor(&request.actor)?;
    Ok(())
}

fn validate_principal_id(principal_id: &str) -> Result<(), ManagedStoreError> {
    if principal_id != "anonymous" && is_safe_principal(principal_id) {
        Ok(())
    } else {
        Err(input_invalid("principal id is invalid"))
    }
}

fn validate_group_name(group: &str) -> Result<(), ManagedStoreError> {
    if group != "anonymous" && is_safe_identifier(group) {
        Ok(())
    } else {
        Err(input_invalid("group name is invalid"))
    }
}

fn validate_actor(actor: &str) -> Result<(), ManagedStoreError> {
    validate_principal_id(actor)
}

fn validate_service_and_name(service: &str, name: &str) -> Result<(), ManagedStoreError> {
    if !is_service_name(service) {
        return Err(input_invalid("service name is invalid"));
    }
    validate_credential_name(name)
}

fn validate_credential_name(name: &str) -> Result<(), ManagedStoreError> {
    if is_safe_identifier(name) {
        Ok(())
    } else {
        Err(input_invalid("credential name is invalid"))
    }
}

fn validate_profile(profile: &str) -> Result<(), ManagedStoreError> {
    if is_safe_identifier(profile) {
        Ok(())
    } else {
        Err(input_invalid("credential profile is invalid"))
    }
}

fn validate_credential_verification_status(status: &str) -> Result<(), ManagedStoreError> {
    if matches!(status, "local_verified" | "upstream_verified") {
        Ok(())
    } else {
        Err(input_invalid("credential verification status is invalid"))
    }
}

fn validate_credential_verification_error_code(error_code: &str) -> Result<(), ManagedStoreError> {
    if is_safe_identifier(error_code) {
        Ok(())
    } else {
        Err(input_invalid(
            "credential verification error code is invalid",
        ))
    }
}

fn validate_safe_key_id(key_id: &str) -> Result<(), ManagedStoreError> {
    if is_safe_identifier(key_id) {
        Ok(())
    } else {
        Err(ManagedStoreError::EncryptionKeyInvalid(
            "key id is invalid".to_string(),
        ))
    }
}

fn validate_uuid_id(id: &str, label: &str) -> Result<(), ManagedStoreError> {
    Uuid::parse_str(id)
        .map(|_| ())
        .map_err(|_| input_invalid(format!("{label} is invalid")))
}

fn validate_canonical_uuid(id: &str, label: &str) -> Result<(), ManagedStoreError> {
    let parsed = Uuid::parse_str(id).map_err(|_| input_invalid(format!("{label} is invalid")))?;
    if parsed.hyphenated().to_string() != id {
        return Err(input_invalid(format!(
            "{label} must be a canonical lowercase UUID"
        )));
    }
    Ok(())
}

fn validate_external_group_id(id: &str) -> Result<(), ManagedStoreError> {
    validate_canonical_uuid(id, "externalGroupId")
}

fn validate_oidc_external_subject(subject: &str) -> Result<(), ManagedStoreError> {
    let Some(rest) = subject.strip_prefix("entra:v1:") else {
        return Err(input_invalid("OIDC external subject is invalid"));
    };
    let Some((tenant_id, object_id)) = rest.split_once(':') else {
        return Err(input_invalid("OIDC external subject is invalid"));
    };
    validate_canonical_uuid(tenant_id, "OIDC tenant")?;
    validate_canonical_uuid(object_id, "OIDC object ID")
}

fn validate_oidc_flow_create_request(
    request: &OidcFlowCreateRequest,
) -> Result<(), ManagedStoreError> {
    if request.state_hash.len() != 32
        || request.browser_binding_hash.len() != 32
        || request.encryption_nonce.len() != 12
        || request.encrypted_payload.is_empty()
        || request.encrypted_payload.len() > 16_384
        || request.return_path.is_empty()
        || request.return_path.len() > 2_048
        || !request.return_path.starts_with('/')
        || request.provider_generation == 0
        || request.max_pending_flows == 0
    {
        return Err(input_invalid("OIDC flow is invalid"));
    }
    normalize_optional_timestamp(Some(&request.expires_at), "expiresAt")?;
    Ok(())
}

fn validate_uuid_for_schema(id: &str, label: &str) -> Result<(), ManagedStoreError> {
    Uuid::parse_str(id)
        .map(|_| ())
        .map_err(|_| ManagedStoreError::SchemaInvalid(format!("{label} is malformed")))
}

fn new_sqlite_secret_ref() -> String {
    format!("sqlite:{}", Uuid::new_v4())
}

fn validate_sqlite_secret_ref(secret_ref: &str) -> Result<(), ManagedStoreError> {
    let Some(uuid) = secret_ref.strip_prefix("sqlite:") else {
        return Err(ManagedStoreError::CredentialInvalid(
            "credential secret reference is invalid".to_string(),
        ));
    };
    validate_uuid_id(uuid, "secretRef")
}

fn validate_sqlite_secret_ref_for_schema(secret_ref: &str) -> Result<(), ManagedStoreError> {
    let Some(uuid) = secret_ref.strip_prefix("sqlite:") else {
        return Err(ManagedStoreError::SchemaInvalid(
            "credential secret reference is malformed".to_string(),
        ));
    };
    validate_uuid_for_schema(uuid, "credential secret reference")
}

fn validate_display_name(value: &str, label: &str) -> Result<(), ManagedStoreError> {
    let trimmed = value.trim();
    if !trimmed.is_empty() && trimmed.len() <= 128 && !trimmed.chars().any(char::is_control) {
        Ok(())
    } else {
        Err(input_invalid(format!(
            "{label} must be 1-128 non-control characters"
        )))
    }
}

fn validate_description(value: &str, label: &str) -> Result<(), ManagedStoreError> {
    let trimmed = value.trim();
    if !trimmed.is_empty() && trimmed.len() <= 1024 && !trimmed.chars().any(char::is_control) {
        Ok(())
    } else {
        Err(input_invalid(format!(
            "{label} must be 1-1024 non-control characters"
        )))
    }
}

fn validate_principal_display_name(value: &str) -> Result<(), ManagedStoreError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > 256 || trimmed.chars().any(char::is_control) {
        return Err(input_invalid(
            "displayName must be 1-256 non-control characters",
        ));
    }
    Ok(())
}

fn validate_principal_email(value: &str) -> Result<(), ManagedStoreError> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.len() > 320
        || trimmed.chars().any(char::is_control)
        || trimmed.matches('@').count() != 1
    {
        return Err(input_invalid("email must be a valid email address"));
    }
    let (local, domain) = trimmed.split_once('@').unwrap_or_default();
    if local.is_empty()
        || domain.is_empty()
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
    {
        return Err(input_invalid("email must be a valid email address"));
    }
    Ok(())
}

fn normalized_optional_profile_value(value: Option<&str>) -> Option<String> {
    value.map(|value| value.trim().to_string())
}

fn normalize_optional_text(value: Option<String>) -> Option<String> {
    value.map(|value| value.trim().to_string())
}

fn validate_right_name(right: &str) -> Result<(), ManagedStoreError> {
    if matches!(
        right,
        "credentials:self:write"
            | "credentials:self:delete"
            | "credentials:self:read_metadata"
            | "credentials:self:verify"
    ) {
        Ok(())
    } else {
        Err(input_invalid("right is not supported in V1"))
    }
}

fn validate_credential_secret(kind: &str, secret: &Value) -> Result<(), ManagedStoreError> {
    let Some(object) = secret.as_object() else {
        return Err(input_invalid("secret must be a JSON object"));
    };
    match kind {
        "basic_api_token" => {
            required_non_empty_string(object, "username")?;
            required_non_empty_string(object, "token")?;
            reject_unexpected_secret_fields(object, &["username", "token"])
        }
        "bearer_token" => {
            required_non_empty_string(object, "token")?;
            reject_unexpected_secret_fields(object, &["token"])
        }
        _ => Err(input_invalid("unsupported credential kind")),
    }
}

fn required_non_empty_string(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<(), ManagedStoreError> {
    match object.get(field).and_then(Value::as_str) {
        Some(value) if !value.is_empty() => Ok(()),
        _ => Err(input_invalid(format!("secret.{field} is required"))),
    }
}

fn reject_unexpected_secret_fields(
    object: &serde_json::Map<String, Value>,
    allowed: &[&str],
) -> Result<(), ManagedStoreError> {
    let allowed = BTreeSet::from_iter(allowed.iter().copied());
    if object.keys().all(|key| allowed.contains(key.as_str())) {
        Ok(())
    } else {
        Err(input_invalid("secret contains unsupported fields"))
    }
}

fn validate_credential_metadata(metadata: &Value) -> Result<(), ManagedStoreError> {
    let Some(object) = metadata.as_object() else {
        return Err(input_invalid("metadata must be a JSON object"));
    };
    reject_secret_like_metadata_keys(metadata)?;
    let encoded = serde_json::to_vec(metadata)
        .map_err(|_| input_invalid("metadata must be JSON serializable"))?;
    if encoded.len() > 8192 {
        return Err(input_invalid("metadata must be at most 8192 bytes"));
    }
    for key in object.keys() {
        if secret_like_metadata_key(key) {
            return Err(input_invalid(
                "metadata must not contain secret-looking fields",
            ));
        }
        if !matches!(
            key.as_str(),
            "displayName" | "description" | "expiresAt" | "source"
        ) {
            return Err(input_invalid(format!(
                "metadata field {key} is not supported in V1"
            )));
        }
    }
    validate_optional_metadata_string(object, "displayName", 256)?;
    validate_optional_metadata_string(object, "description", 2048)?;
    if let Some(expires_at) = object.get("expiresAt")
        && !expires_at.is_null()
        && normalize_optional_timestamp(expires_at.as_str(), "metadata.expiresAt").is_err()
    {
        return Err(input_invalid(
            "metadata.expiresAt must be an RFC3339 timestamp or null",
        ));
    }
    Ok(())
}

fn reject_secret_like_metadata_keys(value: &Value) -> Result<(), ManagedStoreError> {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if secret_like_metadata_key(key) {
                    return Err(input_invalid(
                        "metadata must not contain secret-looking fields",
                    ));
                }
                reject_secret_like_metadata_keys(value)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                reject_secret_like_metadata_keys(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_optional_metadata_string(
    object: &serde_json::Map<String, Value>,
    field: &str,
    max_len: usize,
) -> Result<(), ManagedStoreError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(value)) if value.len() <= max_len => Ok(()),
        Some(_) => Err(input_invalid(format!(
            "metadata.{field} must be a string of at most {max_len} bytes"
        ))),
    }
}

fn secret_like_metadata_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "token" | "password" | "secret" | "authorization" | "cookie" | "key"
    )
}

fn credential_metadata_expires_at(metadata: &Value) -> Option<DateTime<Utc>> {
    metadata
        .get("expiresAt")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
}

fn execution_credential_from_secret(
    kind: &str,
    secret: Value,
) -> Result<ExecutionCredential, ManagedStoreError> {
    validate_credential_secret(kind, &secret).map_err(|error| match error {
        ManagedStoreError::InputInvalid(message) => ManagedStoreError::CredentialInvalid(message),
        other => other,
    })?;
    // Validation above guarantees each kind's non-empty string fields.
    let field = |name: &str| {
        secret
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| {
                ManagedStoreError::CredentialInvalid(format!("secret.{name} is required"))
            })
    };
    match kind {
        "basic_api_token" => Ok(agent_access_provider::host::basic_credential(
            field("username")?,
            field("token")?,
        )),
        "bearer_token" => Ok(agent_access_provider::host::bearer_credential(field(
            "token",
        )?)),
        _ => Err(ManagedStoreError::CredentialInvalid(
            "unsupported credential kind".to_string(),
        )),
    }
}

/// A stored secret as the command credential a command import receives: the
/// `token` or `username_token` of its stored kind, validated as execution
/// validates it. The strings move out of `secret` into zeroizing storage.
fn command_credential_from_secret(
    kind: &str,
    mut secret: Value,
) -> Result<crate::imports::CommandCredential, ManagedStoreError> {
    validate_credential_secret(kind, &secret).map_err(|error| match error {
        ManagedStoreError::InputInvalid(message) => ManagedStoreError::CredentialInvalid(message),
        other => other,
    })?;
    let mut take = |name: &str| match secret
        .as_object_mut()
        .and_then(|object| object.remove(name))
    {
        Some(Value::String(value)) => Ok(value),
        _ => Err(ManagedStoreError::CredentialInvalid(format!(
            "secret.{name} is required"
        ))),
    };
    match kind {
        "basic_api_token" => {
            let username = take("username")?;
            Ok(crate::imports::CommandCredential::username_token(
                username,
                take("token")?,
            ))
        }
        "bearer_token" => Ok(crate::imports::CommandCredential::token(take("token")?)),
        _ => Err(ManagedStoreError::CredentialInvalid(
            "unsupported credential kind".to_string(),
        )),
    }
}

/// One query for list summaries, or a bounded query for a single principal.
/// Only enrollment state is projected; no credential material is selected.
fn sign_in_methods_by_principal(
    conn: &Connection,
    principal_id: Option<&str>,
) -> Result<BTreeMap<String, SignInMethods>, ManagedStoreError> {
    let sql = if principal_id.is_some() {
        "SELECT principal_id, method, status FROM principal_login_methods
         WHERE principal_id = ?1
           AND (method = 'local_password' OR (method = 'oidc' AND external_provider = 'microsoft'))"
    } else {
        "SELECT principal_id, method, status FROM principal_login_methods
         WHERE method = 'local_password' OR (method = 'oidc' AND external_provider = 'microsoft')"
    };
    let mut statement = conn.prepare(sql).map_err(sql_unavailable)?;
    let rows = statement
        .query_map(rusqlite::params_from_iter(principal_id), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(sql_unavailable)?;
    let mut result = BTreeMap::<String, SignInMethods>::new();
    for row in rows {
        let (principal, method, status) = row.map_err(sql_unavailable)?;
        let status = match status.as_str() {
            "active" => SignInMethodStatus::Active,
            "disabled" => SignInMethodStatus::Disabled,
            _ => {
                return Err(ManagedStoreError::SchemaInvalid(
                    "invalid login method status".into(),
                ));
            }
        };
        let summary = result.entry(principal).or_default();
        if method == "local_password" {
            summary.local_password = status;
        } else {
            summary.microsoft = status;
        }
    }
    Ok(result)
}

fn validate_local_password_write(
    request: &LocalPasswordWriteRequest,
) -> Result<(), ManagedStoreError> {
    validate_local_password_set_request(request)?;
    if request.password.len() < request.min_password_length {
        return Err(input_invalid(format!(
            "password must be at least {} bytes",
            request.min_password_length
        )));
    }
    Ok(())
}

/// Caller holds an immediate transaction and has checked the operation's state.
fn write_local_password_tx(
    tx: &rusqlite::Transaction<'_>,
    request: &LocalPasswordWriteRequest,
    password_hash: &str,
    existing: Option<&LoginMethodRecord>,
) -> Result<LoginMethodRecord, ManagedStoreError> {
    let now = normalized_now_string();
    let method_id = existing
        .map(|method| method.login_method_id.clone())
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    if existing.is_some() {
        tx.execute(
            "UPDATE principal_login_methods SET status = 'active', password_hash_phc = ?2,
             password_set_at = ?3, must_change_password = ?4, updated_at = ?3, updated_by = ?5
             WHERE login_method_id = ?1",
            params![
                method_id,
                password_hash,
                now,
                request.password_change_required,
                request.actor
            ],
        )
        .map_err(sql_unavailable)?;
    } else {
        tx.execute(
            "INSERT INTO principal_login_methods
             (login_method_id, principal_id, method, external_provider, external_subject,
              status, password_hash_phc, password_set_at, must_change_password, created_at,
              updated_at, created_by, updated_by)
             VALUES (?1, ?2, 'local_password', NULL, NULL, 'active', ?3, ?4, ?5, ?4, ?4, ?6, ?6)",
            params![
                method_id,
                request.principal_id,
                password_hash,
                now,
                request.password_change_required,
                request.actor
            ],
        )
        .map_err(sql_unavailable)?;
    }
    local_password_failures::clear_principal(tx, &request.principal_id)?;
    revoke_browser_sessions_by_method_tx(
        tx,
        &request.principal_id,
        "local_password",
        &request.actor,
        &now,
    )?;
    login_method_by_id(tx, &method_id)
}

fn principal_by_id(
    conn: &Connection,
    principal_id: &str,
) -> Result<PrincipalRecord, ManagedStoreError> {
    let mut principal = principal_by_id_without_groups(conn, principal_id)?;
    let membership = effective_membership_at_conn(conn, principal_id, &normalized_now_string())?;
    principal.groups = membership.groups;
    Ok(principal)
}

fn principal_by_id_without_groups(
    conn: &Connection,
    principal_id: &str,
) -> Result<PrincipalRecord, ManagedStoreError> {
    let mut principal = conn
        .query_row(
            "SELECT principal_id, kind, display_name, email, external_subject, status,
                created_at, updated_at, disabled_at, created_by, role, self_service_enabled
         FROM principals
         WHERE principal_id = ?1",
            params![principal_id],
            principal_from_row,
        )
        .optional()
        .map_err(sql_unavailable)?
        .ok_or(ManagedStoreError::PrincipalNotFound)?;
    principal.sign_in_methods = sign_in_methods_by_principal(conn, Some(principal_id))?
        .remove(principal_id)
        .unwrap_or_default();
    Ok(principal)
}

fn principal_by_id_for_membership(
    conn: &Connection,
    principal_id: &str,
) -> Result<PrincipalRecord, ManagedStoreError> {
    principal_by_id(conn, principal_id)
}

fn principal_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PrincipalRecord> {
    Ok(PrincipalRecord {
        sign_in_methods: SignInMethods::default(),
        principal_id: row.get(0)?,
        kind: row.get(1)?,
        display_name: row.get(2)?,
        email: row.get(3)?,
        external_subject: row.get(4)?,
        status: row.get(5)?,
        groups: Vec::new(),
        role: row.get::<_, String>(10)?.parse().map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(10, Type::Text, Box::new(error))
        })?,
        self_service_enabled: row.get(11)?,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
        disabled_at: row.get(8)?,
        created_by: row.get(9)?,
    })
}

fn policy_revision(conn: &Connection) -> Result<ManagedPolicyRevision, ManagedStoreError> {
    let revision: Option<(i64, String, String)> = conn
        .query_row(
            "SELECT generation, updated_at, updated_by
             FROM policy_revisions
             WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sql_unavailable)?;
    let Some((generation, updated_at, updated_by)) = revision else {
        return Err(ManagedStoreError::SchemaInvalid(
            "policy revision row is missing".to_string(),
        ));
    };
    let generation = u64::try_from(generation).map_err(|_| {
        ManagedStoreError::SchemaInvalid("policy revision generation is invalid".to_string())
    })?;
    Ok(ManagedPolicyRevision {
        generation,
        updated_at,
        updated_by,
    })
}

/// Load current active policy rows without taking the managed-store mutex again.
pub(crate) fn active_policy_grants_at_conn(
    conn: &Connection,
) -> Result<Vec<ManagedPolicyGrantRecord>, ManagedStoreError> {
    policy_grants(conn, Some("active"))
}

fn policy_grants(
    conn: &Connection,
    status: Option<&str>,
) -> Result<Vec<ManagedPolicyGrantRecord>, ManagedStoreError> {
    let rows = match status {
        Some(status) => {
            let mut statement = conn
                .prepare(
                    "SELECT grant_id, grant_order, service, actions_json,
                            resources_json, credential_mode, priority, status, description,
                            version, created_at, created_by, updated_at, updated_by,
                            disabled_at, deleted_at
                     FROM policy_grants
                     WHERE status = ?1
                     ORDER BY grant_order",
                )
                .map_err(sql_unavailable)?;
            let rows = statement
                .query_map(params![status], policy_grant_row_from_row)
                .map_err(sql_unavailable)?;
            collect_rows(rows)?
        }
        None => {
            let mut statement = conn
                .prepare(
                    "SELECT grant_id, grant_order, service, actions_json,
                            resources_json, credential_mode, priority, status, description,
                            version, created_at, created_by, updated_at, updated_by,
                            disabled_at, deleted_at
                     FROM policy_grants
                     ORDER BY grant_order",
                )
                .map_err(sql_unavailable)?;
            let rows = statement
                .query_map([], policy_grant_row_from_row)
                .map_err(sql_unavailable)?;
            collect_rows(rows)?
        }
    };
    rows.into_iter()
        .map(|row| policy_grant_from_row(conn, row))
        .collect()
}

fn policy_subject_catalog(
    conn: &Connection,
) -> Result<ManagedPolicySubjectCatalog, ManagedStoreError> {
    let principals = {
        let mut statement = conn
            .prepare("SELECT principal_id FROM principals ORDER BY principal_id")
            .map_err(sql_unavailable)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(sql_unavailable)?;
        collect_rows(rows)?.into_iter().collect()
    };
    let groups = {
        let mut statement = conn
            .prepare("SELECT group_id FROM groups ORDER BY group_id")
            .map_err(sql_unavailable)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(sql_unavailable)?;
        collect_rows(rows)?.into_iter().collect()
    };
    Ok(ManagedPolicySubjectCatalog { principals, groups })
}

struct ManagedPolicyGrantRow {
    grant_id: String,
    grant_order: i64,
    service: String,
    actions_json: String,
    resources_json: String,
    credential_mode: String,
    priority: Option<i32>,
    status: String,
    description: Option<String>,
    version: i64,
    created_at: String,
    created_by: String,
    updated_at: String,
    updated_by: String,
    disabled_at: Option<String>,
    deleted_at: Option<String>,
}

fn policy_grant_row_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ManagedPolicyGrantRow> {
    Ok(ManagedPolicyGrantRow {
        grant_id: row.get(0)?,
        grant_order: row.get(1)?,
        service: row.get(2)?,
        actions_json: row.get(3)?,
        resources_json: row.get(4)?,
        credential_mode: row.get(5)?,
        priority: row.get(6)?,
        status: row.get(7)?,
        description: row.get(8)?,
        version: row.get(9)?,
        created_at: row.get(10)?,
        created_by: row.get(11)?,
        updated_at: row.get(12)?,
        updated_by: row.get(13)?,
        disabled_at: row.get(14)?,
        deleted_at: row.get(15)?,
    })
}

fn policy_grant_from_row(
    conn: &Connection,
    row: ManagedPolicyGrantRow,
) -> Result<ManagedPolicyGrantRecord, ManagedStoreError> {
    let subjects = policy_grant_subjects(conn, &row.grant_id, &row.status)?;
    let execution_contexts = policy_grant_contexts(conn, &row.grant_id)?;
    let actions = serde_json::from_str(&row.actions_json).map_err(|_| {
        ManagedStoreError::SchemaInvalid("policy grant actions are malformed".to_string())
    })?;
    let resources = serde_json::from_str(&row.resources_json).map_err(|_| {
        ManagedStoreError::SchemaInvalid("policy grant resource scopes are malformed".to_string())
    })?;
    Ok(ManagedPolicyGrantRecord {
        grant_id: row.grant_id,
        grant_order: row.grant_order,
        subjects,
        execution_contexts,
        service: row.service,
        actions,
        resources,
        credential_mode: row.credential_mode,
        priority: row.priority,
        status: row.status,
        description: row.description,
        version: row.version,
        created_at: row.created_at,
        created_by: row.created_by,
        updated_at: row.updated_at,
        updated_by: row.updated_by,
        disabled_at: row.disabled_at,
        deleted_at: row.deleted_at,
    })
}

fn policy_grant_by_id(
    conn: &Connection,
    grant_id: &str,
) -> Result<ManagedPolicyGrantRecord, ManagedStoreError> {
    let row = conn
        .query_row(
            "SELECT grant_id, grant_order, service, actions_json,
                    resources_json, credential_mode, priority, status, description,
                    version, created_at, created_by, updated_at, updated_by,
                    disabled_at, deleted_at
             FROM policy_grants
             WHERE grant_id = ?1",
            params![grant_id],
            policy_grant_row_from_row,
        )
        .optional()
        .map_err(sql_unavailable)?
        .ok_or(ManagedStoreError::PolicyGrantNotFound)?;
    policy_grant_from_row(conn, row)
}

fn policy_grant_subjects(
    conn: &Connection,
    grant_id: &str,
    grant_status: &str,
) -> Result<Vec<String>, ManagedStoreError> {
    let mut statement = conn
        .prepare(
            "SELECT subject
             FROM policy_grant_subjects
             WHERE grant_id = ?1
             ORDER BY subject_order",
        )
        .map_err(sql_unavailable)?;
    let rows = statement
        .query_map(params![grant_id], |row| row.get::<_, String>(0))
        .map_err(sql_unavailable)?;
    let subjects = collect_rows(rows)?;
    if subjects.is_empty() && grant_status == "active" {
        return Err(ManagedStoreError::SchemaInvalid(format!(
            "active policy grant {grant_id} has no subjects"
        )));
    }
    Ok(subjects)
}

fn policy_grant_contexts(
    conn: &Connection,
    grant_id: &str,
) -> Result<Vec<String>, ManagedStoreError> {
    let mut statement = conn
        .prepare(
            "SELECT execution_context, context_order
             FROM policy_grant_contexts
             WHERE grant_id = ?1
             ORDER BY context_order",
        )
        .map_err(sql_unavailable)?;
    let rows = statement
        .query_map(params![grant_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(sql_unavailable)?;
    let rows = collect_rows(rows)?;
    if rows.is_empty() {
        return Err(ManagedStoreError::SchemaInvalid(format!(
            "policy grant {grant_id} has no execution contexts"
        )));
    }
    if rows.len() > EXECUTION_CONTEXT_MAX_VALUES {
        return Err(ManagedStoreError::SchemaInvalid(format!(
            "policy grant {grant_id} has too many execution contexts"
        )));
    }
    let mut execution_contexts = Vec::with_capacity(rows.len());
    for (index, (execution_context, context_order)) in rows.into_iter().enumerate() {
        let expected_order = i64::try_from(index).map_err(|_| {
            ManagedStoreError::SchemaInvalid(
                "policy grant execution context order overflow".to_string(),
            )
        })?;
        if context_order != expected_order || !is_valid_execution_context_value(&execution_context)
        {
            return Err(ManagedStoreError::SchemaInvalid(format!(
                "policy grant {grant_id} execution contexts are malformed"
            )));
        }
        execution_contexts.push(execution_context);
    }
    Ok(execution_contexts)
}

fn policy_grant_exists(conn: &Connection, grant_id: &str) -> Result<bool, ManagedStoreError> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(1) FROM policy_grants WHERE grant_id = ?1",
            params![grant_id],
            |row| row.get(0),
        )
        .map_err(sql_unavailable)?;
    Ok(count > 0)
}

fn next_policy_grant_order(conn: &Connection) -> Result<i64, ManagedStoreError> {
    conn.query_row(
        "SELECT COALESCE(MAX(grant_order), -1) + 1 FROM policy_grants",
        [],
        |row| row.get(0),
    )
    .map_err(sql_unavailable)
}

fn next_policy_revision(
    previous: &ManagedPolicyRevision,
    updated_at: &str,
    updated_by: &str,
) -> Result<ManagedPolicyRevision, ManagedStoreError> {
    let generation = previous.generation.checked_add(1).ok_or_else(|| {
        ManagedStoreError::SchemaInvalid("policy generation overflow".to_string())
    })?;
    Ok(ManagedPolicyRevision {
        generation,
        updated_at: updated_at.to_string(),
        updated_by: updated_by.to_string(),
    })
}

fn ensure_policy_grant_version(
    grant: &ManagedPolicyGrantRecord,
    expected_version: i64,
) -> Result<(), ManagedStoreError> {
    if grant.version != expected_version {
        return Err(ManagedStoreError::VersionConflict);
    }
    Ok(())
}

fn active_policy_grants_with_replacement(
    conn: &Connection,
    replacement: Option<ManagedPolicyGrantRecord>,
    remove_grant_id: Option<&str>,
) -> Result<Vec<ManagedPolicyGrantRecord>, ManagedStoreError> {
    let mut grants = policy_grants(conn, Some("active"))?;
    if let Some(remove_grant_id) = remove_grant_id {
        grants.retain(|grant| grant.grant_id != remove_grant_id);
    }
    if let Some(replacement) = replacement {
        grants.retain(|grant| grant.grant_id != replacement.grant_id);
        if replacement.status == "active" {
            grants.push(replacement);
        }
    }
    grants.sort_by_key(|grant| grant.grant_order);
    Ok(grants)
}

fn policy_grant_json<T: Serialize>(value: &T, label: &str) -> Result<String, ManagedStoreError> {
    serde_json::to_string(value).map_err(|_| input_invalid(format!("{label} is not serializable")))
}

fn insert_policy_grant(
    conn: &Connection,
    grant: &ManagedPolicyGrantRecord,
) -> Result<(), ManagedStoreError> {
    let actions_json = policy_grant_json(&grant.actions, "actions")?;
    let resources_json = policy_grant_json(&grant.resources, "resources")?;
    conn.execute(
        "INSERT INTO policy_grants
         (grant_id, grant_order, service, actions_json, resources_json,
          credential_mode, priority, status, description, version, created_at, created_by,
          updated_at, updated_by, disabled_at, deleted_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        params![
            grant.grant_id,
            grant.grant_order,
            grant.service,
            actions_json,
            resources_json,
            grant.credential_mode,
            grant.priority,
            grant.status,
            grant.description,
            grant.version,
            grant.created_at,
            grant.created_by,
            grant.updated_at,
            grant.updated_by,
            grant.disabled_at,
            grant.deleted_at,
        ],
    )
    .map_err(sql_unavailable)?;
    insert_policy_grant_subjects(conn, grant)?;
    insert_policy_grant_contexts(conn, grant)?;
    Ok(())
}

fn insert_policy_grant_subjects(
    conn: &Connection,
    grant: &ManagedPolicyGrantRecord,
) -> Result<(), ManagedStoreError> {
    for (index, subject) in grant.subjects.iter().enumerate() {
        let subject_order = i64::try_from(index).map_err(|_| {
            ManagedStoreError::SchemaInvalid("policy grant subject order overflow".to_string())
        })?;
        conn.execute(
            "INSERT INTO policy_grant_subjects (grant_id, subject, subject_order)
             VALUES (?1, ?2, ?3)",
            params![grant.grant_id, subject, subject_order],
        )
        .map_err(sql_unavailable)?;
    }
    Ok(())
}

fn insert_policy_grant_contexts(
    conn: &Connection,
    grant: &ManagedPolicyGrantRecord,
) -> Result<(), ManagedStoreError> {
    for (index, execution_context) in grant.execution_contexts.iter().enumerate() {
        let context_order = i64::try_from(index).map_err(|_| {
            ManagedStoreError::SchemaInvalid(
                "policy grant execution context order overflow".to_string(),
            )
        })?;
        conn.execute(
            "INSERT INTO policy_grant_contexts
             (grant_id, execution_context, context_order)
             VALUES (?1, ?2, ?3)",
            params![grant.grant_id, execution_context, context_order],
        )
        .map_err(sql_unavailable)?;
    }
    Ok(())
}

fn update_policy_grant_record(
    conn: &Connection,
    grant: &ManagedPolicyGrantRecord,
) -> Result<(), ManagedStoreError> {
    let actions_json = policy_grant_json(&grant.actions, "actions")?;
    let resources_json = policy_grant_json(&grant.resources, "resources")?;
    let updated = conn
        .execute(
            "UPDATE policy_grants
             SET service = ?2,
                 actions_json = ?3,
                 resources_json = ?4,
                 credential_mode = ?5,
                 priority = ?6,
                 status = ?7,
                 description = ?8,
                 version = ?9,
                 updated_at = ?10,
                 updated_by = ?11,
                 disabled_at = ?12,
                 deleted_at = ?13
             WHERE grant_id = ?1",
            params![
                grant.grant_id,
                grant.service,
                actions_json,
                resources_json,
                grant.credential_mode,
                grant.priority,
                grant.status,
                grant.description,
                grant.version,
                grant.updated_at,
                grant.updated_by,
                grant.disabled_at,
                grant.deleted_at,
            ],
        )
        .map_err(sql_unavailable)?;
    if updated == 0 {
        return Err(ManagedStoreError::VersionConflict);
    }
    conn.execute(
        "DELETE FROM policy_grant_subjects WHERE grant_id = ?1",
        params![grant.grant_id],
    )
    .map_err(sql_unavailable)?;
    insert_policy_grant_subjects(conn, grant)?;
    conn.execute(
        "DELETE FROM policy_grant_contexts WHERE grant_id = ?1",
        params![grant.grant_id],
    )
    .map_err(sql_unavailable)?;
    insert_policy_grant_contexts(conn, grant)?;
    Ok(())
}

fn update_policy_revision(
    conn: &Connection,
    revision: &ManagedPolicyRevision,
) -> Result<(), ManagedStoreError> {
    let generation = i64::try_from(revision.generation).map_err(|_| {
        ManagedStoreError::SchemaInvalid("policy generation is too large".to_string())
    })?;
    let updated = conn
        .execute(
            "UPDATE policy_revisions
             SET generation = ?1, updated_at = ?2, updated_by = ?3
             WHERE id = 1",
            params![generation, revision.updated_at, revision.updated_by],
        )
        .map_err(sql_unavailable)?;
    if updated != 1 {
        return Err(ManagedStoreError::SchemaInvalid(
            "policy revision row is missing".to_string(),
        ));
    }
    Ok(())
}

fn finalize_policy_mutation<F, P>(
    tx: rusqlite::Transaction<'_>,
    previous_revision: ManagedPolicyRevision,
    revision: ManagedPolicyRevision,
    active_grants: Vec<ManagedPolicyGrantRecord>,
    inactive_validation_grant: Option<ManagedPolicyGrantRecord>,
    mut validate_candidate: F,
    persist: P,
) -> Result<ManagedPolicyMutationResult, ManagedStoreError>
where
    F: FnMut(
        &[ManagedPolicyGrantRecord],
        &ManagedPolicyRevision,
        &ManagedPolicySubjectCatalog,
        &ManagedResourceCatalog,
    ) -> Result<(), ManagedStoreError>,
    P: FnOnce(
        &Connection,
        &ManagedPolicyRevision,
    ) -> Result<ManagedPolicyGrantRecord, ManagedStoreError>,
{
    let subjects = policy_subject_catalog(&tx)?;
    let catalog = resource_catalog(&tx)?;
    validate_grant_resource_references(&active_grants, &catalog)?;
    validate_candidate(&active_grants, &revision, &subjects, &catalog)?;
    if let Some(grant) = inactive_validation_grant.as_ref() {
        validate_grant_resource_references(std::slice::from_ref(grant), &catalog)?;
        validate_candidate(std::slice::from_ref(grant), &revision, &subjects, &catalog)?;
    }
    let grant = persist(&tx, &revision)?;
    tx.commit().map_err(sql_unavailable)?;
    Ok(ManagedPolicyMutationResult {
        catalog,
        previous_revision,
        revision,
        grant,
        active_grants,
    })
}

fn group_by_id(conn: &Connection, group_id: &str) -> Result<GroupRecord, ManagedStoreError> {
    let resolved_at = normalized_now_string();
    conn.query_row(
        "WITH effective(principal_id, group_id) AS (
           SELECT principal_id, group_id FROM principal_groups
           UNION
           SELECT lm.principal_id, b.group_id
           FROM principal_login_methods lm
           JOIN oidc_membership_refresh_state rs ON rs.login_method_id = lm.login_method_id
           JOIN external_principal_groups epg ON epg.login_method_id = lm.login_method_id
           JOIN external_group_bindings b ON b.binding_id = epg.binding_id
           JOIN oidc_provider_state ps ON ps.provider_id = 'microsoft'
           WHERE lm.method = 'oidc' AND lm.external_provider = 'microsoft'
             AND lm.status = 'active' AND ps.enabled = 1 AND b.status = 'active'
             AND rs.valid_until > ?2 AND epg.valid_until > ?2
         )
         SELECT g.group_id, g.display_name, g.description, g.status, g.created_at,
                g.created_by, g.updated_at, g.updated_by, g.disabled_at,
                COUNT(e.principal_id) AS member_count
         FROM groups g
         LEFT JOIN effective e ON e.group_id = g.group_id
         WHERE g.group_id = ?1
         GROUP BY g.group_id, g.display_name, g.description, g.status, g.created_at,
                  g.created_by, g.updated_at, g.updated_by, g.disabled_at",
        params![group_id, resolved_at],
        group_from_row,
    )
    .optional()
    .map_err(sql_unavailable)?
    .ok_or(ManagedStoreError::GroupNotFound)
}

fn group_exists(conn: &Connection, group_id: &str) -> Result<bool, ManagedStoreError> {
    let exists: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM groups WHERE group_id = ?1 LIMIT 1",
            params![group_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql_unavailable)?;
    Ok(exists.is_some())
}

fn group_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<GroupRecord> {
    let member_count: i64 = row.get(9)?;
    Ok(GroupRecord {
        group_id: row.get(0)?,
        display_name: row.get(1)?,
        description: row.get(2)?,
        status: row.get(3)?,
        created_at: row.get(4)?,
        created_by: row.get(5)?,
        updated_at: row.get(6)?,
        updated_by: row.get(7)?,
        disabled_at: row.get(8)?,
        member_count: member_count as u64,
    })
}

fn active_admin_principal_count(conn: &Connection) -> Result<u64, ManagedStoreError> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(1)
             FROM principals p
             WHERE p.kind = 'user' AND p.status = 'active' AND p.role = 'admin'",
            [],
            |row| row.get(0),
        )
        .map_err(sql_unavailable)?;
    Ok(count as u64)
}

fn principal_is_active_admin(
    conn: &Connection,
    principal_id: &str,
) -> Result<bool, ManagedStoreError> {
    let exists: Option<i64> = conn
        .query_row(
            "SELECT 1
             FROM principals p
             WHERE p.principal_id = ?1 AND p.kind = 'user'
                   AND p.status = 'active' AND p.role = 'admin'
             LIMIT 1",
            params![principal_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql_unavailable)?;
    Ok(exists.is_some())
}

fn principal_groups(
    conn: &Connection,
    principal_id: &str,
) -> Result<Vec<String>, ManagedStoreError> {
    Ok(effective_membership_at_conn(conn, principal_id, &normalized_now_string())?.groups)
}

/// Resolve current policy membership on an already-open store connection,
/// including expiry of externally supplied group evidence.
pub(crate) fn principal_policy_groups(
    conn: &Connection,
    principal_id: &str,
) -> Result<Vec<String>, ManagedStoreError> {
    Ok(effective_membership_at_conn(conn, principal_id, &normalized_now_string())?.policy_groups)
}

/// The stored kind of `principal_id` on `conn`; `None` for a principal the
/// store does not hold, such as a configured static principal.
pub(crate) fn principal_kind_at_conn(
    conn: &Connection,
    principal_id: &str,
) -> Result<Option<crate::PrincipalKind>, ManagedStoreError> {
    let kind: Option<String> = conn
        .query_row(
            "SELECT kind FROM principals WHERE principal_id = ?1",
            params![principal_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql_unavailable)?;
    Ok(kind.as_deref().and_then(crate::PrincipalKind::from_stored))
}

fn effective_membership_at_conn(
    conn: &Connection,
    principal_id: &str,
    resolved_at: &str,
) -> Result<EffectiveMembershipRecord, ManagedStoreError> {
    let mut details = BTreeMap::<String, EffectiveGroupMembershipRecord>::new();
    let mut policy_groups = BTreeSet::<String>::new();
    let mut local = conn
        .prepare(
            "SELECT g.group_id, g.status, pg.created_at, pg.created_by
             FROM principal_groups pg JOIN groups g ON g.group_id = pg.group_id
             WHERE pg.principal_id = ?1 ORDER BY g.group_id",
        )
        .map_err(sql_unavailable)?;
    let rows = local
        .query_map(params![principal_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(sql_unavailable)?;
    for row in rows {
        let (group_id, group_status, added_at, added_by) = row.map_err(sql_unavailable)?;
        if group_status == "active" {
            policy_groups.insert(group_id.clone());
        }
        details.insert(
            group_id.clone(),
            EffectiveGroupMembershipRecord {
                group_id,
                effective: true,
                source: "local".to_string(),
                local: Some(LocalMembershipContributionRecord { added_at, added_by }),
                microsoft: Vec::new(),
            },
        );
    }
    let mut external = conn
        .prepare(
            "SELECT g.group_id, g.status, b.binding_id, b.external_group_id,
                    epg.observed_at, epg.valid_until
             FROM principal_login_methods lm
             JOIN oidc_membership_refresh_state rs ON rs.login_method_id = lm.login_method_id
             JOIN external_principal_groups epg ON epg.login_method_id = lm.login_method_id
             JOIN external_group_bindings b ON b.binding_id = epg.binding_id
             JOIN groups g ON g.group_id = b.group_id
             JOIN oidc_provider_state ps ON ps.provider_id = 'microsoft'
             WHERE lm.principal_id = ?1 AND lm.method = 'oidc'
               AND lm.external_provider = 'microsoft' AND lm.status = 'active'
               AND ps.enabled = 1 AND b.status = 'active'
               AND rs.valid_until > ?2 AND epg.valid_until > ?2
             ORDER BY g.group_id, b.binding_id",
        )
        .map_err(sql_unavailable)?;
    let rows = external
        .query_map(params![principal_id, resolved_at], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                MicrosoftMembershipContributionRecord {
                    binding_id: row.get(2)?,
                    external_group_id: row.get(3)?,
                    observed_at: row.get(4)?,
                    valid_until: row.get(5)?,
                    current: true,
                },
            ))
        })
        .map_err(sql_unavailable)?;
    for row in rows {
        let (group_id, group_status, contribution) = row.map_err(sql_unavailable)?;
        if group_status == "active" {
            policy_groups.insert(group_id.clone());
        }
        details
            .entry(group_id.clone())
            .or_insert_with(|| EffectiveGroupMembershipRecord {
                group_id,
                effective: true,
                source: "microsoft".to_string(),
                local: None,
                microsoft: Vec::new(),
            })
            .microsoft
            .push(contribution);
    }
    for detail in details.values_mut() {
        detail.source = match (detail.local.is_some(), detail.microsoft.is_empty()) {
            (true, false) => "local_and_microsoft",
            (true, true) => "local",
            (false, false) => "microsoft",
            (false, true) => unreachable!("effective membership has at least one contribution"),
        }
        .to_string();
    }
    let details = details.into_values().collect::<Vec<_>>();
    let groups = details
        .iter()
        .map(|detail| detail.group_id.clone())
        .collect();
    let policy_groups = policy_groups.into_iter().collect();
    Ok(EffectiveMembershipRecord {
        groups,
        policy_groups,
        details,
    })
}

fn group_members(
    conn: &Connection,
    group_id: &str,
) -> Result<Vec<GroupMemberRecord>, ManagedStoreError> {
    let resolved_at = normalized_now_string();
    let mut statement = conn
        .prepare(
            "WITH contributions(principal_id, created_at, created_by) AS (
               SELECT pg.principal_id, pg.created_at, pg.created_by
               FROM principal_groups pg WHERE pg.group_id = ?1
               UNION ALL
               SELECT lm.principal_id, epg.observed_at, 'oidc-microsoft'
               FROM principal_login_methods lm
               JOIN oidc_membership_refresh_state rs ON rs.login_method_id = lm.login_method_id
               JOIN external_principal_groups epg ON epg.login_method_id = lm.login_method_id
               JOIN external_group_bindings b ON b.binding_id = epg.binding_id
               JOIN oidc_provider_state ps ON ps.provider_id = 'microsoft'
               WHERE b.group_id = ?1 AND lm.method = 'oidc'
                 AND lm.external_provider = 'microsoft' AND lm.status = 'active'
                 AND ps.enabled = 1 AND b.status = 'active'
                 AND rs.valid_until > ?2 AND epg.valid_until > ?2
             )
             SELECT p.principal_id, p.kind, p.display_name, p.email, p.status,
                    MIN(c.created_at), MIN(c.created_by)
             FROM contributions c JOIN principals p ON p.principal_id = c.principal_id
             GROUP BY p.principal_id, p.kind, p.display_name, p.email, p.status
             ORDER BY p.principal_id",
        )
        .map_err(sql_unavailable)?;
    let rows = statement
        .query_map(params![group_id, resolved_at], |row| {
            Ok(GroupMemberRecord {
                principal_id: row.get(0)?,
                kind: Some(row.get(1)?),
                display_name: row.get(2)?,
                email: row.get(3)?,
                status: Some(row.get(4)?),
                created_at: row.get(5)?,
                created_by: row.get(6)?,
                membership: None,
            })
        })
        .map_err(sql_unavailable)?;
    let mut members = collect_rows(rows)?;
    for member in &mut members {
        member.membership = effective_membership_at_conn(conn, &member.principal_id, &resolved_at)?
            .details
            .into_iter()
            .find(|membership| membership.group_id == group_id);
    }
    Ok(members)
}

fn broker_token_by_id(
    conn: &Connection,
    token_id: &str,
) -> Result<BrokerTokenRecord, ManagedStoreError> {
    conn.query_row(
        "SELECT token_id, token_hash, principal_id, name, token_class, scopes_json,
                created_at, expires_at, revoked_at, revoked_by, paused_at, paused_by,
                last_used_at, created_by
         FROM broker_tokens
         WHERE token_id = ?1",
        params![token_id],
        broker_token_from_row,
    )
    .optional()
    .map_err(sql_unavailable)?
    .ok_or(ManagedStoreError::BrokerTokenNotFound)
}

fn broker_token_by_id_principal_class(
    conn: &Connection,
    token_id: &str,
    principal_id: &str,
    token_class: BrokerTokenClass,
) -> Result<BrokerTokenRecord, ManagedStoreError> {
    conn.query_row(
        "SELECT token_id, token_hash, principal_id, name, token_class, scopes_json,
                created_at, expires_at, revoked_at, revoked_by, paused_at, paused_by,
                last_used_at, created_by
         FROM broker_tokens
         WHERE token_id = ?1
           AND principal_id = ?2
           AND token_class = ?3",
        params![token_id, principal_id, token_class.as_str()],
        broker_token_from_row,
    )
    .optional()
    .map_err(sql_unavailable)?
    .ok_or(ManagedStoreError::BrokerTokenNotFound)
}

fn broker_token_by_hash(
    conn: &Connection,
    token_hash: &str,
) -> Result<Option<BrokerTokenRecord>, ManagedStoreError> {
    conn.query_row(
        "SELECT token_id, token_hash, principal_id, name, token_class, scopes_json,
                created_at, expires_at, revoked_at, revoked_by, paused_at, paused_by,
                last_used_at, created_by
         FROM broker_tokens
         WHERE token_hash = ?1",
        params![token_hash],
        broker_token_from_row,
    )
    .optional()
    .map_err(sql_unavailable)
}

#[derive(Clone, Copy)]
enum TokenPauseTransition {
    Pause,
    Resume,
}

fn transition_agent_token_pause_tx(
    tx: &rusqlite::Transaction<'_>,
    token_id: &str,
    principal_id: Option<&str>,
    actor: &str,
    now: &str,
    transition: TokenPauseTransition,
    catalog: Option<&ManagedResourceCatalog>,
) -> Result<BrokerTokenRecord, ManagedStoreError> {
    let record = broker_token_by_id(tx, token_id)?;
    ensure_agent_token_transition_scope(&record, principal_id)?;
    ensure_agent_token_transition_not_terminal(&record)?;
    if matches!(transition, TokenPauseTransition::Resume) {
        validate_token_resource_references(tx, &record.scopes, catalog)?;
    }

    let already_desired = match transition {
        TokenPauseTransition::Pause => record.paused_at.is_some(),
        TokenPauseTransition::Resume => record.paused_at.is_none(),
    };
    if already_desired {
        return Ok(record);
    }

    let changed = match transition {
        TokenPauseTransition::Pause => tx.execute(
            "UPDATE broker_tokens
             SET paused_at = ?2, paused_by = ?3
             WHERE token_id = ?1
               AND paused_at IS NULL
               AND revoked_at IS NULL
               AND (expires_at IS NULL OR expires_at > ?2)",
            params![token_id, now, actor],
        ),
        TokenPauseTransition::Resume => tx.execute(
            "UPDATE broker_tokens
             SET paused_at = NULL, paused_by = NULL
             WHERE token_id = ?1
               AND paused_at IS NOT NULL
               AND revoked_at IS NULL
               AND (expires_at IS NULL OR expires_at > ?2)",
            params![token_id, now],
        ),
    }
    .map_err(sql_unavailable)?;

    let result = broker_token_by_id(tx, token_id)?;
    ensure_agent_token_transition_scope(&result, principal_id)?;
    if changed == 0 {
        ensure_agent_token_transition_not_terminal(&result)?;
        let reached_desired = match transition {
            TokenPauseTransition::Pause => result.paused_at.is_some(),
            TokenPauseTransition::Resume => result.paused_at.is_none(),
        };
        if !reached_desired {
            return Err(ManagedStoreError::BrokerTokenStateConflict);
        }
    }
    Ok(result)
}

fn ensure_agent_token_transition_scope(
    record: &BrokerTokenRecord,
    principal_id: Option<&str>,
) -> Result<(), ManagedStoreError> {
    if record.token_class != BrokerTokenClass::AgentInvoke
        || principal_id.is_some_and(|principal_id| principal_id != record.principal_id)
    {
        Err(ManagedStoreError::BrokerTokenNotFound)
    } else {
        Ok(())
    }
}

fn ensure_agent_token_transition_not_terminal(
    record: &BrokerTokenRecord,
) -> Result<(), ManagedStoreError> {
    if record.revoked_at.is_some() || timestamp_is_past(record.expires_at.as_deref()) {
        Err(ManagedStoreError::BrokerTokenStateConflict)
    } else {
        Ok(())
    }
}

fn broker_token_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<BrokerTokenRecord> {
    let token_class_raw: String = row.get(4)?;
    let scopes_raw: String = row.get(5)?;
    let token_class = token_class_raw.parse().map_err(|()| {
        rusqlite::Error::FromSqlConversionFailure(
            4,
            Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid broker token class: {token_class_raw}"),
            )),
        )
    })?;
    let scopes = serde_json::from_str(&scopes_raw).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(5, Type::Text, Box::new(error))
    })?;
    let paused_at: Option<String> = row.get(10)?;
    let paused_by: Option<String> = row.get(11)?;
    if paused_at.is_some() != paused_by.is_some()
        || paused_at
            .as_deref()
            .is_some_and(|value| DateTime::parse_from_rfc3339(value).is_err())
        || paused_by
            .as_deref()
            .is_some_and(|value| validate_actor(value).is_err())
    {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            10,
            Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid broker token pause metadata",
            )),
        ));
    }
    Ok(BrokerTokenRecord {
        token_id: row.get(0)?,
        token_hash: row.get(1)?,
        principal_id: row.get(2)?,
        name: row.get(3)?,
        token_class,
        scopes,
        created_at: row.get(6)?,
        expires_at: row.get(7)?,
        revoked_at: row.get(8)?,
        revoked_by: row.get(9)?,
        paused_at,
        paused_by,
        last_used_at: row.get(12)?,
        created_by: row.get(13)?,
    })
}

fn browser_session_token_exists(
    conn: &Connection,
    token_id: &str,
) -> Result<bool, ManagedStoreError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM browser_sessions WHERE token_id = ?1)",
        params![token_id],
        |row| row.get::<_, bool>(0),
    )
    .map_err(sql_unavailable)
}

fn login_method_by_id(
    conn: &Connection,
    login_method_id: &str,
) -> Result<LoginMethodRecord, ManagedStoreError> {
    conn.query_row(
        "SELECT login_method_id, principal_id, method, external_provider, external_subject,
                status, password_set_at, must_change_password, created_at, updated_at,
                created_by, updated_by
         FROM principal_login_methods
         WHERE login_method_id = ?1",
        params![login_method_id],
        login_method_from_row,
    )
    .optional()
    .map_err(sql_unavailable)?
    .ok_or_else(|| input_invalid("login method is not configured"))
    .and_then(|mut record| {
        local_password_failures::attach_lockout(conn, &mut record)?;
        Ok(record)
    })
}

fn oidc_provider_state(
    conn: &Connection,
) -> Result<Option<OidcProviderStateRecord>, ManagedStoreError> {
    conn.query_row(
        "SELECT provider_id, tenant_id, client_id, enabled, config_generation,
                config_fingerprint, external_membership_ttl_s, updated_at
         FROM oidc_provider_state WHERE provider_id = 'microsoft'",
        [],
        |row| {
            Ok(OidcProviderStateRecord {
                provider_id: row.get(0)?,
                tenant_id: row.get(1)?,
                client_id: row.get(2)?,
                enabled: row.get(3)?,
                config_generation: row.get::<_, i64>(4)? as u64,
                config_fingerprint: row.get(5)?,
                external_membership_ttl_seconds: row.get::<_, i64>(6)? as u64,
                updated_at: row.get(7)?,
            })
        },
    )
    .optional()
    .map_err(sql_unavailable)
}

fn require_oidc_provider_generation(
    conn: &Connection,
    generation: u64,
) -> Result<OidcProviderStateRecord, ManagedStoreError> {
    let state = oidc_provider_state(conn)?.ok_or(ManagedStoreError::OidcProviderUnavailable)?;
    if !state.enabled || state.config_generation != generation {
        return Err(ManagedStoreError::OidcProviderUnavailable);
    }
    Ok(state)
}

fn advance_oidc_subject_watermark_tx(
    conn: &Connection,
    external_subject: &str,
    flow_sequence: u64,
    updated_at: &str,
) -> Result<bool, ManagedStoreError> {
    let changed = conn
        .execute(
            "INSERT INTO oidc_subject_flow_watermarks
             (external_subject, last_flow_sequence, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(external_subject) DO UPDATE SET
               last_flow_sequence = excluded.last_flow_sequence,
               updated_at = excluded.updated_at
             WHERE oidc_subject_flow_watermarks.last_flow_sequence < excluded.last_flow_sequence",
            params![external_subject, flow_sequence as i64, updated_at],
        )
        .map_err(sql_unavailable)?;
    Ok(changed != 0)
}

fn oidc_flow_by_sequence(
    conn: &Connection,
    flow_sequence: i64,
) -> Result<OidcFlowRecord, ManagedStoreError> {
    conn.query_row(
        "SELECT flow_sequence, state_hash, browser_binding_hash, provider_generation,
                encrypted_payload, encryption_nonce, return_path, created_at, expires_at,
                consumed_at, outcome_code
         FROM oidc_authorization_flows WHERE flow_sequence = ?1",
        params![flow_sequence],
        |row| {
            Ok(OidcFlowRecord {
                flow_sequence: row.get::<_, i64>(0)? as u64,
                state_hash: row.get(1)?,
                browser_binding_hash: row.get(2)?,
                provider_generation: row.get::<_, i64>(3)? as u64,
                encrypted_payload: row.get(4)?,
                encryption_nonce: row.get(5)?,
                return_path: row.get(6)?,
                created_at: row.get(7)?,
                expires_at: row.get(8)?,
                consumed_at: row.get(9)?,
                outcome_code: row.get(10)?,
            })
        },
    )
    .optional()
    .map_err(sql_unavailable)?
    .ok_or(ManagedStoreError::OidcFlowInvalid)
}

fn oidc_login_method_for_principal(
    conn: &Connection,
    principal_id: &str,
) -> Result<Option<LoginMethodRecord>, ManagedStoreError> {
    conn.query_row(
        "SELECT login_method_id, principal_id, method, external_provider, external_subject,
                status, password_set_at, must_change_password, created_at, updated_at,
                created_by, updated_by
         FROM principal_login_methods
         WHERE principal_id = ?1 AND method = 'oidc' AND external_provider = 'microsoft'",
        params![principal_id],
        login_method_from_row,
    )
    .optional()
    .map_err(sql_unavailable)
}

fn oidc_login_method_for_subject(
    conn: &Connection,
    external_subject: &str,
) -> Result<Option<LoginMethodRecord>, ManagedStoreError> {
    conn.query_row(
        "SELECT login_method_id, principal_id, method, external_provider, external_subject,
                status, password_set_at, must_change_password, created_at, updated_at,
                created_by, updated_by
         FROM principal_login_methods
         WHERE method = 'oidc' AND external_provider = 'microsoft' AND external_subject = ?1",
        params![external_subject],
        login_method_from_row,
    )
    .optional()
    .map_err(sql_unavailable)
}

fn external_group_binding_by_id(
    conn: &Connection,
    binding_id: &str,
) -> Result<ExternalGroupBindingRecord, ManagedStoreError> {
    conn.query_row(
        "SELECT binding_id, external_group_id, group_id, status, created_at, created_by,
                updated_at, updated_by
         FROM external_group_bindings WHERE binding_id = ?1",
        params![binding_id],
        external_group_binding_from_row,
    )
    .optional()
    .map_err(sql_unavailable)?
    .ok_or(ManagedStoreError::ExternalGroupBindingNotFound)
}

fn external_group_bindings(
    conn: &Connection,
    group_id: Option<&str>,
) -> Result<Vec<ExternalGroupBindingRecord>, ManagedStoreError> {
    let mut statement = conn
        .prepare(
            "SELECT binding_id, external_group_id, group_id, status, created_at, created_by,
                    updated_at, updated_by
             FROM external_group_bindings
             WHERE ?1 IS NULL OR group_id = ?1
             ORDER BY group_id, external_group_id",
        )
        .map_err(sql_unavailable)?;
    let rows = statement
        .query_map(params![group_id], external_group_binding_from_row)
        .map_err(sql_unavailable)?;
    collect_rows(rows)
}

fn external_group_binding_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<ExternalGroupBindingRecord> {
    Ok(ExternalGroupBindingRecord {
        binding_id: row.get(0)?,
        external_group_id: row.get(1)?,
        group_id: row.get(2)?,
        status: row.get(3)?,
        created_at: row.get(4)?,
        created_by: row.get(5)?,
        updated_at: row.get(6)?,
        updated_by: row.get(7)?,
    })
}

fn local_password_login_method(
    conn: &Connection,
    principal_id: &str,
) -> Result<Option<LoginMethodRecord>, ManagedStoreError> {
    conn.query_row(
        "SELECT login_method_id, principal_id, method, external_provider, external_subject,
                status, password_set_at, must_change_password, created_at, updated_at,
                created_by, updated_by
         FROM principal_login_methods
         WHERE principal_id = ?1 AND method = 'local_password'",
        params![principal_id],
        login_method_from_row,
    )
    .optional()
    .map_err(sql_unavailable)
}

// A PHC includes a fresh random salt on every password write, making it a
// credential revision independent of timestamp resolution.
#[derive(PartialEq, Eq)]
struct LocalPasswordCandidate {
    login_method_id: String,
    password_hash_phc: String,
}

fn local_password_candidate(
    conn: &Connection,
    request: &LocalPasswordVerifyRequest,
) -> Result<Option<LocalPasswordCandidate>, ManagedStoreError> {
    let principal = match principal_by_id_without_groups(conn, &request.principal_id) {
        Ok(principal) => principal,
        Err(ManagedStoreError::PrincipalNotFound) => return Ok(None),
        Err(error) => return Err(error),
    };
    if principal.status != "active" || principal.kind != "user" {
        return Ok(None);
    }
    let Some(method) = local_password_login_method(conn, &request.principal_id)?
        .filter(|method| method.status == "active")
    else {
        return Ok(None);
    };
    Ok(Some(LocalPasswordCandidate {
        password_hash_phc: local_password_hash(conn, &method.login_method_id)?,
        login_method_id: method.login_method_id,
    }))
}

fn recheck_local_password_candidate(
    conn: &Connection,
    candidate: Option<&LocalPasswordCandidate>,
    request: &LocalPasswordVerifyRequest,
) -> Result<Option<VerifiedLocalPassword>, ManagedStoreError> {
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    if local_password_candidate(conn, request)?.as_ref() != Some(candidate) {
        return Ok(None);
    }
    let principal = principal_by_id(conn, &request.principal_id)?;
    let method = local_password_login_method(conn, &request.principal_id)?
        .ok_or(ManagedStoreError::LocalLoginFailed)?;
    Ok(Some(VerifiedLocalPassword {
        sign_in_methods: principal.sign_in_methods,
        principal_id: request.principal_id.clone(),
        display_name: principal.display_name,
        email: principal.email,
        policy_groups: principal_policy_groups(conn, &request.principal_id)?,
        groups: principal.groups,
        role: principal.role,
        self_service_enabled: principal.self_service_enabled,
        login_method_id: method.login_method_id,
        password_change_required: method.must_change_password,
    }))
}

fn local_password_hash(
    conn: &Connection,
    login_method_id: &str,
) -> Result<String, ManagedStoreError> {
    conn.query_row(
        "SELECT password_hash_phc
         FROM principal_login_methods
         WHERE login_method_id = ?1 AND method = 'local_password'",
        params![login_method_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(sql_unavailable)?
    .ok_or_else(|| input_invalid("local password login method is not configured"))
}

/// Maps a login-method row. The lockout summary is filled separately by
/// `local_password_failures::attach_lockout`.
fn login_method_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<LoginMethodRecord> {
    Ok(LoginMethodRecord {
        login_method_id: row.get(0)?,
        principal_id: row.get(1)?,
        method: row.get(2)?,
        external_provider: row.get(3)?,
        external_subject: row.get(4)?,
        status: row.get(5)?,
        password_set_at: row.get(6)?,
        must_change_password: row.get(7)?,
        locked: false,
        locked_until: None,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
        created_by: row.get(10)?,
        updated_by: row.get(11)?,
    })
}

fn browser_session_by_token_id(
    conn: &Connection,
    token_id: &str,
) -> Result<BrowserSessionRecord, ManagedStoreError> {
    conn.query_row(
        "SELECT token_id, principal_id, login_method, login_method_id, auth_time, created_at,
                password_change_required
         FROM browser_sessions
         WHERE token_id = ?1",
        params![token_id],
        browser_session_from_row,
    )
    .optional()
    .map_err(sql_unavailable)?
    .ok_or(ManagedStoreError::BrokerTokenNotFound)
}

fn browser_session_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<BrowserSessionRecord> {
    Ok(BrowserSessionRecord {
        token_id: row.get(0)?,
        principal_id: row.get(1)?,
        login_method: row.get(2)?,
        login_method_id: row.get(3)?,
        auth_time: row.get(4)?,
        created_at: row.get(5)?,
        password_change_required: row.get(6)?,
    })
}

fn revoke_browser_sessions_by_method_tx(
    tx: &rusqlite::Transaction<'_>,
    principal_id: &str,
    login_method: &str,
    actor: &str,
    now: &str,
) -> Result<(), ManagedStoreError> {
    tx.execute(
        "UPDATE broker_tokens
         SET revoked_at = COALESCE(revoked_at, ?4),
             revoked_by = COALESCE(revoked_by, ?3)
         WHERE token_id IN (
             SELECT token_id
             FROM browser_sessions
             WHERE principal_id = ?1 AND login_method = ?2
         )",
        params![principal_id, login_method, actor, now],
    )
    .map_err(sql_unavailable)?;
    Ok(())
}

fn revoke_browser_sessions_by_login_method_id_tx(
    conn: &Connection,
    login_method_id: &str,
    actor: &str,
    now: &str,
) -> Result<u64, ManagedStoreError> {
    let changed = conn
        .execute(
            "UPDATE broker_tokens
             SET revoked_at = COALESCE(revoked_at, ?3), revoked_by = COALESCE(revoked_by, ?2)
             WHERE token_id IN (
               SELECT token_id FROM browser_sessions WHERE login_method_id = ?1
             )",
            params![login_method_id, actor, now],
        )
        .map_err(sql_unavailable)?;
    Ok(changed as u64)
}

fn expire_all_oidc_membership_tx(
    conn: &Connection,
    actor: &str,
    now: &str,
) -> Result<(), ManagedStoreError> {
    conn.execute("DELETE FROM external_principal_groups", [])
        .map_err(sql_unavailable)?;
    conn.execute("DELETE FROM oidc_membership_refresh_state", [])
        .map_err(sql_unavailable)?;
    conn.execute(
        "UPDATE broker_tokens
         SET revoked_at = COALESCE(revoked_at, ?2), revoked_by = COALESCE(revoked_by, ?1)
         WHERE token_id IN (
           SELECT bs.token_id FROM browser_sessions bs
           JOIN principal_login_methods lm ON lm.login_method_id = bs.login_method_id
           WHERE lm.method = 'oidc' AND lm.external_provider = 'microsoft'
         )",
        params![actor, now],
    )
    .map_err(sql_unavailable)?;
    Ok(())
}

fn clamp_oidc_membership_ttl_tx(
    conn: &Connection,
    ttl_seconds: u64,
    now: &str,
) -> Result<(), ManagedStoreError> {
    for table in ["oidc_membership_refresh_state", "external_principal_groups"] {
        let sql = format!("SELECT rowid, evidence_at, valid_until FROM {table}");
        let mut statement = conn.prepare(&sql).map_err(sql_unavailable)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(sql_unavailable)?;
        let rows = collect_rows(rows)?;
        drop(statement);
        for (rowid, evidence_at, valid_until) in rows {
            let evidence = DateTime::parse_from_rfc3339(&evidence_at)
                .map_err(|_| {
                    ManagedStoreError::SchemaInvalid(
                        "OIDC evidence timestamp is malformed".to_string(),
                    )
                })?
                .with_timezone(&Utc);
            let ceiling = normalized_timestamp(evidence + Duration::seconds(ttl_seconds as i64));
            if ceiling < valid_until {
                let update = format!(
                    "UPDATE {table} SET valid_until = ?2, updated_at = ?3 WHERE rowid = ?1"
                );
                conn.execute(&update, params![rowid, ceiling, now])
                    .map_err(sql_unavailable)?;
            }
        }
    }
    Ok(())
}

fn issue_browser_session_tx(
    conn: &Connection,
    hasher: &BrokerTokenHasher,
    request: &BrowserSessionIssueRequest,
    now: &str,
) -> Result<IssuedBrowserSession, ManagedStoreError> {
    validate_browser_session_issue_request(request)?;
    let principal = principal_by_id(conn, &request.principal_id)?;
    if principal.status != "active" {
        return Err(ManagedStoreError::PrincipalDisabled);
    }
    require_interactive_principal(&principal)?;
    let login_method_id = request
        .login_method_id
        .as_deref()
        .ok_or_else(|| input_invalid("browser session login method is required"))?;
    let login_method = login_method_by_id(conn, login_method_id)?;
    if login_method.principal_id != request.principal_id
        || login_method.method != request.login_method
        || login_method.status != "active"
    {
        return Err(input_invalid("browser session login method is invalid"));
    }
    let raw_token = generate_broker_token(&BrokerTokenClass::UserManage);
    let token_hash = hasher.hash(&raw_token)?;
    let issued_at = DateTime::parse_from_rfc3339(now)
        .map_err(|_| input_invalid("browser session issue time is invalid"))?
        .with_timezone(&Utc);
    let expires_at =
        normalized_timestamp(issued_at + Duration::seconds(request.ttl_seconds as i64));
    let token_id = Uuid::new_v4().to_string();
    let scopes_json = "{}";
    let token_name = if request.login_method == "oidc" {
        "oidc:microsoft:browser-session".to_string()
    } else {
        "local_password:browser-session".to_string()
    };
    conn.execute(
        "INSERT INTO broker_tokens
         (token_id, token_hash, principal_id, name, token_class, scopes_json, created_at,
          expires_at, revoked_at, revoked_by, last_used_at, created_by)
         VALUES (?1, ?2, ?3, ?4, 'user_manage', ?5, ?6, ?7, NULL, NULL, NULL, ?8)",
        params![
            token_id,
            token_hash,
            request.principal_id,
            token_name,
            scopes_json,
            now,
            expires_at,
            request.created_by
        ],
    )
    .map_err(sql_unavailable)?;
    conn.execute(
        "INSERT INTO browser_sessions
         (token_id, principal_id, login_method, login_method_id, auth_time, created_at,
          password_change_required)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6)",
        params![
            token_id,
            request.principal_id,
            request.login_method,
            login_method_id,
            now,
            request.password_change_required
        ],
    )
    .map_err(sql_unavailable)?;
    Ok(IssuedBrowserSession {
        token: raw_token,
        record: broker_token_by_id(conn, &token_id)?,
        session: browser_session_by_token_id(conn, &token_id)?,
    })
}

fn right_by_id(conn: &Connection, right_id: &str) -> Result<RightRecord, ManagedStoreError> {
    conn.query_row(
        "SELECT right_id, principal_id, right_name, service, credential_name,
                resource_scope_json, created_by, created_at, expires_at, revoked_at,
                revoked_by, reason
         FROM rights
         WHERE right_id = ?1",
        params![right_id],
        right_from_row,
    )
    .optional()
    .map_err(sql_unavailable)?
    .ok_or(ManagedStoreError::RightMissing)
}

fn right_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RightRecord> {
    Ok(RightRecord {
        right_id: row.get(0)?,
        principal_id: row.get(1)?,
        right: row.get(2)?,
        service: row.get(3)?,
        credential_name: row.get(4)?,
        resource_scope_json: row.get(5)?,
        created_by: row.get(6)?,
        created_at: row.get(7)?,
        expires_at: row.get(8)?,
        revoked_at: row.get(9)?,
        revoked_by: row.get(10)?,
        reason: row.get(11)?,
    })
}

fn credential_metadata_by_tuple(
    conn: &Connection,
    owner_principal_id: &str,
    service: &str,
    name: &str,
) -> Result<CredentialMetadata, ManagedStoreError> {
    conn.query_row(
        "SELECT credential_id, owner_principal_id, owner_kind, service, name,
                profile, credential_kind, metadata_json, secret_backend, secret_ref,
                material_version, status, created_at, updated_at, created_by, updated_by,
                last_used_at, last_verified_at, verification_status,
                last_verification_attempt_at, last_verification_error_code
         FROM credentials
         WHERE owner_kind = 'user'
           AND owner_principal_id = ?1
           AND service = ?2
           AND name = ?3",
        params![owner_principal_id, service, name],
        credential_metadata_from_row,
    )
    .optional()
    .map_err(sql_unavailable)?
    .ok_or(ManagedStoreError::CredentialNotFound)
}

fn credential_metadata_by_id(
    conn: &Connection,
    credential_id: &str,
) -> Result<CredentialMetadata, ManagedStoreError> {
    conn.query_row(
        "SELECT credential_id, owner_principal_id, owner_kind, service, name,
                profile, credential_kind, metadata_json, secret_backend, secret_ref,
                material_version, status, created_at, updated_at, created_by, updated_by,
                last_used_at, last_verified_at, verification_status,
                last_verification_attempt_at, last_verification_error_code
         FROM credentials
         WHERE credential_id = ?1",
        params![credential_id],
        credential_metadata_from_row,
    )
    .optional()
    .map_err(sql_unavailable)?
    .ok_or(ManagedStoreError::CredentialNotFound)
}

fn credential_metadata_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CredentialMetadata> {
    let metadata_raw: String = row.get(7)?;
    let metadata = serde_json::from_str(&metadata_raw).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(7, Type::Text, Box::new(error))
    })?;
    Ok(CredentialMetadata {
        credential_id: row.get(0)?,
        owner_principal: row.get(1)?,
        owner_kind: row.get(2)?,
        service: row.get(3)?,
        name: row.get(4)?,
        profile: row.get(5)?,
        credential_kind: row.get(6)?,
        metadata,
        secret_backend: row.get(8)?,
        secret_ref: row.get(9)?,
        material_version: row.get(10)?,
        status: row.get(11)?,
        created_at: row.get(12)?,
        updated_at: row.get(13)?,
        created_by: row.get(14)?,
        updated_by: row.get(15)?,
        last_used_at: row.get(16)?,
        last_verified_at: row.get(17)?,
        verification_status: row.get(18)?,
        last_verification_attempt_at: row.get(19)?,
        last_verification_error_code: row.get(20)?,
    })
}

pub(crate) fn secret_reference_management_authority_conn(
    conn: &Connection,
    principal: &str,
) -> Result<ManagedManagementAuthority, ManagedStoreError> {
    management_authority_conn(conn, principal)
}

pub(crate) fn require_credential_right_conn(
    conn: &Connection,
    principal_id: &str,
    right: &str,
    service: &str,
    credential_name: &str,
) -> Result<(), ManagedStoreError> {
    if has_credential_right_conn(conn, principal_id, right, service, credential_name)? {
        Ok(())
    } else {
        Err(ManagedStoreError::RightMissing)
    }
}

fn has_credential_right_conn(
    conn: &Connection,
    principal_id: &str,
    right: &str,
    service: &str,
    credential_name: &str,
) -> Result<bool, ManagedStoreError> {
    validate_principal_id(principal_id)?;
    validate_right_name(right)?;
    validate_service_and_name(service, credential_name)?;
    let now = normalized_now_string();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(1)
                 FROM rights
                 WHERE principal_id = ?1
                   AND right_name = ?2
                   AND (service IS NULL OR service = ?3)
                   AND (credential_name IS NULL OR credential_name = ?4)
                   AND resource_scope_json IS NULL
                   AND revoked_at IS NULL
                   AND (expires_at IS NULL OR expires_at > ?5)",
            params![principal_id, right, service, credential_name, now],
            |row| row.get(0),
        )
        .map_err(sql_unavailable)?;
    Ok(count > 0)
}

fn upsert_user_credential_conn(
    conn: &Connection,
    key_ring: &CredentialKeyRing,
    request: CredentialWriteRequest,
    purpose: CredentialManagementPurpose,
) -> Result<CredentialMetadata, ManagedStoreError> {
    validate_credential_write_request(&request)?;
    validate_credential_metadata(&request.metadata)?;
    validate_credential_secret(&request.credential_kind, &request.secret)?;
    let now = now_string();
    purpose.check_active_owner(conn, &request.owner_principal_id)?;
    let existing: Option<(String, String, String, String)> = conn
        .query_row(
            "SELECT credential_id, created_at, secret_backend, secret_ref
                 FROM credentials
                 WHERE owner_kind = 'user'
                   AND owner_principal_id = ?1
                   AND service = ?2
                   AND name = ?3",
            params![request.owner_principal_id, request.service, request.name],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(sql_unavailable)?;
    let (credential_id, created_at, secret_backend, secret_ref) = match existing {
        Some((credential_id, created_at, secret_backend, secret_ref)) => {
            if secret_backend != SQLITE_ENCRYPTED_BACKEND {
                return Err(ManagedStoreError::CredentialInvalid(
                    "credential secret backend is not supported".to_string(),
                ));
            }
            validate_sqlite_secret_ref(&secret_ref)?;
            (credential_id, created_at, secret_backend, secret_ref)
        }
        None => (
            Uuid::new_v4().to_string(),
            now.clone(),
            SQLITE_ENCRYPTED_BACKEND.to_string(),
            new_sqlite_secret_ref(),
        ),
    };
    let material_version = Uuid::new_v4().to_string();
    let key_id = key_ring.active_key_id().to_string();
    let aad = CredentialAad {
        credential_id: credential_id.clone(),
        owner_kind: "user".to_string(),
        owner_principal_id: request.owner_principal_id.clone(),
        service: request.service.clone(),
        name: request.name.clone(),
        profile: request.profile.clone(),
        credential_kind: request.credential_kind.clone(),
        secret_backend: secret_backend.clone(),
        secret_ref: secret_ref.clone(),
        material_version: material_version.clone(),
        key_id: key_id.clone(),
    };
    let encrypted = key_ring.encrypt(&request.secret, &aad)?;
    let metadata_json = serde_json::to_string(&request.metadata)
        .map_err(|_| input_invalid("metadata must be JSON serializable"))?;
    conn.execute(
        "INSERT INTO credentials
             (credential_id, owner_principal_id, owner_kind, service, name, profile,
              credential_kind, metadata_json, secret_backend, secret_ref, material_version,
              status, created_at, updated_at, created_by, updated_by, last_used_at,
              last_verified_at, verification_status, last_verification_attempt_at,
              last_verification_error_code)
             VALUES (?1, ?2, 'user', ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'active',
                     ?11, ?12, ?13, ?14, NULL, NULL, 'not_verified', NULL, NULL)
             ON CONFLICT(owner_kind, owner_principal_id, service, name)
             DO UPDATE SET profile = excluded.profile,
                           credential_kind = excluded.credential_kind,
                           metadata_json = excluded.metadata_json,
                           secret_backend = excluded.secret_backend,
                           secret_ref = excluded.secret_ref,
                           material_version = excluded.material_version,
                           status = 'active',
                           updated_at = excluded.updated_at,
                           updated_by = excluded.updated_by,
                           last_verified_at = NULL,
                           verification_status = 'not_verified',
                           last_verification_attempt_at = NULL,
                           last_verification_error_code = NULL",
        params![
            credential_id,
            request.owner_principal_id,
            request.service,
            request.name,
            request.profile,
            request.credential_kind,
            metadata_json,
            secret_backend,
            secret_ref,
            material_version,
            created_at,
            now,
            request.actor,
            request.actor
        ],
    )
    .map_err(sql_unavailable)?;
    let material_changed = conn
        .execute(
            "INSERT INTO credential_secret_material
             (secret_ref, credential_id, backend, secret_ciphertext, secret_nonce, key_id,
              created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(secret_ref)
             DO UPDATE SET credential_id = excluded.credential_id,
                           backend = excluded.backend,
                           secret_ciphertext = excluded.secret_ciphertext,
                           secret_nonce = excluded.secret_nonce,
                           key_id = excluded.key_id,
                           updated_at = excluded.updated_at
             WHERE credential_secret_material.credential_id = excluded.credential_id",
            params![
                aad.secret_ref,
                credential_id,
                SQLITE_ENCRYPTED_BACKEND,
                encrypted.ciphertext,
                encrypted.nonce,
                encrypted.key_id,
                created_at,
                now
            ],
        )
        .map_err(sql_unavailable)?;
    if material_changed == 0 {
        return Err(ManagedStoreError::SchemaInvalid(
            "credential secret material is inconsistent".to_string(),
        ));
    }
    let metadata = credential_metadata_by_tuple(
        conn,
        &request.owner_principal_id,
        &request.service,
        &request.name,
    )?;
    Ok(metadata)
}

fn encrypted_credential_by_tuple(
    conn: &Connection,
    owner_principal_id: &str,
    service: &str,
    name: &str,
) -> Result<EncryptedCredentialRow, ManagedStoreError> {
    conn.query_row(
        "SELECT c.credential_id, c.owner_principal_id, c.owner_kind, c.service, c.name,
                c.profile, c.credential_kind, c.metadata_json, c.secret_backend, c.secret_ref,
                c.material_version, c.status, m.secret_ciphertext, m.secret_nonce, m.key_id
         FROM credentials c
         INNER JOIN credential_secret_material m ON m.secret_ref = c.secret_ref
         WHERE c.owner_kind = 'user'
           AND c.owner_principal_id = ?1
           AND c.service = ?2
           AND c.name = ?3",
        params![owner_principal_id, service, name],
        encrypted_credential_from_row,
    )
    .optional()
    .map_err(sql_unavailable)?
    .ok_or(ManagedStoreError::CredentialNotFound)
}

fn credential_secret_refs_by_key(
    conn: &Connection,
    key_id: &str,
) -> Result<Vec<String>, ManagedStoreError> {
    let mut statement = conn
        .prepare(
            "SELECT m.secret_ref
             FROM credential_secret_material m
             INNER JOIN credentials c ON c.credential_id = m.credential_id
             WHERE m.key_id = ?1 AND c.status = 'active'
             ORDER BY c.credential_id, m.secret_ref",
        )
        .map_err(sql_unavailable)?;
    let rows = statement
        .query_map(params![key_id], |row| row.get::<_, String>(0))
        .map_err(sql_unavailable)?;
    collect_rows(rows)
}

fn encrypted_credential_by_secret_ref_and_key(
    conn: &Connection,
    secret_ref: &str,
    key_id: &str,
) -> Result<Option<EncryptedCredentialRow>, ManagedStoreError> {
    conn.query_row(
        "SELECT c.credential_id, c.owner_principal_id, c.owner_kind, c.service, c.name,
                c.profile, c.credential_kind, c.metadata_json, c.secret_backend, c.secret_ref,
                c.material_version, c.status, m.secret_ciphertext, m.secret_nonce, m.key_id
         FROM credential_secret_material m
         INNER JOIN credentials c ON c.credential_id = m.credential_id
                                AND c.secret_ref = m.secret_ref
         WHERE m.secret_ref = ?1 AND m.key_id = ?2 AND c.status = 'active'",
        params![secret_ref, key_id],
        encrypted_credential_from_row,
    )
    .optional()
    .map_err(sql_unavailable)
}

fn encrypted_credential_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<EncryptedCredentialRow> {
    let metadata_raw: String = row.get(7)?;
    let metadata = serde_json::from_str(&metadata_raw).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(7, Type::Text, Box::new(error))
    })?;
    Ok(EncryptedCredentialRow {
        credential_id: row.get(0)?,
        owner_principal_id: row.get(1)?,
        owner_kind: row.get(2)?,
        service: row.get(3)?,
        name: row.get(4)?,
        profile: row.get(5)?,
        credential_kind: row.get(6)?,
        metadata,
        secret_backend: row.get(8)?,
        secret_ref: row.get(9)?,
        material_version: row.get(10)?,
        status: row.get(11)?,
        secret_ciphertext: row.get(12)?,
        secret_nonce: row.get(13)?,
        key_id: row.get(14)?,
    })
}

fn execution_credential_from_encrypted_row(
    key_ring: &CredentialKeyRing,
    row: &EncryptedCredentialRow,
    expected_profile: &str,
) -> Result<ExecutionCredential, ManagedStoreError> {
    check_usable_encrypted_row(row, expected_profile)?;
    decrypt_execution_credential(key_ring, row)
}

/// The command credential of a usable stored row, as
/// [`execution_credential_from_encrypted_row`] checks usability.
fn command_credential_from_encrypted_row(
    key_ring: &CredentialKeyRing,
    row: &EncryptedCredentialRow,
    expected_profile: &str,
) -> Result<crate::imports::CommandCredential, ManagedStoreError> {
    check_usable_encrypted_row(row, expected_profile)?;
    let aad = credential_aad(row);
    let secret = key_ring.decrypt(&row.key_id, &row.secret_nonce, &row.secret_ciphertext, &aad)?;
    command_credential_from_secret(&row.credential_kind, secret)
}

/// A stored row execution may use: enabled, of the configured profile and
/// backend, with a valid secret reference and version, and not expired.
fn check_usable_encrypted_row(
    row: &EncryptedCredentialRow,
    expected_profile: &str,
) -> Result<(), ManagedStoreError> {
    if row.status == "disabled" {
        return Err(ManagedStoreError::CredentialNotFound);
    }
    if row.profile != expected_profile {
        return Err(ManagedStoreError::CredentialInvalid(
            "stored credential profile does not match configured profile".to_string(),
        ));
    }
    if row.secret_backend != SQLITE_ENCRYPTED_BACKEND {
        return Err(ManagedStoreError::CredentialInvalid(
            "stored credential secret backend is not supported".to_string(),
        ));
    }
    validate_sqlite_secret_ref(&row.secret_ref)?;
    validate_uuid_id(&row.material_version, "materialVersion")?;
    if credential_metadata_expires_at(&row.metadata)
        .is_some_and(|expires_at| expires_at <= Utc::now())
    {
        return Err(ManagedStoreError::CredentialExpired);
    }
    Ok(())
}

fn credential_aad(row: &EncryptedCredentialRow) -> CredentialAad {
    CredentialAad {
        credential_id: row.credential_id.clone(),
        owner_kind: row.owner_kind.clone(),
        owner_principal_id: row.owner_principal_id.clone(),
        service: row.service.clone(),
        name: row.name.clone(),
        profile: row.profile.clone(),
        credential_kind: row.credential_kind.clone(),
        secret_backend: row.secret_backend.clone(),
        secret_ref: row.secret_ref.clone(),
        material_version: row.material_version.clone(),
        key_id: row.key_id.clone(),
    }
}

fn decrypt_execution_credential(
    key_ring: &CredentialKeyRing,
    row: &EncryptedCredentialRow,
) -> Result<ExecutionCredential, ManagedStoreError> {
    let aad = credential_aad(row);
    let secret = key_ring.decrypt(&row.key_id, &row.secret_nonce, &row.secret_ciphertext, &aad)?;
    execution_credential_from_secret(&row.credential_kind, secret)
}

fn collect_rows<T>(
    rows: rusqlite::MappedRows<'_, impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>>,
) -> Result<Vec<T>, ManagedStoreError> {
    rows.collect::<Result<Vec<_>, _>>().map_err(sql_unavailable)
}

fn timestamp_is_past(timestamp: Option<&str>) -> bool {
    match timestamp {
        Some(value) => DateTime::parse_from_rfc3339(value)
            .map(|value| value.with_timezone(&Utc) <= Utc::now())
            .unwrap_or(true),
        None => false,
    }
}

fn normalize_optional_timestamp(
    timestamp: Option<&str>,
    field: &str,
) -> Result<Option<String>, ManagedStoreError> {
    let Some(timestamp) = timestamp else {
        return Ok(None);
    };
    if timestamp.trim().is_empty() {
        return Err(input_invalid(format!(
            "{field} must be an RFC3339 timestamp"
        )));
    }
    let parsed = DateTime::parse_from_rfc3339(timestamp)
        .map_err(|_| input_invalid(format!("{field} must be an RFC3339 timestamp")))?;
    Ok(Some(normalized_timestamp(parsed.with_timezone(&Utc))))
}

fn input_invalid(message: impl Into<String>) -> ManagedStoreError {
    ManagedStoreError::InputInvalid(message.into())
}

fn map_oidc_flow_insert_error(error: rusqlite::Error) -> ManagedStoreError {
    if matches!(
        error,
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ErrorCode::ConstraintViolation,
                ..
            },
            _
        )
    ) {
        ManagedStoreError::OidcFlowInvalid
    } else {
        sql_unavailable(error)
    }
}

fn map_external_binding_insert_error(error: rusqlite::Error) -> ManagedStoreError {
    if matches!(
        error,
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ErrorCode::ConstraintViolation,
                ..
            },
            _
        )
    ) {
        ManagedStoreError::ExternalGroupBindingConflict
    } else {
        sql_unavailable(error)
    }
}

fn map_oidc_method_insert_error(error: rusqlite::Error) -> ManagedStoreError {
    if matches!(
        error,
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ErrorCode::ConstraintViolation,
                ..
            },
            _
        )
    ) {
        ManagedStoreError::OidcLoginMethodConflict
    } else {
        sql_unavailable(error)
    }
}

fn normalized_timestamp(timestamp: DateTime<Utc>) -> String {
    timestamp.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn normalized_now_string() -> String {
    normalized_timestamp(Utc::now())
}

fn now_string() -> String {
    Utc::now().to_rfc3339()
}

use sqlite_support::sha256_hex;

fn sql_unavailable(error: rusqlite::Error) -> ManagedStoreError {
    ManagedStoreError::Unavailable(error.to_string())
}

fn restrict_sqlite_files(path: &Path) -> Result<(), ManagedStoreError> {
    Ok(sqlite_support::restrict_sqlite_files(
        path,
        MANAGED_STORE_LABEL,
    )?)
}

#[cfg(test)]
use sqlite_support::sqlite_sidecar_paths;

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_provider::test_support::{basic_credential, bearer_credential};
    include!("managed_store/principal_access_tests.rs");
    include!("managed_store/identity_access_tests.rs");
    include!("managed_store/stored_credential_golden_tests.rs");
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::json;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use tempfile::TempDir;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn key(value: u8) -> String {
        URL_SAFE_NO_PAD.encode([value; 32])
    }

    fn broker_token_hasher_for_test(value: u8) -> BrokerTokenHasher {
        BrokerTokenHasher {
            key: Arc::new([value; 32]),
        }
    }

    fn local_password_hasher_for_test(value: u8) -> LocalPasswordHasher {
        LocalPasswordHasher {
            verification_hook: None,
            key: Arc::new([value; 32]),
        }
    }

    fn raw_store_config(path: &Path, auto_migrate: bool) -> ManagedStoreConfig {
        ManagedStoreConfig {
            kind: "sqlite".to_string(),
            path: path.display().to_string(),
            require_registered_principal_for_invocation: false,
            auto_migrate,
        }
    }

    fn store_config(path: &Path) -> ManagedStoreConfig {
        #[cfg(unix)]
        if let Some(parent) = path.parent()
            && parent.exists()
        {
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        }
        raw_store_config(path, true)
    }

    #[test]
    fn startup_migration_rejects_existing_untracked_managed_tables() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "CREATE TABLE credentials (credential_id TEXT PRIMARY KEY)",
            [],
        )
        .unwrap();
        drop(conn);

        let error =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap_err();
        assert!(
            matches!(error, ManagedStoreError::SchemaInvalid(message) if message.contains("preserve the database"))
        );
    }

    fn key_ring(active: &str) -> CredentialKeyRing {
        key_ring_with_keys(active, &[(active, 7)])
    }

    fn key_ring_with_keys(active: &str, keys: &[(&str, u8)]) -> CredentialKeyRing {
        let temp = TempDir::new().unwrap();
        let mut configs = Vec::new();
        for (id, value) in keys {
            let key_path = temp.path().join(format!("{id}.key"));
            fs::write(&key_path, key(*value)).unwrap();
            configs.push(CredentialEncryptionKeyConfig {
                id: id.to_string(),
                provider: "file".to_string(),
                env: None,
                path: Some(key_path.display().to_string()),
            });
        }
        let config = CredentialEncryptionConfig {
            active_key: active.to_string(),
            keys: configs,
        };
        CredentialKeyRing::load(&config).unwrap()
    }

    fn create_alice(store: &ManagedStore) {
        store
            .create_or_update_principal(PrincipalWriteRequest {
                role: crate::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "alice".to_string(),
                kind: "user".to_string(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".to_string(),
            })
            .unwrap();
    }

    const TEST_OIDC_TENANT: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1";
    const TEST_OIDC_CLIENT: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2";
    const TEST_OIDC_USER: &str = "cccccccc-cccc-4ccc-8ccc-ccccccccccc3";
    const TEST_OIDC_USER_TWO: &str = "dddddddd-dddd-4ddd-8ddd-ddddddddddd4";
    const TEST_EXTERNAL_GROUP_A: &str = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee5";
    const TEST_EXTERNAL_GROUP_B: &str = "ffffffff-ffff-4fff-8fff-fffffffffff6";

    fn reconcile_test_oidc_provider(
        store: &ManagedStore,
        enabled: bool,
        ttl_seconds: u64,
        fingerprint: &str,
    ) -> OidcProviderStateRecord {
        store
            .reconcile_oidc_provider_state(OidcProviderStateReconcileRequest {
                tenant_id: TEST_OIDC_TENANT.to_string(),
                client_id: TEST_OIDC_CLIENT.to_string(),
                enabled,
                config_fingerprint: fingerprint.to_string(),
                external_membership_ttl_seconds: ttl_seconds,
                invalidate_existing_evidence: false,
                actor: "admin".to_string(),
            })
            .unwrap()
    }

    fn create_test_group(store: &ManagedStore, group_id: &str) {
        store
            .create_group(GroupWriteRequest {
                group_id: group_id.to_string(),
                display_name: None,
                description: None,
                created_by: "admin".to_string(),
            })
            .unwrap();
    }

    fn test_oidc_subject(user_object_id: &str) -> String {
        format!("entra:v1:{TEST_OIDC_TENANT}:{user_object_id}")
    }

    fn test_oidc_completion_request(
        flow_sequence: u64,
        provider_generation: u64,
        user_object_id: &str,
        principal_id: &str,
        external_group_ids: &[&str],
        callback_now: &str,
    ) -> OidcCompleteLoginRequest {
        OidcCompleteLoginRequest {
            flow_sequence,
            provider_generation,
            external_subject: test_oidc_subject(user_object_id),
            external_group_ids: external_group_ids
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            jit_provisioning: true,
            jit_principal_id: principal_id.to_string(),
            display_name: Some("OIDC User".to_string()),
            email: Some("oidc@example.com".to_string()),
            evidence_at: callback_now.to_string(),
            callback_now: callback_now.to_string(),
            session_ttl_seconds: 3_600,
            created_by: "oidc-microsoft".to_string(),
        }
    }

    fn policy_grant_create_request(grant_id: String) -> ManagedPolicyGrantCreateRequest {
        ManagedPolicyGrantCreateRequest {
            grant_id: Some(grant_id),
            subjects: vec!["group:anonymous".to_string()],
            execution_contexts: vec!["default".to_string()],
            service: "fake".to_string(),
            actions: vec!["echo".to_string()],
            resources: ResourceSelection::default(),
            credential_mode: "service".to_string(),
            priority: None,
            status: None,
            description: None,
            created_by: "admin".to_string(),
        }
    }

    #[test]
    fn policy_grant_ids_accept_safe_slugs_and_reject_unsafe_values() {
        let mut request = policy_grant_create_request("jira-eng-search".to_string());
        validate_policy_grant_create_request(&request).unwrap();

        for grant_id in [
            "",
            "bad id",
            "toml:0",
            "id/with/slash",
            ".",
            "..",
            "export",
            "validate",
        ] {
            request.grant_id = Some(grant_id.to_string());
            let error = validate_policy_grant_create_request(&request).unwrap_err();
            assert!(
                matches!(&error, ManagedStoreError::InputInvalid(message) if message.contains("grantId must be 1-128 characters")),
                "unexpected error for {grant_id:?}: {error:?}"
            );
        }

        request.grant_id = Some("a".repeat(129));
        let error = validate_policy_grant_create_request(&request).unwrap_err();
        assert!(
            matches!(&error, ManagedStoreError::InputInvalid(message) if message.contains("grantId must be 1-128 characters")),
            "unexpected error for overlong grantId: {error:?}"
        );
    }

    #[test]
    fn policy_grant_execution_contexts_require_nonempty_unique_canonical_values() {
        let mut request = policy_grant_create_request("grant-context-validation".to_string());
        request.execution_contexts.clear();
        assert!(matches!(
            validate_policy_grant_create_request(&request).unwrap_err(),
            ManagedStoreError::InputInvalid(message)
                if message == "executionContexts must not be empty"
        ));

        request.execution_contexts = vec!["internal".to_string(), "internal".to_string()];
        assert!(matches!(
            validate_policy_grant_create_request(&request).unwrap_err(),
            ManagedStoreError::InputInvalid(message)
                if message.contains("duplicates an earlier execution context")
        ));

        for invalid in ["Internal", " internal", "external,internal", "a.b"] {
            request.execution_contexts = vec![invalid.to_string()];
            assert!(matches!(
                validate_policy_grant_create_request(&request).unwrap_err(),
                ManagedStoreError::InputInvalid(message)
                    if message.contains("must match [a-z][a-z0-9_-]{0,63}")
            ));
        }
    }

    #[test]
    fn managed_groups_are_first_class_policy_subjects() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        create_alice(&store);

        let group = store
            .create_group(GroupWriteRequest {
                group_id: "users".to_string(),
                display_name: Some("Users".to_string()),
                description: Some("Regular users".to_string()),
                created_by: "admin".to_string(),
            })
            .unwrap();
        assert_eq!(group.group_id, "users");
        assert_eq!(group.status, "active");
        assert_eq!(group.member_count, 0);
        assert!(group.created_at.is_some());
        assert_eq!(store.list_groups().unwrap().len(), 1);
        assert!(matches!(
            store
                .create_group(GroupWriteRequest {
                    group_id: "users".to_string(),
                    display_name: None,
                    description: None,
                    created_by: "admin".to_string(),
                })
                .unwrap_err(),
            ManagedStoreError::VersionConflict
        ));

        store.add_group("alice", "users", "admin").unwrap();
        assert_eq!(store.groups("alice").unwrap(), vec!["users".to_string()]);
        assert_eq!(
            store.policy_groups("alice").unwrap(),
            vec!["users".to_string()]
        );
        let members = store.group_members("users").unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].principal_id, "alice");

        let hasher = broker_token_hasher_for_test(31);
        let issued = store
            .issue_broker_token(
                &hasher,
                BrokerTokenIssueRequest {
                    principal_id: "alice".to_string(),
                    name: "alice token".to_string(),
                    token_class: BrokerTokenClass::AgentInvoke,
                    scopes: json!({"allowedExecutionContexts": ["default"]}),
                    expires_at: None,
                    created_by: "admin".to_string(),
                },
            )
            .unwrap();
        let resolved = store.resolve_broker_token(&hasher, &issued.token).unwrap();
        assert_eq!(resolved.principal_kind, Some(crate::PrincipalKind::User));
        assert_eq!(resolved.groups, vec!["users".to_string()]);
        assert_eq!(resolved.policy_groups, vec!["users".to_string()]);

        let disabled = store
            .patch_group(GroupPatchRequest {
                group_id: "users".to_string(),
                display_name: Some(None),
                description: Some(Some("Disabled users".to_string())),
                status: Some("disabled".to_string()),
                updated_by: "admin".to_string(),
            })
            .unwrap();
        assert_eq!(disabled.status, "disabled");
        assert!(disabled.disabled_at.is_some());
        assert_eq!(disabled.display_name, None);
        assert_eq!(disabled.description.as_deref(), Some("Disabled users"));
        assert_eq!(store.groups("alice").unwrap(), vec!["users".to_string()]);
        assert!(store.policy_groups("alice").unwrap().is_empty());
        let resolved = store.resolve_broker_token(&hasher, &issued.token).unwrap();
        assert_eq!(resolved.groups, vec!["users".to_string()]);
        assert!(resolved.policy_groups.is_empty());

        store.remove_group("alice", "users").unwrap();
        assert!(store.group_members("users").unwrap().is_empty());
    }

    #[test]
    fn managed_principals_reject_reserved_anonymous_id() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();

        let error = store
            .create_principal(PrincipalWriteRequest {
                role: crate::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "anonymous".to_string(),
                kind: "user".to_string(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".to_string(),
            })
            .unwrap_err();
        assert!(matches!(
            error,
            ManagedStoreError::InputInvalid(message) if message == "principal id is invalid"
        ));
    }

    #[test]
    fn managed_group_membership_requires_existing_principal_and_group() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        create_alice(&store);
        store
            .create_group(GroupWriteRequest {
                group_id: "users".to_string(),
                display_name: None,
                description: None,
                created_by: "admin".to_string(),
            })
            .unwrap();

        assert!(matches!(
            store.principal("missing").unwrap_err(),
            ManagedStoreError::PrincipalNotFound
        ));
        assert!(matches!(
            store
                .patch_principal(PrincipalPatchRequest {
                    principal_id: "missing".to_string(),
                    display_name: None,
                    email: None,
                    status: Some("disabled".to_string()),
                })
                .unwrap_err(),
            ManagedStoreError::PrincipalNotFound
        ));
        assert!(matches!(
            store.add_group("missing", "users", "admin").unwrap_err(),
            ManagedStoreError::PrincipalNotFound
        ));
        assert!(matches!(
            store.add_group("alice", "missing", "admin").unwrap_err(),
            ManagedStoreError::GroupNotFound
        ));
        assert!(matches!(
            store.remove_group("missing", "users").unwrap_err(),
            ManagedStoreError::PrincipalNotFound
        ));
        assert!(matches!(
            store.remove_group("alice", "missing").unwrap_err(),
            ManagedStoreError::GroupNotFound
        ));
        assert!(matches!(
            store
                .create_group(GroupWriteRequest {
                    group_id: "anonymous".to_string(),
                    display_name: None,
                    description: None,
                    created_by: "admin".to_string(),
                })
                .unwrap_err(),
            ManagedStoreError::InputInvalid(_)
        ));

        store
            .patch_principal(PrincipalPatchRequest {
                principal_id: "alice".to_string(),
                display_name: None,
                email: None,
                status: Some("disabled".to_string()),
            })
            .unwrap();
        store.add_group("alice", "users", "admin").unwrap();
        assert_eq!(store.groups("alice").unwrap(), vec!["users".to_string()]);
        assert!(matches!(
            store.active_principal("alice").unwrap_err(),
            ManagedStoreError::PrincipalDisabled
        ));
    }

    fn put_alice_jira_credential(
        store: &ManagedStore,
        ring: &CredentialKeyRing,
        token: &str,
    ) -> CredentialMetadata {
        store
            .upsert_user_credential(
                ring,
                CredentialWriteRequest {
                    owner_principal_id: "alice".to_string(),
                    service: "jira".to_string(),
                    name: "default".to_string(),
                    profile: "jira-cloud-api-token".to_string(),
                    credential_kind: "basic_api_token".to_string(),
                    secret: json!({"username":"alice@example.com","token":token}),
                    metadata: json!({"displayName":"Jira"}),
                    actor: "alice".to_string(),
                },
                crate::CredentialManagementPurpose::Administrative,
            )
            .unwrap()
    }

    fn table_columns(conn: &Connection, table: &str) -> Vec<String> {
        let mut statement = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap();
        statement
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    fn migration_rows(path: &Path) -> Vec<(String, String, String)> {
        let conn = Connection::open(path).unwrap();
        let mut statement = conn
            .prepare("SELECT version, checksum, applied_at FROM schema_migrations ORDER BY version")
            .unwrap();
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    fn create_latest_with_ledger(path: &Path) -> Connection {
        ManagedStore::open(&store_config(path), ManagedStoreOpenMode::Startup).unwrap();
        Connection::open(path).unwrap()
    }

    #[test]
    fn fresh_baseline_checksum_is_stable() {
        assert_eq!(
            sha256_hex(MANAGED_STORE_BASELINE_SQL.as_bytes()),
            MANAGED_STORE_BASELINE_CHECKSUM
        );
        assert_eq!(
            ManagedStore::schema_checksum(),
            production_migration_catalog().current_schema_checksum()
        );
        assert_eq!(
            CREDENTIAL_AAD_SCHEMA_VERSION,
            "002_credential_secret_material"
        );
    }

    #[test]
    fn cloudbees_namespace_migration_preserves_resource_members() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        conn.execute_batch(MANAGED_STORE_BASELINE_SQL).unwrap();
        conn.execute_batch(IDENTITY_TOKENS_SQL).unwrap();
        conn.execute_batch(
            "INSERT INTO resources VALUES
             ('repo', 'git_repository', 'namespace', 'team', NULL, '[\"default\"]', 1, 1,
              '2026-01-01', 'admin', '2026-01-01', 'admin');
             INSERT INTO resource_groups VALUES
             ('group', 'Example', 1, '2026-01-01', 'admin', '2026-01-01', 'admin');
             INSERT INTO resource_group_members VALUES ('group', 'repo', 'include');",
        )
        .unwrap();
        conn.execute_batch(CLOUDBEES_CI_JOB_NAMESPACE_SQL).unwrap();
        conn.execute_batch(
            "INSERT INTO resources VALUES
             ('ci', 'cloudbees_ci_job', 'namespace', 'team-ci/payments', NULL, '[\"default\"]',
              1, 1, '2026-01-01', 'admin', '2026-01-01', 'admin');",
        )
        .unwrap();
        let members: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM resource_group_members WHERE resource_id = 'repo'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(members, 1);
        validate_cloudbees_ci_structure(&conn).unwrap();
    }

    #[test]
    fn upgrades_identity_token_store_to_cloudbees_namespace_schema() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let config = store_config(&path);
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        conn.execute_batch(MANAGED_STORE_BASELINE_SQL).unwrap();
        conn.execute_batch(IDENTITY_TOKENS_SQL).unwrap();
        conn.execute(
            "INSERT INTO schema_migrations(version, checksum, applied_at) VALUES (?1, ?2, ?3)",
            params![
                MANAGED_STORE_BASELINE_SCHEMA_VERSION,
                MANAGED_STORE_BASELINE_CHECKSUM,
                now_string()
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO schema_migrations(version, checksum, applied_at) VALUES (?1, ?2, ?3)",
            params![
                MANAGED_STORE_IDENTITY_TOKENS_VERSION,
                MANAGED_STORE_MIGRATIONS[1].checksum,
                now_string()
            ],
        )
        .unwrap();
        conn.execute_batch(
            "INSERT INTO principals
             (principal_id, kind, display_name, email, external_subject, status, created_at,
              updated_at, disabled_at, created_by)
             VALUES ('agent', 'service_account', NULL, NULL, NULL, 'active',
                     '2026-01-01', '2026-01-01', NULL, 'admin');
             INSERT INTO resources VALUES
             ('repo', 'git_repository', 'exact', 'team/repo', NULL, '[\"default\"]', 1, 1,
              '2026-01-01', 'admin', '2026-01-01', 'admin'),
             ('excluded', 'git_repository', 'exact', 'team/secret', NULL, '[\"default\"]', 1, 1,
              '2026-01-01', 'admin', '2026-01-01', 'admin');
             INSERT INTO resource_groups VALUES
             ('group', 'Team repositories', 1, '2026-01-01', 'admin', '2026-01-01', 'admin');
             INSERT INTO resource_group_members VALUES
             ('group', 'repo', 'include'), ('group', 'excluded', 'exclude');",
        )
        .unwrap();
        let selection = json!({"resourceIds": ["repo"], "resourceGroupIds": ["group"]});
        let token_scopes = json!({
            "allowedServices": ["gitlab"],
            "allowedExecutionContexts": ["default"],
            "serviceRestrictions": {
                "gitlab": {"actions": ["project.view"], "resources": selection}
            }
        });
        conn.execute(
            "INSERT INTO policy_grants
             (grant_id, grant_order, service, actions_json, resources_json, credential_mode,
              priority, status, description, version, created_at, created_by, updated_at,
              updated_by, disabled_at, deleted_at)
             VALUES ('grant-repo', 0, 'gitlab', '[\"project.view\"]', ?1, 'service', NULL,
                     'active', NULL, 1, '2026-01-01', 'admin', '2026-01-01', 'admin', NULL, NULL)",
            params![selection.to_string()],
        )
        .unwrap();
        conn.execute_batch(
            "INSERT INTO policy_grant_subjects VALUES ('grant-repo', 'service:agent', 0);
             INSERT INTO policy_grant_contexts VALUES ('grant-repo', 'default', 0);",
        )
        .unwrap();
        let token_id = Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO broker_tokens
             (token_id, token_hash, principal_id, name, token_class, scopes_json,
              created_at, expires_at, revoked_at, revoked_by, last_used_at, created_by)
             VALUES (?1, 'stored-token-hash', 'agent', 'repo token', 'agent_invoke', ?2,
                     '2026-01-01', NULL, NULL, NULL, NULL, 'admin')",
            params![token_id, token_scopes.to_string()],
        )
        .unwrap();
        drop(conn);
        let store = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
        assert_eq!(
            store.status().unwrap().schema_version,
            MANAGED_STORE_SCHEMA_VERSION
        );
        assert!(store.migration_applied_this_open(MANAGED_STORE_SCHEMA_VERSION));
        let group = store.resource_group("group").unwrap();
        assert_eq!(group.definition.included_resource_ids, vec!["repo"]);
        assert_eq!(group.definition.excluded_resource_ids, vec!["excluded"]);
        assert_eq!(store.resource("repo").unwrap().definition.id, "repo");
        assert_eq!(
            store.resource("excluded").unwrap().definition.id,
            "excluded"
        );
        let grant = store.policy_grant("grant-repo").unwrap();
        assert_eq!(grant.resources.resource_ids, vec!["repo"]);
        assert_eq!(grant.resources.resource_group_ids, vec!["group"]);
        let token = store.broker_token(&token_id).unwrap();
        assert_eq!(token.scopes, token_scopes);
        AgentInvokeTokenCaveats::parse_stored(&token.scopes).unwrap();
        validate_token_resource_references(&store.connection.lock().unwrap(), &token.scopes, None)
            .unwrap();
        store.load_policy_export().unwrap();
    }

    #[test]
    fn fresh_store_initializes_complete_resource_policy_baseline() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        assert_eq!(
            store.status().unwrap().schema_version,
            MANAGED_STORE_SCHEMA_VERSION
        );
        assert!(store.migration_applied_this_open(MANAGED_STORE_SCHEMA_VERSION));
        let rows = migration_rows(&path);
        assert_eq!(rows.len(), MANAGED_STORE_MIGRATIONS.len());
        assert_eq!(rows[0].0, MANAGED_STORE_BASELINE_SCHEMA_VERSION);
        assert_eq!(rows[0].1, MANAGED_STORE_BASELINE_CHECKSUM);
        assert_eq!(rows[1].0, MANAGED_STORE_IDENTITY_TOKENS_VERSION);
        assert_eq!(rows[2].0, MANAGED_STORE_CLOUDBEES_CI_VERSION);
        assert_eq!(rows[3].0, MANAGED_STORE_REMOVE_SHELL_APPROVAL_VERSION);
        assert_eq!(rows[4].0, MANAGED_STORE_OAUTH_VERSION);
        assert_eq!(rows[5].0, MANAGED_STORE_REGISTERED_RESOURCE_TYPES_VERSION);
        assert_eq!(rows[6].0, MANAGED_STORE_RESOURCE_ATTRIBUTES_VERSION);
        assert_eq!(rows[7].0, MANAGED_STORE_LOCAL_PASSWORD_FAILURES_VERSION);
        assert_eq!(rows[8].0, MANAGED_STORE_PRINCIPAL_SERVICE_LIMITS_VERSION);
        assert_eq!(rows[9].0, MANAGED_STORE_IMPORTED_SERVICES_VERSION);
        assert_eq!(rows[10].0, MANAGED_STORE_OAUTH_DISCOVERY_REVISION_VERSION);
        assert_eq!(rows[11].0, MANAGED_STORE_PRINCIPAL_ACCESS_VERSION);
        assert_eq!(rows[12].0, MANAGED_STORE_TRUSTED_USER_IDENTITY_VERSION);
        assert_eq!(rows[13].0, MANAGED_STORE_COMMAND_IMPORTS_VERSION);
        assert_eq!(rows[14].0, MANAGED_STORE_OAUTH_REVOCATIONS_VERSION);
        assert_eq!(rows[15].0, MANAGED_STORE_SECRET_REFERENCES_VERSION);
        assert_eq!(rows[15].0, MANAGED_STORE_SCHEMA_VERSION);
        assert_eq!(store.policy_revision().unwrap().generation, 0);
        let conn = Connection::open(&path).unwrap();
        for table in ["resources", "resource_groups", "resource_group_members"] {
            assert!(sqlite_object_exists(&conn, "table", table).unwrap());
        }
        let columns = table_columns(&conn, "policy_grants");
        assert!(columns.contains(&"resources_json".to_string()));
        assert!(!columns.contains(&"resource_scopes_json".to_string()));
        assert!(!table_columns(&conn, "broker_tokens").contains(&"device_name".to_string()));
    }

    #[test]
    fn existing_store_removes_shell_approval_tables_without_losing_policy() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(MANAGED_STORE_BASELINE_SQL).unwrap();
        conn.execute_batch(IDENTITY_TOKENS_SQL).unwrap();
        conn.execute_batch(CLOUDBEES_CI_JOB_NAMESPACE_SQL).unwrap();
        conn.execute_batch("UPDATE policy_revisions SET generation = 7 WHERE id = 1;")
            .unwrap();
        for migration in &MANAGED_STORE_MIGRATIONS[..3] {
            conn.execute(
                "INSERT INTO schema_migrations(version, checksum, applied_at) VALUES (?1, ?2, ?3)",
                params![migration.version, migration.checksum, now_string()],
            )
            .unwrap();
        }
        drop(conn);

        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        assert!(store.migration_applied_this_open(MANAGED_STORE_REMOVE_SHELL_APPROVAL_VERSION));
        assert!(store.migration_applied_this_open(MANAGED_STORE_SCHEMA_VERSION));
        assert_eq!(store.policy_revision().unwrap().generation, 7);
        let conn = Connection::open(&path).unwrap();
        assert!(!sqlite_object_exists(&conn, "table", "shell_approval_policy").unwrap());
        assert!(!sqlite_object_exists(&conn, "table", "shell_approval_revisions").unwrap());
        assert!(sqlite_object_exists(&conn, "table", "credentials").unwrap());
    }

    #[test]
    fn main_schema_17_upgrades_to_oauth_without_changing_existing_migration_ledger() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let config = store_config(&path);
        let previous_catalog = ManagedStoreMigrationCatalog {
            migrations: &MANAGED_STORE_MIGRATIONS[..4],
        };
        let previous = ManagedStore::open_with_catalog(
            &config,
            ManagedStoreOpenMode::Startup,
            previous_catalog,
        )
        .unwrap();
        previous
            .connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE policy_revisions SET generation = 7 WHERE id = 1",
                [],
            )
            .unwrap();
        drop(previous);
        let before = migration_rows(&path);
        assert_eq!(before.len(), 4);
        assert_eq!(before[3].0, "017_remove_shell_approval");
        assert_eq!(
            before[3].1,
            "2d945372e95a4d7545f88ee4463f3b742b903a533a08611eead4845d2fc102c7"
        );
        assert!(matches!(
            ManagedStore::open(&config, ManagedStoreOpenMode::Reload).unwrap_err(),
            ManagedStoreError::MigrationRequired
        ));
        assert_eq!(migration_rows(&path), before);

        let store = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
        assert_eq!(
            store.status().unwrap().schema_version,
            MANAGED_STORE_SCHEMA_VERSION
        );
        assert!(store.migration_applied_this_open(MANAGED_STORE_OAUTH_VERSION));
        assert!(store.migration_applied_this_open(MANAGED_STORE_SCHEMA_VERSION));
        assert!(!store.migration_applied_this_open(MANAGED_STORE_REMOVE_SHELL_APPROVAL_VERSION));
        let after = migration_rows(&path);
        assert_eq!(after.len(), MANAGED_STORE_MIGRATIONS.len());
        assert_eq!(after[..4], before);
        assert_eq!(after[4].0, "018_oauth_foundation");
        assert_eq!(after[5].0, "019_registered_resource_types");
        assert_eq!(store.policy_revision().unwrap().generation, 7);
        {
            let conn = store.connection.lock().unwrap();
            assert!(sqlite_object_exists(&conn, "table", "oauth_registrations").unwrap());
            assert!(sqlite_object_exists(&conn, "table", "oauth_slots").unwrap());
            assert!(!sqlite_object_exists(&conn, "table", "shell_approval_policy").unwrap());
            assert!(!sqlite_object_exists(&conn, "table", "shell_approval_revisions").unwrap());
        }
        drop(store);
        let reopened = ManagedStore::open(&config, ManagedStoreOpenMode::Reload).unwrap();
        assert!(!reopened.migration_applied_this_open(MANAGED_STORE_SCHEMA_VERSION));
        assert_eq!(migration_rows(&path), after);
    }

    #[test]
    fn schema_18_upgrade_preserves_resources_and_moves_type_rules_to_the_registry() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let config = store_config(&path);
        let previous_catalog = ManagedStoreMigrationCatalog {
            migrations: &MANAGED_STORE_MIGRATIONS[..5],
        };
        let previous = ManagedStore::open_with_catalog(
            &config,
            ManagedStoreOpenMode::Startup,
            previous_catalog,
        )
        .unwrap();
        {
            let conn = previous.connection.lock().unwrap();
            conn.execute_batch(
                "INSERT INTO resources VALUES ('jobs', 'cloudbees_ci_job', 'namespace', 'team-ci/payments', NULL, '[\"default\"]', 1, 1, 't', 'admin', 't', 'admin');
                 INSERT INTO resources VALUES ('eng', 'jira_project', 'exact', 'ENG', NULL, '[\"default\"]', 1, 1, 't', 'admin', 't', 'admin');
                 INSERT INTO resource_groups VALUES ('group', 'Group', 1, 't', 'admin', 't', 'admin');
                 INSERT INTO resource_group_members VALUES ('group', 'jobs', 'include');
                 INSERT INTO resource_group_members VALUES ('group', 'eng', 'exclude');",
            )
            .unwrap();
            // Schema 18 still hard-codes which types may use namespace selectors.
            assert!(
                conn.execute(
                    "INSERT INTO resources VALUES ('spaces', 'confluence_space', 'namespace', 'ENG', NULL, '[\"default\"]', 1, 1, 't', 'admin', 't', 'admin')",
                    [],
                )
                .is_err()
            );
        }
        drop(previous);

        let store = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
        assert!(store.migration_applied_this_open(MANAGED_STORE_SCHEMA_VERSION));
        let catalog = store.load_policy_snapshot().unwrap().catalog;
        assert_eq!(
            catalog
                .resources
                .iter()
                .map(|resource| (resource.id.as_str(), resource.resource_type.as_str()))
                .collect::<Vec<_>>(),
            [("eng", "jira_project"), ("jobs", "cloudbees_ci_job")]
        );
        assert_eq!(catalog.resource_groups[0].included_resource_ids, ["jobs"]);
        assert_eq!(catalog.resource_groups[0].excluded_resource_ids, ["eng"]);
        let conn = store.connection.lock().unwrap();
        // Selector support is a registry rule now; storage only checks shape.
        conn.execute(
            "INSERT INTO resources VALUES ('future', 'future_type', 'namespace', 'a', NULL, '[\"default\"]', 1, 1, 't', 'admin', 't', 'admin')",
            [],
        )
        .unwrap();
        assert!(
            conn.execute(
                "INSERT INTO resources VALUES ('bad', 'Bad-Type', 'exact', 'a', NULL, '[\"default\"]', 1, 1, 't', 'admin', 't', 'admin')",
                [],
            )
            .is_err()
        );
    }

    #[test]
    fn policy_grants_load_from_managed_store() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let now = now_string();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        conn.execute(
            "UPDATE policy_revisions
             SET generation = 3, updated_at = ?1, updated_by = 'admin'
             WHERE id = 1",
            params![now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO policy_grants
             (grant_id, grant_order, service, actions_json, resources_json,
              credential_mode, priority, status, description, version, created_at, created_by,
              updated_at, updated_by, disabled_at, deleted_at)
             VALUES
             ('grant-active', 0, 'fake', '[\"echo\"]',
              '{\"resourceIds\":[],\"resourceGroupIds\":[]}', 'service', 10, 'active', 'active grant', 2,
              ?1, 'admin', ?1, 'admin', NULL, NULL),
             ('grant-disabled', 1, 'fake', '[\"echo\"]',
              '{\"resourceIds\":[],\"resourceGroupIds\":[]}', 'service', NULL, 'disabled', NULL, 1,
              ?1, 'admin', ?1, 'admin', ?1, NULL)",
            params![now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO policy_grant_subjects (grant_id, subject, subject_order)
             VALUES
             ('grant-active', 'group:agents', 0),
             ('grant-active', 'user:agent-one', 1),
             ('grant-disabled', 'group:agents', 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO policy_grant_contexts
             (grant_id, execution_context, context_order)
             VALUES
             ('grant-active', 'internal', 0),
             ('grant-active', 'workstation', 1),
             ('grant-disabled', 'default', 0)",
            [],
        )
        .unwrap();

        let revision = store.policy_revision().unwrap();
        assert_eq!(revision.generation, 3);
        assert_eq!(revision.updated_by, "admin");
        assert_eq!(store.policy_grants().unwrap().len(), 2);
        let active = store.active_policy_grants().unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].grant_id, "grant-active");
        assert_eq!(
            active[0].subjects,
            vec!["group:agents".to_string(), "user:agent-one".to_string()]
        );
        assert_eq!(active[0].priority, Some(10));
        assert_eq!(
            active[0].execution_contexts,
            vec!["internal".to_string(), "workstation".to_string()]
        );
        assert_eq!(active[0].actions, vec!["echo".to_string()]);
        assert_eq!(active[0].resources, ResourceSelection::default());
    }

    #[test]
    fn policy_grant_mutations_increment_revision_and_enforce_versions() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let grant_id = "jira-eng-search".to_string();

        let created = store
            .create_policy_grant(
                policy_grant_create_request(grant_id.clone()),
                |grants, revision, subjects, _catalog| {
                    assert_eq!(revision.generation, 1);
                    assert_eq!(grants.len(), 1);
                    assert_eq!(grants[0].grant_id, grant_id);
                    assert!(subjects.groups.is_empty());
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(created.previous_revision.generation, 0);
        assert_eq!(created.revision.generation, 1);
        assert_eq!(created.grant.version, 1);
        assert_eq!(store.policy_revision().unwrap().generation, 1);

        let patched = store
            .patch_policy_grant(
                ManagedPolicyGrantPatchRequest {
                    grant_id: created.grant.grant_id.clone(),
                    expected_version: created.grant.version,
                    subjects: None,
                    execution_contexts: Some(vec![
                        "internal".to_string(),
                        "workstation".to_string(),
                    ]),
                    service: Some("fake".to_string()),
                    actions: None,
                    resources: None,
                    credential_mode: None,
                    priority: Some(Some(10)),
                    status: None,
                    description: Some(Some("Reads TEST".to_string())),
                    updated_by: "admin".to_string(),
                },
                |grants, revision, _subjects, _catalog| {
                    assert_eq!(revision.generation, 2);
                    assert_eq!(grants.len(), 1);
                    assert_eq!(grants[0].priority, Some(10));
                    assert_eq!(
                        grants[0].execution_contexts,
                        vec!["internal".to_string(), "workstation".to_string()]
                    );
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(patched.grant.version, 2);
        assert_eq!(
            patched.grant.execution_contexts,
            vec!["internal".to_string(), "workstation".to_string()]
        );
        assert_eq!(patched.grant.description.as_deref(), Some("Reads TEST"));

        let stale = store
            .disable_policy_grant(
                ManagedPolicyGrantStatusRequest {
                    grant_id: patched.grant.grant_id.clone(),
                    expected_version: 1,
                    updated_by: "admin".to_string(),
                },
                |_, _, _, _| Ok(()),
            )
            .unwrap_err();
        assert!(matches!(stale, ManagedStoreError::VersionConflict));
        assert_eq!(stale.reason_code(), ReasonCode::VersionConflict);

        let missing = store
            .disable_policy_grant(
                ManagedPolicyGrantStatusRequest {
                    grant_id: Uuid::new_v4().to_string(),
                    expected_version: 1,
                    updated_by: "admin".to_string(),
                },
                |_, _, _, _| Ok(()),
            )
            .unwrap_err();
        assert!(matches!(missing, ManagedStoreError::PolicyGrantNotFound));
        assert_eq!(missing.reason_code(), ReasonCode::PolicyGrantNotFound);

        let disabled = store
            .disable_policy_grant(
                ManagedPolicyGrantStatusRequest {
                    grant_id: patched.grant.grant_id.clone(),
                    expected_version: patched.grant.version,
                    updated_by: "admin".to_string(),
                },
                |grants, revision, _subjects, _catalog| {
                    assert_eq!(revision.generation, 3);
                    assert!(grants.is_empty());
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(disabled.grant.status, "disabled");
        assert!(disabled.grant.disabled_at.is_some());
        assert!(store.active_policy_grants().unwrap().is_empty());

        let enabled = store
            .enable_policy_grant(
                ManagedPolicyGrantStatusRequest {
                    grant_id: disabled.grant.grant_id.clone(),
                    expected_version: disabled.grant.version,
                    updated_by: "admin".to_string(),
                },
                |grants, revision, _subjects, _catalog| {
                    assert_eq!(revision.generation, 4);
                    assert_eq!(grants.len(), 1);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(enabled.grant.status, "active");
        assert!(enabled.grant.disabled_at.is_none());
        assert_eq!(enabled.grant.version, 4);

        let disabled_again = store
            .disable_policy_grant(
                ManagedPolicyGrantStatusRequest {
                    grant_id: enabled.grant.grant_id,
                    expected_version: enabled.grant.version,
                    updated_by: "admin".to_string(),
                },
                |grants, revision, _subjects, _catalog| {
                    assert_eq!(revision.generation, 5);
                    assert!(grants.is_empty());
                    Ok(())
                },
            )
            .unwrap();
        let disabled_at = disabled_again.grant.disabled_at.clone();
        assert!(disabled_at.is_some());

        let mut disabled_auth_patch_validation_calls = 0;
        let disabled_auth_patch = store
            .patch_policy_grant(
                ManagedPolicyGrantPatchRequest {
                    grant_id: disabled_again.grant.grant_id,
                    expected_version: disabled_again.grant.version,
                    subjects: None,
                    execution_contexts: None,
                    service: Some("removed_service".to_string()),
                    actions: None,
                    resources: None,
                    credential_mode: None,
                    priority: None,
                    status: None,
                    description: None,
                    updated_by: "admin".to_string(),
                },
                |grants, revision, _subjects, _catalog| {
                    assert_eq!(revision.generation, 6);
                    match disabled_auth_patch_validation_calls {
                        0 => assert!(grants.is_empty()),
                        1 => {
                            assert_eq!(grants.len(), 1);
                            assert_eq!(grants[0].status, "disabled");
                            assert_eq!(grants[0].service, "removed_service");
                        }
                        _ => panic!("unexpected disabled grant validation call"),
                    }
                    disabled_auth_patch_validation_calls += 1;
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(disabled_auth_patch_validation_calls, 2);
        assert_eq!(disabled_auth_patch.grant.version, 6);
        assert_eq!(disabled_auth_patch.grant.status, "disabled");
        assert_eq!(disabled_auth_patch.grant.disabled_at, disabled_at);

        let mut disabled_metadata_patch_validation_calls = 0;
        let disabled_patch = store
            .patch_policy_grant(
                ManagedPolicyGrantPatchRequest {
                    grant_id: disabled_auth_patch.grant.grant_id,
                    expected_version: disabled_auth_patch.grant.version,
                    subjects: None,
                    execution_contexts: None,
                    service: None,
                    actions: None,
                    resources: None,
                    credential_mode: None,
                    priority: None,
                    status: None,
                    description: Some(Some("Retained for audit".to_string())),
                    updated_by: "admin".to_string(),
                },
                |grants, revision, _subjects, _catalog| {
                    assert_eq!(revision.generation, 7);
                    assert!(grants.is_empty());
                    disabled_metadata_patch_validation_calls += 1;
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(disabled_metadata_patch_validation_calls, 1);
        assert_eq!(disabled_patch.grant.version, 7);
        assert_eq!(disabled_patch.grant.status, "disabled");
        assert_eq!(
            disabled_patch.grant.description.as_deref(),
            Some("Retained for audit")
        );
        assert_eq!(disabled_patch.grant.disabled_at, disabled_at);

        let deleted = store
            .delete_policy_grant(
                ManagedPolicyGrantStatusRequest {
                    grant_id: disabled_patch.grant.grant_id,
                    expected_version: disabled_patch.grant.version,
                    updated_by: "admin".to_string(),
                },
                |grants, revision, _subjects, _catalog| {
                    assert_eq!(revision.generation, 8);
                    assert!(grants.is_empty());
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(deleted.grant.status, "deleted");
        assert_eq!(deleted.grant.disabled_at, disabled_at);
        assert!(deleted.grant.deleted_at.is_some());
    }

    #[test]
    fn scoped_policy_mutations_authorize_stored_service_before_version_checks() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let mut request = policy_grant_create_request("grant-scoped".to_string());
        request.service = "jira".to_string();
        let grant = store
            .create_policy_grant(request, |_, _, _, _| Ok(()))
            .unwrap()
            .grant;
        let grant = store
            .patch_policy_grant(
                ManagedPolicyGrantPatchRequest {
                    grant_id: grant.grant_id,
                    expected_version: grant.version,
                    subjects: None,
                    execution_contexts: None,
                    service: None,
                    actions: None,
                    resources: None,
                    credential_mode: None,
                    priority: None,
                    status: None,
                    description: Some(Some("versioned".to_string())),
                    updated_by: "admin".to_string(),
                },
                |_, _, _, _| Ok(()),
            )
            .unwrap()
            .grant;
        let scope = PolicyWriteScope::Services {
            services: BTreeSet::from(["confluence".to_string()]),
        };

        for expected_version in [grant.version - 1, grant.version, grant.version + 1] {
            let error = store
                .disable_policy_grant_authorized(
                    ManagedPolicyGrantStatusRequest {
                        grant_id: grant.grant_id.clone(),
                        expected_version,
                        updated_by: "admin".to_string(),
                    },
                    &scope,
                    |_, _, _, _| Ok(()),
                )
                .unwrap_err();
            assert!(
                matches!(error, ManagedStoreError::PolicyGrantNotFound),
                "unexpected scoped mutation error for version {expected_version}: {error:?}"
            );
        }
        assert_eq!(
            store.policy_grant(&grant.grant_id).unwrap().status,
            "active"
        );
        assert_eq!(store.policy_revision().unwrap().generation, 2);
    }

    #[test]
    fn scoped_policy_patch_allows_unchanged_service_and_rejects_moves() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let mut create = policy_grant_create_request("grant-service-lock".to_string());
        create.service = "jira".to_string();
        let grant = store
            .create_policy_grant(create, |_, _, _, _| Ok(()))
            .unwrap()
            .grant;
        let scope = PolicyWriteScope::Services {
            services: BTreeSet::from(["jira".to_string(), "confluence".to_string()]),
        };
        let patch = |service, expected_version| ManagedPolicyGrantPatchRequest {
            grant_id: grant.grant_id.clone(),
            expected_version,
            subjects: None,
            execution_contexts: None,
            service,
            actions: None,
            resources: None,
            credential_mode: None,
            priority: None,
            status: None,
            description: Some(Some("scoped edit".to_string())),
            updated_by: "admin".to_string(),
        };

        store
            .validate_policy_grant_patch_authorized(
                patch(None, grant.version),
                &scope.as_read_scope(),
                |_, _, _, _| Ok(()),
            )
            .unwrap();
        let unchanged = store
            .patch_policy_grant_authorized(
                patch(Some("jira".to_string()), grant.version),
                &scope,
                |_, _, _, _| Ok(()),
            )
            .unwrap()
            .grant;
        assert_eq!(unchanged.service, "jira");

        for validate_only in [true, false] {
            let request = patch(Some("confluence".to_string()), 1);
            let error = if validate_only {
                store
                    .validate_policy_grant_patch_authorized(
                        request,
                        &scope.as_read_scope(),
                        |_, _, _, _| Ok(()),
                    )
                    .unwrap_err()
            } else {
                store
                    .patch_policy_grant_authorized(request, &scope, |_, _, _, _| Ok(()))
                    .unwrap_err()
            };
            assert!(matches!(
                error,
                ManagedStoreError::PolicyManagementServiceMoveDenied
            ));
        }
        assert_eq!(store.policy_grant(&grant.grant_id).unwrap().service, "jira");
    }

    #[test]
    fn service_policy_management_assignments_require_direct_manager_and_are_idempotent() {
        let temp = TempDir::new().unwrap();
        let store = ManagedStore::open(
            &store_config(&temp.path().join("store.sqlite")),
            ManagedStoreOpenMode::Startup,
        )
        .unwrap();
        create_alice(&store);
        create_test_group(&store, "owners");
        store.add_group("alice", "owners", "admin").unwrap();
        let request = ServicePolicyManagementAssignmentPutRequest {
            service: "jira".into(),
            principal_id: "alice".into(),
            created_by: "admin".into(),
        };
        assert!(matches!(
            store.put_service_policy_management_assignment(request.clone()),
            Err(ManagedStoreError::InputInvalid(_))
        ));
        store
            .patch_principal_access(PrincipalAccessPatchRequest {
                principal_id: "alice".into(),
                role: Some(PrincipalRole::ServicePolicyManager),
                self_service_enabled: None,
                actor: "admin".into(),
            })
            .unwrap();
        let direct = store
            .put_service_policy_management_assignment(request.clone())
            .unwrap();
        assert_eq!(
            store
                .put_service_policy_management_assignment(request)
                .unwrap(),
            direct
        );
        assert_eq!(
            store
                .effective_service_policy_management_services("alice")
                .unwrap(),
            vec!["jira"]
        );
        assert_eq!(
            store
                .effective_service_policy_management_authorities("alice")
                .unwrap(),
            vec![EffectiveServicePolicyManagementAuthority {
                service: "jira".into(),
                assignment_id: direct.assignment_id,
                principal_id: "alice".into()
            }]
        );
        assert!(
            store
                .delete_service_policy_management_assignment("jira", "alice")
                .unwrap()
        );
        assert!(
            !store
                .delete_service_policy_management_assignment("jira", "alice")
                .unwrap()
        );
        assert!(
            store
                .effective_service_policy_management_services("alice")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn policy_grant_candidate_validation_runs_before_commit() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();

        let error = store
            .create_policy_grant(
                policy_grant_create_request(Uuid::new_v4().to_string()),
                |grants, revision, _subjects, _catalog| {
                    assert_eq!(grants.len(), 1);
                    assert_eq!(revision.generation, 1);
                    Err(ManagedStoreError::InputInvalid(
                        "candidate rejected".to_string(),
                    ))
                },
            )
            .unwrap_err();

        assert!(
            matches!(error, ManagedStoreError::InputInvalid(message) if message == "candidate rejected")
        );
        assert_eq!(store.policy_revision().unwrap().generation, 0);
        assert!(store.policy_grants().unwrap().is_empty());
    }

    #[test]
    fn malformed_policy_grant_json_is_schema_invalid() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let now = now_string();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        conn.execute(
            "INSERT INTO policy_grants
             (grant_id, grant_order, service, actions_json, resources_json,
              credential_mode, priority, status, description, version, created_at, created_by,
              updated_at, updated_by, disabled_at, deleted_at)
             VALUES
             ('grant-malformed', 0, 'fake', '{malformed}',
              '{\"resourceIds\":[],\"resourceGroupIds\":[]}', 'service', NULL, 'active', NULL, 1,
              ?1, 'admin', ?1, 'admin', NULL, NULL)",
            params![now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO policy_grant_subjects (grant_id, subject, subject_order)
             VALUES ('grant-malformed', 'group:agents', 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO policy_grant_contexts
             (grant_id, execution_context, context_order)
             VALUES ('grant-malformed', 'default', 0)",
            [],
        )
        .unwrap();

        assert!(matches!(
            store.active_policy_grants().unwrap_err(),
            ManagedStoreError::SchemaInvalid(message)
                if message == "policy grant actions are malformed"
        ));

        conn.execute(
            "UPDATE policy_grants
             SET actions_json = '[\"echo\"]',
                 resources_json = '{malformed}'
             WHERE grant_id = 'grant-malformed'",
            [],
        )
        .unwrap();

        assert!(matches!(
            store.active_policy_grants().unwrap_err(),
            ManagedStoreError::SchemaInvalid(message)
                if message == "policy grant resource scopes are malformed"
        ));
    }

    #[test]
    fn malformed_policy_grant_context_rows_are_schema_invalid() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let grant_id = "grant-context-corruption".to_string();
        store
            .create_policy_grant(
                policy_grant_create_request(grant_id.clone()),
                |_, _, _, _| Ok(()),
            )
            .unwrap();
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "DELETE FROM policy_grant_contexts WHERE grant_id = ?1",
            params![grant_id],
        )
        .unwrap();
        assert!(matches!(
            store.active_policy_grants().unwrap_err(),
            ManagedStoreError::SchemaInvalid(message)
                if message.contains("has no execution contexts")
        ));

        conn.execute(
            "INSERT INTO policy_grant_contexts
             (grant_id, execution_context, context_order) VALUES (?1, 'internal', 1)",
            params![grant_id],
        )
        .unwrap();
        assert!(matches!(
            store.active_policy_grants().unwrap_err(),
            ManagedStoreError::SchemaInvalid(message)
                if message.contains("execution contexts are malformed")
        ));

        conn.execute(
            "UPDATE policy_grant_contexts
             SET execution_context = 'Internal', context_order = 0
             WHERE grant_id = ?1",
            params![grant_id],
        )
        .unwrap();
        assert!(matches!(
            store.active_policy_grants().unwrap_err(),
            ManagedStoreError::SchemaInvalid(message)
                if message.contains("execution contexts are malformed")
        ));

        conn.execute(
            "DELETE FROM policy_grant_contexts WHERE grant_id = ?1",
            params![grant_id],
        )
        .unwrap();
        for index in 0..=EXECUTION_CONTEXT_MAX_VALUES {
            conn.execute(
                "INSERT INTO policy_grant_contexts
                 (grant_id, execution_context, context_order) VALUES (?1, ?2, ?3)",
                params![
                    grant_id,
                    format!("context-{index}"),
                    i64::try_from(index).unwrap()
                ],
            )
            .unwrap();
        }
        assert!(matches!(
            store.active_policy_grants().unwrap_err(),
            ManagedStoreError::SchemaInvalid(message)
                if message.contains("has too many execution contexts")
        ));
    }

    #[test]
    fn current_store_admits_without_rewriting_ledger() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let before = migration_rows(&path);

        let mut config = store_config(&path);
        config.auto_migrate = false;
        ManagedStore::open(&config, ManagedStoreOpenMode::Reload).unwrap();

        assert_eq!(migration_rows(&path), before);
    }

    #[test]
    fn auto_migrate_false_rejects_empty_store() {
        let temp = TempDir::new().unwrap();
        #[cfg(unix)]
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("store.sqlite");
        Connection::open(&path).unwrap();

        let error = ManagedStore::open(
            &raw_store_config(&path, false),
            ManagedStoreOpenMode::Startup,
        )
        .unwrap_err();

        assert!(matches!(error, ManagedStoreError::MigrationRequired));
    }

    #[test]
    fn incompatible_stores_are_rejected_without_modification() {
        for legacy_version in [
            "001_managed_store_v1",
            "013_drop_broker_token_device_name",
            "999_future",
        ] {
            let temp = TempDir::new().unwrap();
            let path = temp.path().join("store.sqlite");
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE schema_migrations (version TEXT PRIMARY KEY, checksum TEXT NOT NULL, applied_at TEXT NOT NULL);
                 CREATE TABLE sentinel (value TEXT NOT NULL);
                 INSERT INTO sentinel VALUES ('preserve me');"
            ).unwrap();
            conn.execute(
                "INSERT INTO schema_migrations VALUES (?1, 'old', '2026-01-01T00:00:00Z')",
                [legacy_version],
            )
            .unwrap();
            drop(conn);
            let before = fs::read(&path).unwrap();
            for mode in [ManagedStoreOpenMode::Startup, ManagedStoreOpenMode::Reload] {
                let error = ManagedStore::open(&store_config(&path), mode).unwrap_err();
                let ManagedStoreError::SchemaInvalid(message) = error else {
                    panic!("expected an incompatible-schema error");
                };
                assert!(message.contains("preserve the database"));
                assert!(message.contains("compatible broker binary"));
                assert!(message.contains("matching backup"));
                assert!(message.contains("For unsupported older schemas"));
                assert!(message.contains("docs/operator-guide.md#upgrade-and-rollback"));
                assert!(message.contains("fresh store at a new path"));
                assert!(!message.contains("reset"));
                assert!(!message.contains("recreate"));
                assert_eq!(fs::read(&path).unwrap(), before);
            }
        }
    }

    #[test]
    fn newer_store_ledger_requires_compatible_binary_or_backup_without_modification() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("newer.sqlite");
        let conn = create_latest_with_ledger(&path);
        conn.execute(
            "INSERT INTO schema_migrations VALUES ('999_future', 'future-checksum', '2026-01-01T00:00:00Z')",
            [],
        )
        .unwrap();
        drop(conn);
        let before = fs::read(&path).unwrap();
        let before_ledger = migration_rows(&path);
        for mode in [ManagedStoreOpenMode::Startup, ManagedStoreOpenMode::Reload] {
            let error = ManagedStore::open(&store_config(&path), mode).unwrap_err();
            let ManagedStoreError::SchemaInvalid(message) = error else {
                panic!("expected a newer-schema error");
            };
            assert!(message.contains("newer than this broker supports"));
            assert!(message.contains("preserve the database"));
            assert!(message.contains("compatible broker binary"));
            assert!(message.contains("matching pre-upgrade backup"));
            assert!(!message.contains("fresh store"));
            assert!(!message.contains("reset"));
            assert!(!message.contains("recreate"));
            assert_eq!(migration_rows(&path), before_ledger);
            assert_eq!(fs::read(&path).unwrap(), before);
        }
    }

    #[test]
    fn malformed_or_untracked_baseline_ledgers_are_rejected() {
        for (name, sql) in [
            (
                "malformed",
                "DROP TABLE schema_migrations; CREATE TABLE schema_migrations (version TEXT PRIMARY KEY);",
            ),
            ("empty", "DELETE FROM schema_migrations;"),
            (
                "checksum",
                "UPDATE schema_migrations SET checksum = 'wrong';",
            ),
            (
                "extra",
                "INSERT INTO schema_migrations VALUES ('999_future', 'wrong', '2026-01-01T00:00:00Z');",
            ),
        ] {
            let temp = TempDir::new().unwrap();
            let path = temp.path().join(format!("{name}.sqlite"));
            create_latest_with_ledger(&path).execute_batch(sql).unwrap();
            assert!(matches!(
                ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup)
                    .unwrap_err(),
                ManagedStoreError::SchemaInvalid(_)
            ));
        }
    }

    #[test]
    fn structural_validation_rejects_resource_catalog_tampering() {
        for sql in [
            "DROP TABLE resources",
            "DROP TABLE resource_groups",
            "DROP TABLE resource_group_members",
            "DROP INDEX idx_resource_group_members_resource",
            "ALTER TABLE resources DROP COLUMN enabled",
        ] {
            let temp = TempDir::new().unwrap();
            let path = temp.path().join("store.sqlite");
            let conn = create_latest_with_ledger(&path);
            conn.execute_batch("PRAGMA foreign_keys = OFF").unwrap();
            conn.execute_batch(sql).unwrap();
            drop(conn);
            assert!(matches!(
                ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Reload).unwrap_err(),
                ManagedStoreError::SchemaInvalid(_)
            ));
        }
    }

    #[test]
    fn structural_validation_rejects_tampering() {
        let temp = TempDir::new().unwrap();

        let path = temp.path().join("missing-table.sqlite");
        create_latest_with_ledger(&path)
            .execute("DROP TABLE rights", [])
            .unwrap();
        assert!(matches!(
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Reload).unwrap_err(),
            ManagedStoreError::SchemaInvalid(_)
        ));

        let path = temp
            .path()
            .join("missing-policy-grant-contexts-table.sqlite");
        create_latest_with_ledger(&path)
            .execute("DROP TABLE policy_grant_contexts", [])
            .unwrap();
        assert!(matches!(
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Reload).unwrap_err(),
            ManagedStoreError::SchemaInvalid(_)
        ));

        let path = temp.path().join("missing-index.sqlite");
        create_latest_with_ledger(&path)
            .execute("DROP INDEX idx_credentials_owner", [])
            .unwrap();
        assert!(matches!(
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Reload).unwrap_err(),
            ManagedStoreError::SchemaInvalid(_)
        ));

        let path = temp
            .path()
            .join("missing-policy-grant-contexts-index.sqlite");
        create_latest_with_ledger(&path)
            .execute("DROP INDEX idx_policy_grant_contexts_context", [])
            .unwrap();
        assert!(matches!(
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Reload).unwrap_err(),
            ManagedStoreError::SchemaInvalid(_)
        ));

        let path = temp.path().join("missing-column.sqlite");
        create_latest_with_ledger(&path)
            .execute(
                "ALTER TABLE credentials DROP COLUMN verification_status",
                [],
            )
            .unwrap();
        assert!(matches!(
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Reload).unwrap_err(),
            ManagedStoreError::SchemaInvalid(_)
        ));

        let path = temp.path().join("unexpected-column.sqlite");
        create_latest_with_ledger(&path)
            .execute(
                "ALTER TABLE credentials ADD COLUMN secret_ciphertext BLOB",
                [],
            )
            .unwrap();
        assert!(matches!(
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Reload).unwrap_err(),
            ManagedStoreError::SchemaInvalid(_)
        ));
    }

    #[test]
    fn structural_validation_rejects_invalid_policy_revision_singleton() {
        let temp = TempDir::new().unwrap();

        let path = temp.path().join("missing-policy-revision.sqlite");
        create_latest_with_ledger(&path)
            .execute("DELETE FROM policy_revisions", [])
            .unwrap();
        assert!(matches!(
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Reload).unwrap_err(),
            ManagedStoreError::SchemaInvalid(message)
                if message.contains("policy revision singleton row is missing")
        ));

        let path = temp.path().join("missing-policy-revision-table.sqlite");
        create_latest_with_ledger(&path)
            .execute("DROP TABLE policy_revisions", [])
            .unwrap();
        assert!(matches!(
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Reload).unwrap_err(),
            ManagedStoreError::SchemaInvalid(_)
        ));
    }

    #[test]
    fn structural_validation_rejects_unknown_table_view_trigger_and_index() {
        for (name, sql) in [
            (
                "unknown-table.sqlite",
                "CREATE TABLE local_notes (note_id TEXT PRIMARY KEY)",
            ),
            (
                "unknown-view.sqlite",
                "CREATE VIEW credential_names AS SELECT name FROM credentials",
            ),
            (
                "unknown-trigger.sqlite",
                "CREATE TRIGGER credential_blocker BEFORE INSERT ON credentials BEGIN SELECT RAISE(ABORT, 'blocked'); END",
            ),
            (
                "unknown-index.sqlite",
                "CREATE INDEX extra_credentials_name ON credentials(name)",
            ),
        ] {
            let temp = TempDir::new().unwrap();
            let path = temp.path().join(name);
            create_latest_with_ledger(&path).execute(sql, []).unwrap();
            assert!(matches!(
                ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Reload).unwrap_err(),
                ManagedStoreError::SchemaInvalid(_)
            ));
        }
    }

    #[test]
    fn structural_validation_rejects_missing_unique_constraint_and_foreign_key() {
        let temp = TempDir::new().unwrap();

        let path = temp.path().join("missing-unique.sqlite");
        let conn = create_latest_with_ledger(&path);
        conn.execute_batch(
            r#"
PRAGMA foreign_keys = OFF;
DROP TABLE credential_secret_material;
DROP TABLE credentials;
CREATE TABLE credentials (
  credential_id TEXT PRIMARY KEY,
  owner_principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
  owner_kind TEXT NOT NULL CHECK (owner_kind IN ('user', 'service_account', 'system')),
  service TEXT NOT NULL,
  name TEXT NOT NULL,
  profile TEXT NOT NULL,
  credential_kind TEXT NOT NULL CHECK (credential_kind IN ('basic_api_token', 'bearer_token')),
  metadata_json TEXT NOT NULL,
  secret_backend TEXT NOT NULL CHECK (secret_backend = 'sqlite_encrypted'),
  secret_ref TEXT NOT NULL,
  material_version TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  last_used_at TEXT,
  last_verified_at TEXT,
  verification_status TEXT
);
CREATE TABLE credential_secret_material (
  secret_ref TEXT PRIMARY KEY,
  credential_id TEXT NOT NULL UNIQUE REFERENCES credentials(credential_id) ON DELETE CASCADE,
  backend TEXT NOT NULL CHECK (backend = 'sqlite_encrypted'),
  secret_ciphertext BLOB NOT NULL,
  secret_nonce BLOB NOT NULL,
  key_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX idx_credentials_owner ON credentials(owner_kind, owner_principal_id, service, name);
CREATE INDEX idx_credential_secret_material_credential ON credential_secret_material(credential_id);
PRAGMA foreign_keys = ON;
"#,
        )
        .unwrap();
        drop(conn);
        assert!(matches!(
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Reload).unwrap_err(),
            ManagedStoreError::SchemaInvalid(_)
        ));

        let path = temp.path().join("missing-fk.sqlite");
        let conn = create_latest_with_ledger(&path);
        conn.execute_batch(
            r#"
PRAGMA foreign_keys = OFF;
DROP TABLE rights;
CREATE TABLE rights (
  right_id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  right_name TEXT NOT NULL,
  service TEXT,
  credential_name TEXT,
  resource_scope_json TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT,
  revoked_at TEXT,
  revoked_by TEXT,
  reason TEXT
);
CREATE INDEX idx_rights_principal ON rights(principal_id, right_name, service, credential_name);
PRAGMA foreign_keys = ON;
"#,
        )
        .unwrap();
        drop(conn);
        assert!(matches!(
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Reload).unwrap_err(),
            ManagedStoreError::SchemaInvalid(_)
        ));
    }

    #[test]
    fn structural_validation_rejects_malformed_secret_material_without_decrypting() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let ring = key_ring("k1");
        create_alice(&store);
        let metadata = put_alice_jira_credential(&store, &ring, "pat");
        {
            let conn = store.connection.lock().unwrap();
            conn.execute_batch("PRAGMA foreign_keys = OFF").unwrap();
            conn.execute(
                "UPDATE credential_secret_material SET credential_id = ?2 WHERE secret_ref = ?1",
                params![metadata.secret_ref, Uuid::new_v4().to_string()],
            )
            .unwrap();
            conn.execute_batch("PRAGMA foreign_keys = ON").unwrap();
        }
        drop(store);

        assert!(matches!(
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Reload).unwrap_err(),
            ManagedStoreError::SchemaInvalid(_)
        ));
    }

    #[test]
    fn check_schema_ready_is_cheap_and_does_not_run_structural_validation() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        {
            let conn = store.connection.lock().unwrap();
            conn.execute("DROP INDEX idx_credentials_owner", [])
                .unwrap();
        }

        store.check_schema_ready().unwrap();
        assert!(matches!(
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Reload).unwrap_err(),
            ManagedStoreError::SchemaInvalid(_)
        ));
    }

    #[test]
    fn ledger_classification_preserves_its_snapshot_during_other_initialization() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let reader = Connection::open(&path).unwrap();
        reader.execute_batch("PRAGMA journal_mode = WAL;").unwrap();
        let writer = Connection::open(&path).unwrap();
        let catalog = production_migration_catalog();

        // Pin the empty snapshot at the first query performed by classification.
        let tx = reader.unchecked_transaction().unwrap();
        assert!(!migrations_table_exists(&tx).unwrap());
        assert_eq!(
            admit_schema(&writer, catalog, true).unwrap().len(),
            catalog.migrations.len()
        );
        // The later query must not see the newly committed tables and misclassify
        // this snapshot as an untracked legacy store.
        assert!(matches!(
            read_validated_ledger(&tx, catalog).unwrap(),
            ValidatedLedger::EmptyDatabase
        ));
        assert!(!reader.is_autocommit());
        tx.commit().unwrap();

        assert!(matches!(
            read_validated_ledger(&reader, catalog).unwrap(),
            ValidatedLedger::Prefix(count) if count == catalog.migrations.len()
        ));
        assert!(reader.is_autocommit());
        assert!(admit_schema(&reader, catalog, true).unwrap().is_empty());
    }

    #[test]
    fn ledger_classification_releases_read_transaction_before_initialization() {
        let conn = Connection::open_in_memory().unwrap();
        let catalog = production_migration_catalog();
        assert!(matches!(
            read_validated_ledger(&conn, catalog).unwrap(),
            ValidatedLedger::EmptyDatabase
        ));
        assert!(conn.is_autocommit());
        assert_eq!(
            admit_schema(&conn, catalog, true).unwrap().len(),
            catalog.migrations.len()
        );
        assert!(conn.is_autocommit());
    }

    #[test]
    fn concurrent_managed_store_initializers_do_not_double_apply() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let config = store_config(&path);
        Connection::open(&path).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let handles = (0..2)
            .map(|_| {
                let barrier = barrier.clone();
                let config = config.clone();
                thread::spawn(move || {
                    barrier.wait();
                    ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(migration_rows(&path).len(), MANAGED_STORE_MIGRATIONS.len());
    }

    #[test]
    fn migrates_and_reports_status() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let status = store.status().unwrap();
        assert_eq!(status.schema_version, MANAGED_STORE_SCHEMA_VERSION);
        assert_eq!(status.principals, 0);
    }

    fn local_write(password: &str) -> LocalPasswordWriteRequest {
        LocalPasswordWriteRequest {
            principal_id: "alice".into(),
            password: password.into(),
            min_password_length: 8,
            password_change_required: false,
            actor: "admin".into(),
        }
    }

    fn local_change(password: &str, replacement: bool) -> LocalPasswordChangeRequest {
        LocalPasswordChangeRequest {
            verification: LocalPasswordVerifyRequest {
                principal_id: "alice".into(),
                password: password.into(),
                source: "203.0.113.10".into(),
                max_failed_attempts: 3,
                lockout_ttl_seconds: 60,
            },
            new_password: "changed-password".into(),
            min_password_length: 8,
            replace_local_session: replacement,
            session_ttl_seconds: 3600,
        }
    }

    fn block_password_verification(
        hasher: &mut LocalPasswordHasher,
    ) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let release_rx = Mutex::new(release_rx);
        hasher.verification_hook = Some(Arc::new(move || {
            entered_tx.send(()).unwrap();
            release_rx.lock().unwrap().recv().unwrap();
        }));
        (entered_rx, release_tx)
    }

    #[test]
    fn local_password_hash_work_is_bounded_and_does_not_block_token_resolution() {
        let temp = TempDir::new().unwrap();
        let store = ManagedStore::open(
            &store_config(&temp.path().join("store.sqlite")),
            ManagedStoreOpenMode::Startup,
        )
        .unwrap();
        create_alice(&store);
        let mut hasher = local_password_hasher_for_test(21);
        let tokens = broker_token_hasher_for_test(22);
        store
            .enable_local_password(&hasher, local_write("first-password"))
            .unwrap();
        let issued = store
            .issue_broker_token(
                &tokens,
                BrokerTokenIssueRequest {
                    principal_id: "alice".into(),
                    name: "existing agent".into(),
                    token_class: BrokerTokenClass::AgentInvoke,
                    scopes: json!({"allowedExecutionContexts": ["default"]}),
                    expires_at: None,
                    created_by: "admin".into(),
                },
            )
            .unwrap();
        let (entered, release) = block_password_verification(&mut hasher);
        let handles = ["alice", "unknown-principal"].map(|principal| {
            let store = store.clone();
            let hasher = hasher.clone();
            std::thread::spawn(move || {
                let mut request = local_change("first-password", false).verification;
                request.principal_id = principal.into();
                store.verify_local_password(&hasher, request)
            })
        });
        for _ in 0..2 {
            entered
                .recv_timeout(std::time::Duration::from_secs(30))
                .unwrap();
        }
        for index in 0..32 {
            let mut request = local_change("bad-password", false).verification;
            request.principal_id = format!("unknown-{index}");
            assert!(matches!(
                store.verify_local_password(&hasher, request),
                Err(ManagedStoreError::LocalPasswordBusy)
            ));
        }
        let (resolved_tx, resolved_rx) = std::sync::mpsc::channel();
        let token_store = store.clone();
        let resolver = std::thread::spawn(move || {
            resolved_tx
                .send(token_store.resolve_broker_token(&tokens, &issued.token))
                .unwrap();
        });
        let resolved = resolved_rx.recv_timeout(std::time::Duration::from_secs(5));
        // Always release workers before assertions so a failed lock-isolation
        // regression cannot leave blocked test threads behind.
        for _ in 0..2 {
            release.send(()).unwrap();
        }
        let [known, unknown] = handles.map(|handle| handle.join().unwrap());
        resolver.join().unwrap();
        assert_eq!(resolved.unwrap().unwrap().principal_id, "alice");
        assert!(known.is_ok());
        assert!(matches!(unknown, Err(ManagedStoreError::LocalLoginFailed)));
        assert_eq!(store.local_password_work.hashes.available_permits(), 2);
    }

    #[test]
    fn local_password_admin_recovery_survives_saturated_login_hash_work() {
        let temp = TempDir::new().unwrap();
        let store = ManagedStore::open(
            &store_config(&temp.path().join("store.sqlite")),
            ManagedStoreOpenMode::Startup,
        )
        .unwrap();
        create_alice(&store);
        store
            .create_or_update_principal(PrincipalWriteRequest {
                role: crate::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "bob".into(),
                kind: "user".into(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".into(),
            })
            .unwrap();
        let mut hasher = local_password_hasher_for_test(21);
        store
            .enable_local_password(&hasher, local_write("first-password"))
            .unwrap();
        let (entered, release) = block_password_verification(&mut hasher);
        let handles = ["alice", "unknown-principal"].map(|principal| {
            let store = store.clone();
            let hasher = hasher.clone();
            std::thread::spawn(move || {
                let mut request = local_change("first-password", false).verification;
                request.principal_id = principal.into();
                store.verify_local_password(&hasher, request)
            })
        });
        for _ in 0..2 {
            entered
                .recv_timeout(std::time::Duration::from_secs(30))
                .unwrap();
        }
        assert_eq!(store.local_password_work.hashes.available_permits(), 0);
        let admin_store = store.clone();
        let admin_hasher = hasher.clone();
        let (admin_tx, admin_rx) = std::sync::mpsc::channel();
        let admin = std::thread::spawn(move || {
            let reset = admin_store
                .reset_local_password(&admin_hasher, local_write("replacement-password"));
            let mut request = local_write("enrolled-password");
            request.principal_id = "bob".into();
            let enrollment = admin_store.enable_local_password(&admin_hasher, request);
            admin_tx.send((reset, enrollment)).unwrap();
        });
        let completed = admin_rx.recv_timeout(std::time::Duration::from_secs(30));
        // Release login jobs even if recovery regresses, before asserting that
        // both administrative operations completed while those jobs were held.
        for _ in 0..2 {
            release.send(()).unwrap();
        }
        let outcomes = handles.map(|handle| handle.join().unwrap());
        admin.join().unwrap();
        let (reset, enrollment) = completed.unwrap();
        assert!(reset.is_ok(), "{reset:?}");
        assert!(enrollment.is_ok(), "{enrollment:?}");
        for outcome in outcomes {
            assert!(matches!(outcome, Err(ManagedStoreError::LocalLoginFailed)));
        }
        assert_eq!(store.local_password_work.hashes.available_permits(), 2);
        assert_eq!(
            store.local_password_work.admin_hashes.available_permits(),
            1
        );
        hasher.verification_hook = None;
        for (principal, password) in [
            ("alice", "replacement-password"),
            ("bob", "enrolled-password"),
        ] {
            let mut request = local_change(password, false).verification;
            request.principal_id = principal.into();
            assert!(store.verify_local_password(&hasher, request).is_ok());
        }
    }

    #[test]
    fn local_password_request_admission_is_shared_across_reload_without_queuing() {
        let temp = TempDir::new().unwrap();
        let config = store_config(&temp.path().join("store.sqlite"));
        let store = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
        let first = store.try_admit_local_password_request().unwrap();
        let second = store.clone().try_admit_local_password_request().unwrap();
        let hash_first = store.try_acquire_work().unwrap();
        let hash_second = store.try_acquire_work().unwrap();
        let admin_hash = store.try_acquire_admin_password_work().unwrap();
        // Reopen as hot reload does while old-snapshot jobs retain permits.
        let reloaded = ManagedStore::open(&config, ManagedStoreOpenMode::Reload).unwrap();
        assert!(matches!(
            reloaded.try_admit_local_password_request(),
            Err(ManagedStoreError::LocalPasswordBusy)
        ));
        assert!(matches!(
            reloaded.try_acquire_work(),
            Err(ManagedStoreError::LocalPasswordBusy)
        ));
        assert!(matches!(
            reloaded.try_acquire_admin_password_work(),
            Err(ManagedStoreError::LocalPasswordBusy)
        ));
        let hasher = local_password_hasher_for_test(21);
        assert!(matches!(
            reloaded.reset_local_password(&hasher, local_write("replacement-password")),
            Err(ManagedStoreError::LocalPasswordBusy)
        ));
        assert!(matches!(
            reloaded.enable_local_password(&hasher, local_write("enrolled-password")),
            Err(ManagedStoreError::LocalPasswordBusy)
        ));
        drop(first);
        drop(hash_first);
        drop(admin_hash);
        assert!(reloaded.try_admit_local_password_request().is_ok());
        assert!(reloaded.try_acquire_work().is_ok());
        assert!(reloaded.try_acquire_admin_password_work().is_ok());
        drop(second);
        drop(hash_second);
    }

    #[test]
    fn local_password_session_rechecks_reset_and_disable_after_hashing() {
        for mutation in ["reset", "disable_method", "disable_principal"] {
            let temp = TempDir::new().unwrap();
            let store = ManagedStore::open(
                &store_config(&temp.path().join("store.sqlite")),
                ManagedStoreOpenMode::Startup,
            )
            .unwrap();
            create_alice(&store);
            let mut hasher = local_password_hasher_for_test(21);
            let tokens = broker_token_hasher_for_test(22);
            store
                .enable_local_password(&hasher, local_write("first-password"))
                .unwrap();
            let (entered, release) = block_password_verification(&mut hasher);
            let task_store = store.clone();
            let task_hasher = hasher.clone();
            let handle = std::thread::spawn(move || {
                task_store.authenticate_local_password_session(
                    &task_hasher,
                    &tokens,
                    local_change("first-password", false).verification,
                    3600,
                )
            });
            entered
                .recv_timeout(std::time::Duration::from_secs(30))
                .unwrap();
            match mutation {
                "reset" => {
                    store
                        .reset_local_password(&hasher, local_write("replacement-password"))
                        .unwrap();
                }
                "disable_method" => {
                    store.disable_local_password("alice", "admin").unwrap();
                }
                "disable_principal" => {
                    store.set_principal_enabled("alice", false).unwrap();
                }
                _ => unreachable!(),
            }
            release.send(()).unwrap();
            assert!(
                matches!(
                    handle.join().unwrap(),
                    Err(ManagedStoreError::LocalLoginFailed)
                ),
                "{mutation}"
            );
            let count: i64 = store
                .connection
                .lock()
                .unwrap()
                .query_row("SELECT COUNT(*) FROM browser_sessions", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "{mutation}");
        }
    }

    #[test]
    fn local_password_change_cannot_overwrite_concurrent_reset() {
        let temp = TempDir::new().unwrap();
        let store = ManagedStore::open(
            &store_config(&temp.path().join("store.sqlite")),
            ManagedStoreOpenMode::Startup,
        )
        .unwrap();
        create_alice(&store);
        let mut hasher = local_password_hasher_for_test(21);
        let tokens = broker_token_hasher_for_test(22);
        store
            .enable_local_password(&hasher, local_write("first-password"))
            .unwrap();
        let (entered, release) = block_password_verification(&mut hasher);
        let task_store = store.clone();
        let task_hasher = hasher.clone();
        let handle = std::thread::spawn(move || {
            task_store.change_local_password(
                &task_hasher,
                &tokens,
                local_change("first-password", true),
            )
        });
        entered
            .recv_timeout(std::time::Duration::from_secs(30))
            .unwrap();
        store
            .reset_local_password(&hasher, local_write("replacement-password"))
            .unwrap();
        release.send(()).unwrap();
        assert!(matches!(
            handle.join().unwrap(),
            Err(ManagedStoreError::LocalLoginFailed)
        ));
        hasher.verification_hook = None;
        assert!(
            store
                .verify_local_password(
                    &hasher,
                    local_change("replacement-password", false).verification
                )
                .is_ok()
        );
    }

    #[test]
    fn local_password_enrollment_is_explicit_and_summaries_describe_methods() {
        let temp = TempDir::new().unwrap();
        let store = ManagedStore::open(
            &store_config(&temp.path().join("store.sqlite")),
            ManagedStoreOpenMode::Startup,
        )
        .unwrap();
        create_alice(&store);
        let hasher = local_password_hasher_for_test(21);
        let tokens = broker_token_hasher_for_test(22);
        assert_eq!(
            store.principal("alice").unwrap().sign_in_methods,
            SignInMethods::default()
        );
        assert!(matches!(
            store.reset_local_password(&hasher, local_write("first-password")),
            Err(ManagedStoreError::LocalPasswordNotEnabled)
        ));
        assert!(store.list_login_methods("alice").unwrap().is_empty());
        reconcile_test_oidc_provider(&store, true, 3600, "dual-config");
        store
            .link_oidc_login_method(OidcLoginMethodLinkRequest {
                principal_id: "alice".into(),
                user_object_id: TEST_OIDC_USER.into(),
                actor: "admin".into(),
            })
            .unwrap();
        let enabled = store
            .enable_local_password(&hasher, local_write("first-password"))
            .unwrap();
        assert_eq!(enabled.previous_status, SignInMethodStatus::Absent);
        assert!(matches!(
            store.enable_local_password(&hasher, local_write("other-password")),
            Err(ManagedStoreError::LocalPasswordAlreadyEnabled)
        ));
        let summary = SignInMethods {
            local_password: SignInMethodStatus::Active,
            microsoft: SignInMethodStatus::Active,
        };
        assert_eq!(store.principal("alice").unwrap().sign_in_methods, summary);
        assert_eq!(store.list_principals().unwrap()[0].sign_in_methods, summary);
        let serialized = serde_json::to_string(&store.list_principals().unwrap()).unwrap();
        assert!(
            !serialized.contains("first-password")
                && !serialized.contains("passwordHash")
                && !serialized.contains(TEST_OIDC_USER)
        );
        store.disable_local_password("alice", "admin").unwrap();
        assert!(matches!(
            store.reset_local_password(&hasher, local_write("new-password")),
            Err(ManagedStoreError::LocalPasswordNotEnabled)
        ));
        assert!(matches!(
            store.change_local_password(&hasher, &tokens, local_change("first-password", false)),
            Err(ManagedStoreError::LocalLoginFailed)
        ));
        assert_eq!(
            store
                .principal("alice")
                .unwrap()
                .sign_in_methods
                .local_password,
            SignInMethodStatus::Disabled
        );
        let enabled = store
            .enable_local_password(&hasher, local_write("replacement-password"))
            .unwrap();
        assert_eq!(enabled.previous_status, SignInMethodStatus::Disabled);
        assert_eq!(enabled.method.status, "active");
        assert!(
            store
                .verify_local_password(&hasher, local_change("first-password", false).verification)
                .is_err()
        );
        assert!(
            store
                .verify_local_password(
                    &hasher,
                    local_change("replacement-password", false).verification
                )
                .is_ok()
        );
    }

    #[test]
    fn local_password_change_commits_replacement_session_and_revokes_old_sessions() {
        let temp = TempDir::new().unwrap();
        let store = ManagedStore::open(
            &store_config(&temp.path().join("store.sqlite")),
            ManagedStoreOpenMode::Startup,
        )
        .unwrap();
        create_alice(&store);
        let hasher = local_password_hasher_for_test(23);
        let tokens = broker_token_hasher_for_test(24);
        let method = store
            .enable_local_password(&hasher, local_write("first-password"))
            .unwrap()
            .method;
        let old = store
            .issue_browser_session(
                &tokens,
                BrowserSessionIssueRequest {
                    principal_id: "alice".into(),
                    login_method: "local_password".into(),
                    login_method_id: Some(method.login_method_id),
                    ttl_seconds: 3600,
                    password_change_required: false,
                    created_by: "alice".into(),
                },
            )
            .unwrap();
        let changed = store
            .change_local_password(&hasher, &tokens, local_change("first-password", true))
            .unwrap();
        let new = changed.replacement_session.unwrap();
        assert!(!changed.verified.password_change_required);
        assert!(store.resolve_browser_session(&tokens, &old.token).is_err());
        assert!(store.resolve_browser_session(&tokens, &new.token).is_ok());
        assert!(
            store
                .verify_local_password(&hasher, local_change("first-password", false).verification)
                .is_err()
        );
        assert!(
            store
                .verify_local_password(
                    &hasher,
                    local_change("changed-password", false).verification
                )
                .is_ok()
        );
        // A replacement-session failure rolls back the password and revocations.
        let mut invalid = local_change("changed-password", true);
        invalid.session_ttl_seconds = 0;
        assert!(
            store
                .change_local_password(&hasher, &tokens, invalid)
                .is_err()
        );
        assert!(store.resolve_browser_session(&tokens, &new.token).is_ok());
    }

    #[test]
    fn local_password_change_cannot_undo_a_disable_from_another_connection() {
        assert_local_password_operation_observes_concurrent_write(false, false);
    }

    #[test]
    fn local_password_change_cannot_undo_a_reset_from_another_connection() {
        assert_local_password_operation_observes_concurrent_write(true, false);
    }

    #[test]
    fn local_password_login_cannot_issue_after_a_disable_from_another_connection() {
        assert_local_password_operation_observes_concurrent_write(false, true);
    }

    #[test]
    fn local_password_login_cannot_issue_after_a_same_timestamp_reset() {
        assert_local_password_operation_observes_concurrent_write(true, true);
    }

    fn assert_local_password_operation_observes_concurrent_write(reset: bool, login: bool) {
        use std::cell::RefCell;
        use std::sync::mpsc::{Receiver, Sender, channel};
        thread_local! {
            // SQLite's busy callback cannot capture state. Thread-local channels
            // make this handshake independent of parallel tests.
            static WRITE_LOCK_WAIT: RefCell<Option<(Sender<()>, Receiver<()>)>> = const { RefCell::new(None) };
        }

        let temp = TempDir::new().unwrap();
        let config = store_config(&temp.path().join("store.sqlite"));
        let store = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
        create_alice(&store);
        let hasher = local_password_hasher_for_test(25);
        store
            .enable_local_password(&hasher, local_write("first-password"))
            .unwrap();
        let other = ManagedStore::open(&config, ManagedStoreOpenMode::Reload).unwrap();
        let admin_hash = hasher.hash_password("admin-password").unwrap();
        let mut conn = store.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        if reset {
            let existing = local_password_login_method(&tx, "alice").unwrap().unwrap();
            write_local_password_tx(
                &tx,
                &local_write("admin-password"),
                &admin_hash,
                Some(&existing),
            )
            .unwrap();
            // A rapid reset may share its predecessor's timestamp. Authorization
            // must observe the current hash even when that timestamp is identical.
            tx.execute(
                "UPDATE principal_login_methods SET password_set_at = ?1 WHERE login_method_id = ?2",
                params![existing.password_set_at, existing.login_method_id],
            )
            .unwrap();
        } else {
            tx.execute(
                "UPDATE principal_login_methods SET status = 'disabled' WHERE principal_id = 'alice'",
                [],
            ).unwrap();
        }
        let (blocked, ready) = channel();
        let (resume, released) = channel();
        let worker_hasher = hasher.clone();
        let task = std::thread::spawn(move || {
            WRITE_LOCK_WAIT.with(|slot| *slot.borrow_mut() = Some((blocked, released)));
            other
                .connection
                .lock()
                .unwrap()
                .busy_handler(Some(|_| {
                    WRITE_LOCK_WAIT.with(|slot| {
                        let Some((blocked, released)) = slot.borrow_mut().take() else {
                            return false;
                        };
                        blocked.send(()).is_ok() && released.recv().is_ok()
                    })
                }))
                .unwrap();
            if login {
                other
                    .authenticate_local_password_session(
                        &worker_hasher,
                        &broker_token_hasher_for_test(26),
                        local_change("first-password", false).verification,
                        3600,
                    )
                    .map(|_| ())
            } else {
                other
                    .change_local_password(
                        &worker_hasher,
                        &broker_token_hasher_for_test(26),
                        local_change("first-password", true),
                    )
                    .map(|_| ())
            }
        });
        // This notification comes from SQLite while BEGIN IMMEDIATE is blocked,
        // so authentication is provably interleaved with the pending admin write.
        ready
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        tx.commit().unwrap();
        drop(conn);
        resume.send(()).unwrap();
        assert!(matches!(
            task.join().unwrap(),
            Err(ManagedStoreError::LocalLoginFailed)
        ));
        assert!(
            store
                .list_broker_tokens_for_principal("alice")
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store
                .principal("alice")
                .unwrap()
                .sign_in_methods
                .local_password,
            if reset {
                SignInMethodStatus::Active
            } else {
                SignInMethodStatus::Disabled
            }
        );
        if reset {
            assert!(
                store
                    .verify_local_password(
                        &hasher,
                        local_change("admin-password", false).verification,
                    )
                    .is_ok()
            );
            assert!(matches!(
                store.verify_local_password(
                    &hasher,
                    local_change("changed-password", false).verification,
                ),
                Err(ManagedStoreError::LocalLoginFailed)
            ));
        }
    }

    #[test]
    fn local_password_reset_revokes_existing_browser_sessions() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        create_alice(&store);
        let password_hasher = local_password_hasher_for_test(11);
        let token_hasher = broker_token_hasher_for_test(12);

        let method = store
            .enable_local_password(
                &password_hasher,
                LocalPasswordWriteRequest {
                    principal_id: "alice".to_string(),
                    password: "first-password".to_string(),
                    min_password_length: 8,
                    password_change_required: true,
                    actor: "admin".to_string(),
                },
            )
            .unwrap()
            .method;
        assert!(method.must_change_password);
        let password_hash_phc = {
            let conn = store.connection.lock().unwrap();
            local_password_hash(&conn, &method.login_method_id).unwrap()
        };
        assert!(password_hash_phc.contains("m=65536,t=3,p=1"));
        let verified = store
            .verify_local_password(
                &password_hasher,
                LocalPasswordVerifyRequest {
                    principal_id: "alice".to_string(),
                    password: "first-password".to_string(),
                    source: "203.0.113.10".to_string(),
                    max_failed_attempts: 3,
                    lockout_ttl_seconds: 60,
                },
            )
            .unwrap();
        assert!(verified.password_change_required);
        let session = store
            .issue_browser_session(
                &token_hasher,
                BrowserSessionIssueRequest {
                    principal_id: "alice".to_string(),
                    login_method: "local_password".to_string(),
                    login_method_id: Some(verified.login_method_id),
                    ttl_seconds: 3600,
                    password_change_required: verified.password_change_required,
                    created_by: "alice".to_string(),
                },
            )
            .unwrap();

        assert_eq!(
            store
                .resolve_browser_session(&token_hasher, &session.token)
                .unwrap()
                .principal_id,
            "alice"
        );

        store
            .reset_local_password(
                &password_hasher,
                LocalPasswordWriteRequest {
                    principal_id: "alice".to_string(),
                    password: "second-password".to_string(),
                    min_password_length: 8,
                    password_change_required: false,
                    actor: "admin".to_string(),
                },
            )
            .unwrap();

        assert!(matches!(
            store
                .resolve_browser_session(&token_hasher, &session.token)
                .unwrap_err(),
            ManagedStoreError::BrokerTokenRevoked
        ));
        assert!(matches!(
            store
                .verify_local_password(
                    &password_hasher,
                    LocalPasswordVerifyRequest {
                        principal_id: "alice".to_string(),
                        password: "first-password".to_string(),
                        source: "203.0.113.10".to_string(),
                        max_failed_attempts: 3,
                        lockout_ttl_seconds: 60,
                    },
                )
                .unwrap_err(),
            ManagedStoreError::LocalLoginFailed
        ));
        assert!(
            store
                .verify_local_password(
                    &password_hasher,
                    LocalPasswordVerifyRequest {
                        principal_id: "alice".to_string(),
                        password: "second-password".to_string(),
                        source: "203.0.113.10".to_string(),
                        max_failed_attempts: 3,
                        lockout_ttl_seconds: 60,
                    },
                )
                .is_ok()
        );
        let serialized = serde_json::to_value(method).unwrap();
        assert!(serialized.get("passwordHashPhc").is_none());
    }

    #[test]
    fn local_password_admin_methods_work_for_disabled_principals() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        create_alice(&store);
        store.set_principal_enabled("alice", false).unwrap();
        let password_hasher = local_password_hasher_for_test(17);

        let method = store
            .enable_local_password(
                &password_hasher,
                LocalPasswordWriteRequest {
                    principal_id: "alice".to_string(),
                    password: "disabled-password".to_string(),
                    min_password_length: 8,
                    password_change_required: false,
                    actor: "admin".to_string(),
                },
            )
            .unwrap()
            .method;
        assert!(!method.must_change_password);
        assert_eq!(store.list_login_methods("alice").unwrap().len(), 1);

        let disabled = store.disable_local_password("alice", "admin").unwrap();
        assert_eq!(disabled.status, "disabled");
        let unlocked = store.unlock_local_password("alice", "admin").unwrap();
        assert_eq!(unlocked.status, "disabled");
        assert!(matches!(
            store
                .verify_local_password(
                    &password_hasher,
                    LocalPasswordVerifyRequest {
                        principal_id: "alice".to_string(),
                        password: "disabled-password".to_string(),
                        source: "203.0.113.10".to_string(),
                        max_failed_attempts: 3,
                        lockout_ttl_seconds: 60,
                    },
                )
                .unwrap_err(),
            ManagedStoreError::LocalLoginFailed
        ));
    }

    #[test]
    fn service_accounts_are_noninteractive_and_only_receive_agent_tokens() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let password_hasher = local_password_hasher_for_test(71);
        let token_hasher = broker_token_hasher_for_test(72);
        let service_account = store
            .create_principal(PrincipalWriteRequest {
                role: crate::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "svc-reporter".to_string(),
                kind: "service_account".to_string(),
                display_name: Some("Reporting service".to_string()),
                email: None,
                external_subject: None,
                created_by: "admin".to_string(),
            })
            .unwrap();
        assert_eq!(service_account.kind, "service_account");

        assert!(matches!(
            store.enable_local_password(
                &password_hasher,
                LocalPasswordWriteRequest {
                    principal_id: "svc-reporter".to_string(),
                    password: "service-account-password".to_string(),
                    min_password_length: 8,
                    password_change_required: false,
                    actor: "admin".to_string(),
                },
            ),
            Err(ManagedStoreError::InputInvalid(message))
                if message == "operation is only available to interactive user principals"
        ));
        assert!(matches!(
            store.link_oidc_login_method(OidcLoginMethodLinkRequest {
                principal_id: "svc-reporter".to_string(),
                user_object_id: TEST_OIDC_USER.to_string(),
                actor: "admin".to_string(),
            }),
            Err(ManagedStoreError::InputInvalid(_))
        ));
        assert!(matches!(
            store.patch_principal_access(crate::PrincipalAccessPatchRequest {
                principal_id: ("svc-reporter").into(),
                role: Some(crate::PrincipalRole::Admin),
                self_service_enabled: None,
                actor: ("admin").into()
            }),
            Err(ManagedStoreError::InputInvalid(_))
        ));
        create_test_group(&store, "configured-admins");
        store
            .add_group("svc-reporter", "configured-admins", "admin")
            .unwrap();
        assert!(
            !store
                .principal("svc-reporter")
                .map(|principal| principal.role == crate::PrincipalRole::Admin)
                .unwrap()
        );
        assert_eq!(store.active_admin_principal_count().unwrap(), 0);

        for token_class in [BrokerTokenClass::UserManage, BrokerTokenClass::Admin] {
            assert!(matches!(
                store.issue_broker_token(
                    &token_hasher,
                    BrokerTokenIssueRequest {
                        principal_id: "svc-reporter".to_string(),
                        name: "interactive token".to_string(),
                        token_class,
                        scopes: json!({}),
                        expires_at: None,
                        created_by: "admin".to_string(),
                    },
                ),
                Err(ManagedStoreError::InputInvalid(message))
                    if message == "service accounts may only receive agent_invoke tokens"
            ));
        }

        let agent = store
            .issue_broker_token(
                &token_hasher,
                BrokerTokenIssueRequest {
                    principal_id: "svc-reporter".to_string(),
                    name: "reporting agent".to_string(),
                    token_class: BrokerTokenClass::AgentInvoke,
                    scopes: json!({
                        "allowedServices": ["fake"],
                        "allowedExecutionContexts": ["internal"],
                        "serviceRestrictions": {
                            "fake": {
                                "actions": ["echo"],
                                "resources": {}
                            }
                        }
                    }),
                    expires_at: None,
                    created_by: "admin".to_string(),
                },
            )
            .unwrap();
        let resolved = store
            .resolve_broker_token(&token_hasher, &agent.token)
            .unwrap();
        assert_eq!(resolved.principal_id, "svc-reporter");
        assert_eq!(
            resolved.principal_kind,
            Some(crate::PrincipalKind::ServiceAccount)
        );
        let conn = store.connection.lock().unwrap();
        assert_eq!(
            principal_kind_at_conn(&conn, "svc-reporter").unwrap(),
            Some(crate::PrincipalKind::ServiceAccount)
        );
        assert_eq!(principal_kind_at_conn(&conn, "not-stored").unwrap(), None);
        drop(conn);

        store
            .create_principal(PrincipalWriteRequest {
                role: crate::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "legacy-service".to_string(),
                kind: "user".to_string(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".to_string(),
            })
            .unwrap();
        let method = store
            .enable_local_password(
                &password_hasher,
                LocalPasswordWriteRequest {
                    principal_id: "legacy-service".to_string(),
                    password: "legacy-service-password".to_string(),
                    min_password_length: 8,
                    password_change_required: false,
                    actor: "admin".to_string(),
                },
            )
            .unwrap()
            .method;
        store
            .patch_principal_access(crate::PrincipalAccessPatchRequest {
                principal_id: ("legacy-service").into(),
                role: Some(crate::PrincipalRole::Admin),
                self_service_enabled: None,
                actor: ("admin").into(),
            })
            .unwrap();
        assert_eq!(store.active_admin_principal_count().unwrap(), 1);
        let session = store
            .issue_browser_session(
                &token_hasher,
                BrowserSessionIssueRequest {
                    principal_id: "legacy-service".to_string(),
                    login_method: "local_password".to_string(),
                    login_method_id: Some(method.login_method_id.clone()),
                    ttl_seconds: 3_600,
                    password_change_required: false,
                    created_by: "legacy-service".to_string(),
                },
            )
            .unwrap();
        let management = store
            .issue_broker_token(
                &token_hasher,
                BrokerTokenIssueRequest {
                    principal_id: "legacy-service".to_string(),
                    name: "legacy setup".to_string(),
                    token_class: BrokerTokenClass::UserManage,
                    scopes: json!({}),
                    expires_at: None,
                    created_by: "admin".to_string(),
                },
            )
            .unwrap();
        let oidc_provider =
            reconcile_test_oidc_provider(&store, true, 3_600, "service-account-login-test");
        store
            .link_oidc_login_method(OidcLoginMethodLinkRequest {
                principal_id: "legacy-service".to_string(),
                user_object_id: TEST_OIDC_USER.to_string(),
                actor: "admin".to_string(),
            })
            .unwrap();
        assert!(matches!(
            store.create_or_update_principal(PrincipalWriteRequest {
                role: crate::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "legacy-service".to_string(),
                kind: "service_account".to_string(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".to_string(),
            }),
            Err(ManagedStoreError::InputInvalid(_))
        ));
        // Simulate legacy corruption predating the human-kind guard. Normal writes
        // cannot create this state; the old token/login rejection still matters.
        store.connection.lock().unwrap().execute_batch("DROP TRIGGER principal_identity_access_preserve_human_kind;
            DELETE FROM principal_identity_access WHERE principal_id='legacy-service';
            UPDATE principals SET role='user',self_service_enabled=0,kind='service_account' WHERE principal_id='legacy-service';").unwrap();
        assert_eq!(
            store.active_admin_principal_count().unwrap(),
            0,
            "a legacy admin-role row cannot make a noninteractive principal count as an admin"
        );
        assert!(matches!(
            store.unlock_local_password("legacy-service", "admin"),
            Err(ManagedStoreError::InputInvalid(message))
                if message == "operation is only available to interactive user principals"
        ));
        assert!(matches!(
            store.disable_local_password("legacy-service", "admin"),
            Err(ManagedStoreError::InputInvalid(message))
                if message == "operation is only available to interactive user principals"
        ));

        assert!(matches!(
            store.verify_local_password(
                &password_hasher,
                LocalPasswordVerifyRequest {
                    principal_id: "legacy-service".to_string(),
                    password: "legacy-service-password".to_string(),
                    source: "203.0.113.10".to_string(),
                    max_failed_attempts: 3,
                    lockout_ttl_seconds: 60,
                },
            ),
            Err(ManagedStoreError::LocalLoginFailed)
        ));
        assert!(matches!(
            store.resolve_browser_session(&token_hasher, &session.token),
            Err(ManagedStoreError::BrokerTokenClassDenied)
        ));
        assert!(matches!(
            store.resolve_broker_token(&token_hasher, &management.token),
            Err(ManagedStoreError::BrokerTokenClassDenied)
        ));
        assert!(
            store
                .broker_token(&management.record.token_id)
                .unwrap()
                .last_used_at
                .is_none(),
            "kind-denied management tokens must not record successful use"
        );
        let callback_now = normalized_now_string();
        assert!(matches!(
            store
                .complete_oidc_login(
                    &token_hasher,
                    test_oidc_completion_request(
                        1,
                        oidc_provider.config_generation,
                        TEST_OIDC_USER,
                        "legacy-service",
                        &[],
                        &callback_now,
                    ),
                )
                .unwrap(),
            OidcCompletionOutcome::Denied { reason }
                if reason == "principal_not_interactive"
        ));
        assert!(matches!(
            store.issue_browser_session(
                &token_hasher,
                BrowserSessionIssueRequest {
                    principal_id: "legacy-service".to_string(),
                    login_method: "local_password".to_string(),
                    login_method_id: Some(method.login_method_id),
                    ttl_seconds: 3_600,
                    password_change_required: false,
                    created_by: "admin".to_string(),
                },
            ),
            Err(ManagedStoreError::InputInvalid(_))
        ));
    }

    #[test]
    fn initial_admin_bootstrap_creates_forced_reset_admin_login() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let password_hasher = local_password_hasher_for_test(21);
        let token_hasher = broker_token_hasher_for_test(22);

        let principal = store
            .bootstrap_initial_admin(
                &password_hasher,
                InitialAdminBootstrapRequest {
                    principal_id: "admin".to_string(),
                    password: "initial-admin-password".to_string(),
                    min_password_length: 8,
                },
            )
            .unwrap();

        assert_eq!(principal.principal_id, "admin");
        assert_eq!(principal.role, PrincipalRole::Admin);
        let identity_access = store.identity_access("admin").unwrap();
        assert!(!identity_access.paused);
        assert_eq!(identity_access.version, 1);
        assert_eq!(identity_access.updated_by, "system:initial_admin");
        assert_eq!(store.principal_count().unwrap(), 1);
        assert_eq!(store.active_admin_principal_count().unwrap(), 1);

        let verified = store
            .verify_local_password(
                &password_hasher,
                LocalPasswordVerifyRequest {
                    principal_id: "admin".to_string(),
                    password: "initial-admin-password".to_string(),
                    source: "203.0.113.10".to_string(),
                    max_failed_attempts: 3,
                    lockout_ttl_seconds: 60,
                },
            )
            .unwrap();
        assert!(verified.password_change_required);
        assert_eq!(verified.role, PrincipalRole::Admin);
        let issued = store
            .issue_browser_session(
                &token_hasher,
                BrowserSessionIssueRequest {
                    principal_id: "admin".to_string(),
                    login_method: "local_password".to_string(),
                    login_method_id: Some(verified.login_method_id),
                    ttl_seconds: 3600,
                    password_change_required: verified.password_change_required,
                    created_by: "admin".to_string(),
                },
            )
            .unwrap();
        let session = store
            .resolve_browser_session(&token_hasher, &issued.token)
            .unwrap();
        assert_eq!(session.role, PrincipalRole::Admin);
        assert!(session.password_change_required);
    }

    #[test]
    fn last_active_admin_guards_disable_role_and_local_password() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        create_alice(&store);
        store
            .patch_principal_access(crate::PrincipalAccessPatchRequest {
                principal_id: ("alice").into(),
                role: Some(crate::PrincipalRole::Admin),
                self_service_enabled: None,
                actor: ("admin").into(),
            })
            .unwrap();
        let password_hasher = local_password_hasher_for_test(23);
        store
            .enable_local_password(
                &password_hasher,
                LocalPasswordWriteRequest {
                    principal_id: "alice".to_string(),
                    password: "alice-admin-password".to_string(),
                    min_password_length: 8,
                    password_change_required: false,
                    actor: "admin".to_string(),
                },
            )
            .unwrap();

        assert!(matches!(
            store.set_principal_enabled("alice", false).unwrap_err(),
            ManagedStoreError::InputInvalid(_)
        ));
        assert!(matches!(
            store
                .patch_principal_access(crate::PrincipalAccessPatchRequest {
                    principal_id: ("alice").into(),
                    role: Some(crate::PrincipalRole::User),
                    self_service_enabled: None,
                    actor: "test".into()
                })
                .unwrap_err(),
            ManagedStoreError::InputInvalid(_)
        ));
        assert!(matches!(
            store.disable_local_password("alice", "admin").unwrap_err(),
            ManagedStoreError::InputInvalid(_)
        ));

        store
            .create_principal(PrincipalWriteRequest {
                role: crate::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "bob".to_string(),
                kind: "user".to_string(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".to_string(),
            })
            .unwrap();
        store
            .patch_principal_access(crate::PrincipalAccessPatchRequest {
                principal_id: ("bob").into(),
                role: Some(crate::PrincipalRole::Admin),
                self_service_enabled: None,
                actor: ("alice").into(),
            })
            .unwrap();

        store.set_principal_enabled("alice", false).unwrap();
        assert_eq!(store.principal("alice").unwrap().status, "disabled");
        assert_eq!(store.active_admin_principal_count().unwrap(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn managed_store_creates_database_owner_only() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path().join("store");
        let path = dir.join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        create_alice(&store);

        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&path), 0o600);
        for sidecar in sqlite_sidecar_paths(&path) {
            if sidecar.exists() {
                assert_eq!(mode(&sidecar), 0o600);
            }
        }
    }

    // Permission enforcement never opens an existing store file: closing any
    // descriptor for the database or a sidecar would release the POSIX locks
    // the live connections of this process hold. `lock_probe` reads those
    // locks from a separate process.

    #[cfg(unix)]
    #[test]
    fn managed_store_startup_open_keeps_its_sqlite_locks() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let config = store_config(&path);
        let created = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
        create_alice(&created);
        crate::sqlite_support::lock_probe::assert_sqlite_locks_held(&path, "creating the store");
        drop(created);

        // A restart opens the existing WAL-mode store.
        let restarted = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
        crate::sqlite_support::lock_probe::assert_sqlite_locks_held(
            &path,
            "reopening the store at startup",
        );
        assert_eq!(restarted.principal("alice").unwrap().principal_id, "alice");
    }

    #[cfg(unix)]
    #[test]
    fn managed_store_reload_open_keeps_the_sqlite_locks_of_the_live_store() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let config = store_config(&path);
        let live = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
        create_alice(&live);
        crate::sqlite_support::lock_probe::assert_sqlite_locks_held(&path, "opening the store");
        let files = std::iter::once(path.clone())
            .chain(sqlite_sidecar_paths(&path))
            .collect::<Vec<_>>();
        for file in &files {
            fs::set_permissions(file, fs::Permissions::from_mode(0o644)).unwrap();
        }

        let reloaded = ManagedStore::open(&config, ManagedStoreOpenMode::Reload).unwrap();

        for file in &files {
            assert_eq!(mode(file), 0o600, "{}", file.display());
        }
        crate::sqlite_support::lock_probe::assert_sqlite_locks_held(
            &path,
            "a reload-mode open while the first store is live",
        );
        reloaded
            .create_principal(PrincipalWriteRequest {
                role: crate::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "bob".to_string(),
                kind: "user".to_string(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".to_string(),
            })
            .unwrap();
        assert_eq!(live.principal("bob").unwrap().principal_id, "bob");
        assert_eq!(reloaded.principal("alice").unwrap().principal_id, "alice");
        crate::sqlite_support::lock_probe::assert_sqlite_locks_held(
            &path,
            "writes and reads on both stores",
        );
    }

    #[cfg(unix)]
    #[test]
    fn managed_store_reload_rejects_symlink_database_before_sqlite_open() {
        let temp = TempDir::new().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let target = temp.path().join("target.sqlite");
        let link = temp.path().join("store.sqlite");
        fs::write(&target, b"not a sqlite database").unwrap();
        symlink(&target, &link).unwrap();

        let error =
            ManagedStore::open(&store_config(&link), ManagedStoreOpenMode::Reload).unwrap_err();

        assert!(matches!(
            error,
            ManagedStoreError::Unavailable(message)
                if message.contains("failed to restrict managed store file")
        ));
        assert!(!temp.path().join("target.sqlite-wal").exists());
        assert!(!temp.path().join("store.sqlite-wal").exists());
    }

    #[cfg(unix)]
    #[test]
    fn managed_store_reload_rejects_hard_linked_database_before_sqlite_open() {
        let temp = TempDir::new().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let target = temp.path().join("target.sqlite");
        let link = temp.path().join("store.sqlite");
        fs::write(&target, b"not a sqlite database").unwrap();
        fs::hard_link(&target, &link).unwrap();

        let error =
            ManagedStore::open(&store_config(&link), ManagedStoreOpenMode::Reload).unwrap_err();

        assert!(matches!(
            error,
            ManagedStoreError::Unavailable(message)
                if message.contains("sensitive file must not have multiple hard links")
        ));
        assert!(!temp.path().join("target.sqlite-wal").exists());
        assert!(!temp.path().join("store.sqlite-wal").exists());
    }

    #[cfg(unix)]
    #[test]
    fn managed_store_reload_rejects_symlink_sidecar_before_sqlite_open() {
        let temp = TempDir::new().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("store.sqlite");
        let sidecar_target = temp.path().join("target.wal");
        fs::write(&path, b"not a sqlite database").unwrap();
        fs::write(&sidecar_target, b"sidecar target").unwrap();
        symlink(&sidecar_target, temp.path().join("store.sqlite-wal")).unwrap();

        let error =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Reload).unwrap_err();

        assert!(matches!(
            error,
            ManagedStoreError::Unavailable(message)
                if message.contains("failed to restrict managed store sidecar")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn managed_store_reload_rejects_hard_linked_sidecar_before_sqlite_open() {
        let temp = TempDir::new().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("store.sqlite");
        let sidecar_target = temp.path().join("target.wal");
        fs::write(&path, b"not a sqlite database").unwrap();
        fs::write(&sidecar_target, b"sidecar target").unwrap();
        fs::hard_link(&sidecar_target, temp.path().join("store.sqlite-wal")).unwrap();

        let error =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Reload).unwrap_err();

        assert!(matches!(
            error,
            ManagedStoreError::Unavailable(message)
                if message.contains("sensitive file must not have multiple hard links")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn managed_store_without_auto_migrate_rejects_non_private_parent_before_open() {
        let temp = TempDir::new().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let path = temp.path().join("store.sqlite");
        fs::write(&path, b"not a sqlite database").unwrap();

        let error = ManagedStore::open(
            &raw_store_config(&path, false),
            ManagedStoreOpenMode::Startup,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ManagedStoreError::Unavailable(message)
                if message.contains("failed to validate managed store directory")
                    && message.contains("owner-only")
        ));
        assert!(!temp.path().join("store.sqlite-wal").exists());
    }

    #[test]
    fn reload_rejects_unmigrated_database() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        Connection::open(&path).unwrap();
        let mut config = store_config(&path);
        config.auto_migrate = false;
        let error = ManagedStore::open(&config, ManagedStoreOpenMode::Reload).unwrap_err();
        assert!(matches!(error, ManagedStoreError::MigrationRequired));
    }

    #[test]
    fn encrypts_decrypts_and_rejects_wrong_aad() {
        let ring = key_ring("k1");
        let aad = CredentialAad {
            credential_id: "credential".to_string(),
            owner_kind: "user".to_string(),
            owner_principal_id: "alice".to_string(),
            service: "jira".to_string(),
            name: "default".to_string(),
            profile: "jira-cloud-api-token".to_string(),
            credential_kind: "basic_api_token".to_string(),
            secret_backend: SQLITE_ENCRYPTED_BACKEND.to_string(),
            secret_ref: "sqlite:00000000-0000-4000-8000-000000000001".to_string(),
            material_version: "00000000-0000-4000-8000-000000000002".to_string(),
            key_id: "k1".to_string(),
        };
        let secret = json!({"username":"alice@example.com","token":"pat"});
        let encrypted = ring.encrypt(&secret, &aad).unwrap();
        assert_ne!(encrypted.ciphertext, serde_json::to_vec(&secret).unwrap());
        let decrypted = ring
            .decrypt(
                &encrypted.key_id,
                &encrypted.nonce,
                &encrypted.ciphertext,
                &aad,
            )
            .unwrap();
        assert_eq!(decrypted, secret);
        for wrong_aad in [
            CredentialAad {
                credential_id: "other-credential".to_string(),
                ..aad.clone()
            },
            CredentialAad {
                owner_kind: "service_account".to_string(),
                ..aad.clone()
            },
            CredentialAad {
                owner_principal_id: "bob".to_string(),
                ..aad.clone()
            },
            CredentialAad {
                service: "confluence".to_string(),
                ..aad.clone()
            },
            CredentialAad {
                name: "other".to_string(),
                ..aad.clone()
            },
            CredentialAad {
                profile: "other-profile".to_string(),
                ..aad.clone()
            },
            CredentialAad {
                credential_kind: "bearer_token".to_string(),
                ..aad.clone()
            },
            CredentialAad {
                secret_backend: "other_backend".to_string(),
                ..aad.clone()
            },
            CredentialAad {
                secret_ref: "sqlite:00000000-0000-4000-8000-000000000003".to_string(),
                ..aad.clone()
            },
            CredentialAad {
                material_version: "00000000-0000-4000-8000-000000000004".to_string(),
                ..aad.clone()
            },
            CredentialAad {
                key_id: "other-key".to_string(),
                ..aad.clone()
            },
        ] {
            let error = ring
                .decrypt(
                    &encrypted.key_id,
                    &encrypted.nonce,
                    &encrypted.ciphertext,
                    &wrong_aad,
                )
                .unwrap_err();
            assert!(matches!(error, ManagedStoreError::CredentialDecryptFailed));
        }
    }

    #[test]
    fn token_hashes_do_not_store_raw_tokens() {
        let temp = TempDir::new().unwrap();
        let key_path = temp.path().join("hash-key");
        fs::write(&key_path, key(9)).unwrap();
        let hasher = BrokerTokenHasher::load(&BrokerTokensConfig {
            hash_key_ref: format!("file:{}", key_path.display()),
            default_agent_invoke_ttl: None,
            default_user_manage_ttl: None,
            default_admin_ttl: None,
            max_self_issued_agent_invoke_ttl: None,
            ..Default::default()
        })
        .unwrap();
        let token = generate_broker_token(&BrokerTokenClass::AgentInvoke);
        let hash = hasher.hash(&token).unwrap();
        assert_ne!(hash, token);
        assert_eq!(hash, hasher.hash(&token).unwrap());
    }

    #[test]
    fn broker_token_issue_can_require_active_principal_role() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let key_path = temp.path().join("hash-key");
        fs::write(&key_path, key(9)).unwrap();
        let hasher = BrokerTokenHasher::load(&BrokerTokensConfig {
            hash_key_ref: format!("file:{}", key_path.display()),
            default_agent_invoke_ttl: None,
            default_user_manage_ttl: None,
            default_admin_ttl: None,
            max_self_issued_agent_invoke_ttl: None,
            ..Default::default()
        })
        .unwrap();
        store
            .create_or_update_principal(PrincipalWriteRequest {
                role: crate::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "alice".to_string(),
                kind: "user".to_string(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".to_string(),
            })
            .unwrap();
        let request = BrokerTokenIssueRequest {
            principal_id: "alice".to_string(),
            name: "admin".to_string(),
            token_class: BrokerTokenClass::Admin,
            scopes: json!({}),
            expires_at: None,
            created_by: "admin".to_string(),
        };
        assert!(matches!(
            store
                .issue_broker_token(&hasher, request.clone())
                .unwrap_err(),
            ManagedStoreError::InputInvalid(_)
        ));
        store
            .patch_principal_access(crate::PrincipalAccessPatchRequest {
                principal_id: ("alice").into(),
                role: Some(crate::PrincipalRole::Admin),
                self_service_enabled: None,
                actor: ("admin").into(),
            })
            .unwrap();
        let issued = store.issue_broker_token(&hasher, request).unwrap();
        assert_eq!(issued.record.token_class, BrokerTokenClass::Admin);

        store
            .create_or_update_principal(PrincipalWriteRequest {
                role: crate::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "bob".to_string(),
                kind: "user".to_string(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".to_string(),
            })
            .unwrap();
        store
            .patch_principal(PrincipalPatchRequest {
                principal_id: "bob".to_string(),
                display_name: None,
                email: None,
                status: Some("disabled".to_string()),
            })
            .unwrap();
        assert!(matches!(
            store
                .issue_broker_token(
                    &hasher,
                    BrokerTokenIssueRequest {
                        principal_id: "bob".to_string(),
                        name: "admin".to_string(),
                        token_class: BrokerTokenClass::Admin,
                        scopes: json!({}),
                        expires_at: None,
                        created_by: "admin".to_string(),
                    }
                )
                .unwrap_err(),
            ManagedStoreError::PrincipalDisabled
        ));
    }

    #[test]
    fn agent_token_issuance_validates_class_specific_caveats_before_insert() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let hasher = broker_token_hasher_for_test(41);
        create_alice(&store);

        for scopes in [
            json!({}),
            json!({"allowedServices": ["jira"]}),
            json!({"allowedExecutionContexts": null}),
            json!({"allowedExecutionContexts": []}),
            json!({"allowedExecutionContexts": ["External"]}),
            json!({"allowedExecutionContexts": ["default", "default"]}),
            json!({"allowedExecutionContexts": ["default"], "unknownCaveat": true}),
        ] {
            let error = store
                .issue_broker_token(
                    &hasher,
                    BrokerTokenIssueRequest {
                        principal_id: "alice".to_string(),
                        name: "invalid agent".to_string(),
                        token_class: BrokerTokenClass::AgentInvoke,
                        scopes,
                        expires_at: None,
                        created_by: "admin".to_string(),
                    },
                )
                .unwrap_err();
            assert!(matches!(error, ManagedStoreError::InputInvalid(_)));
        }

        let administrative = store
            .issue_broker_token(
                &hasher,
                BrokerTokenIssueRequest {
                    principal_id: "alice".to_string(),
                    name: "multi-context agent".to_string(),
                    token_class: BrokerTokenClass::AgentInvoke,
                    scopes: json!({
                        "allowedServices": ["jira"],
                        "allowedExecutionContexts": ["workstation", "external"]
                    }),
                    expires_at: None,
                    created_by: "admin".to_string(),
                },
            )
            .unwrap();
        assert_eq!(
            administrative.record.scopes,
            json!({
                "allowedServices": ["jira"],
                "allowedExecutionContexts": ["workstation", "external"]
            })
        );

        for scopes in [json!({}), json!({"allowedExecutionContexts": []})] {
            let error = store
                .issue_self_agent_token(
                    &hasher,
                    SelfAgentTokenIssueRequest {
                        principal_id: "alice".to_string(),
                        name: "invalid self token".to_string(),
                        scopes,
                        expires_at: None,
                        created_by: "alice".to_string(),
                    },
                )
                .unwrap_err();
            assert!(matches!(error, ManagedStoreError::InputInvalid(_)));
        }
        let self_issued = store
            .issue_self_agent_token(
                &hasher,
                SelfAgentTokenIssueRequest {
                    principal_id: "alice".to_string(),
                    name: "multi-context self token".to_string(),
                    scopes: json!({
                        "allowedExecutionContexts": ["workstation", "external"]
                    }),
                    expires_at: None,
                    created_by: "alice".to_string(),
                },
            )
            .unwrap();
        assert_eq!(
            self_issued.record.scopes,
            json!({"allowedExecutionContexts": ["workstation", "external"]})
        );

        let management = store
            .issue_broker_token(
                &hasher,
                BrokerTokenIssueRequest {
                    principal_id: "alice".to_string(),
                    name: "management token".to_string(),
                    token_class: BrokerTokenClass::UserManage,
                    scopes: json!({"existingManagementSemantics": null}),
                    expires_at: None,
                    created_by: "admin".to_string(),
                },
            )
            .unwrap();
        assert_eq!(
            management.record.scopes,
            json!({"existingManagementSemantics": null})
        );
    }

    #[test]
    fn agent_token_pause_resume_is_idempotent_and_preserves_the_token() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let hasher = broker_token_hasher_for_test(43);
        create_alice(&store);
        let issued = store
            .issue_self_agent_token(
                &hasher,
                SelfAgentTokenIssueRequest {
                    principal_id: "alice".to_string(),
                    name: "supervised agent".to_string(),
                    scopes: json!({"allowedExecutionContexts": ["default"]}),
                    expires_at: None,
                    created_by: "alice".to_string(),
                },
            )
            .unwrap();

        let paused = store
            .pause_principal_agent_token(
                "alice",
                &issued.record.token_id,
                "alice",
                AgentTokenManagementPurpose::Personal,
            )
            .unwrap();
        assert!(paused.paused_at.is_some());
        assert_eq!(paused.paused_by.as_deref(), Some("alice"));
        assert_eq!(paused.last_used_at, None);
        assert!(matches!(
            store.resolve_broker_token(&hasher, &issued.token),
            Err(ManagedStoreError::BrokerTokenPaused)
        ));
        assert_eq!(
            store
                .broker_token(&issued.record.token_id)
                .unwrap()
                .last_used_at,
            None
        );

        let paused_again = store
            .pause_broker_token(&issued.record.token_id, "admin")
            .unwrap();
        assert_eq!(paused_again.paused_at, paused.paused_at);
        assert_eq!(paused_again.paused_by, paused.paused_by);

        let resumed = store
            .resume_principal_agent_token(
                "alice",
                &issued.record.token_id,
                "alice",
                AgentTokenManagementPurpose::Personal,
            )
            .unwrap();
        assert_eq!(resumed.paused_at, None);
        assert_eq!(resumed.paused_by, None);
        let resumed_again = store
            .resume_broker_token(&issued.record.token_id, "admin")
            .unwrap();
        assert_eq!(resumed_again.paused_at, None);
        assert!(store.resolve_broker_token(&hasher, &issued.token).is_ok());
    }

    #[test]
    fn agent_token_pause_conceals_scope_and_rejects_terminal_or_other_classes() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let hasher = broker_token_hasher_for_test(44);
        create_alice(&store);
        store
            .create_or_update_principal(PrincipalWriteRequest {
                role: crate::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "bob".to_string(),
                kind: "user".to_string(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".to_string(),
            })
            .unwrap();
        let issued = store
            .issue_broker_token(
                &hasher,
                BrokerTokenIssueRequest {
                    principal_id: "alice".to_string(),
                    name: "agent".to_string(),
                    token_class: BrokerTokenClass::AgentInvoke,
                    scopes: json!({"allowedExecutionContexts": ["default"]}),
                    expires_at: None,
                    created_by: "admin".to_string(),
                },
            )
            .unwrap();
        assert!(matches!(
            store.pause_principal_agent_token(
                "bob",
                &issued.record.token_id,
                "bob",
                AgentTokenManagementPurpose::Personal
            ),
            Err(ManagedStoreError::BrokerTokenNotFound)
        ));
        store
            .revoke_broker_token(&issued.record.token_id, "admin")
            .unwrap();
        assert!(matches!(
            store.pause_principal_agent_token(
                "bob",
                &issued.record.token_id,
                "bob",
                AgentTokenManagementPurpose::Personal
            ),
            Err(ManagedStoreError::BrokerTokenNotFound)
        ));
        assert!(matches!(
            store.pause_principal_agent_token(
                "alice",
                &issued.record.token_id,
                "alice",
                AgentTokenManagementPurpose::Personal
            ),
            Err(ManagedStoreError::BrokerTokenStateConflict)
        ));

        let management = store
            .issue_broker_token(
                &hasher,
                BrokerTokenIssueRequest {
                    principal_id: "alice".to_string(),
                    name: "management".to_string(),
                    token_class: BrokerTokenClass::UserManage,
                    scopes: json!({}),
                    expires_at: None,
                    created_by: "admin".to_string(),
                },
            )
            .unwrap();
        assert!(matches!(
            store.pause_broker_token(&management.record.token_id, "admin"),
            Err(ManagedStoreError::BrokerTokenNotFound)
        ));

        let expired = store
            .issue_broker_token(
                &hasher,
                BrokerTokenIssueRequest {
                    principal_id: "alice".to_string(),
                    name: "expired".to_string(),
                    token_class: BrokerTokenClass::AgentInvoke,
                    scopes: json!({"allowedExecutionContexts": ["default"]}),
                    expires_at: Some("2020-01-01T00:00:00Z".to_string()),
                    created_by: "admin".to_string(),
                },
            )
            .unwrap();
        assert!(matches!(
            store.resume_broker_token(&expired.record.token_id, "admin"),
            Err(ManagedStoreError::BrokerTokenStateConflict)
        ));
    }

    #[test]
    fn concurrent_resume_and_revoke_leave_the_token_revoked() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let issuing_store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let hasher = broker_token_hasher_for_test(45);
        create_alice(&issuing_store);
        let issued = issuing_store
            .issue_broker_token(
                &hasher,
                BrokerTokenIssueRequest {
                    principal_id: "alice".to_string(),
                    name: "race".to_string(),
                    token_class: BrokerTokenClass::AgentInvoke,
                    scopes: json!({"allowedExecutionContexts": ["default"]}),
                    expires_at: None,
                    created_by: "admin".to_string(),
                },
            )
            .unwrap();
        issuing_store
            .pause_broker_token(&issued.record.token_id, "admin")
            .unwrap();
        drop(issuing_store);

        let resume_store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let revoke_store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let resume_barrier = barrier.clone();
        let resume_token_id = issued.record.token_id.clone();
        let resume = thread::spawn(move || {
            resume_barrier.wait();
            resume_store.resume_broker_token(&resume_token_id, "admin")
        });
        let revoke_token_id = issued.record.token_id.clone();
        let revoke = thread::spawn(move || {
            barrier.wait();
            revoke_store.revoke_broker_token(&revoke_token_id, "admin")
        });
        let resume_result = resume.join().unwrap();
        revoke.join().unwrap().unwrap();

        let final_store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let record = final_store.broker_token(&issued.record.token_id).unwrap();
        assert!(record.revoked_at.is_some());
        assert!(matches!(
            final_store.resolve_broker_token(&hasher, &issued.token),
            Err(ManagedStoreError::BrokerTokenRevoked)
        ));
        if let Err(error) = resume_result {
            assert!(matches!(error, ManagedStoreError::BrokerTokenStateConflict));
        }
    }

    #[test]
    fn malformed_broker_token_pause_metadata_fails_closed() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let hasher = broker_token_hasher_for_test(46);
        create_alice(&store);
        let issued = store
            .issue_broker_token(
                &hasher,
                BrokerTokenIssueRequest {
                    principal_id: "alice".to_string(),
                    name: "agent".to_string(),
                    token_class: BrokerTokenClass::AgentInvoke,
                    scopes: json!({"allowedExecutionContexts": ["default"]}),
                    expires_at: None,
                    created_by: "admin".to_string(),
                },
            )
            .unwrap();
        {
            let conn = store.connection.lock().unwrap();
            conn.execute(
                "UPDATE broker_tokens SET paused_at = 'not-a-timestamp', paused_by = 'admin'
                 WHERE token_id = ?1",
                params![issued.record.token_id],
            )
            .unwrap();
        }
        assert!(matches!(
            store.resolve_broker_token(&hasher, &issued.token),
            Err(ManagedStoreError::Unavailable(_))
        ));
    }

    #[test]
    fn stored_agent_token_rows_reject_obsolete_and_corrupt_caveats() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let hasher = broker_token_hasher_for_test(42);
        create_alice(&store);
        let issued = store
            .issue_broker_token(
                &hasher,
                BrokerTokenIssueRequest {
                    principal_id: "alice".to_string(),
                    name: "agent".to_string(),
                    token_class: BrokerTokenClass::AgentInvoke,
                    scopes: json!({"allowedExecutionContexts": ["default"]}),
                    expires_at: None,
                    created_by: "admin".to_string(),
                },
            )
            .unwrap();

        {
            let conn = store.connection.lock().unwrap();
            conn.execute(
                "UPDATE broker_tokens SET scopes_json = ?2 WHERE token_id = ?1",
                params![issued.record.token_id, r#"{"allowedServices":["jira"]}"#],
            )
            .unwrap();
        }
        let legacy = store.resolve_broker_token(&hasher, &issued.token).unwrap();
        assert!(AgentInvokeTokenCaveats::parse_stored(&legacy.scopes).is_err());

        {
            let conn = store.connection.lock().unwrap();
            conn.execute(
                "UPDATE broker_tokens SET scopes_json = ?2 WHERE token_id = ?1",
                params![issued.record.token_id, r#"{"allowedExecutionContexts":[]}"#],
            )
            .unwrap();
        }
        let corrupt = store.resolve_broker_token(&hasher, &issued.token).unwrap();
        assert!(AgentInvokeTokenCaveats::parse_stored(&corrupt.scopes).is_err());
    }

    #[test]
    fn broker_token_resolution_rejects_corrupt_class_and_scopes_rows() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let key_path = temp.path().join("hash-key");
        fs::write(&key_path, key(9)).unwrap();
        let hasher = BrokerTokenHasher::load(&BrokerTokensConfig {
            hash_key_ref: format!("file:{}", key_path.display()),
            default_agent_invoke_ttl: None,
            default_user_manage_ttl: None,
            default_admin_ttl: None,
            max_self_issued_agent_invoke_ttl: None,
            ..Default::default()
        })
        .unwrap();
        store
            .create_or_update_principal(PrincipalWriteRequest {
                role: crate::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "alice".to_string(),
                kind: "user".to_string(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".to_string(),
            })
            .unwrap();
        let issued = store
            .issue_broker_token(
                &hasher,
                BrokerTokenIssueRequest {
                    principal_id: "alice".to_string(),
                    name: "agent".to_string(),
                    token_class: BrokerTokenClass::AgentInvoke,
                    scopes: json!({
                        "allowedServices": ["jira"],
                        "allowedExecutionContexts": ["default"]
                    }),
                    expires_at: None,
                    created_by: "admin".to_string(),
                },
            )
            .unwrap();
        {
            let conn = store.connection.lock().unwrap();
            conn.execute(
                "UPDATE broker_tokens SET scopes_json = ?2 WHERE token_id = ?1",
                params![issued.record.token_id, "{not json"],
            )
            .unwrap();
        }
        assert!(matches!(
            store
                .resolve_broker_token(&hasher, &issued.token)
                .unwrap_err(),
            ManagedStoreError::Unavailable(_)
        ));

        let issued = store
            .issue_broker_token(
                &hasher,
                BrokerTokenIssueRequest {
                    principal_id: "alice".to_string(),
                    name: "agent2".to_string(),
                    token_class: BrokerTokenClass::AgentInvoke,
                    scopes: json!({"allowedExecutionContexts": ["default"]}),
                    expires_at: None,
                    created_by: "admin".to_string(),
                },
            )
            .unwrap();
        {
            let conn = store.connection.lock().unwrap();
            conn.execute_batch("PRAGMA ignore_check_constraints = ON;")
                .unwrap();
            conn.execute(
                "UPDATE broker_tokens SET token_class = 'god_mode' WHERE token_id = ?1",
                params![issued.record.token_id],
            )
            .unwrap();
            conn.execute_batch("PRAGMA ignore_check_constraints = OFF;")
                .unwrap();
        }
        assert!(matches!(
            store
                .resolve_broker_token(&hasher, &issued.token)
                .unwrap_err(),
            ManagedStoreError::Unavailable(_)
        ));
    }

    #[test]
    fn rejects_malformed_expiry_and_nested_secret_metadata() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let ring = key_ring("k1");
        store
            .create_or_update_principal(PrincipalWriteRequest {
                role: crate::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "alice".to_string(),
                kind: "user".to_string(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".to_string(),
            })
            .unwrap();

        let bad_right = store.grant_right(RightGrantRequest {
            principal_id: "alice".to_string(),
            right: "credentials:self:write".to_string(),
            service: Some("jira".to_string()),
            credential_name: Some("default".to_string()),
            resource_scope_json: None,
            created_by: "admin".to_string(),
            expires_at: Some("not-a-time".to_string()),
            reason: None,
        });
        assert!(matches!(
            bad_right.unwrap_err(),
            ManagedStoreError::InputInvalid(_)
        ));

        let bad_metadata = store.upsert_user_credential(
            &ring,
            CredentialWriteRequest {
                owner_principal_id: "alice".to_string(),
                service: "jira".to_string(),
                name: "default".to_string(),
                profile: "jira-cloud-api-token".to_string(),
                credential_kind: "basic_api_token".to_string(),
                secret: json!({"username":"alice@example.com","token":"pat"}),
                metadata: json!({"source":{"token":"must-not-appear"}}),
                actor: "alice".to_string(),
            },
            crate::CredentialManagementPurpose::Administrative,
        );
        assert!(matches!(
            bad_metadata.unwrap_err(),
            ManagedStoreError::InputInvalid(_)
        ));
    }

    #[test]
    fn stores_and_resolves_user_credential() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let ring = key_ring("k1");
        store
            .create_or_update_principal(PrincipalWriteRequest {
                role: crate::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "alice".to_string(),
                kind: "user".to_string(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".to_string(),
            })
            .unwrap();
        let metadata = store
            .upsert_user_credential(
                &ring,
                CredentialWriteRequest {
                    owner_principal_id: "alice".to_string(),
                    service: "jira".to_string(),
                    name: "default".to_string(),
                    profile: "jira-cloud-api-token".to_string(),
                    credential_kind: "basic_api_token".to_string(),
                    secret: json!({"username":"alice@example.com","token":"pat"}),
                    metadata: json!({"displayName":"Jira"}),
                    actor: "alice".to_string(),
                },
                crate::CredentialManagementPurpose::Administrative,
            )
            .unwrap();
        assert_eq!(
            metadata.verification_status.as_deref(),
            Some("not_verified")
        );
        assert!(metadata.last_verified_at.is_none());
        assert!(metadata.last_verification_attempt_at.is_none());
        assert!(metadata.last_verification_error_code.is_none());
        let credential = store
            .resolve_user_credential(&ring, "alice", "jira", "default", "jira-cloud-api-token")
            .unwrap();
        assert_eq!(credential.kind().as_str(), "basic_api_token");
        assert_eq!(credential, basic_credential("alice@example.com", "pat"));
        let verified = store
            .verify_user_credential(
                &ring,
                "alice",
                "jira",
                "default",
                "jira-cloud-api-token",
                crate::CredentialManagementPurpose::Administrative,
            )
            .unwrap();
        assert_eq!(
            verified.verification_status.as_deref(),
            Some("local_verified")
        );
        assert!(verified.last_verified_at.is_some());
        assert!(verified.last_verification_attempt_at.is_some());
        assert!(verified.last_verification_error_code.is_none());
        let upstream_candidate = store
            .resolve_user_credential_for_verification(
                &ring,
                "alice",
                "jira",
                "default",
                "jira-cloud-api-token",
                crate::CredentialManagementPurpose::Administrative,
            )
            .unwrap();
        let upstream_verified = store
            .mark_user_credential_verified_if_current(
                &upstream_candidate.target,
                "upstream_verified",
                crate::CredentialManagementPurpose::Administrative,
            )
            .unwrap();
        assert_eq!(
            upstream_verified.verification_status.as_deref(),
            Some("upstream_verified")
        );
        assert!(upstream_verified.last_verified_at.is_some());
        assert!(upstream_verified.last_verification_attempt_at.is_some());
        assert!(upstream_verified.last_verification_error_code.is_none());
    }

    #[test]
    fn failed_credential_verification_records_attempt_without_success_time() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let ring = key_ring("k1");
        create_alice(&store);
        put_alice_jira_credential(&store, &ring, "pat");

        let candidate = store
            .resolve_user_credential_for_verification(
                &ring,
                "alice",
                "jira",
                "default",
                "jira-cloud-api-token",
                crate::CredentialManagementPurpose::Administrative,
            )
            .unwrap();
        let failed = store
            .mark_user_credential_verification_failed_if_current(
                &candidate.target,
                ReasonCode::UpstreamUnauthorized.as_str(),
                crate::CredentialManagementPurpose::Administrative,
            )
            .unwrap();

        assert_eq!(
            failed.verification_status.as_deref(),
            Some("verification_failed")
        );
        assert!(failed.last_verified_at.is_none());
        assert!(failed.last_verification_attempt_at.is_some());
        assert_eq!(
            failed.last_verification_error_code.as_deref(),
            Some("upstream_unauthorized")
        );

        let verified = store
            .mark_user_credential_verified_if_current(
                &candidate.target,
                "upstream_verified",
                crate::CredentialManagementPurpose::Administrative,
            )
            .unwrap();
        assert_eq!(
            verified.verification_status.as_deref(),
            Some("upstream_verified")
        );
        assert!(verified.last_verified_at.is_some());
        assert!(verified.last_verification_attempt_at.is_some());
        assert!(verified.last_verification_error_code.is_none());
    }

    #[test]
    fn credential_secret_material_is_split_and_deleted_with_metadata() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let ring = key_ring("k1");
        create_alice(&store);
        let metadata = put_alice_jira_credential(&store, &ring, "pat");

        let serialized = serde_json::to_value(&metadata).unwrap();
        assert!(serialized.get("secretBackend").is_none());
        assert!(serialized.get("secretRef").is_none());
        assert!(serialized.get("materialVersion").is_none());
        assert!(serialized.get("keyId").is_none());

        {
            let conn = store.connection.lock().unwrap();
            let credential_columns = table_columns(&conn, "credentials");
            assert!(!credential_columns.contains(&"secret_ciphertext".to_string()));
            assert!(!credential_columns.contains(&"secret_nonce".to_string()));
            assert!(!credential_columns.contains(&"key_id".to_string()));
            let material_count: i64 = conn
                .query_row(
                    "SELECT COUNT(1)
                     FROM credential_secret_material
                     WHERE credential_id = ?1 AND secret_ref = ?2",
                    params![metadata.credential_id, metadata.secret_ref],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(material_count, 1);
        }

        let deleted = store
            .delete_user_credential(
                "alice",
                "jira",
                "default",
                crate::CredentialManagementPurpose::Administrative,
            )
            .unwrap();
        assert_eq!(deleted.credential_id, metadata.credential_id);
        let conn = store.connection.lock().unwrap();
        let material_count: i64 = conn
            .query_row(
                "SELECT COUNT(1) FROM credential_secret_material WHERE credential_id = ?1",
                params![metadata.credential_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(material_count, 0);
    }

    #[test]
    fn updating_secret_changes_material_version_and_preserves_secret_ref() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let ring = key_ring("k1");
        create_alice(&store);
        let first = put_alice_jira_credential(&store, &ring, "old-pat");
        let verified = store
            .verify_user_credential(
                &ring,
                "alice",
                "jira",
                "default",
                "jira-cloud-api-token",
                crate::CredentialManagementPurpose::Administrative,
            )
            .unwrap();
        assert_eq!(
            verified.verification_status.as_deref(),
            Some("local_verified")
        );

        let second = put_alice_jira_credential(&store, &ring, "new-pat");
        assert_eq!(second.credential_id, first.credential_id);
        assert_eq!(second.secret_ref, first.secret_ref);
        assert_ne!(second.material_version, first.material_version);
        assert!(second.last_verified_at.is_none());
        assert_eq!(second.verification_status.as_deref(), Some("not_verified"));
        assert!(second.last_verification_attempt_at.is_none());
        assert!(second.last_verification_error_code.is_none());

        let credential = store
            .resolve_user_credential(&ring, "alice", "jira", "default", "jira-cloud-api-token")
            .unwrap();
        assert_eq!(credential, basic_credential("alice@example.com", "new-pat"));
    }

    #[test]
    fn upsert_rejects_material_ref_owned_by_another_credential() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let ring = key_ring("k1");
        create_alice(&store);
        let alice = put_alice_jira_credential(&store, &ring, "alice-pat");
        store
            .create_or_update_principal(PrincipalWriteRequest {
                role: crate::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "bob".to_string(),
                kind: "user".to_string(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".to_string(),
            })
            .unwrap();

        let bob_credential_id = Uuid::new_v4().to_string();
        let now = now_string();
        {
            let conn = store.connection.lock().unwrap();
            conn.execute(
                "INSERT INTO credentials
                 (credential_id, owner_principal_id, owner_kind, service, name, profile,
                  credential_kind, metadata_json, secret_backend, secret_ref, material_version,
                  status, created_at, updated_at, created_by, updated_by)
                 VALUES (?1, 'bob', 'user', 'jira', 'default', 'jira-cloud-api-token',
                         'basic_api_token', '{}', ?2, ?3, ?4, 'active', ?5, ?5, 'admin', 'admin')",
                params![
                    bob_credential_id,
                    SQLITE_ENCRYPTED_BACKEND,
                    alice.secret_ref,
                    Uuid::new_v4().to_string(),
                    now
                ],
            )
            .unwrap();
        }

        let error = store
            .upsert_user_credential(
                &ring,
                CredentialWriteRequest {
                    owner_principal_id: "bob".to_string(),
                    service: "jira".to_string(),
                    name: "default".to_string(),
                    profile: "jira-cloud-api-token".to_string(),
                    credential_kind: "basic_api_token".to_string(),
                    secret: json!({"username":"bob@example.com","token":"bob-pat"}),
                    metadata: json!({}),
                    actor: "bob".to_string(),
                },
                crate::CredentialManagementPurpose::Administrative,
            )
            .unwrap_err();
        assert!(matches!(error, ManagedStoreError::SchemaInvalid(_)));

        let conn = store.connection.lock().unwrap();
        let material_owner: String = conn
            .query_row(
                "SELECT credential_id FROM credential_secret_material WHERE secret_ref = ?1",
                params![alice.secret_ref],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(material_owner, alice.credential_id);
    }

    #[test]
    fn rewrap_preserves_material_version_and_metadata_timestamp() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let ring = key_ring_with_keys("k1", &[("k1", 7), ("k2", 8)]);
        create_alice(&store);
        let before = put_alice_jira_credential(&store, &ring, "pat");
        let verification_candidate = store
            .resolve_user_credential_for_verification(
                &ring,
                "alice",
                "jira",
                "default",
                "jira-cloud-api-token",
                crate::CredentialManagementPurpose::Administrative,
            )
            .unwrap();

        let summary = store
            .rewrap_credentials(&ring, "k1", "k2", "admin")
            .unwrap();
        assert_eq!(summary.rewrapped, 1);
        assert_eq!(summary.conflicts, 0);
        assert_eq!(store.active_credential_key_ids().unwrap(), vec!["k2"]);

        let after = store
            .credential_by_tuple("alice", "jira", "default")
            .unwrap();
        assert_eq!(after.material_version, before.material_version);
        assert_eq!(after.updated_at, before.updated_at);
        assert_eq!(after.updated_by, before.updated_by);
        let credential = store
            .resolve_user_credential(&ring, "alice", "jira", "default", "jira-cloud-api-token")
            .unwrap();
        assert_eq!(credential, basic_credential("alice@example.com", "pat"));
        let verified = store
            .mark_user_credential_verified_if_current(
                &verification_candidate.target,
                "upstream_verified",
                crate::CredentialManagementPurpose::Administrative,
            )
            .unwrap();
        assert_eq!(
            verified.verification_status.as_deref(),
            Some("upstream_verified")
        );
    }

    #[test]
    fn rewrap_counts_conflict_when_material_no_longer_matches_metadata_ref() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let ring = key_ring_with_keys("k1", &[("k1", 7), ("k2", 8)]);
        create_alice(&store);
        let metadata = put_alice_jira_credential(&store, &ring, "pat");
        {
            let conn = store.connection.lock().unwrap();
            conn.execute(
                "UPDATE credentials SET secret_ref = ?2 WHERE credential_id = ?1",
                params![metadata.credential_id, new_sqlite_secret_ref()],
            )
            .unwrap();
        }

        let summary = store
            .rewrap_credentials(&ring, "k1", "k2", "admin")
            .unwrap();
        assert_eq!(summary.rewrapped, 0);
        assert_eq!(summary.conflicts, 1);
        let conn = store.connection.lock().unwrap();
        let key_id: String = conn
            .query_row(
                "SELECT key_id FROM credential_secret_material WHERE secret_ref = ?1",
                params![metadata.secret_ref],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(key_id, "k1");
    }

    #[test]
    fn persisted_secret_material_aad_rejects_metadata_tampering() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let ring = key_ring("k1");
        create_alice(&store);
        let metadata = put_alice_jira_credential(&store, &ring, "pat");

        {
            let conn = store.connection.lock().unwrap();
            conn.execute(
                "UPDATE credentials SET material_version = ?2 WHERE credential_id = ?1",
                params![metadata.credential_id, Uuid::new_v4().to_string()],
            )
            .unwrap();
        }
        let error = store
            .resolve_user_credential(&ring, "alice", "jira", "default", "jira-cloud-api-token")
            .unwrap_err();
        assert!(matches!(error, ManagedStoreError::CredentialDecryptFailed));

        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        create_alice(&store);
        let metadata = put_alice_jira_credential(&store, &ring, "pat");
        let replacement_ref = new_sqlite_secret_ref();
        {
            let conn = store.connection.lock().unwrap();
            conn.execute(
                "UPDATE credential_secret_material SET secret_ref = ?2 WHERE secret_ref = ?1",
                params![metadata.secret_ref, replacement_ref],
            )
            .unwrap();
            conn.execute(
                "UPDATE credentials SET secret_ref = ?2 WHERE credential_id = ?1",
                params![metadata.credential_id, replacement_ref],
            )
            .unwrap();
        }
        let error = store
            .resolve_user_credential(&ring, "alice", "jira", "default", "jira-cloud-api-token")
            .unwrap_err();
        assert!(matches!(error, ManagedStoreError::CredentialDecryptFailed));
    }

    #[test]
    fn readiness_detects_secret_material_integrity_failures() {
        fn populated_store() -> (TempDir, ManagedStore, CredentialKeyRing, CredentialMetadata) {
            let temp = TempDir::new().unwrap();
            let path = temp.path().join("store.sqlite");
            let store =
                ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
            let ring = key_ring("k1");
            create_alice(&store);
            let metadata = put_alice_jira_credential(&store, &ring, "pat");
            (temp, store, ring, metadata)
        }

        let (_temp, store, ring, metadata) = populated_store();
        {
            let conn = store.connection.lock().unwrap();
            conn.execute(
                "DELETE FROM credential_secret_material WHERE secret_ref = ?1",
                params![metadata.secret_ref],
            )
            .unwrap();
        }
        assert!(matches!(
            store.check_ready(Some(&ring)).unwrap_err(),
            ManagedStoreError::SchemaInvalid(_)
        ));

        let (_temp, store, ring, metadata) = populated_store();
        {
            let conn = store.connection.lock().unwrap();
            conn.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
            conn.execute(
                "UPDATE credential_secret_material SET credential_id = ?2 WHERE secret_ref = ?1",
                params![metadata.secret_ref, Uuid::new_v4().to_string()],
            )
            .unwrap();
            conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        }
        assert!(matches!(
            store.check_ready(Some(&ring)).unwrap_err(),
            ManagedStoreError::SchemaInvalid(_)
        ));

        let (_temp, store, _ring, _metadata) = populated_store();
        let wrong_ring = key_ring("k2");
        assert!(matches!(
            store.check_ready(Some(&wrong_ring)).unwrap_err(),
            ManagedStoreError::EncryptionKeyMissing(_)
        ));

        let (_temp, store, ring, _metadata) = populated_store();
        store.check_ready(Some(&ring)).unwrap();
        let wrong_ring = key_ring_with_keys("k1", &[("k1", 8)]);
        assert!(matches!(
            store.check_ready(Some(&wrong_ring)).unwrap_err(),
            ManagedStoreError::CredentialDecryptFailed
        ));
        // Schema admission has no key material and remains independent of the
        // cryptographic readiness check, even with the wrong key configured.
        check_secret_material_ready(&store.connection.lock().unwrap(), None).unwrap();

        for column in ["secret_nonce", "secret_ciphertext"] {
            let (_temp, store, ring, metadata) = populated_store();
            store
                .connection
                .lock()
                .unwrap()
                .execute(
                    &format!(
                        "UPDATE credential_secret_material SET {column} = X'00' WHERE secret_ref = ?1"
                    ),
                    params![metadata.secret_ref],
                )
                .unwrap();
            assert!(matches!(
                check_secret_material_ready(&store.connection.lock().unwrap(), None),
                Err(ManagedStoreError::SchemaInvalid(_))
            ));
            assert!(matches!(
                store.check_ready(Some(&ring)),
                Err(ManagedStoreError::SchemaInvalid(_))
            ));
        }

        let (_temp, store, ring, metadata) = populated_store();
        {
            let conn = store.connection.lock().unwrap();
            let mut row = encrypted_credential_by_tuple(&conn, "alice", "jira", "default").unwrap();
            row.secret_ciphertext[0] ^= 1;
            conn.execute(
                "UPDATE credential_secret_material SET secret_ciphertext = ?2 WHERE secret_ref = ?1",
                params![metadata.secret_ref, row.secret_ciphertext],
            )
            .unwrap();
            check_secret_material_ready(&conn, None).unwrap();
        }
        assert!(matches!(
            store.check_ready(Some(&ring)),
            Err(ManagedStoreError::CredentialDecryptFailed)
        ));

        // Even authenticated JSON must satisfy the stored credential kind.
        let (_temp, store, ring, metadata) = populated_store();
        {
            let conn = store.connection.lock().unwrap();
            let row = encrypted_credential_by_tuple(&conn, "alice", "jira", "default").unwrap();
            let malformed = ring
                .encrypt(
                    &json!({"username":"alice@example.com","token":""}),
                    &credential_aad(&row),
                )
                .unwrap();
            conn.execute(
                "UPDATE credential_secret_material SET secret_nonce = ?2, secret_ciphertext = ?3 WHERE secret_ref = ?1",
                params![metadata.secret_ref, malformed.nonce, malformed.ciphertext],
            )
            .unwrap();
            check_secret_material_ready(&conn, None).unwrap();
        }
        assert!(matches!(
            store.check_ready(Some(&ring)),
            Err(ManagedStoreError::CredentialInvalid(_))
        ));

        // Expiry belongs to invocation authorization, not stored integrity.
        let (_temp, store, ring, metadata) = populated_store();
        store
            .connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE credentials SET metadata_json = ?2 WHERE credential_id = ?1",
                params![
                    metadata.credential_id,
                    json!({"expiresAt":"2000-01-01T00:00:00Z"}).to_string()
                ],
            )
            .unwrap();
        store.check_ready(Some(&ring)).unwrap();
        assert!(matches!(
            store.resolve_user_credential(
                &ring,
                "alice",
                "jira",
                "default",
                "jira-cloud-api-token"
            ),
            Err(ManagedStoreError::CredentialExpired)
        ));

        let (_temp, store, ring, metadata) = populated_store();
        {
            let conn = store.connection.lock().unwrap();
            conn.execute_batch("PRAGMA ignore_check_constraints = ON;")
                .unwrap();
            conn.execute(
                "UPDATE credentials SET secret_backend = 'vault_kv_v2' WHERE credential_id = ?1",
                params![metadata.credential_id],
            )
            .unwrap();
            conn.execute_batch("PRAGMA ignore_check_constraints = OFF;")
                .unwrap();
        }
        assert!(matches!(
            store.check_ready(Some(&ring)).unwrap_err(),
            ManagedStoreError::SchemaInvalid(_)
        ));
    }

    #[test]
    fn credential_verification_target_must_match_current_secret_version() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let ring = key_ring("k1");
        store
            .create_or_update_principal(PrincipalWriteRequest {
                role: crate::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "alice".to_string(),
                kind: "user".to_string(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".to_string(),
            })
            .unwrap();
        store
            .upsert_user_credential(
                &ring,
                CredentialWriteRequest {
                    owner_principal_id: "alice".to_string(),
                    service: "jira".to_string(),
                    name: "default".to_string(),
                    profile: "jira-cloud-api-token".to_string(),
                    credential_kind: "basic_api_token".to_string(),
                    secret: json!({"username":"alice@example.com","token":"old-pat"}),
                    metadata: json!({"displayName":"Jira"}),
                    actor: "alice".to_string(),
                },
                crate::CredentialManagementPurpose::Administrative,
            )
            .unwrap();
        let old_candidate = store
            .resolve_user_credential_for_verification(
                &ring,
                "alice",
                "jira",
                "default",
                "jira-cloud-api-token",
                crate::CredentialManagementPurpose::Administrative,
            )
            .unwrap();
        assert_eq!(
            old_candidate.credential,
            basic_credential("alice@example.com", "old-pat")
        );
        let verified = store
            .mark_user_credential_verified_if_current(
                &old_candidate.target,
                "upstream_verified",
                crate::CredentialManagementPurpose::Administrative,
            )
            .unwrap();
        assert_eq!(
            verified.verification_status.as_deref(),
            Some("upstream_verified")
        );

        let rotated = store
            .upsert_user_credential(
                &ring,
                CredentialWriteRequest {
                    owner_principal_id: "alice".to_string(),
                    service: "jira".to_string(),
                    name: "default".to_string(),
                    profile: "jira-cloud-api-token".to_string(),
                    credential_kind: "basic_api_token".to_string(),
                    secret: json!({"username":"alice@example.com","token":"new-pat"}),
                    metadata: json!({"displayName":"Jira"}),
                    actor: "alice".to_string(),
                },
                crate::CredentialManagementPurpose::Administrative,
            )
            .unwrap();
        assert!(rotated.last_verified_at.is_none());
        assert_eq!(rotated.verification_status.as_deref(), Some("not_verified"));
        assert!(rotated.last_verification_attempt_at.is_none());
        assert!(rotated.last_verification_error_code.is_none());

        let stale_mark = store.mark_user_credential_verified_if_current(
            &old_candidate.target,
            "upstream_verified",
            crate::CredentialManagementPurpose::Administrative,
        );
        assert!(matches!(
            stale_mark.unwrap_err(),
            ManagedStoreError::VersionConflict
        ));
        let stale_failure = store.mark_user_credential_verification_failed_if_current(
            &old_candidate.target,
            ReasonCode::UpstreamUnauthorized.as_str(),
            crate::CredentialManagementPurpose::Administrative,
        );
        assert!(matches!(
            stale_failure.unwrap_err(),
            ManagedStoreError::VersionConflict
        ));
        let after_stale_mark = store
            .credential_by_tuple("alice", "jira", "default")
            .unwrap();
        assert!(after_stale_mark.last_verified_at.is_none());
        assert_eq!(
            after_stale_mark.verification_status.as_deref(),
            Some("not_verified")
        );
        assert!(after_stale_mark.last_verification_attempt_at.is_none());
        assert!(after_stale_mark.last_verification_error_code.is_none());

        let current_candidate = store
            .resolve_user_credential_for_verification(
                &ring,
                "alice",
                "jira",
                "default",
                "jira-cloud-api-token",
                crate::CredentialManagementPurpose::Administrative,
            )
            .unwrap();
        assert_eq!(
            current_candidate.credential,
            basic_credential("alice@example.com", "new-pat")
        );
        let current_verified = store
            .mark_user_credential_verified_if_current(
                &current_candidate.target,
                "upstream_verified",
                crate::CredentialManagementPurpose::Administrative,
            )
            .unwrap();
        assert_eq!(
            current_verified.verification_status.as_deref(),
            Some("upstream_verified")
        );
    }

    #[test]
    fn oidc_flow_capacity_claim_and_replay_are_durable() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let provider = reconcile_test_oidc_provider(&store, true, 3_600, "flow-config");
        let expires_at = normalized_timestamp(Utc::now() + Duration::minutes(5));
        let flow_request = |state_byte| OidcFlowCreateRequest {
            state_hash: vec![state_byte; 32],
            browser_binding_hash: vec![7; 32],
            provider_generation: provider.config_generation,
            encrypted_payload: vec![8, 9, 10],
            encryption_nonce: vec![11; 12],
            return_path: "/portal".to_string(),
            expires_at: expires_at.clone(),
            max_pending_flows: 1,
        };

        let created = store.create_oidc_flow(flow_request(1)).unwrap();
        assert_eq!(created.flow_sequence, 1);
        assert!(matches!(
            store.create_oidc_flow(flow_request(2)),
            Err(ManagedStoreError::OidcFlowCapacity)
        ));
        let claim = OidcFlowClaimRequest {
            state_hash: vec![1; 32],
            browser_binding_hash: vec![7; 32],
            provider_generation: provider.config_generation,
            outcome_code: "callback_claimed".to_string(),
        };
        let claimed = store.claim_oidc_flow(claim.clone()).unwrap();
        assert!(claimed.consumed_at.is_some());
        assert_eq!(claimed.outcome_code.as_deref(), Some("callback_claimed"));
        assert!(matches!(
            store.claim_oidc_flow(claim),
            Err(ManagedStoreError::OidcFlowInvalid)
        ));
        store
            .connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE oidc_authorization_flows
                 SET created_at = '1969-12-31T23:59:00Z', expires_at = '1970-01-01T00:00:00Z'
                 WHERE flow_sequence = ?1",
                params![claimed.flow_sequence as i64],
            )
            .unwrap();
        let second = store.create_oidc_flow(flow_request(2)).unwrap();
        assert_eq!(second.flow_sequence, 2);
        let expired_consumed_rows: i64 = store
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(1) FROM oidc_authorization_flows WHERE flow_sequence = ?1",
                params![claimed.flow_sequence as i64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(expired_consumed_rows, 0);

        store
            .connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE oidc_authorization_flows
                 SET created_at = '1969-12-31T23:59:00Z',
                     expires_at = '1970-01-01T00:00:00Z'
                 WHERE flow_sequence = ?1",
                params![second.flow_sequence as i64],
            )
            .unwrap();
        assert!(matches!(
            store.claim_oidc_flow(OidcFlowClaimRequest {
                state_hash: vec![2; 32],
                browser_binding_hash: vec![7; 32],
                provider_generation: provider.config_generation,
                outcome_code: "callback_claimed".to_string(),
            }),
            Err(ManagedStoreError::OidcFlowExpired)
        ));
    }

    #[test]
    fn oidc_completion_normalizes_fractional_timestamps_before_expiry_checks() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let provider = reconcile_test_oidc_provider(&store, true, 3_600, "time-config");
        let callback = DateTime::<Utc>::from_timestamp(1_800_000_000, 500_000_000).unwrap();
        let evidence = callback - Duration::seconds(3_600);
        let mut request = test_oidc_completion_request(
            1,
            provider.config_generation,
            TEST_OIDC_USER,
            "fractional-time-user",
            &[],
            &callback.to_rfc3339_opts(SecondsFormat::Millis, true),
        );
        request.evidence_at = evidence.to_rfc3339_opts(SecondsFormat::Millis, true);

        let outcome = store
            .complete_oidc_login(&broker_token_hasher_for_test(43), request)
            .unwrap();
        assert!(matches!(
            outcome,
            OidcCompletionOutcome::Denied { ref reason } if reason == "evidence_expired"
        ));
        assert!(store.list_principals().unwrap().is_empty());
    }

    #[test]
    fn oidc_insert_error_mappers_preserve_operational_store_failures() {
        assert_eq!(
            ManagedStoreError::OidcProviderUnavailable.reason_code(),
            ReasonCode::OidcUnavailable
        );
        assert_eq!(
            ManagedStoreError::OidcLoginMethodConflict.reason_code(),
            ReasonCode::OidcLoginMethodConflict
        );
        assert_eq!(
            ManagedStoreError::ExternalGroupBindingNotFound.reason_code(),
            ReasonCode::ExternalGroupBindingNotFound
        );
        assert_eq!(
            ManagedStoreError::ExternalGroupBindingConflict.reason_code(),
            ReasonCode::ExternalGroupBindingConflict
        );
        assert_eq!(
            ManagedStoreError::OidcAdmissionDenied.reason_code(),
            ReasonCode::OidcAdmissionDenied
        );
        let busy = || {
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
                None,
            )
        };
        assert!(matches!(
            map_oidc_flow_insert_error(busy()),
            ManagedStoreError::Unavailable(_)
        ));
        assert!(matches!(
            map_external_binding_insert_error(busy()),
            ManagedStoreError::Unavailable(_)
        ));
        assert!(matches!(
            map_oidc_method_insert_error(busy()),
            ManagedStoreError::Unavailable(_)
        ));

        let constraint = || {
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT),
                None,
            )
        };
        assert!(matches!(
            map_oidc_flow_insert_error(constraint()),
            ManagedStoreError::OidcFlowInvalid
        ));
        assert!(matches!(
            map_external_binding_insert_error(constraint()),
            ManagedStoreError::ExternalGroupBindingConflict
        ));
        assert!(matches!(
            map_oidc_method_insert_error(constraint()),
            ManagedStoreError::OidcLoginMethodConflict
        ));
    }

    #[test]
    fn oidc_denials_commit_subject_watermarks_in_strict_flow_order() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let provider = reconcile_test_oidc_provider(&store, true, 3_600, "watermark-config");
        let now = normalized_now_string();
        let hasher = broker_token_hasher_for_test(41);
        let denied = store
            .complete_oidc_login(
                &hasher,
                test_oidc_completion_request(
                    10,
                    provider.config_generation,
                    TEST_OIDC_USER,
                    "denied-user",
                    &[],
                    &now,
                ),
            )
            .unwrap();
        assert!(matches!(
            denied,
            OidcCompletionOutcome::Denied { ref reason } if reason == "no_mapped_group"
        ));
        assert_eq!(
            store
                .complete_oidc_login(
                    &hasher,
                    test_oidc_completion_request(
                        10,
                        provider.config_generation,
                        TEST_OIDC_USER,
                        "denied-user",
                        &[],
                        &now,
                    ),
                )
                .unwrap(),
            OidcCompletionOutcome::Superseded
        );
        assert!(
            store
                .record_trusted_incomplete_oidc_callback(
                    &test_oidc_subject(TEST_OIDC_USER),
                    11,
                    provider.config_generation,
                    &now,
                )
                .unwrap()
        );
        assert!(
            !store
                .record_trusted_incomplete_oidc_callback(
                    &test_oidc_subject(TEST_OIDC_USER),
                    9,
                    provider.config_generation,
                    &now,
                )
                .unwrap()
        );
        assert!(matches!(
            store.principal("denied-user"),
            Err(ManagedStoreError::PrincipalNotFound)
        ));
    }

    #[test]
    fn oidc_jit_completion_is_atomic_and_effective_membership_dedupes_and_expires() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let provider = reconcile_test_oidc_provider(&store, true, 7_200, "jit-config");
        create_test_group(&store, "team-a");
        create_test_group(&store, "team-b");
        let team_a_binding = store
            .create_external_group_binding(ExternalGroupBindingCreateRequest {
                external_group_id: TEST_EXTERNAL_GROUP_A.to_string(),
                group_id: "team-a".to_string(),
                actor: "admin".to_string(),
            })
            .unwrap();
        let team_b_binding = store
            .create_external_group_binding(ExternalGroupBindingCreateRequest {
                external_group_id: TEST_EXTERNAL_GROUP_B.to_string(),
                group_id: "team-b".to_string(),
                actor: "admin".to_string(),
            })
            .unwrap();
        let now = normalized_now_string();
        let hasher = broker_token_hasher_for_test(42);
        let mut rollback_request = test_oidc_completion_request(
            20,
            provider.config_generation,
            TEST_OIDC_USER,
            "oidc-user",
            &[TEST_EXTERNAL_GROUP_A, TEST_EXTERNAL_GROUP_B],
            &now,
        );
        rollback_request.session_ttl_seconds = 0;
        assert!(matches!(
            store.complete_oidc_login(&hasher, rollback_request),
            Err(ManagedStoreError::InputInvalid(_))
        ));
        assert!(matches!(
            store.principal("oidc-user"),
            Err(ManagedStoreError::PrincipalNotFound)
        ));
        assert_eq!(
            store
                .connection
                .lock()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM principal_identity_access WHERE principal_id='oidc-user'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0,
            "failed OIDC creation rolls back its identity gate"
        );

        let succeeded = store
            .complete_oidc_login(
                &hasher,
                test_oidc_completion_request(
                    20,
                    provider.config_generation,
                    TEST_OIDC_USER,
                    "oidc-user",
                    &[TEST_EXTERNAL_GROUP_A, TEST_EXTERNAL_GROUP_B],
                    &now,
                ),
            )
            .unwrap();
        let OidcCompletionOutcome::Succeeded {
            result,
            jit_created,
        } = succeeded
        else {
            panic!("expected successful JIT completion");
        };
        assert!(jit_created);
        assert_eq!(store.identity_access("oidc-user").unwrap().version, 1);
        assert_eq!(result.principal.display_name.as_deref(), Some("OIDC User"));
        assert_eq!(result.principal.email.as_deref(), Some("oidc@example.com"));
        assert_eq!(result.membership.groups, vec!["team-a", "team-b"]);
        assert_eq!(result.membership.policy_groups, vec!["team-a", "team-b"]);
        assert!(
            store
                .effective_service_policy_management_authorities("oidc-user")
                .unwrap()
                .is_empty(),
            "OIDC group membership never assigns a management role or scope"
        );
        assert_eq!(result.session.record.name, "oidc:microsoft:browser-session");
        assert_eq!(
            store
                .resolve_browser_session(&hasher, &result.session.token)
                .unwrap()
                .groups,
            vec!["team-a", "team-b"]
        );

        store.add_group("oidc-user", "team-a", "admin").unwrap();
        let mixed = store.effective_membership_at("oidc-user", &now).unwrap();
        assert_eq!(mixed.groups, vec!["team-a", "team-b"]);
        let team_a = mixed
            .details
            .iter()
            .find(|detail| detail.group_id == "team-a")
            .unwrap();
        assert_eq!(team_a.source, "local_and_microsoft");
        assert!(team_a.local.is_some());
        assert_eq!(team_a.microsoft.len(), 1);
        assert_eq!(team_a.microsoft[0].binding_id, team_a_binding.binding_id);
        assert!(team_a.microsoft[0].current);
        assert_eq!(
            store
                .effective_service_policy_management_authorities("oidc-user")
                .unwrap()
                .len(),
            0,
            "mixed local and Microsoft membership never supplies management authority",
        );
        assert_eq!(store.group("team-a").unwrap().member_count, 1);
        let member = store.group_members("team-a").unwrap().remove(0);
        assert_eq!(member.principal_id, "oidc-user");
        assert_eq!(member.membership.unwrap().source, "local_and_microsoft");

        let removal = store
            .remove_local_group_with_effect("oidc-user", "team-a")
            .unwrap();
        assert!(removal.removed);
        assert!(removal.still_effective);
        let team_a_valid_until: String = store
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT valid_until FROM external_principal_groups epg
                 JOIN external_group_bindings b ON b.binding_id = epg.binding_id
                 WHERE b.group_id = 'team-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            store
                .effective_membership_at("oidc-user", &team_a_valid_until)
                .unwrap()
                .policy_groups,
            Vec::<String>::new(),
            "Microsoft-only authority expires at the existing strict boundary",
        );
        let after_local_removal = store.principal("oidc-user").unwrap();
        assert_eq!(after_local_removal.groups, vec!["team-a", "team-b"]);
        assert_eq!(
            store
                .effective_membership_at("oidc-user", &now)
                .unwrap()
                .details[0]
                .source,
            "microsoft"
        );
        store.add_group("oidc-user", "team-a", "admin").unwrap();

        assert!(matches!(
            store.delete_external_group_binding(&team_b_binding.binding_id),
            Err(ManagedStoreError::ExternalGroupBindingConflict)
        ));
        let disabled = store
            .set_external_group_binding_enabled(&team_b_binding.binding_id, false, "admin")
            .unwrap();
        assert_eq!(disabled.status, "disabled");
        assert_eq!(
            store
                .effective_service_policy_management_services("oidc-user")
                .unwrap(),
            Vec::<String>::new(),
            "external membership remains independent of management authority",
        );
        assert_eq!(
            store
                .effective_membership_at("oidc-user", &now)
                .unwrap()
                .groups,
            vec!["team-a"]
        );
        store
            .delete_external_group_binding(&team_b_binding.binding_id)
            .unwrap();
        assert!(matches!(
            store.external_group_binding(&team_b_binding.binding_id),
            Err(ManagedStoreError::ExternalGroupBindingNotFound)
        ));

        let valid_until: String = store
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT valid_until FROM oidc_membership_refresh_state WHERE login_method_id = ?1",
                params![result.login_method.login_method_id],
                |row| row.get(0),
            )
            .unwrap();
        let expired = store
            .effective_membership_at("oidc-user", &valid_until)
            .unwrap();
        assert_eq!(expired.groups, vec!["team-a"]);
        assert!(expired.details[0].microsoft.is_empty());
        let fractional_same_second = valid_until.replace('Z', ".500Z");
        let fractionally_expired = store
            .effective_membership_at("oidc-user", &fractional_same_second)
            .unwrap();
        assert_eq!(fractionally_expired.groups, vec!["team-a"]);
        assert!(fractionally_expired.details[0].microsoft.is_empty());

        let clamped = reconcile_test_oidc_provider(&store, true, 900, "jit-config-clamped");
        assert!(clamped.config_generation > provider.config_generation);
        let clamped_until: String = store
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT valid_until FROM oidc_membership_refresh_state WHERE login_method_id = ?1",
                params![result.login_method.login_method_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(clamped_until < valid_until);

        reconcile_test_oidc_provider(&store, false, 900, "jit-config-disabled");
        let conn = store.connection.lock().unwrap();
        let evidence_rows: i64 = conn
            .query_row(
                "SELECT COUNT(1) FROM oidc_membership_refresh_state",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(evidence_rows, 0);
        drop(conn);
        assert!(matches!(
            store.resolve_broker_token(&hasher, &result.session.token),
            Err(ManagedStoreError::BrokerTokenRevoked)
        ));
    }

    #[test]
    fn bound_oidc_empty_groups_login_succeeds_and_link_conflicts_unlink_session() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let store =
            ManagedStore::open(&store_config(&path), ManagedStoreOpenMode::Startup).unwrap();
        let provider = reconcile_test_oidc_provider(&store, true, 3_600, "link-config");
        create_alice(&store);
        store
            .create_principal(PrincipalWriteRequest {
                role: crate::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "bob".to_string(),
                kind: "user".to_string(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".to_string(),
            })
            .unwrap();
        assert!(matches!(
            store.link_oidc_login_method(OidcLoginMethodLinkRequest {
                principal_id: "alice".to_string(),
                user_object_id: TEST_OIDC_USER.to_uppercase(),
                actor: "admin".to_string(),
            }),
            Err(ManagedStoreError::InputInvalid(_))
        ));
        let method = store
            .link_oidc_login_method(OidcLoginMethodLinkRequest {
                principal_id: "alice".to_string(),
                user_object_id: TEST_OIDC_USER.to_string(),
                actor: "admin".to_string(),
            })
            .unwrap();
        store
            .connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE principal_login_methods SET status = 'disabled'
                 WHERE login_method_id = ?1",
                params![method.login_method_id],
            )
            .unwrap();
        let reactivated = store
            .link_oidc_login_method(OidcLoginMethodLinkRequest {
                principal_id: "alice".to_string(),
                user_object_id: TEST_OIDC_USER.to_string(),
                actor: "admin".to_string(),
            })
            .unwrap();
        assert_eq!(reactivated.login_method_id, method.login_method_id);
        assert_eq!(reactivated.status, "active");
        assert!(matches!(
            store.link_oidc_login_method(OidcLoginMethodLinkRequest {
                principal_id: "bob".to_string(),
                user_object_id: TEST_OIDC_USER.to_string(),
                actor: "admin".to_string(),
            }),
            Err(ManagedStoreError::OidcLoginMethodConflict)
        ));
        assert!(matches!(
            store.link_oidc_login_method(OidcLoginMethodLinkRequest {
                principal_id: "alice".to_string(),
                user_object_id: TEST_OIDC_USER_TWO.to_string(),
                actor: "admin".to_string(),
            }),
            Err(ManagedStoreError::OidcLoginMethodConflict)
        ));

        let now = normalized_now_string();
        let hasher = broker_token_hasher_for_test(43);
        let success = store
            .complete_oidc_login(
                &hasher,
                test_oidc_completion_request(
                    30,
                    provider.config_generation,
                    TEST_OIDC_USER,
                    "unused-jit-id",
                    &[],
                    &now,
                ),
            )
            .unwrap();
        let OidcCompletionOutcome::Succeeded {
            result,
            jit_created,
        } = success
        else {
            panic!("expected bound login to succeed");
        };
        assert!(!jit_created);
        assert_eq!(result.login_method.login_method_id, method.login_method_id);
        assert!(result.membership.groups.is_empty());
        store.unlink_oidc_login_method("alice", "admin").unwrap();
        assert!(store.list_login_methods("alice").unwrap().is_empty());
        assert!(matches!(
            store.resolve_broker_token(&hasher, &result.session.token),
            Err(ManagedStoreError::BrokerTokenRevoked)
        ));
    }
}
