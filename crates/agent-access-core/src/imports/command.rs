//! The internal command hook: how core runs a command import's process.
//!
//! A command import's adapter builds [`super::ImportedProvider::Command`]. Core
//! uses its [`Provider`] half for everything an imported provider does before
//! dispatch, such as resolving scopes, but never calls
//! [`Provider::invoke`] or [`Provider::verify_execution_credential`] on it.
//! A command receives what the SDK withholds from every provider (plaintext
//! credentials, the full caller, resolved grants, decrypted resource
//! attributes and proxy credentials), so core assembles that request itself
//! and calls [`CommandProvider::invoke_command`] or
//! [`CommandProvider::verify_command`] instead, inside the same hook context,
//! contract checks, finalization and audit as `Provider::invoke`.
//!
//! The order of a call is fixed:
//!
//! 1. admission: input schema, policy and the authority plan;
//! 2. a [`CommandPermit`] from the command name's concurrency budget, waited
//!    for until the call deadline;
//! 3. final checks immediately before spawning: the import dispatch fence
//!    (which also compares the `[command_imports.<name>]` entry), resource
//!    attribute bindings, and the credentials;
//! 4. core builds the [`CommandRequest`];
//! 5. core calls the hook, which hands the permit to the supervisor of the
//!    `<path> invoke` or `<path> verify` process it spawns.
//!
//! The supervisor keeps the permit until the process group is killed and
//! reaped, and records what happened to the process into the call's
//! [`CommandProcessFacts`], which outlive the invocation future.
//!
//! The SDK's no-plaintext rule is unchanged for every other provider; the hook
//! is part of the internal import contract and changes no supported API.
use super::{CommandPermit, CommandProcessFacts, CommandSecrets};
use agent_access_provider::{
    Provider, ProviderCredentialVerification, ProviderError, ProviderResult, ReasonCode,
};
use async_trait::async_trait;
use serde::Serialize;
use std::ffi::OsString;
use std::io::Write;
use tokio::time::Instant;
use zeroize::Zeroize;

/// The manifest and request format a command speaks.
pub const COMMAND_FORMAT: &str = "agent-access-command/1";

/// One request document, encoded for a command process's stdin.
///
/// Core builds it after the budget permit and the final checks, and it may
/// hold plaintext credentials, decrypted private attributes and proxy
/// credentials. Its buffer is zeroized on drop, including every intermediate
/// buffer it outgrew while encoding. It has no `Debug`, `Clone` or
/// `Serialize`: its only output is [`Self::stdin`].
pub struct CommandRequest {
    stdin: Vec<u8>,
}

impl CommandRequest {
    /// The largest encoded request: 1 MiB.
    pub const MAX_BYTES: usize = 1024 * 1024;

    /// Encodes one request document as compact JSON. Core's request builders
    /// encode every request a command receives; adapter tests may encode
    /// their own. A document over [`Self::MAX_BYTES`] fails
    /// `operation_failed` before spawning; the caller adds the `not_applied`
    /// receipt a write action reports.
    pub fn encode(document: &impl Serialize) -> Result<Self, ProviderError> {
        let mut writer = ZeroizingWriter::default();
        serde_json::to_writer(&mut writer, document).map_err(|_| {
            ProviderError::error(
                ReasonCode::OperationFailed,
                "the command request exceeds 1 MiB or cannot be encoded",
            )
        })?;
        Ok(Self {
            stdin: std::mem::take(&mut writer.buffer),
        })
    }

    /// The bytes to write to the process's stdin, then close it.
    pub fn stdin(&self) -> &[u8] {
        &self.stdin
    }
}

impl Drop for CommandRequest {
    fn drop(&mut self) {
        self.stdin.zeroize();
    }
}

/// A bounded writer that never leaves a copy of earlier contents behind when
/// it grows: it moves into a larger buffer and zeroizes the old one.
#[derive(Default)]
struct ZeroizingWriter {
    buffer: Vec<u8>,
}

impl Write for ZeroizingWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let needed = self.buffer.len() + bytes.len();
        if needed > CommandRequest::MAX_BYTES {
            return Err(std::io::Error::other("command request exceeds 1 MiB"));
        }
        if needed > self.buffer.capacity() {
            let capacity = needed
                .max(self.buffer.capacity().saturating_mul(2))
                .clamp(4096, CommandRequest::MAX_BYTES);
            let mut grown = Vec::with_capacity(capacity);
            grown.extend_from_slice(&self.buffer);
            self.buffer.zeroize();
            self.buffer = grown;
        }
        self.buffer.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for ZeroizingWriter {
    fn drop(&mut self) {
        self.buffer.zeroize();
    }
}

/// One admitted invocation of a command import's action, as core hands it to
/// [`CommandProvider::invoke_command`] after the permit and final checks.
pub struct CommandInvocation {
    action: String,
    read_only: bool,
    run: CommandRun,
}

impl CommandInvocation {
    /// Core builds one per call, in the order the module documentation
    /// states; adapter tests may build their own. It has no network
    /// variables and a fresh facts cell until
    /// [`Self::with_environment`] and [`Self::with_facts`] supply them.
    pub fn new(
        action: String,
        read_only: bool,
        request: CommandRequest,
        deadline: Instant,
        permit: CommandPermit,
    ) -> Self {
        Self {
            action,
            read_only,
            run: CommandRun::new(request, deadline, permit),
        }
    }

    /// The network variables core sets, from the Broker's egress settings,
    /// beside the configured `env` of the command.
    pub fn with_environment(mut self, environment: Vec<(&'static str, OsString)>) -> Self {
        self.run.environment = environment;
        self
    }

    /// The cell the supervisor records the process facts into, shared with
    /// whoever finalizes the call.
    pub fn with_facts(mut self, facts: CommandProcessFacts) -> Self {
        self.run.facts = facts;
        self
    }

    /// The secrets the request supplies, which the response must not echo
    /// outside the sensitive result.
    pub fn with_secrets(mut self, secrets: CommandSecrets) -> Self {
        self.run.secrets = secrets;
        self
    }

    /// The Broker action ID of the accepted action.
    pub fn action(&self) -> &str {
        &self.action
    }

    /// The administrator's reviewed classification. Receipts apply only to
    /// write-capable actions.
    pub fn read_only(&self) -> bool {
        self.read_only
    }

    /// The request for `<path> invoke`.
    pub fn request(&self) -> &CommandRequest {
        &self.run.request
    }

    /// The command deadline set at admission: the earlier of admission plus
    /// the command's `timeout` and the host operation deadline.
    pub fn deadline(&self) -> Instant {
        self.run.deadline
    }

    /// What the process run takes over.
    pub fn into_run(self) -> CommandRun {
        self.run
    }
}

/// One credential verification of a command import, as core hands it to
/// [`CommandProvider::verify_command`]. Core calls it only for a command
/// whose accepted metadata declares `verify: true`; otherwise verification
/// is unsupported, as the provider contract defines.
pub struct CommandVerification {
    run: CommandRun,
}

impl CommandVerification {
    /// Core builds one per verification, after taking `permit` from the
    /// command's budget; adapter tests may build their own.
    pub fn new(request: CommandRequest, deadline: Instant, permit: CommandPermit) -> Self {
        Self {
            run: CommandRun::new(request, deadline, permit),
        }
    }

    /// The network variables core sets beside the configured `env`.
    pub fn with_environment(mut self, environment: Vec<(&'static str, OsString)>) -> Self {
        self.run.environment = environment;
        self
    }

    /// The cell the supervisor records the process facts into.
    pub fn with_facts(mut self, facts: CommandProcessFacts) -> Self {
        self.run.facts = facts;
        self
    }

    /// The secrets the request supplies, which the response must not echo.
    pub fn with_secrets(mut self, secrets: CommandSecrets) -> Self {
        self.run.secrets = secrets;
        self
    }

    /// The request for `<path> verify`.
    pub fn request(&self) -> &CommandRequest {
        &self.run.request
    }

    pub fn deadline(&self) -> Instant {
        self.run.deadline
    }

    /// What the process run takes over.
    pub fn into_run(self) -> CommandRun {
        self.run
    }
}

/// What one `invoke` or `verify` process takes over from core: its stdin
/// request, its deadline, the budget permit its supervisor holds until the
/// process group is reaped, the network variables set beside the configured
/// `env`, the facts cell the supervisor records into, and the secrets the
/// request supplies, which the response mapping checks the output against.
pub struct CommandRun {
    pub request: CommandRequest,
    pub deadline: Instant,
    pub permit: CommandPermit,
    pub environment: Vec<(&'static str, OsString)>,
    pub facts: CommandProcessFacts,
    pub secrets: CommandSecrets,
}

impl CommandRun {
    fn new(request: CommandRequest, deadline: Instant, permit: CommandPermit) -> Self {
        Self {
            request,
            deadline,
            permit,
            environment: Vec::new(),
            facts: CommandProcessFacts::new(),
            secrets: CommandSecrets::new(),
        }
    }
}

/// The command hook a command import's provider implements beside
/// [`Provider`].
///
/// Each method runs one process under the permit it is handed, maps its
/// response and never finalizes or audits: core's owned operation does that
/// once. A failure before the process starts leaves the facts unspawned and
/// reports a `not_applied` write receipt; after spawning, a generic failure
/// is `operation_failed` with an `unknown` write receipt.
#[async_trait]
pub trait CommandProvider: Provider {
    /// Runs `<path> invoke` for one admitted call.
    async fn invoke_command(
        &self,
        invocation: CommandInvocation,
    ) -> Result<ProviderResult, ProviderError>;

    /// Runs `<path> verify` for a service or personal credential.
    async fn verify_command(
        &self,
        verification: CommandVerification,
    ) -> Result<ProviderCredentialVerification, ProviderError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn requests_encode_compact_json_within_one_mebibyte() {
        let request =
            CommandRequest::encode(&json!({"format": COMMAND_FORMAT, "inputs": {"a": 1}})).unwrap();
        assert_eq!(
            request.stdin(),
            br#"{"format":"agent-access-command/1","inputs":{"a":1}}"#
        );
        let large = "x".repeat(CommandRequest::MAX_BYTES - 2);
        assert_eq!(
            CommandRequest::encode(&large).unwrap().stdin().len(),
            CommandRequest::MAX_BYTES
        );
        let error = CommandRequest::encode(&"x".repeat(CommandRequest::MAX_BYTES))
            .err()
            .unwrap();
        assert_eq!(error.reason_code(), ReasonCode::OperationFailed);
    }

    #[test]
    fn the_writer_grows_without_exceeding_its_bound() {
        let mut writer = ZeroizingWriter::default();
        for _ in 0..100 {
            writer.write_all(&[7; 1000]).unwrap();
        }
        assert_eq!(writer.buffer.len(), 100_000);
        assert!(writer.buffer.capacity() <= CommandRequest::MAX_BYTES);
        assert!(
            writer
                .write_all(&vec![0; CommandRequest::MAX_BYTES])
                .is_err()
        );
    }
}
