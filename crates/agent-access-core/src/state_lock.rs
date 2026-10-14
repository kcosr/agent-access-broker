use crate::{BrokerConfig, audit_file_identity_key, fs_permissions, os_host_name};
use chrono::Utc;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;

#[cfg(unix)]
const PRIVATE_LOCK_FILE_MODE: u32 = 0o600;
#[cfg(windows)]
const WINDOWS_LOCK_RANGE_LOW: u32 = 1;
#[cfg(windows)]
const WINDOWS_LOCK_RANGE_HIGH: u32 = 0;

const MANAGED_STORE_LOCK_SUFFIX: &str = ".agent-access.lock";
const AUDIT_LOCK_SUFFIX: &str = ".agent-access.lock";
const UPLOAD_SPOOL_LOCK_FILE: &str = ".agent-access-broker.spool.lock";

/// The process that acquires state locks, recorded in each new lock file's
/// holder metadata: its program (the executable's assembly name) and version,
/// and the broker's effective node ID. The holder never names a lock file, so
/// differently named programs contend for the same state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateLockHolder<'a> {
    program: &'a str,
    version: &'a str,
    node_id: &'a str,
}

impl<'a> StateLockHolder<'a> {
    pub const fn new(program: &'a str, version: &'a str, node_id: &'a str) -> Self {
        Self {
            program,
            version,
            node_id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StateLockDomain {
    ManagedStore,
    Audit,
    UploadSpool,
}

impl StateLockDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ManagedStore => "managed_store",
            Self::Audit => "audit",
            Self::UploadSpool => "upload_spool",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateLockFailureKind {
    Held,
    Unsupported,
    PathInvalid,
    IoError,
}

#[derive(Debug, Clone)]
pub struct StateLockError {
    kind: StateLockFailureKind,
    domains: Vec<StateLockDomain>,
    target_paths: Vec<PathBuf>,
    lock_file: PathBuf,
    message: String,
    holder_metadata: Option<String>,
}

impl StateLockError {
    pub fn kind(&self) -> StateLockFailureKind {
        self.kind
    }

    pub fn lock_file(&self) -> &Path {
        &self.lock_file
    }

    pub fn target_paths(&self) -> &[PathBuf] {
        &self.target_paths
    }

    pub fn domains(&self) -> &[StateLockDomain] {
        &self.domains
    }

    pub fn operator_message(&self) -> String {
        let domains = domain_label(&self.domains);
        let target = target_label(&self.target_paths);
        match self.kind {
            StateLockFailureKind::Held => {
                let mut message = format!(
                    "{domains} state lock is held for {target}; another broker process may already own this local state set"
                );
                if let Some(metadata) = sanitized_metadata_snippet(self.holder_metadata.as_deref())
                {
                    message.push_str(&format!("; holder metadata: {metadata}"));
                }
                message
            }
            StateLockFailureKind::Unsupported => format!(
                "{domains} state lock is unsupported for {target}: {}",
                self.message
            ),
            StateLockFailureKind::PathInvalid => format!(
                "{domains} state lock path is invalid for {target} via {}: {}",
                self.lock_file.display(),
                self.message
            ),
            StateLockFailureKind::IoError => format!(
                "{domains} state lock failed for {target} via {}: {}",
                self.lock_file.display(),
                self.message
            ),
        }
    }

    fn from_backend(info: &StateLockInfo, failure: BackendFailure) -> Self {
        Self {
            kind: failure.kind,
            domains: info.domains.clone(),
            target_paths: info.target_paths.clone(),
            lock_file: info.lock_file.clone(),
            message: failure.message,
            holder_metadata: failure.holder_metadata,
        }
    }
}

impl fmt::Display for StateLockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.operator_message())
    }
}

impl std::error::Error for StateLockError {}

type StateLockResult<T> = Result<T, Box<StateLockError>>;

pub struct StateLockSet {
    entries: Vec<StateLockEntry>,
}

impl fmt::Debug for StateLockSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StateLockSet")
            .field("infos", &self.infos())
            .finish()
    }
}

struct StateLockEntry {
    info: StateLockInfo,
    handle: Arc<StateLockHandle>,
}

struct StateLockHandle {
    _guard: Box<dyn HeldStateLock>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateLockInfo {
    pub domains: Vec<StateLockDomain>,
    pub target_paths: Vec<PathBuf>,
    pub lock_file: PathBuf,
    pub identity: PathBuf,
}

trait HeldStateLock: Send + Sync {}

struct FileStateLock {
    #[allow(dead_code)]
    file: File,
}

impl HeldStateLock for FileStateLock {}

#[cfg(unix)]
impl Drop for FileStateLock {
    fn drop(&mut self) {
        // flock belongs to the open file description. Closing this descriptor
        // alone does not release it while a forked child retains an inherited
        // descriptor before exec, so release ownership explicitly on guard drop.
        unsafe {
            let _ = libc::flock(std::os::fd::AsRawFd::as_raw_fd(&self.file), libc::LOCK_UN);
        }
    }
}

#[cfg(windows)]
impl Drop for FileStateLock {
    fn drop(&mut self) {
        let mut overlapped = windows_overlapped();
        unsafe {
            let _ = windows_sys::Win32::Storage::FileSystem::UnlockFileEx(
                self.file.as_raw_handle(),
                0,
                WINDOWS_LOCK_RANGE_LOW,
                WINDOWS_LOCK_RANGE_HIGH,
                &mut overlapped,
            );
        }
    }
}

impl StateLockSet {
    pub fn empty() -> Arc<Self> {
        Arc::new(Self {
            entries: Vec::new(),
        })
    }

    /// Acquires the state locks for `config` on behalf of `holder`, whose
    /// identity new lock files record.
    pub fn acquire_for_config(
        config: &BrokerConfig,
        config_path: &Path,
        holder: &StateLockHolder<'_>,
        reuse: Option<&StateLockSet>,
    ) -> StateLockResult<Arc<Self>> {
        let reuse_sets = reuse.into_iter().collect::<Vec<_>>();
        Self::acquire_for_config_with_backend(
            config,
            config_path,
            holder,
            reuse_sets.as_slice(),
            &RealStateLockBackend,
        )
    }

    pub fn acquire_for_config_reusing(
        config: &BrokerConfig,
        config_path: &Path,
        holder: &StateLockHolder<'_>,
        reuse: &[Arc<StateLockSet>],
    ) -> StateLockResult<Arc<Self>> {
        let reuse_sets = reuse.iter().map(Arc::as_ref).collect::<Vec<_>>();
        Self::acquire_for_config_with_backend(
            config,
            config_path,
            holder,
            reuse_sets.as_slice(),
            &RealStateLockBackend,
        )
    }

    pub fn infos(&self) -> Vec<StateLockInfo> {
        self.entries
            .iter()
            .map(|entry| entry.info.clone())
            .collect()
    }

    pub fn has_identity(&self, identity: &Path) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.info.identity == identity)
    }

    pub fn shares_identity_handle_with(&self, other: &Self, identity: &Path) -> bool {
        let left = self
            .entries
            .iter()
            .find(|entry| entry.info.identity == identity);
        let right = other
            .entries
            .iter()
            .find(|entry| entry.info.identity == identity);
        match (left, right) {
            (Some(left), Some(right)) => Arc::ptr_eq(&left.handle, &right.handle),
            _ => false,
        }
    }

    /// Acquires only the audit state lock for `config`, for offline audit
    /// commands that must not run while a broker owns the audit store.
    /// Returns an empty set when audit is disabled.
    pub fn acquire_audit_for_config(
        config: &BrokerConfig,
        config_path: &Path,
        holder: &StateLockHolder<'_>,
    ) -> StateLockResult<Arc<Self>> {
        let mut targets = BTreeMap::new();
        if let Some(audit) = &config.audit {
            insert_audit_target(&mut targets, audit)?;
        }
        Self::acquire_targets(
            targets
                .into_values()
                .map(StateLockTargetBuilder::into_info)
                .collect(),
            config_path,
            holder,
            &[],
            &RealStateLockBackend,
        )
    }

    fn acquire_for_config_with_backend<B: StateLockBackend>(
        config: &BrokerConfig,
        config_path: &Path,
        holder: &StateLockHolder<'_>,
        reuse: &[&StateLockSet],
        backend: &B,
    ) -> StateLockResult<Arc<Self>> {
        let targets = resolve_state_lock_targets(config)?;
        Self::acquire_targets(targets, config_path, holder, reuse, backend)
    }

    fn acquire_targets<B: StateLockBackend>(
        targets: Vec<StateLockInfo>,
        config_path: &Path,
        holder: &StateLockHolder<'_>,
        reuse: &[&StateLockSet],
        backend: &B,
    ) -> StateLockResult<Arc<Self>> {
        let mut entries = Vec::with_capacity(targets.len());
        for info in targets {
            if let Some(handle) = reuse
                .iter()
                .find_map(|set| set.handle_for_identity(&info.identity))
            {
                entries.push(StateLockEntry {
                    info,
                    handle: Arc::clone(handle),
                });
                continue;
            }

            let metadata = StateLockMetadata::new(config_path, holder, &info);
            let guard = backend
                .acquire(&info, &metadata)
                .map_err(|failure| Box::new(StateLockError::from_backend(&info, failure)))?;
            entries.push(StateLockEntry {
                info,
                handle: Arc::new(StateLockHandle { _guard: guard }),
            });
        }
        Ok(Arc::new(Self { entries }))
    }

    fn handle_for_identity(&self, identity: &Path) -> Option<&Arc<StateLockHandle>> {
        self.entries
            .iter()
            .find(|entry| entry.info.identity == identity)
            .map(|entry| &entry.handle)
    }
}

trait StateLockBackend {
    fn acquire(
        &self,
        info: &StateLockInfo,
        metadata: &StateLockMetadata,
    ) -> Result<Box<dyn HeldStateLock>, BackendFailure>;
}

#[derive(Debug)]
struct BackendFailure {
    kind: StateLockFailureKind,
    message: String,
    holder_metadata: Option<String>,
}

impl BackendFailure {
    fn new(kind: StateLockFailureKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            holder_metadata: None,
        }
    }

    fn held(message: impl Into<String>, holder_metadata: Option<String>) -> Self {
        Self {
            kind: StateLockFailureKind::Held,
            message: message.into(),
            holder_metadata,
        }
    }
}

struct RealStateLockBackend;

impl StateLockBackend for RealStateLockBackend {
    fn acquire(
        &self,
        info: &StateLockInfo,
        metadata: &StateLockMetadata,
    ) -> Result<Box<dyn HeldStateLock>, BackendFailure> {
        let file = open_lock_file(&info.lock_file)?;
        lock_file_nonblocking(&file, &info.lock_file)?;
        // Own the acquired lock before any further fallible work, so metadata
        // failures release it with the same semantics as an admitted guard.
        let mut guard = FileStateLock { file };
        write_lock_metadata(&mut guard.file, metadata).map_err(|error| {
            BackendFailure::new(
                StateLockFailureKind::IoError,
                format!("failed to write lock metadata: {error}"),
            )
        })?;
        Ok(Box::new(guard))
    }
}

#[derive(Serialize)]
struct StateLockMetadata {
    program: String,
    #[serde(rename = "programVersion")]
    program_version: String,
    domains: Vec<&'static str>,
    pid: u32,
    hostname: String,
    #[serde(rename = "nodeId")]
    node_id: String,
    #[serde(rename = "startedAt")]
    started_at: String,
    #[serde(rename = "configPath")]
    config_path: String,
    #[serde(rename = "targetPaths")]
    target_paths: Vec<String>,
    #[serde(rename = "lockFile")]
    lock_file: String,
}

impl StateLockMetadata {
    fn new(config_path: &Path, holder: &StateLockHolder<'_>, info: &StateLockInfo) -> Self {
        Self {
            program: holder.program.to_string(),
            program_version: holder.version.to_string(),
            domains: info.domains.iter().map(|domain| domain.as_str()).collect(),
            pid: std::process::id(),
            hostname: hostname(),
            node_id: holder.node_id.to_string(),
            started_at: Utc::now().to_rfc3339(),
            config_path: config_path.display().to_string(),
            target_paths: info
                .target_paths
                .iter()
                .map(|path| path.display().to_string())
                .collect(),
            lock_file: info.lock_file.display().to_string(),
        }
    }
}

pub fn resolve_state_lock_targets(config: &BrokerConfig) -> StateLockResult<Vec<StateLockInfo>> {
    let mut targets = BTreeMap::<PathBuf, StateLockTargetBuilder>::new();

    if let Some(managed_store) = &config.managed_store {
        let path = Path::new(&managed_store.path);
        if !path.is_absolute() {
            return Err(target_path_error(
                StateLockDomain::ManagedStore,
                path,
                managed_store_lock_file_for_path(path),
                "managed_store.path must be absolute".to_string(),
            ));
        }
        if managed_store.auto_migrate {
            if let Some(parent) = path.parent() {
                fs_permissions::ensure_private_dir(parent).map_err(|error| {
                    target_path_error(
                        StateLockDomain::ManagedStore,
                        path,
                        managed_store_lock_file_for_path(path),
                        format!("failed to create managed store directory: {error}"),
                    )
                })?;
            }
        } else {
            fs_permissions::validate_private_parent(path).map_err(|error| {
                target_path_error(
                    StateLockDomain::ManagedStore,
                    path,
                    managed_store_lock_file_for_path(path),
                    format!("failed to validate managed store directory: {error}"),
                )
            })?;
        }
        let target_path = file_identity(path).map_err(|message| {
            target_path_error(
                StateLockDomain::ManagedStore,
                path,
                managed_store_lock_file_for_path(path),
                message,
            )
        })?;
        let lock_file = target_path.with_file_name(format!(
            "{}{MANAGED_STORE_LOCK_SUFFIX}",
            target_path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("managed.sqlite3")
        ));
        insert_target(
            &mut targets,
            StateLockDomain::ManagedStore,
            target_path,
            lock_file,
        )?;
    }

    if let Some(audit) = &config.audit {
        insert_audit_target(&mut targets, audit)?;
    }

    let spool_dir = Path::new(&config.limits.upload_spool_dir);
    fs_permissions::ensure_private_dir(spool_dir).map_err(|error| {
        target_path_error(
            StateLockDomain::UploadSpool,
            spool_dir,
            spool_dir.join(UPLOAD_SPOOL_LOCK_FILE),
            format!("failed to create upload spool directory: {error}"),
        )
    })?;
    let target_path = fs::canonicalize(spool_dir).map_err(|error| {
        target_path_error(
            StateLockDomain::UploadSpool,
            spool_dir,
            spool_dir.join(UPLOAD_SPOOL_LOCK_FILE),
            format!("failed to canonicalize upload spool directory: {error}"),
        )
    })?;
    let lock_file = target_path.join(UPLOAD_SPOOL_LOCK_FILE);
    insert_target(
        &mut targets,
        StateLockDomain::UploadSpool,
        target_path,
        lock_file,
    )?;

    Ok(targets
        .into_values()
        .map(StateLockTargetBuilder::into_info)
        .collect())
}

fn insert_audit_target(
    targets: &mut BTreeMap<PathBuf, StateLockTargetBuilder>,
    audit: &crate::AuditConfig,
) -> StateLockResult<()> {
    let path = Path::new(&audit.path);
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs_permissions::ensure_private_dir(parent).map_err(|error| {
            target_path_error(
                StateLockDomain::Audit,
                path,
                audit_lock_file_for_path(path),
                format!("failed to create audit directory: {error}"),
            )
        })?;
    }
    let target_path = audit_file_identity_key(path);
    let lock_file = target_path.with_file_name(format!(
        "{}{AUDIT_LOCK_SUFFIX}",
        target_path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("audit.jsonl")
    ));
    insert_target(targets, StateLockDomain::Audit, target_path, lock_file)
}

fn insert_target(
    targets: &mut BTreeMap<PathBuf, StateLockTargetBuilder>,
    domain: StateLockDomain,
    target_path: PathBuf,
    lock_file: PathBuf,
) -> StateLockResult<()> {
    let identity = lock_file_identity(&lock_file)
        .map_err(|message| target_path_error(domain, &target_path, lock_file.clone(), message))?;
    targets
        .entry(identity.clone())
        .or_insert_with(|| StateLockTargetBuilder {
            identity,
            lock_file,
            domains: BTreeSet::new(),
            target_paths: BTreeSet::new(),
        })
        .insert(domain, target_path);
    Ok(())
}

struct StateLockTargetBuilder {
    identity: PathBuf,
    lock_file: PathBuf,
    domains: BTreeSet<StateLockDomain>,
    target_paths: BTreeSet<PathBuf>,
}

impl StateLockTargetBuilder {
    fn insert(&mut self, domain: StateLockDomain, target_path: PathBuf) {
        self.domains.insert(domain);
        self.target_paths.insert(target_path);
    }

    fn into_info(self) -> StateLockInfo {
        StateLockInfo {
            domains: self.domains.into_iter().collect(),
            target_paths: self.target_paths.into_iter().collect(),
            lock_file: self.lock_file,
            identity: self.identity,
        }
    }
}

fn managed_store_lock_file_for_path(path: &Path) -> PathBuf {
    path.with_file_name(format!(
        "{}{MANAGED_STORE_LOCK_SUFFIX}",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("managed.sqlite3")
    ))
}

fn audit_lock_file_for_path(path: &Path) -> PathBuf {
    path.with_file_name(format!(
        "{}{AUDIT_LOCK_SUFFIX}",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("audit.jsonl")
    ))
}

fn file_identity(path: &Path) -> Result<PathBuf, String> {
    let Some(file_name) = path.file_name() else {
        return Err(format!("{} must include a file name", path.display()));
    };
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let canonical_parent = fs::canonicalize(parent)
        .map_err(|error| format!("failed to canonicalize {}: {error}", parent.display()))?;
    Ok(canonical_parent.join(file_name))
}

fn lock_file_identity(lock_file: &Path) -> Result<PathBuf, String> {
    file_identity(lock_file)
}

fn target_path_error(
    domain: StateLockDomain,
    target_path: &Path,
    lock_file: PathBuf,
    message: String,
) -> Box<StateLockError> {
    Box::new(StateLockError {
        kind: StateLockFailureKind::PathInvalid,
        domains: vec![domain],
        target_paths: vec![target_path.to_path_buf()],
        lock_file,
        message,
        holder_metadata: None,
    })
}

fn open_lock_file(path: &Path) -> Result<File, BackendFailure> {
    fs_permissions::validate_private_parent(path).map_err(|error| {
        BackendFailure::new(
            StateLockFailureKind::PathInvalid,
            format!("failed to validate lock parent directory: {error}"),
        )
    })?;
    validate_existing_lock_file(path)?;

    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    options
        .mode(PRIVATE_LOCK_FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path).map_err(|error| {
        let kind = if is_symlink_open_error(&error) {
            StateLockFailureKind::PathInvalid
        } else {
            StateLockFailureKind::IoError
        };
        BackendFailure::new(kind, format!("failed to open lock file: {error}"))
    })?;
    validate_open_lock_file(path, &file)?;
    Ok(file)
}

fn validate_existing_lock_file(path: &Path) -> Result<(), BackendFailure> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_lock_metadata(path, &metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(BackendFailure::new(
            StateLockFailureKind::IoError,
            format!("failed to inspect lock file: {error}"),
        )),
    }
}

fn validate_open_lock_file(path: &Path, file: &File) -> Result<(), BackendFailure> {
    let metadata = file.metadata().map_err(|error| {
        BackendFailure::new(
            StateLockFailureKind::IoError,
            format!("failed to inspect open lock file: {error}"),
        )
    })?;
    validate_lock_metadata(path, &metadata)
}

#[cfg(unix)]
fn validate_lock_metadata(path: &Path, metadata: &fs::Metadata) -> Result<(), BackendFailure> {
    if metadata.file_type().is_symlink() {
        return Err(invalid_lock_path(path, "lock file must not be a symlink"));
    }
    if !metadata.is_file() {
        return Err(invalid_lock_path(path, "lock file must be a regular file"));
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(invalid_lock_path(
            path,
            "lock file must be owned by the broker process user",
        ));
    }
    if metadata.nlink() != 1 {
        return Err(invalid_lock_path(
            path,
            "lock file must not have multiple hard links",
        ));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode != PRIVATE_LOCK_FILE_MODE {
        return Err(invalid_lock_path(
            path,
            "lock file must be owner read/write only (0600)",
        ));
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn validate_lock_metadata(path: &Path, metadata: &fs::Metadata) -> Result<(), BackendFailure> {
    if !metadata.is_file() {
        return Err(invalid_lock_path(path, "lock file must be a regular file"));
    }
    Ok(())
}

#[cfg(windows)]
fn validate_lock_metadata(path: &Path, metadata: &fs::Metadata) -> Result<(), BackendFailure> {
    if metadata.file_type().is_symlink()
        || metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
    {
        return Err(invalid_lock_path(path, "lock file must not be a symlink"));
    }
    if !metadata.is_file() {
        return Err(invalid_lock_path(path, "lock file must be a regular file"));
    }
    if metadata.number_of_links() != 1 {
        return Err(invalid_lock_path(
            path,
            "lock file must not have multiple hard links",
        ));
    }
    if metadata.permissions().readonly() {
        return Err(invalid_lock_path(path, "lock file must be writable"));
    }
    Ok(())
}

fn invalid_lock_path(path: &Path, message: &str) -> BackendFailure {
    BackendFailure::new(
        StateLockFailureKind::PathInvalid,
        format!("{}: {message}", path.display()),
    )
}

#[cfg(unix)]
fn lock_file_nonblocking(file: &File, path: &Path) -> Result<(), BackendFailure> {
    let result = unsafe {
        libc::flock(
            std::os::fd::AsRawFd::as_raw_fd(file),
            libc::LOCK_EX | libc::LOCK_NB,
        )
    };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN => {
            Err(BackendFailure::held(
                format!("lock is held: {error}"),
                fs::read_to_string(path).ok(),
            ))
        }
        Some(code) if is_unsupported_lock_errno(code) => Err(BackendFailure::new(
            StateLockFailureKind::Unsupported,
            format!("advisory locking is unsupported: {error}"),
        )),
        _ => Err(BackendFailure::new(
            StateLockFailureKind::IoError,
            format!("failed to acquire advisory lock: {error}"),
        )),
    }
}

#[cfg(windows)]
fn lock_file_nonblocking(file: &File, _path: &Path) -> Result<(), BackendFailure> {
    let mut overlapped = windows_overlapped();
    let result = unsafe {
        windows_sys::Win32::Storage::FileSystem::LockFileEx(
            file.as_raw_handle(),
            windows_sys::Win32::Storage::FileSystem::LOCKFILE_EXCLUSIVE_LOCK
                | windows_sys::Win32::Storage::FileSystem::LOCKFILE_FAIL_IMMEDIATELY,
            0,
            WINDOWS_LOCK_RANGE_LOW,
            WINDOWS_LOCK_RANGE_HIGH,
            &mut overlapped,
        )
    };
    if result != 0 {
        return Ok(());
    }
    let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
    if code == windows_sys::Win32::Foundation::ERROR_LOCK_VIOLATION {
        return Err(BackendFailure::held("lock is held", None));
    }
    if windows_unsupported_lock_error(code) {
        return Err(BackendFailure::new(
            StateLockFailureKind::Unsupported,
            format!("advisory locking is unsupported: Windows error {code}"),
        ));
    }
    Err(BackendFailure::new(
        StateLockFailureKind::IoError,
        format!("failed to acquire advisory lock: Windows error {code}"),
    ))
}

#[cfg(not(unix))]
#[cfg(not(windows))]
fn lock_file_nonblocking(_file: &File, _path: &Path) -> Result<(), BackendFailure> {
    Err(BackendFailure::new(
        StateLockFailureKind::Unsupported,
        "state locks are not implemented on this platform",
    ))
}

#[cfg(unix)]
fn is_unsupported_lock_errno(code: i32) -> bool {
    code == libc::ENOLCK || code == libc::EOPNOTSUPP || code == libc::ENOSYS || code == libc::EINVAL
}

#[cfg(windows)]
fn windows_overlapped() -> windows_sys::Win32::System::IO::OVERLAPPED {
    unsafe { std::mem::zeroed() }
}

#[cfg(windows)]
fn windows_unsupported_lock_error(code: u32) -> bool {
    code == windows_sys::Win32::Foundation::ERROR_INVALID_FUNCTION
        || code == windows_sys::Win32::Foundation::ERROR_CALL_NOT_IMPLEMENTED
        || code == windows_sys::Win32::Foundation::ERROR_NOT_SUPPORTED
        || code == windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER
}

fn write_lock_metadata(file: &mut File, metadata: &StateLockMetadata) -> io::Result<()> {
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    serde_json::to_writer(&mut *file, metadata).map_err(io::Error::other)?;
    file.write_all(b"\n")?;
    file.sync_all()
}

#[cfg(unix)]
fn is_symlink_open_error(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::ELOOP)
}

#[cfg(not(unix))]
fn is_symlink_open_error(_error: &io::Error) -> bool {
    false
}

fn domain_label(domains: &[StateLockDomain]) -> String {
    domains
        .iter()
        .map(|domain| domain.as_str())
        .collect::<Vec<_>>()
        .join("/")
}

fn target_label(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn sanitized_metadata_snippet(metadata: Option<&str>) -> Option<String> {
    let metadata = metadata?.trim();
    if metadata.is_empty() {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(metadata).ok()?;
    let object = value.as_object()?;
    let mut sanitized = serde_json::Map::new();

    insert_sanitized_string(object, &mut sanitized, "program");
    insert_sanitized_string(object, &mut sanitized, "programVersion");
    insert_sanitized_string_array(object, &mut sanitized, "domains");
    if let Some(pid) = object.get("pid").and_then(serde_json::Value::as_u64) {
        sanitized.insert("pid".to_string(), serde_json::Value::from(pid));
    }
    insert_sanitized_string(object, &mut sanitized, "hostname");
    insert_sanitized_string(object, &mut sanitized, "nodeId");
    insert_sanitized_string(object, &mut sanitized, "startedAt");
    insert_sanitized_string(object, &mut sanitized, "configPath");
    insert_sanitized_string_array(object, &mut sanitized, "targetPaths");
    insert_sanitized_string(object, &mut sanitized, "lockFile");

    if sanitized.is_empty() {
        return None;
    }
    serde_json::to_string(&serde_json::Value::Object(sanitized))
        .ok()
        .map(|snippet| truncate_display_string(&snippet, 500))
}

fn insert_sanitized_string(
    source: &serde_json::Map<String, serde_json::Value>,
    target: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
) {
    if let Some(value) = source
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(|value| sanitize_metadata_string(value, 160))
    {
        target.insert(key.to_string(), serde_json::Value::String(value));
    }
}

fn insert_sanitized_string_array(
    source: &serde_json::Map<String, serde_json::Value>,
    target: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
) {
    let Some(values) = source.get(key).and_then(serde_json::Value::as_array) else {
        return;
    };
    let sanitized = values
        .iter()
        .filter_map(serde_json::Value::as_str)
        .take(8)
        .map(|value| serde_json::Value::String(sanitize_metadata_string(value, 160)))
        .collect::<Vec<_>>();
    if !sanitized.is_empty() {
        target.insert(key.to_string(), serde_json::Value::Array(sanitized));
    }
}

fn sanitize_metadata_string(value: &str, max_chars: usize) -> String {
    let mut sanitized = String::new();
    let mut truncated = false;
    for (index, ch) in value.chars().enumerate() {
        if index >= max_chars {
            truncated = true;
            break;
        }
        sanitized.push(if ch.is_control() { ' ' } else { ch });
    }
    if truncated {
        sanitized.push_str("...");
    }
    sanitized
}

fn truncate_display_string(value: &str, max_chars: usize) -> String {
    let mut truncated = String::new();
    let mut chars = value.chars();
    for _ in 0..max_chars {
        let Some(ch) = chars.next() else {
            return value.to_string();
        };
        truncated.push(ch);
    }
    truncated.push_str("...");
    truncated
}

fn hostname() -> String {
    os_host_name().unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuditConfig, AuditStoreType, BrowserAuthConfig, CredentialsConfig, DeploymentConfig,
        IdentityConfig, LimitsConfig, ManagedStoreConfig, ManagementConfig, NetworkConfig,
        PolicyConfig, PortalConfig, ProvidersConfig,
    };
    use std::sync::{Mutex, MutexGuard, OnceLock};
    use tempfile::TempDir;

    #[cfg(unix)]
    use std::os::unix::fs::{PermissionsExt, symlink};

    struct FakeGuard;

    impl HeldStateLock for FakeGuard {}

    struct FakeBackend {
        failures: Mutex<Vec<StateLockFailureKind>>,
        acquired: Mutex<Vec<PathBuf>>,
    }

    impl FakeBackend {
        fn new(failures: Vec<StateLockFailureKind>) -> Self {
            Self {
                failures: Mutex::new(failures),
                acquired: Mutex::new(Vec::new()),
            }
        }
    }

    impl StateLockBackend for FakeBackend {
        fn acquire(
            &self,
            info: &StateLockInfo,
            _metadata: &StateLockMetadata,
        ) -> Result<Box<dyn HeldStateLock>, BackendFailure> {
            self.acquired.lock().unwrap().push(info.identity.clone());
            if let Some(kind) = self.failures.lock().unwrap().pop() {
                return Err(BackendFailure::new(kind, "fake failure"));
            }
            Ok(Box::new(FakeGuard))
        }
    }

    struct CurrentDirGuard {
        _guard: MutexGuard<'static, ()>,
        previous: PathBuf,
    }

    impl CurrentDirGuard {
        fn enter(path: &Path) -> Self {
            static CWD_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
            let guard = CWD_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
            let previous = std::env::current_dir().unwrap();
            std::env::set_current_dir(path).unwrap();
            Self {
                _guard: guard,
                previous,
            }
        }
    }

    impl Drop for CurrentDirGuard {
        fn drop(&mut self) {
            std::env::set_current_dir(&self.previous).unwrap();
        }
    }

    const TEST_NODE_ID: &str = "state-lock-test-node";
    const TEST_HOLDER: StateLockHolder<'static> =
        StateLockHolder::new("example-broker", "1.2.3", TEST_NODE_ID);

    fn config_with_paths(
        managed_store_path: Option<&Path>,
        audit_path: Option<&Path>,
        spool_dir: &Path,
    ) -> BrokerConfig {
        BrokerConfig {
            imports: Default::default(),
            oauth: Default::default(),
            deployment: DeploymentConfig {
                enable_fake_service: true,
                ..DeploymentConfig::default()
            },
            network: NetworkConfig::default(),
            execution_context: None,
            identity: IdentityConfig {
                trusted_callers: BTreeMap::new(),
                mode: "anonymous".to_string(),
                authority: "toml".to_string(),
                sources: Vec::new(),
                groups: Vec::new(),
            },
            credentials: CredentialsConfig::default(),
            managed_store: managed_store_path.map(|path| ManagedStoreConfig {
                kind: "sqlite".to_string(),
                path: path.display().to_string(),
                require_registered_principal_for_invocation: false,
                auto_migrate: true,
            }),
            credential_encryption: None,
            management: ManagementConfig::default(),
            broker_tokens: None,
            browser_auth: BrowserAuthConfig::default(),
            portal: PortalConfig::default(),
            mcp: Default::default(),
            policy: PolicyConfig {
                authority: "toml".to_string(),
                resources: Vec::new(),
                resource_groups: Vec::new(),
                default_decision: "deny".to_string(),
                grants: Vec::new(),
            },
            attribution: crate::AttributionConfig::default(),
            providers: ProvidersConfig::new(crate::tests::test_backend_registry())
                .with(agent_access_fake::FakeProviderConfig::default()),
            gateways: BTreeMap::new(),
            limits: LimitsConfig::new(spool_dir.display().to_string()),
            audit: audit_path
                .map(|path| AuditConfig::new(AuditStoreType::Jsonl, path.display().to_string())),
        }
    }

    #[test]
    fn lock_identity_canonicalizes_equivalent_paths() {
        let temp = TempDir::new().unwrap();
        #[cfg(unix)]
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let store_dir = temp.path().join("state");
        fs_permissions::ensure_private_dir(&store_dir).unwrap();
        let canonical = store_dir.join("managed.sqlite3");
        let equivalent = store_dir.join("..").join("state").join("managed.sqlite3");
        let spool_dir = temp.path().join("spool");

        let first = config_with_paths(Some(&canonical), None, &spool_dir);
        let second = config_with_paths(Some(&equivalent), None, &spool_dir);
        let first_targets = resolve_state_lock_targets(&first).unwrap();
        let second_targets = resolve_state_lock_targets(&second).unwrap();

        let first_store = first_targets
            .iter()
            .find(|target| target.domains == vec![StateLockDomain::ManagedStore])
            .unwrap();
        let second_store = second_targets
            .iter()
            .find(|target| target.domains == vec![StateLockDomain::ManagedStore])
            .unwrap();
        assert_eq!(first_store.identity, second_store.identity);
    }

    #[test]
    fn relative_upload_spool_dir_is_created_and_canonicalized_from_cwd() {
        let temp = TempDir::new().unwrap();
        #[cfg(unix)]
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let _cwd = CurrentDirGuard::enter(temp.path());
        let config = config_with_paths(None, None, Path::new("relative-spool"));

        let targets = resolve_state_lock_targets(&config).unwrap();

        let spool = targets
            .iter()
            .find(|target| target.domains == vec![StateLockDomain::UploadSpool])
            .unwrap();
        assert_eq!(spool.target_paths[0], temp.path().join("relative-spool"));
        assert!(spool.lock_file.ends_with(UPLOAD_SPOOL_LOCK_FILE));
    }

    #[test]
    fn relative_managed_store_path_is_rejected_by_lock_admission_without_creation() {
        let temp = TempDir::new().unwrap();
        #[cfg(unix)]
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let _cwd = CurrentDirGuard::enter(temp.path());
        let config = config_with_paths(
            Some(Path::new("relative-managed/managed.sqlite3")),
            None,
            Path::new("spool"),
        );

        let error = resolve_state_lock_targets(&config).unwrap_err();

        assert_eq!(error.kind(), StateLockFailureKind::PathInvalid);
        assert!(error.operator_message().contains("must be absolute"));
        assert!(!temp.path().join("relative-managed").exists());
    }

    #[test]
    fn audit_lock_identity_matches_audit_file_identity_key() {
        let temp = TempDir::new().unwrap();
        #[cfg(unix)]
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let audit_dir = temp.path().join("audit");
        fs_permissions::ensure_private_dir(&audit_dir).unwrap();
        let audit_path = audit_dir.join("..").join("audit").join("audit.jsonl");
        let spool_dir = temp.path().join("spool");
        let config = config_with_paths(None, Some(&audit_path), &spool_dir);

        let targets = resolve_state_lock_targets(&config).unwrap();
        let audit = targets
            .iter()
            .find(|target| target.domains == vec![StateLockDomain::Audit])
            .unwrap();

        assert_eq!(audit.target_paths[0], audit_file_identity_key(&audit_path));
    }

    #[test]
    fn state_lock_targets_deduplicate_same_underlying_lock_file() {
        let temp = TempDir::new().unwrap();
        #[cfg(unix)]
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let state_path = temp.path().join("shared.sqlite3");
        let spool_dir = temp.path().join("spool");
        let config = config_with_paths(Some(&state_path), Some(&state_path), &spool_dir);

        let targets = resolve_state_lock_targets(&config).unwrap();

        assert_eq!(targets.len(), 2);
        let shared = targets
            .iter()
            .find(|target| target.domains.contains(&StateLockDomain::ManagedStore))
            .unwrap();
        assert_eq!(
            shared.domains,
            vec![StateLockDomain::ManagedStore, StateLockDomain::Audit]
        );
    }

    #[test]
    fn state_lock_names_are_stable_and_distinct_for_distinct_targets() {
        let temp = TempDir::new().unwrap();
        #[cfg(unix)]
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let store = temp.path().join("store.sqlite3");
        let audit = temp.path().join("audit.jsonl");
        let spool_dir = temp.path().join("spool");
        let config = config_with_paths(Some(&store), Some(&audit), &spool_dir);

        let targets = resolve_state_lock_targets(&config).unwrap();
        let lock_files = targets
            .iter()
            .map(|target| target.lock_file.file_name().unwrap().to_owned())
            .collect::<BTreeSet<_>>();

        assert!(lock_files.contains(std::ffi::OsStr::new("store.sqlite3.agent-access.lock")));
        assert!(lock_files.contains(std::ffi::OsStr::new("audit.jsonl.agent-access.lock")));
        assert!(lock_files.contains(std::ffi::OsStr::new(UPLOAD_SPOOL_LOCK_FILE)));
        assert_eq!(lock_files.len(), 3);
    }

    #[test]
    fn fake_backend_surfaces_typed_failures() {
        let temp = TempDir::new().unwrap();
        #[cfg(unix)]
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let config = config_with_paths(None, None, &temp.path().join("spool"));
        for kind in [
            StateLockFailureKind::Held,
            StateLockFailureKind::Unsupported,
            StateLockFailureKind::PathInvalid,
            StateLockFailureKind::IoError,
        ] {
            let backend = FakeBackend::new(vec![kind]);
            let error = StateLockSet::acquire_for_config_with_backend(
                &config,
                Path::new("/tmp/config.toml"),
                &TEST_HOLDER,
                &[],
                &backend,
            )
            .unwrap_err();
            assert_eq!(error.kind(), kind);
        }
    }

    #[test]
    fn unchanged_candidate_reuses_existing_lock_handle() {
        let temp = TempDir::new().unwrap();
        #[cfg(unix)]
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let config = config_with_paths(None, None, &temp.path().join("spool"));
        let first = StateLockSet::acquire_for_config(
            &config,
            Path::new("/tmp/config.toml"),
            &TEST_HOLDER,
            None,
        )
        .unwrap();
        let identity = first.infos()[0].identity.clone();

        let second = StateLockSet::acquire_for_config(
            &config,
            Path::new("/tmp/config.toml"),
            &TEST_HOLDER,
            Some(first.as_ref()),
        )
        .unwrap();

        assert!(second.shares_identity_handle_with(first.as_ref(), &identity));
    }

    #[test]
    fn reused_lock_handle_keeps_generation_local_domain_info() {
        let temp = TempDir::new().unwrap();
        #[cfg(unix)]
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let shared_path = temp.path().join("shared.sqlite3");
        let spool_dir = temp.path().join("spool");
        let store_only = config_with_paths(Some(&shared_path), None, &spool_dir);
        let store_and_audit = config_with_paths(Some(&shared_path), Some(&shared_path), &spool_dir);

        let first = StateLockSet::acquire_for_config(
            &store_only,
            Path::new("/tmp/config.toml"),
            &TEST_HOLDER,
            None,
        )
        .unwrap();
        let shared_identity = first
            .infos()
            .into_iter()
            .find(|info| info.domains == vec![StateLockDomain::ManagedStore])
            .unwrap()
            .identity;

        let second = StateLockSet::acquire_for_config(
            &store_and_audit,
            Path::new("/tmp/config.toml"),
            &TEST_HOLDER,
            Some(first.as_ref()),
        )
        .unwrap();
        assert!(second.shares_identity_handle_with(first.as_ref(), &shared_identity));
        assert_eq!(
            domains_for_identity(first.as_ref(), &shared_identity),
            vec![StateLockDomain::ManagedStore]
        );
        assert_eq!(
            domains_for_identity(second.as_ref(), &shared_identity),
            vec![StateLockDomain::ManagedStore, StateLockDomain::Audit]
        );

        let third = StateLockSet::acquire_for_config(
            &store_only,
            Path::new("/tmp/config.toml"),
            &TEST_HOLDER,
            Some(second.as_ref()),
        )
        .unwrap();
        assert!(third.shares_identity_handle_with(second.as_ref(), &shared_identity));
        assert_eq!(
            domains_for_identity(second.as_ref(), &shared_identity),
            vec![StateLockDomain::ManagedStore, StateLockDomain::Audit]
        );
        assert_eq!(
            domains_for_identity(third.as_ref(), &shared_identity),
            vec![StateLockDomain::ManagedStore]
        );
    }

    fn domains_for_identity(set: &StateLockSet, identity: &Path) -> Vec<StateLockDomain> {
        set.infos()
            .into_iter()
            .find(|info| info.identity == identity)
            .unwrap()
            .domains
    }

    #[test]
    fn held_lock_metadata_diagnostics_are_allowlisted_and_sanitized() {
        let metadata = serde_json::json!({
            "program": "example-broker",
            "programVersion": "1.2.3",
            "domains": ["audit"],
            "pid": 12345,
            "hostname": "broker\nhost",
            "nodeId": "broker-prod-1",
            "startedAt": "2026-06-22T03:28:33Z",
            "configPath": "/etc/agent-access/config.toml",
            "targetPaths": [format!("/var/log/{}", "a".repeat(220))],
            "lockFile": "/var/log/agent-access/audit.jsonl.agent-access.lock",
            "token": "secret-token-material"
        })
        .to_string();
        let error = StateLockError {
            kind: StateLockFailureKind::Held,
            domains: vec![StateLockDomain::Audit],
            target_paths: vec![PathBuf::from("/var/log/agent-access/audit.jsonl")],
            lock_file: PathBuf::from("/var/log/agent-access/audit.jsonl.agent-access.lock"),
            message: "held".to_string(),
            holder_metadata: Some(metadata),
        };

        let message = error.operator_message();

        assert!(message.contains("\"program\":\"example-broker\""));
        assert!(message.contains("\"programVersion\":\"1.2.3\""));
        assert!(message.contains("broker host"));
        assert!(message.contains("\"nodeId\":\"broker-prod-1\""));
        assert!(message.contains("aaa..."));
        assert!(!message.contains("secret-token-material"));
        assert!(!message.contains('\n'));
    }

    #[test]
    fn malformed_lock_metadata_is_not_echoed_in_diagnostics() {
        let error = StateLockError {
            kind: StateLockFailureKind::Held,
            domains: vec![StateLockDomain::UploadSpool],
            target_paths: vec![PathBuf::from("/var/spool/agent-access")],
            lock_file: PathBuf::from("/var/spool/agent-access/.agent-access-broker.spool.lock"),
            message: "held".to_string(),
            holder_metadata: Some("not-json-secret-material".to_string()),
        };

        let message = error.operator_message();

        assert!(!message.contains("not-json-secret-material"));
        assert!(!message.contains("holder metadata"));
    }

    #[cfg(unix)]
    #[test]
    fn hostname_uses_os_source_when_hostname_env_is_absent() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("state_lock::tests::hostname_child_without_env_uses_os_source")
            .arg("--nocapture")
            .env("AGENT_ACCESS_CORE_HOSTNAME_CHILD", "1")
            .env_remove("HOSTNAME")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "hostname child probe failed: status={}; stdout={}; stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(unix)]
    #[test]
    fn hostname_child_without_env_uses_os_source() {
        if std::env::var("AGENT_ACCESS_CORE_HOSTNAME_CHILD").is_err() {
            return;
        }
        assert!(std::env::var("HOSTNAME").is_err());
        assert_eq!(hostname(), expected_unix_hostname().unwrap());
    }

    #[cfg(unix)]
    fn expected_unix_hostname() -> Option<String> {
        let mut buffer = [0_u8; 256];
        let result = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };
        if result != 0 {
            return None;
        }
        let length = buffer
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(buffer.len());
        String::from_utf8(buffer[..length].to_vec())
            .ok()
            .filter(|hostname| !hostname.trim().is_empty())
    }

    #[test]
    fn stale_unlocked_lock_file_is_reused_and_metadata_overwritten() {
        let temp = TempDir::new().unwrap();
        #[cfg(unix)]
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let config = config_with_paths(None, None, &temp.path().join("spool"));
        let target = resolve_state_lock_targets(&config).unwrap().remove(0);
        fs::write(&target.lock_file, b"stale").unwrap();
        #[cfg(unix)]
        fs::set_permissions(&target.lock_file, fs::Permissions::from_mode(0o600)).unwrap();

        let locks = StateLockSet::acquire_for_config(
            &config,
            Path::new("/tmp/config.toml"),
            &TEST_HOLDER,
            None,
        )
        .unwrap();

        assert!(locks.has_identity(&target.identity));
        let metadata = fs::read_to_string(&target.lock_file).unwrap();
        assert!(metadata.contains("\"program\":\"example-broker\""));
        assert!(metadata.contains("\"programVersion\":\"1.2.3\""));
        assert!(metadata.contains("\"nodeId\":\"state-lock-test-node\""));
        assert!(!metadata.contains("stale"));
    }

    #[cfg(unix)]
    #[test]
    fn invalid_lock_files_are_rejected() {
        let temp = TempDir::new().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let spool = temp.path().join("spool");
        let config = config_with_paths(None, None, &spool);
        let target = resolve_state_lock_targets(&config).unwrap().remove(0);

        fs::write(&target.lock_file, b"bad").unwrap();
        fs::set_permissions(&target.lock_file, fs::Permissions::from_mode(0o644)).unwrap();
        let error = StateLockSet::acquire_for_config(
            &config,
            Path::new("/tmp/config.toml"),
            &TEST_HOLDER,
            None,
        )
        .unwrap_err();
        assert_eq!(error.kind(), StateLockFailureKind::PathInvalid);

        fs::remove_file(&target.lock_file).unwrap();
        let hard_link = target.lock_file.with_extension("hard");
        fs::write(&target.lock_file, b"bad").unwrap();
        fs::set_permissions(&target.lock_file, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&target.lock_file, &hard_link).unwrap();
        let error = StateLockSet::acquire_for_config(
            &config,
            Path::new("/tmp/config.toml"),
            &TEST_HOLDER,
            None,
        )
        .unwrap_err();
        assert_eq!(error.kind(), StateLockFailureKind::PathInvalid);

        fs::remove_file(&hard_link).unwrap();
        fs::remove_file(&target.lock_file).unwrap();
        let symlink_target = target.lock_file.with_extension("target");
        fs::write(&symlink_target, b"bad").unwrap();
        symlink(&symlink_target, &target.lock_file).unwrap();
        let error = StateLockSet::acquire_for_config(
            &config,
            Path::new("/tmp/config.toml"),
            &TEST_HOLDER,
            None,
        )
        .unwrap_err();
        assert_eq!(error.kind(), StateLockFailureKind::PathInvalid);
    }

    #[test]
    fn candidate_only_locks_release_after_failed_admission() {
        let temp = TempDir::new().unwrap();
        #[cfg(unix)]
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let active = config_with_paths(None, None, &temp.path().join("active-spool"));
        let candidate = config_with_paths(None, None, &temp.path().join("candidate-spool"));
        let active_locks = StateLockSet::acquire_for_config(
            &active,
            Path::new("/tmp/config.toml"),
            &TEST_HOLDER,
            None,
        )
        .unwrap();
        let candidate_locks = StateLockSet::acquire_for_config(
            &candidate,
            Path::new("/tmp/config.toml"),
            &TEST_HOLDER,
            Some(active_locks.as_ref()),
        )
        .unwrap();
        drop(candidate_locks);

        let reacquired = StateLockSet::acquire_for_config(
            &candidate,
            Path::new("/tmp/config.toml"),
            &TEST_HOLDER,
            None,
        )
        .unwrap();
        assert_eq!(reacquired.infos().len(), 1);
    }

    #[test]
    fn old_generation_locks_remain_held_while_referenced() {
        let temp = TempDir::new().unwrap();
        #[cfg(unix)]
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let old = config_with_paths(None, None, &temp.path().join("old-spool"));
        let old_locks = StateLockSet::acquire_for_config(
            &old,
            Path::new("/tmp/config.toml"),
            &TEST_HOLDER,
            None,
        )
        .unwrap();
        let conflict = StateLockSet::acquire_for_config(
            &old,
            Path::new("/tmp/config.toml"),
            &TEST_HOLDER,
            None,
        )
        .unwrap_err();
        assert_eq!(conflict.kind(), StateLockFailureKind::Held);

        drop(old_locks);
        let reacquired = StateLockSet::acquire_for_config(
            &old,
            Path::new("/tmp/config.toml"),
            &TEST_HOLDER,
            None,
        )
        .unwrap();
        assert_eq!(reacquired.infos().len(), 1);
    }

    #[test]
    fn differently_named_programs_contend_for_the_same_state() {
        let temp = TempDir::new().unwrap();
        #[cfg(unix)]
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let store = temp.path().join("store.sqlite3");
        let audit = temp.path().join("audit.jsonl");
        let config = config_with_paths(Some(&store), Some(&audit), &temp.path().join("spool"));
        let held = StateLockSet::acquire_for_config(
            &config,
            Path::new("/tmp/config.toml"),
            &TEST_HOLDER,
            None,
        )
        .unwrap();
        let other = StateLockHolder::new("downstream-broker", "9.0.0", "other-node");
        let conflict =
            StateLockSet::acquire_for_config(&config, Path::new("/tmp/other.toml"), &other, None)
                .unwrap_err();
        assert_eq!(conflict.kind(), StateLockFailureKind::Held);
        // The holder never names the lock files.
        assert_eq!(
            conflict.lock_file(),
            resolve_state_lock_targets(&config).unwrap()[0].lock_file
        );
        // The diagnostic names the holder's program and version.
        let message = conflict.operator_message();
        assert!(
            message.contains("\"program\":\"example-broker\""),
            "{message}"
        );
        assert!(
            message.contains("\"programVersion\":\"1.2.3\""),
            "{message}"
        );

        drop(held);
        let acquired =
            StateLockSet::acquire_for_config(&config, Path::new("/tmp/other.toml"), &other, None)
                .unwrap();
        let metadata = fs::read_to_string(&acquired.infos()[0].lock_file).unwrap();
        assert!(metadata.contains("\"program\":\"downstream-broker\""));
    }

    #[cfg(unix)]
    #[test]
    fn unix_guard_drop_releases_lock_while_duplicated_descriptor_remains_open() {
        let temp = TempDir::new().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("state.lock");
        let file = open_lock_file(&path).unwrap();
        lock_file_nonblocking(&file, &path).unwrap();
        let guard = FileStateLock { file };
        // dup shares the open file description just like a descriptor inherited
        // by fork. Holding it here reproduces that lifetime deterministically.
        let inherited = guard.file.try_clone().unwrap();
        let contender = open_lock_file(&path).unwrap();
        assert_eq!(
            lock_file_nonblocking(&contender, &path).unwrap_err().kind,
            StateLockFailureKind::Held
        );

        drop(guard);
        lock_file_nonblocking(&contender, &path).unwrap();
        let contender = FileStateLock { file: contender };
        drop(inherited);
        let third = open_lock_file(&path).unwrap();
        assert_eq!(
            lock_file_nonblocking(&third, &path).unwrap_err().kind,
            StateLockFailureKind::Held,
            "closing the old description must not release the new owner's lock"
        );
        drop(contender);
        lock_file_nonblocking(&third, &path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unix_flock_survives_closing_unrelated_descriptor_for_second_process() {
        let temp = TempDir::new().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let config = config_with_paths(None, None, &temp.path().join("spool"));
        let locks = StateLockSet::acquire_for_config(
            &config,
            Path::new("/tmp/config.toml"),
            &TEST_HOLDER,
            None,
        )
        .unwrap();
        let lock_file = locks.infos()[0].lock_file.clone();
        let unrelated = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_file)
            .unwrap();
        drop(unrelated);

        run_child_lock_probe(&config.limits.upload_spool_dir, "held");
        drop(locks);
        run_child_lock_probe(&config.limits.upload_spool_dir, "free");
    }

    #[cfg(unix)]
    #[test]
    fn state_lock_child_try_acquire_from_env() {
        let Ok(spool_dir) = std::env::var("AGENT_ACCESS_CORE_LOCK_CHILD_SPOOL") else {
            return;
        };
        let expectation = std::env::var("AGENT_ACCESS_CORE_LOCK_CHILD_EXPECT").unwrap_or_default();
        let config = config_with_paths(None, None, Path::new(&spool_dir));
        let result = StateLockSet::acquire_for_config(
            &config,
            Path::new("/tmp/config.toml"),
            &TEST_HOLDER,
            None,
        );
        match expectation.as_str() {
            "held" => {
                let error = result.unwrap_err();
                assert_eq!(error.kind(), StateLockFailureKind::Held);
            }
            "free" => {
                assert!(result.is_ok());
            }
            other => panic!("unknown lock child expectation {other}"),
        }
    }

    #[cfg(unix)]
    fn run_child_lock_probe(spool_dir: &str, expectation: &str) {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("state_lock::tests::state_lock_child_try_acquire_from_env")
            .arg("--nocapture")
            .env("AGENT_ACCESS_CORE_LOCK_CHILD_SPOOL", spool_dir)
            .env("AGENT_ACCESS_CORE_LOCK_CHILD_EXPECT", expectation)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child lock probe failed: status={}; stdout={}; stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
