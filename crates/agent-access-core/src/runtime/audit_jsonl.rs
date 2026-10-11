//! The JSONL audit storage backend (`audit.type = "jsonl"`): one JSON line
//! per record, size rotation to `<file>.<UTC timestamp>Z.<uuid>`, age-based
//! retention of rotated files, and the configured durability.

use super::{
    AUDIT_RETENTION_PRUNE_INTERVAL, AuditAppendEntry, AuditAppendKind, AuditAppendOutcome,
    AuditFailureClass, AuditFailureSet, AuditHealthChange, AuditMaintenanceOutcome,
    AuditMaintenanceProgress, AuditStorage, AuditStorageConfig, AuditStorageOutcome,
    AuditWriterTestEventKind, emit_audit_writer_test_event,
};
use crate::AuditDurability;
use crate::fs_permissions;
use chrono::{NaiveDateTime, Utc};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use uuid::Uuid;

/// JSONL-only settings.
pub(super) struct JsonlStorageConfig {
    pub(super) rotate_bytes: u64,
}

pub(super) struct JsonlAuditStorage {
    config: AuditStorageConfig,
    rotate_bytes: u64,
    parent_ready: bool,
    last_prune: Option<SystemTime>,
}

/// Why a JSONL append failed.
enum JsonlAppendError {
    Rotation(std::io::Error),
    Write(std::io::Error),
}

impl JsonlAuditStorage {
    /// Opening is lazy: the parent directory is created and validated by the
    /// first append or probe, as the state lock already created it at
    /// startup.
    pub(super) fn open(config: AuditStorageConfig, jsonl: JsonlStorageConfig) -> Self {
        Self {
            config,
            rotate_bytes: jsonl.rotate_bytes,
            parent_ready: false,
            last_prune: None,
        }
    }

    fn append_record(
        &mut self,
        entry: &AuditAppendEntry<'_>,
    ) -> Result<(bool, bool), JsonlAppendError> {
        self.ensure_parent_once().map_err(JsonlAppendError::Write)?;
        self.validate_parent().map_err(JsonlAppendError::Write)?;
        fs_permissions::restrict_existing_file(&self.config.path)
            .map_err(JsonlAppendError::Write)?;
        let line = serde_json::to_string(entry.record)
            .map_err(|error| JsonlAppendError::Write(std::io::Error::other(error)))?;
        let rotated = self.rotate_if_needed(line.len() as u64 + 1)?;
        let write = || -> std::io::Result<()> {
            let mut file = fs_permissions::open_private_append(&self.config.path)?;
            file.write_all(line.as_bytes())?;
            file.write_all(b"\n")?;
            self.apply_file_durability(&file)
        };
        write().map_err(JsonlAppendError::Write)?;
        Ok((rotated, self.mark_prune_due_if_due()))
    }

    fn ensure_parent_once(&mut self) -> std::io::Result<()> {
        if self.parent_ready {
            return Ok(());
        }
        if let Some(parent) = self.config.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs_permissions::ensure_private_dir(parent)?;
        }
        self.parent_ready = true;
        Ok(())
    }

    fn rotate_if_needed(&mut self, next_bytes: u64) -> Result<bool, JsonlAppendError> {
        let Ok(metadata) = fs::metadata(&self.config.path) else {
            return Ok(false);
        };
        if metadata.len() == 0 || metadata.len().saturating_add(next_bytes) <= self.rotate_bytes {
            return Ok(false);
        }
        if self.config.durability != AuditDurability::Write {
            let file = fs_permissions::open_private_append(&self.config.path)
                .map_err(JsonlAppendError::Write)?;
            self.apply_file_durability(&file)
                .map_err(JsonlAppendError::Write)?;
        }
        let rotated = rotated_audit_path(&self.config.path);
        fs::rename(&self.config.path, &rotated).map_err(JsonlAppendError::Rotation)?;
        if self.config.durability != AuditDurability::Write {
            self.sync_parent_dir().map_err(JsonlAppendError::Rotation)?;
        }
        Ok(true)
    }

    fn mark_prune_due_if_due(&mut self) -> bool {
        let now = SystemTime::now();
        let due = self
            .last_prune
            .and_then(|timestamp| now.duration_since(timestamp).ok())
            .is_none_or(|age| age >= AUDIT_RETENTION_PRUNE_INTERVAL);
        if due {
            self.last_prune = Some(now);
        }
        due
    }

    /// Deletes rotated files older than `retention_days`. Only names that
    /// rotation produces are candidates; the state lock file and any other
    /// file that merely shares the `<file>.` prefix are never deleted.
    fn prune_retained(&mut self) -> std::io::Result<()> {
        emit_audit_writer_test_event(&self.config.path_label, AuditWriterTestEventKind::Prune);
        self.validate_parent()?;
        let Some(parent) = self.config.path.parent() else {
            return Ok(());
        };
        let Some(file_name) = self
            .config
            .path
            .file_name()
            .and_then(|value| value.to_str())
        else {
            return Ok(());
        };
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        let retention = Duration::from_secs(self.config.retention_days as u64 * 24 * 60 * 60);
        let now = SystemTime::now();
        let mut removed = false;
        for entry in fs::read_dir(parent)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !is_rotated_audit_file_name(file_name, name) {
                continue;
            }
            let metadata = entry.metadata()?;
            let Ok(modified) = metadata.modified() else {
                continue;
            };
            if now.duration_since(modified).unwrap_or_default() > retention {
                fs::remove_file(entry.path())?;
                removed = true;
            }
        }
        if removed && self.config.durability != AuditDurability::Write {
            self.sync_parent_dir()?;
        }
        Ok(())
    }

    fn validate_parent(&self) -> std::io::Result<()> {
        fs_permissions::validate_private_parent(&self.config.path)
    }

    fn probe_writable(&mut self) -> std::io::Result<()> {
        self.ensure_parent_once()?;
        self.validate_parent()?;
        self.check_directory_mutations()?;
        let file = fs_permissions::open_private_append(&self.config.path)?;
        self.apply_file_durability(&file)
    }

    fn check_directory_mutations(&self) -> std::io::Result<()> {
        let Some(parent) = self.config.path.parent() else {
            return Ok(());
        };
        if parent.as_os_str().is_empty() {
            return Ok(());
        }
        let probe = parent.join(format!(".agent-access-audit-probe-{}", Uuid::new_v4()));
        let renamed = parent.join(format!(".agent-access-audit-probe-{}", Uuid::new_v4()));
        let result = (|| {
            let mut file = fs_permissions::open_private_create_new(&probe)?;
            file.write_all(b"x")?;
            self.apply_file_durability(&file)?;
            fs::rename(&probe, &renamed)?;
            if self.config.durability != AuditDurability::Write {
                self.sync_parent_dir()?;
            }
            fs::remove_file(&renamed)?;
            if self.config.durability != AuditDurability::Write {
                self.sync_parent_dir()?;
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&probe);
            let _ = fs::remove_file(&renamed);
        }
        result
    }

    fn apply_file_durability(&self, file: &fs::File) -> std::io::Result<()> {
        match self.config.durability {
            AuditDurability::Write => Ok(()),
            AuditDurability::SyncData => {
                emit_audit_writer_test_event(
                    &self.config.path_label,
                    AuditWriterTestEventKind::FileSync(AuditDurability::SyncData),
                );
                file.sync_data()
            }
            AuditDurability::SyncAll => {
                emit_audit_writer_test_event(
                    &self.config.path_label,
                    AuditWriterTestEventKind::FileSync(AuditDurability::SyncAll),
                );
                file.sync_all()
            }
        }
    }

    fn sync_parent_dir(&self) -> std::io::Result<()> {
        let Some(parent) = self.config.path.parent() else {
            return Ok(());
        };
        if parent.as_os_str().is_empty() {
            return Ok(());
        }
        emit_audit_writer_test_event(
            &self.config.path_label,
            AuditWriterTestEventKind::ParentDirSync(self.config.durability),
        );
        fs::File::open(parent)?.sync_all()
    }
}

impl AuditStorage for JsonlAuditStorage {
    fn append_batch(
        &mut self,
        entries: &[AuditAppendEntry<'_>],
        _recorded: AuditFailureSet,
    ) -> AuditAppendOutcome {
        let mut maintenance_due = false;
        let entries = entries
            .iter()
            .map(|entry| match self.append_record(entry) {
                Ok((rotated, prune_due)) => {
                    maintenance_due |= prune_due;
                    AuditStorageOutcome {
                        result: Ok(()),
                        health: append_success_change(entry.kind, rotated),
                    }
                }
                Err(JsonlAppendError::Rotation(error)) => AuditStorageOutcome {
                    result: Err(error),
                    health: append_failure_change(entry.kind, true),
                },
                Err(JsonlAppendError::Write(error)) => AuditStorageOutcome {
                    result: Err(error),
                    health: append_failure_change(entry.kind, false),
                },
            })
            .collect();
        AuditAppendOutcome {
            entries,
            health: AuditHealthChange::default(),
            maintenance_due,
        }
    }

    fn probe(&mut self, _recorded: AuditFailureSet) -> AuditStorageOutcome {
        let result = self.probe_writable();
        let health = if result.is_ok() {
            probe_success_change()
        } else {
            AuditHealthChange {
                mark: AuditFailureSet::of(&[AuditFailureClass::Probe]),
                clear: AuditFailureSet::EMPTY,
            }
        };
        AuditStorageOutcome { result, health }
    }

    /// Retention is one slice: pruning rotated files.
    fn run_maintenance_slice(&mut self) -> AuditMaintenanceOutcome {
        let result = self.prune_retained();
        let prune = AuditFailureSet::of(&[AuditFailureClass::Prune]);
        let health = if result.is_ok() {
            AuditHealthChange {
                mark: AuditFailureSet::EMPTY,
                clear: prune,
            }
        } else {
            AuditHealthChange {
                mark: prune,
                clear: AuditFailureSet::EMPTY,
            }
        };
        AuditMaintenanceOutcome {
            operation: "prune",
            result,
            health,
            progress: AuditMaintenanceProgress::Done,
        }
    }

    fn finishes_maintenance_at_shutdown(&self) -> bool {
        true
    }

    fn close(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A successful required append clears `Append` and `TerminalWrite`; a
/// successful terminal append clears `TerminalWrite`. Either also clears
/// `Rotation` when it rotated the file.
fn append_success_change(kind: AuditAppendKind, rotated: bool) -> AuditHealthChange {
    let mut clear = AuditFailureSet::of(&[AuditFailureClass::TerminalWrite]);
    if kind == AuditAppendKind::Required {
        clear = clear.with(AuditFailureClass::Append);
    }
    if rotated {
        clear = clear.with(AuditFailureClass::Rotation);
    }
    AuditHealthChange {
        mark: AuditFailureSet::EMPTY,
        clear,
    }
}

/// A failed rotation records `Rotation` (for a required append, instead of
/// `Append`); any failed terminal append records `TerminalWrite`.
fn append_failure_change(kind: AuditAppendKind, rotation: bool) -> AuditHealthChange {
    let mark = match (kind, rotation) {
        (AuditAppendKind::Required, true) => AuditFailureSet::of(&[AuditFailureClass::Rotation]),
        (AuditAppendKind::Required, false) => AuditFailureSet::of(&[AuditFailureClass::Append]),
        (AuditAppendKind::Terminal, true) => AuditFailureSet::of(&[
            AuditFailureClass::Rotation,
            AuditFailureClass::TerminalWrite,
        ]),
        (AuditAppendKind::Terminal, false) => {
            AuditFailureSet::of(&[AuditFailureClass::TerminalWrite])
        }
    };
    AuditHealthChange {
        mark,
        clear: AuditFailureSet::EMPTY,
    }
}

/// A successful JSONL probe clears every class except `WriterExit`.
pub(super) fn probe_success_change() -> AuditHealthChange {
    AuditHealthChange {
        mark: AuditFailureSet::EMPTY,
        clear: AuditFailureSet::recoverable(),
    }
}

const ROTATED_TIMESTAMP_FORMAT: &str = "%Y%m%dT%H%M%S%.fZ";

fn rotated_audit_path(path: &Path) -> PathBuf {
    let timestamp = Utc::now().format(ROTATED_TIMESTAMP_FORMAT);
    let suffix = Uuid::new_v4();
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("audit.jsonl");
    path.with_file_name(format!("{file_name}.{timestamp}.{suffix}"))
}

/// Whether `candidate` is a name [`rotated_audit_path`] produces for
/// `file_name`: `<file_name>.<%Y%m%dT%H%M%S%.fZ>.<hyphenated lowercase UUID>`,
/// where the fraction is absent or 3, 6, or 9 digits.
fn is_rotated_audit_file_name(file_name: &str, candidate: &str) -> bool {
    let Some(rest) = candidate
        .strip_prefix(file_name)
        .and_then(|rest| rest.strip_prefix('.'))
    else {
        return false;
    };
    let Some((timestamp, suffix)) = rest.split_once("Z.") else {
        return false;
    };
    let (seconds, fraction) = match timestamp.split_once('.') {
        Some((seconds, fraction)) => (seconds, Some(fraction)),
        None => (timestamp, None),
    };
    seconds.len() == 15
        && seconds.bytes().all(|byte| byte.is_ascii_alphanumeric())
        && NaiveDateTime::parse_from_str(seconds, "%Y%m%dT%H%M%S").is_ok()
        && fraction.is_none_or(|fraction| {
            matches!(fraction.len(), 3 | 6 | 9)
                && fraction.bytes().all(|byte| byte.is_ascii_digit())
        })
        && Uuid::try_parse(suffix).is_ok_and(|uuid| uuid.hyphenated().to_string() == suffix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotated_names_round_trip_through_the_prune_pattern() {
        let path = Path::new("/var/log/agent-access/audit.jsonl");
        for _ in 0..64 {
            let rotated = rotated_audit_path(path);
            let name = rotated.file_name().unwrap().to_str().unwrap();
            assert!(is_rotated_audit_file_name("audit.jsonl", name), "{name}");
        }
    }

    #[test]
    fn prune_pattern_matches_only_rotated_names() {
        let uuid = "0191f2a4-8d4e-4b8a-9c2e-6f1d2a3b4c5d";
        for rotated in [
            format!("audit.jsonl.20260926T101112Z.{uuid}"),
            format!("audit.jsonl.20260926T101112.123Z.{uuid}"),
            format!("audit.jsonl.20260926T101112.123456Z.{uuid}"),
            format!("audit.jsonl.20260926T101112.123456789Z.{uuid}"),
        ] {
            assert!(
                is_rotated_audit_file_name("audit.jsonl", &rotated),
                "{rotated}"
            );
        }
        for other in [
            "audit.jsonl".to_string(),
            "audit.jsonl.agent-access.lock".to_string(),
            "audit.jsonl.bak".to_string(),
            "audit.jsonl.20260926T101112Z.old".to_string(),
            format!("audit.jsonl.20260926T101112Z.{}", uuid.to_uppercase()),
            format!("audit.jsonl.20260926T101112Z.{uuid}.gz"),
            format!("audit.jsonl.20260926T101112.12Z.{uuid}"),
            format!("audit.jsonl.20261326T101112Z.{uuid}"),
            format!("audit.jsonl.2026092T101112Z.{uuid}"),
            format!("audit.jsonl20260926T101112Z.{uuid}"),
            format!("other.jsonl.20260926T101112Z.{uuid}"),
            format!("audit.jsonl.x.20260926T101112Z.{uuid}"),
        ] {
            assert!(
                !is_rotated_audit_file_name("audit.jsonl", &other),
                "{other}"
            );
        }
    }

    #[test]
    fn jsonl_health_changes_follow_per_class_clearing_rules() {
        use AuditFailureClass::*;
        let set = |classes: &[AuditFailureClass]| AuditFailureSet::of(classes);

        assert_eq!(
            append_success_change(AuditAppendKind::Required, false).clear,
            set(&[Append, TerminalWrite])
        );
        assert_eq!(
            append_success_change(AuditAppendKind::Required, true).clear,
            set(&[Append, TerminalWrite, Rotation])
        );
        assert_eq!(
            append_success_change(AuditAppendKind::Terminal, false).clear,
            set(&[TerminalWrite])
        );
        assert_eq!(
            append_success_change(AuditAppendKind::Terminal, true).clear,
            set(&[TerminalWrite, Rotation])
        );
        assert_eq!(
            append_failure_change(AuditAppendKind::Required, false).mark,
            set(&[Append])
        );
        assert_eq!(
            append_failure_change(AuditAppendKind::Required, true).mark,
            set(&[Rotation])
        );
        assert_eq!(
            append_failure_change(AuditAppendKind::Terminal, false).mark,
            set(&[TerminalWrite])
        );
        assert_eq!(
            append_failure_change(AuditAppendKind::Terminal, true).mark,
            set(&[Rotation, TerminalWrite])
        );
        assert_eq!(
            probe_success_change().clear,
            set(&[Append, Rotation, Prune, Probe, TerminalWrite])
        );
    }
}
