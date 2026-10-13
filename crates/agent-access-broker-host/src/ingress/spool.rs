use agent_access_provider::{ProviderError, ReasonCode};
use std::collections::BTreeMap;
use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, Mutex};

pub(crate) struct UploadSpoolBudgets {
    directories: Mutex<BTreeMap<PathBuf, UploadSpoolCounter>>,
}

struct UploadSpoolCounter {
    used_bytes: u64,
    reservations: usize,
}

pub(crate) struct UploadSpoolReservation {
    budgets: Arc<UploadSpoolBudgets>,
    directory: PathBuf,
    bytes: u64,
}

impl UploadSpoolBudgets {
    pub(crate) fn new() -> Self {
        Self {
            directories: Mutex::new(BTreeMap::new()),
        }
    }

    pub(crate) fn reserve(
        self: &Arc<Self>,
        directory: &FsPath,
        max_bytes: u64,
        bytes: u64,
    ) -> Result<UploadSpoolReservation, ProviderError> {
        if bytes > max_bytes {
            return Err(upload_spool_capacity_error());
        }
        let directory = canonical_spool_dir(directory);
        let mut directories = self.directories.lock().unwrap();
        let counter = directories
            .entry(directory.clone())
            .or_insert(UploadSpoolCounter {
                used_bytes: 0,
                reservations: 0,
            });
        if max_bytes.saturating_sub(counter.used_bytes) < bytes {
            return Err(upload_spool_capacity_error());
        }
        counter.used_bytes += bytes;
        counter.reservations += 1;
        Ok(UploadSpoolReservation {
            budgets: self.clone(),
            directory,
            bytes,
        })
    }
}

impl Drop for UploadSpoolReservation {
    fn drop(&mut self) {
        let mut directories = self.budgets.directories.lock().unwrap();
        if let Some(counter) = directories.get_mut(&self.directory) {
            counter.used_bytes = counter.used_bytes.saturating_sub(self.bytes);
            counter.reservations = counter.reservations.saturating_sub(1);
            if counter.used_bytes == 0 && counter.reservations == 0 {
                directories.remove(&self.directory);
            }
        }
    }
}

fn canonical_spool_dir(path: &FsPath) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn upload_spool_capacity_error() -> ProviderError {
    ProviderError::deny(
        ReasonCode::AttachmentSizeDenied,
        "upload spool capacity is exhausted",
    )
}
