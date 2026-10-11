use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

#[cfg(unix)]
const PRIVATE_DIR_MODE: u32 = 0o700;
#[cfg(unix)]
const PRIVATE_FILE_MODE: u32 = 0o600;

pub(crate) fn ensure_private_dir(path: &Path) -> io::Result<()> {
    if path.as_os_str().is_empty() {
        return Ok(());
    }

    #[cfg(unix)]
    {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(PRIVATE_DIR_MODE);
        builder.create(path)?;
        validate_private_dir(path)
    }

    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)
    }
}

pub(crate) fn open_private_append(path: &Path) -> io::Result<File> {
    validate_private_parent(path)?;
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path)?;
    restrict_open_file(&file)?;
    Ok(file)
}

pub(crate) fn open_private_create_new(path: &Path) -> io::Result<File> {
    validate_private_parent(path)?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path)?;
    restrict_open_file(&file)?;
    Ok(file)
}

pub(crate) fn restrict_existing_file(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW);
        match options.open(path) {
            Ok(file) => restrict_open_file(&file),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// Creates `path` as a new owner-only file, or restricts the existing file
/// by path with [`restrict_private_file_by_path`]. For SQLite databases: a
/// newly created inode holds no locks, so creating it through a descriptor
/// is safe, but an existing database may already be open in this process.
pub(crate) fn ensure_private_file_by_path(path: &Path) -> io::Result<()> {
    match open_private_create_new(path) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            restrict_private_file_by_path(path)
        }
        Err(error) => Err(error),
    }
}

/// Restricts the existing file at `path` to an owner-only (0600) regular
/// file owned by the broker process user with a single link, without
/// opening it. Fails with `NotFound` when `path` does not exist.
///
/// SQLite databases and their `-wal`/`-shm` sidecars must only be restricted
/// this way. On Unix, closing *any* descriptor for a file releases every
/// POSIX record lock the process holds on that file, including the locks a
/// live SQLite connection in this process holds on the database and on its
/// WAL index (the `-shm` dead-man-switch lock tells other processes that
/// the WAL index is in use). SQLite's bookkeeping still believes it holds
/// them, so another process (an online backup, `audit verify`, the sqlite3
/// shell) could then reset the WAL index or checkpoint and delete the WAL
/// under the live connection. So this opens nothing: it inspects the entry
/// with `lstat` and changes its mode with `chmod` by path. Changing the mode
/// by path is acceptable because the parent directory is validated first as
/// owned by and private to the broker process user, so no other user can
/// swap the entry between the check and the `chmod`; the entry is checked
/// again afterwards and must still be the same file.
#[cfg(unix)]
pub(crate) fn restrict_private_file_by_path(path: &Path) -> io::Result<()> {
    validate_private_parent(path)?;
    let before = fs::symlink_metadata(path)?;
    check_sensitive_file(&before)?;
    if before.permissions().mode() & 0o7777 == PRIVATE_FILE_MODE {
        return Ok(());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_FILE_MODE))?;
    let after = fs::symlink_metadata(path)?;
    if (after.dev(), after.ino()) != (before.dev(), before.ino()) {
        return Err(private_permission_error(
            "sensitive file was replaced while its permissions were restricted".to_string(),
        ));
    }
    check_sensitive_file(&after)?;
    if after.permissions().mode() & 0o7777 != PRIVATE_FILE_MODE {
        return Err(private_permission_error(
            "sensitive file must be owner read/write only (0600)".to_string(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn restrict_private_file_by_path(path: &Path) -> io::Result<()> {
    fs::symlink_metadata(path).map(|_| ())
}

/// Checks, without changing anything, that `path` is an owner-only (0600)
/// regular file owned by the broker process user with a single link, and not
/// a symlink. A missing file passes unless `required`.
#[cfg(unix)]
pub(crate) fn check_private_file(path: &Path, required: bool) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound && !required => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(private_permission_error(format!(
            "{} must be a regular file",
            path.display()
        )));
    }
    if metadata.uid() != effective_uid() {
        return Err(private_permission_error(format!(
            "{} must be owned by the broker process user",
            path.display()
        )));
    }
    if metadata.nlink() != 1 {
        return Err(private_permission_error(format!(
            "{} must not have multiple hard links",
            path.display()
        )));
    }
    if metadata.permissions().mode() & 0o777 != PRIVATE_FILE_MODE {
        return Err(private_permission_error(format!(
            "{} must be owner read/write only (0600)",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn check_private_file(path: &Path, required: bool) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound && !required => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
pub(crate) fn validate_private_parent(path: &Path) -> io::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    validate_private_dir(parent)
}

#[cfg(not(unix))]
pub(crate) fn validate_private_parent(path: &Path) -> io::Result<()> {
    let _ = path;
    Ok(())
}

#[cfg(unix)]
fn validate_private_dir(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(private_permission_error(format!(
            "{} must not be a symlink",
            path.display()
        )));
    }
    if !metadata.is_dir() {
        return Err(private_permission_error(format!(
            "{} must be a directory",
            path.display()
        )));
    }
    if metadata.uid() != effective_uid() {
        return Err(private_permission_error(format!(
            "{} must be owned by the broker process user",
            path.display()
        )));
    }
    if metadata.permissions().mode() & 0o777 != PRIVATE_DIR_MODE {
        return Err(private_permission_error(format!(
            "{} must be owner-only (0700)",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn restrict_open_file(file: &File) -> io::Result<()> {
    check_sensitive_file(&file.metadata()?)?;
    file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))?;
    let mode = file.metadata()?.permissions().mode() & 0o777;
    if mode != PRIVATE_FILE_MODE {
        return Err(private_permission_error(
            "sensitive file must be owner read/write only (0600)".to_string(),
        ));
    }
    Ok(())
}

/// A regular file owned by the broker process user with a single link. A
/// symlink or a directory fails with the error that opening it for writing
/// with `O_NOFOLLOW` reports (`ELOOP` or `EISDIR`).
#[cfg(unix)]
fn check_sensitive_file(metadata: &fs::Metadata) -> io::Result<()> {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(io::Error::from_raw_os_error(libc::ELOOP));
    }
    if file_type.is_dir() {
        return Err(io::Error::from_raw_os_error(libc::EISDIR));
    }
    if !file_type.is_file() {
        return Err(private_permission_error(
            "sensitive path must be a regular file".to_string(),
        ));
    }
    if metadata.uid() != effective_uid() {
        return Err(private_permission_error(
            "sensitive file must be owned by the broker process user".to_string(),
        ));
    }
    if metadata.nlink() != 1 {
        return Err(private_permission_error(
            "sensitive file must not have multiple hard links".to_string(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn restrict_open_file(file: &File) -> io::Result<()> {
    let _ = file;
    Ok(())
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

#[cfg(unix)]
fn private_permission_error(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use tempfile::TempDir;

    #[test]
    fn private_file_open_rejects_shared_parent_directory() {
        let temp = TempDir::new().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let error = open_private_append(&temp.path().join("audit.jsonl")).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn private_directory_validation_rejects_owner_only_but_unwritable_directory() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path().join("private");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();

        let error = ensure_private_dir(&dir).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn private_file_open_rejects_symlink_target() {
        let temp = TempDir::new().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let target = temp.path().join("target");
        let link = temp.path().join("link");
        fs::write(&target, b"target").unwrap();
        symlink(&target, &link).unwrap();

        let error = open_private_append(&link).unwrap_err();

        assert!(
            error.raw_os_error() == Some(libc::ELOOP)
                || error.kind() == io::ErrorKind::PermissionDenied
        );
    }

    fn private_temp_dir() -> TempDir {
        let temp = TempDir::new().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        temp
    }

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn restrict_by_path_repairs_the_mode_of_the_same_file() {
        let temp = private_temp_dir();
        let path = temp.path().join("store.sqlite");
        fs::write(&path, b"data").unwrap();
        let inode = fs::symlink_metadata(&path).unwrap().ino();
        for loose in [0o644, 0o400, 0o666] {
            fs::set_permissions(&path, fs::Permissions::from_mode(loose)).unwrap();

            restrict_private_file_by_path(&path).unwrap();

            assert_eq!(mode(&path), 0o600, "{loose:o}");
        }
        assert_eq!(fs::symlink_metadata(&path).unwrap().ino(), inode);
        assert_eq!(fs::read(&path).unwrap(), b"data");
        // Already private: nothing to change.
        restrict_private_file_by_path(&path).unwrap();
        assert_eq!(mode(&path), 0o600);
    }

    #[test]
    fn restrict_by_path_reports_a_missing_file() {
        let temp = private_temp_dir();
        let error = restrict_private_file_by_path(&temp.path().join("missing")).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn restrict_by_path_refuses_a_symlink_without_touching_its_target() {
        let temp = private_temp_dir();
        let target = temp.path().join("target");
        let link = temp.path().join("link");
        fs::write(&target, b"target").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        symlink(&target, &link).unwrap();

        let error = restrict_private_file_by_path(&link).unwrap_err();

        assert_eq!(error.raw_os_error(), Some(libc::ELOOP));
        assert_eq!(mode(&target), 0o644);
        let dangling = temp.path().join("dangling");
        symlink(temp.path().join("nowhere"), &dangling).unwrap();
        let error = restrict_private_file_by_path(&dangling).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ELOOP));
    }

    #[test]
    fn restrict_by_path_refuses_hard_links_directories_and_shared_parents() {
        let temp = private_temp_dir();
        let target = temp.path().join("target");
        let link = temp.path().join("link");
        fs::write(&target, b"target").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        fs::hard_link(&target, &link).unwrap();

        let error = restrict_private_file_by_path(&link).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            error.to_string(),
            "sensitive file must not have multiple hard links"
        );
        assert_eq!(mode(&target), 0o644);

        let directory = temp.path().join("directory");
        fs::create_dir(&directory).unwrap();
        let error = restrict_private_file_by_path(&directory).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EISDIR));

        fs::remove_file(&link).unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let error = restrict_private_file_by_path(&target).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(mode(&target), 0o644);
    }

    #[test]
    fn ensure_by_path_creates_a_private_file_or_restricts_the_existing_one() {
        let temp = private_temp_dir();
        let path = temp.path().join("store.sqlite");

        ensure_private_file_by_path(&path).unwrap();
        assert_eq!(mode(&path), 0o600);

        fs::write(&path, b"data").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        ensure_private_file_by_path(&path).unwrap();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(fs::read(&path).unwrap(), b"data");

        let link = temp.path().join("link.sqlite");
        symlink(temp.path().join("absent"), &link).unwrap();
        let error = ensure_private_file_by_path(&link).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ELOOP));
        assert!(!temp.path().join("absent").exists());
    }

    #[test]
    fn private_file_open_rejects_hard_linked_file() {
        let temp = TempDir::new().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let target = temp.path().join("target");
        let link = temp.path().join("link");
        fs::write(&target, b"target").unwrap();
        fs::hard_link(&target, &link).unwrap();

        let error = open_private_append(&link).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }
}
