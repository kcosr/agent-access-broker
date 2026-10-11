//! Test-only probes of the POSIX record locks SQLite's unix VFS holds on a
//! database and its WAL index, read from a separate process.
//!
//! `fcntl(F_GETLK)` never reports the calling process's own locks, so a
//! probe re-executes this test binary to run only [`sqlite_lock_probe_helper`],
//! which asks for a write lock over two ranges and prints the conflicting
//! lock it finds:
//!
//! - the `-shm` dead-man-switch byte `UNIX_SHM_DMS` = `UNIX_SHM_BASE` +
//!   `SQLITE_SHM_NLOCK` = `(22 + 8) * 4 + 8` = 128, read-locked by every
//!   process that has the WAL index mapped (while no process holds it, the
//!   next one to open the database resets the WAL index); and
//! - the database's shared-lock range `SHARED_FIRST` = `PENDING_BYTE` + 2 =
//!   `0x40000002`, `SHARED_SIZE` = 510 bytes, read-locked by a WAL-mode
//!   connection from its first read until it closes (while no process holds
//!   it, the last connection to close checkpoints and deletes the WAL).
//!
//! Both are read locks of this process while its SQLite connections are
//! intact, and are gone once a stray `close` of another descriptor for the
//! same file released them. The offsets are those of the bundled
//! `sqlite3.c`.
//!
//! The online backup helper likewise backs up an audit database with
//! SQLite's backup API from a separate process.

use super::sqlite_sidecar_paths;
use rusqlite::backup::{Backup, StepResult};
use rusqlite::{Connection, OpenFlags};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

const LOCK_PROBE_HELPER: &str = "sqlite_support::lock_probe::sqlite_lock_probe_helper";
const LOCK_PROBE_DATABASE_ENV: &str = "AGENT_ACCESS_TEST_SQLITE_LOCK_PROBE_DATABASE";
const LOCK_PROBE_OUTPUT: &str = "sqlite-lock-probe:";

const BACKUP_HELPER: &str = "sqlite_support::lock_probe::sqlite_online_backup_helper";
const BACKUP_SOURCE_ENV: &str = "AGENT_ACCESS_TEST_SQLITE_BACKUP_SOURCE";
const BACKUP_TARGET_ENV: &str = "AGENT_ACCESS_TEST_SQLITE_BACKUP_TARGET";
const BACKUP_ROUNDS_ENV: &str = "AGENT_ACCESS_TEST_SQLITE_BACKUP_ROUNDS";
const BACKUP_OUTPUT: &str = "sqlite-online-backup:";

/// `UNIX_SHM_DMS`: the WAL index's dead-man-switch byte.
const SHM_DMS_OFFSET: i64 = 128;
/// `SHARED_FIRST` and `SHARED_SIZE`: the database file's shared-lock range.
const DATABASE_SHARED_FIRST: i64 = 0x4000_0000 + 2;
const DATABASE_SHARED_SIZE: i64 = 510;

/// The lock another process finds over a probed range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Holder {
    /// The file does not exist.
    Missing,
    /// No process holds a conflicting lock.
    Unlocked,
    /// A read lock of the process with this ID.
    Read(u32),
    /// A write lock of the process with this ID.
    Write(u32),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SqliteLocks {
    pub(crate) shm_dead_man_switch: Holder,
    pub(crate) database_shared: Holder,
}

/// The locks another process finds on the database at `database` and on its
/// `-shm` file.
pub(crate) fn probe(database: &Path) -> SqliteLocks {
    let output = helper_command(LOCK_PROBE_HELPER)
        .env(LOCK_PROBE_DATABASE_ENV, database)
        .output()
        .expect("failed to run the SQLite lock probe helper");
    let fields = helper_fields(&output, LOCK_PROBE_OUTPUT);
    SqliteLocks {
        shm_dead_man_switch: parse_holder(field(&fields, "shm_dms")),
        database_shared: parse_holder(field(&fields, "database_shared")),
    }
}

/// Asserts that this process still holds SQLite's read locks on the `-shm`
/// dead-man switch and on the database, as its open connections expect.
#[track_caller]
pub(crate) fn assert_sqlite_locks_held(database: &Path, context: &str) {
    let held = Holder::Read(std::process::id());
    assert_eq!(
        probe(database),
        SqliteLocks {
            shm_dead_man_switch: held,
            database_shared: held,
        },
        "the SQLite locks of this process on {} must survive {context}",
        database.display()
    );
}

/// Starts `rounds` online backups of `source` into `target` in another
/// process, each on a new source connection that is closed afterwards.
pub(crate) fn spawn_online_backup(source: &Path, target: &Path, rounds: usize) -> Child {
    helper_command(BACKUP_HELPER)
        .env(BACKUP_SOURCE_ENV, source)
        .env(BACKUP_TARGET_ENV, target)
        .env(BACKUP_ROUNDS_ENV, rounds.to_string())
        .spawn()
        .expect("failed to start the SQLite online backup helper")
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct OnlineBackupReport {
    /// `PRAGMA integrity_check` of the source, read by the backup process
    /// after its last backup.
    pub(crate) source_integrity: String,
    /// `PRAGMA integrity_check` of the last backup.
    pub(crate) backup_integrity: String,
    /// `audit_events` rows in the last backup.
    pub(crate) backup_rows: i64,
}

/// Waits for a backup started by [`spawn_online_backup`].
pub(crate) fn finish_online_backup(child: Child) -> OnlineBackupReport {
    let output = child
        .wait_with_output()
        .expect("failed to wait for the SQLite online backup helper");
    let fields = helper_fields(&output, BACKUP_OUTPUT);
    OnlineBackupReport {
        source_integrity: field(&fields, "source_integrity").to_string(),
        backup_integrity: field(&fields, "backup_integrity").to_string(),
        backup_rows: field(&fields, "backup_rows").parse().unwrap(),
    }
}

/// This test binary, running only the ignored helper test `helper`.
fn helper_command(helper: &str) -> Command {
    let mut command =
        Command::new(std::env::current_exe().expect("the test binary path is unavailable"));
    command
        .args([
            "--exact",
            helper,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// The `key=value` fields the helper printed after `prefix`.
fn helper_fields(output: &Output, prefix: &str) -> Vec<(String, String)> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "helper failed: {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );
    // libtest prints the test name on the same line first.
    let line = stdout
        .lines()
        .find_map(|line| line.split_once(prefix).map(|(_, fields)| fields))
        .unwrap_or_else(|| panic!("helper printed no {prefix} line\nstdout:\n{stdout}"));
    line.split_whitespace()
        .map(|field| {
            let (key, value) = field.split_once('=').unwrap();
            (key.to_string(), value.to_string())
        })
        .collect()
}

fn field<'a>(fields: &'a [(String, String)], key: &str) -> &'a str {
    fields
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.as_str())
        .unwrap_or_else(|| panic!("helper output has no {key}: {fields:?}"))
}

fn parse_holder(value: &str) -> Holder {
    match value.split_once(':') {
        None if value == "missing" => Holder::Missing,
        None if value == "unlocked" => Holder::Unlocked,
        Some(("read", pid)) => Holder::Read(pid.parse().unwrap()),
        Some(("write", pid)) => Holder::Write(pid.parse().unwrap()),
        _ => panic!("unexpected lock holder {value}"),
    }
}

/// The lock that conflicts with a write lock over `len` bytes at `start` of
/// `path`, as `missing`, `unlocked`, `read:<pid>`, or `write:<pid>`.
fn conflicting_lock(path: &Path, start: i64, len: i64) -> String {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return "missing".to_string();
        }
        Err(error) => panic!("failed to open {}: {error}", path.display()),
    };
    // SAFETY: `flock` is plain data; every field F_GETLK reads is set below.
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = libc::F_WRLCK as libc::c_short;
    lock.l_whence = libc::SEEK_SET as libc::c_short;
    lock.l_start = start as libc::off_t;
    lock.l_len = len as libc::off_t;
    // SAFETY: the descriptor is open and `lock` is a valid `flock`.
    let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETLK, &mut lock) };
    assert_eq!(
        result,
        0,
        "F_GETLK on {} failed: {}",
        path.display(),
        std::io::Error::last_os_error()
    );
    // libc exposes these constants as i16 on macOS and i32 on Linux.
    #[allow(clippy::unnecessary_cast)]
    match i32::from(lock.l_type) {
        kind if kind == libc::F_UNLCK as i32 => "unlocked".to_string(),
        kind if kind == libc::F_RDLCK as i32 => format!("read:{}", lock.l_pid),
        kind if kind == libc::F_WRLCK as i32 => format!("write:{}", lock.l_pid),
        other => panic!("unexpected lock type {other}"),
    }
}

#[test]
#[ignore = "run in a child process by the SQLite lock probes"]
fn sqlite_lock_probe_helper() {
    let Some(database) = std::env::var_os(LOCK_PROBE_DATABASE_ENV) else {
        return;
    };
    let database = PathBuf::from(database);
    let [_, shm] = sqlite_sidecar_paths(&database);
    println!(
        "{LOCK_PROBE_OUTPUT} shm_dms={} database_shared={}",
        conflicting_lock(&shm, SHM_DMS_OFFSET, 1),
        conflicting_lock(&database, DATABASE_SHARED_FIRST, DATABASE_SHARED_SIZE),
    );
}

#[test]
#[ignore = "run in a child process by the SQLite online backup tests"]
fn sqlite_online_backup_helper() {
    let Some(source) = std::env::var_os(BACKUP_SOURCE_ENV) else {
        return;
    };
    let source = PathBuf::from(source);
    let target = PathBuf::from(std::env::var_os(BACKUP_TARGET_ENV).unwrap());
    let rounds: usize = std::env::var(BACKUP_ROUNDS_ENV).unwrap().parse().unwrap();
    let mut source_integrity = String::new();
    for round in 0..rounds {
        // A new read-write connection each round, as `sqlite3 <db> .backup`
        // opens one: closing it is when SQLite checkpoints and deletes the
        // WAL if no other process holds the database's shared lock.
        let conn = open_backup_source(&source);
        let mut destination = Connection::open(&target).unwrap();
        copy_all_pages(&conn, &mut destination);
        drop(destination);
        if round + 1 == rounds {
            source_integrity = integrity_check(&conn);
        }
        drop(conn);
    }
    let backup = Connection::open_with_flags(&target, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let backup_rows: i64 = backup
        .query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))
        .unwrap();
    println!(
        "{BACKUP_OUTPUT} source_integrity={source_integrity} backup_integrity={} backup_rows={backup_rows}",
        integrity_check(&backup)
    );
}

fn open_backup_source(path: &Path) -> Connection {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .unwrap();
    conn.busy_timeout(Duration::from_secs(5)).unwrap();
    conn
}

/// Copies every page in one step, which reads one snapshot of the source
/// and so never restarts because the live writer committed meanwhile.
fn copy_all_pages(source: &Connection, destination: &mut Connection) {
    let backup = Backup::new(source, destination).unwrap();
    loop {
        match backup.step(-1).unwrap() {
            StepResult::Done => return,
            StepResult::More | StepResult::Busy | StepResult::Locked => {
                std::thread::sleep(Duration::from_millis(5));
            }
            _ => unreachable!("unknown backup step result"),
        }
    }
}

/// `PRAGMA integrity_check` as one space-free token: `ok`, or the problems.
fn integrity_check(conn: &Connection) -> String {
    let mut statement = conn.prepare("PRAGMA integrity_check").unwrap();
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    rows.join(";").replace(char::is_whitespace, "_")
}
