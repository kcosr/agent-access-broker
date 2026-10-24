//! Bounded retained discovery bytes. Catalog reads select only safe metadata.
use super::*;
use crate::imports::IMPORT_MAX_DOCUMENT_BYTES;

fn invalid_data() -> ManagedStoreError {
    ManagedStoreError::SchemaInvalid("retained imported document is invalid".into())
}

/// Read-only receipt issued by document preparation and returned in the catalog.
/// Consumers inspect these fields; constructing a receipt does not authorize a
/// document write, which requires the opaque runtime-issued preparation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ImportedDocumentMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    pub byte_length: u64,
    pub sha256: String,
}

pub(crate) fn validate_document_filename(filename: Option<&str>) -> Result<(), ManagedStoreError> {
    if filename.is_some_and(|name| {
        name.is_empty()
            || name.len() > 255
            || name.chars().all(|c| c == '.')
            || name
                .chars()
                .any(|c| c.is_control() || matches!(c, '/' | '\\'))
    }) {
        return Err(input_invalid(
            "document filename must be a basename of at most 255 UTF-8 bytes",
        ));
    }
    Ok(())
}

pub(crate) fn validate_document_bytes(bytes: &[u8]) -> Result<(), ManagedStoreError> {
    if bytes.is_empty()
        || bytes.len() > IMPORT_MAX_DOCUMENT_BYTES
        || std::str::from_utf8(bytes).is_err()
    {
        return Err(input_invalid(
            "document must contain bounded UTF-8 JSON bytes",
        ));
    }
    Ok(())
}

pub(super) fn metadata(
    conn: &Connection,
    service: &str,
) -> Result<Option<ImportedDocumentMetadata>, ManagedStoreError> {
    let metadata: Option<ImportedDocumentMetadata> = conn
        .query_row(
            "SELECT filename,byte_length,sha256 FROM imported_source_documents WHERE service=?1",
            [service],
            |row| {
                let byte_length: i64 = row.get(1)?;
                Ok(ImportedDocumentMetadata {
                    filename: row.get(0)?,
                    byte_length: u64::try_from(byte_length).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(1, Type::Integer, Box::new(error))
                    })?,
                    sha256: row.get(2)?,
                })
            },
        )
        .optional()
        .map_err(sql_unavailable)?;
    if let Some(value) = &metadata {
        validate_document_filename(value.filename.as_deref()).map_err(|_| invalid_data())?;
        if value.byte_length == 0
            || value.byte_length > IMPORT_MAX_DOCUMENT_BYTES as u64
            || value.sha256.len() != 64
            || !value
                .sha256
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(invalid_data());
        }
    }
    Ok(metadata)
}

impl ManagedStore {
    /// Load retained bytes only for discovery, pinned to the admitted service.
    pub(crate) fn imported_document(
        &self,
        expected: &ImportedServiceRecord,
    ) -> Result<Vec<u8>, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        let record = imported_store::service_record(&conn, &expected.definition.service)?
            .ok_or(ManagedStoreError::VersionConflict)?;
        if record.version != expected.version
            || record.definition != expected.definition
            || record.document != expected.document
        {
            return Err(ManagedStoreError::VersionConflict);
        }
        let metadata = record
            .document
            .ok_or_else(|| input_invalid("upload a document before discovering this import"))?;
        read_document(&conn, &expected.definition.service, &metadata)
    }
}

fn read_document(
    conn: &Connection,
    service: &str,
    metadata: &ImportedDocumentMetadata,
) -> Result<Vec<u8>, ManagedStoreError> {
    let bytes: Vec<u8> = conn
        .query_row(
            "SELECT content FROM imported_source_documents WHERE service=?1",
            [service],
            |row| row.get(0),
        )
        .map_err(sql_unavailable)?;
    validate_document_bytes(&bytes).map_err(|_| invalid_data())?;
    if bytes.len() as u64 != metadata.byte_length || sha256_hex(&bytes) != metadata.sha256 {
        return Err(invalid_data());
    }
    Ok(bytes)
}

pub(super) fn write(
    conn: &Connection,
    service: &str,
    upload: &crate::PreparedImportedDocumentUpload,
) -> Result<(), ManagedStoreError> {
    let metadata = upload.metadata();
    let byte_length = i64::try_from(metadata.byte_length).map_err(|_| invalid_data())?;
    conn.execute("INSERT INTO imported_source_documents(service,filename,byte_length,sha256,content) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(service) DO UPDATE SET filename=excluded.filename,byte_length=excluded.byte_length,sha256=excluded.sha256,content=excluded.content",
        params![service, metadata.filename, byte_length, metadata.sha256, upload.bytes()]).map_err(sql_unavailable)?;
    Ok(())
}

pub(super) fn check_rows(conn: &Connection) -> Result<(), ManagedStoreError> {
    let mut statement = conn
        .prepare("SELECT service FROM imported_source_documents ORDER BY service")
        .map_err(sql_unavailable)?;
    let names: Vec<String> = collect_rows(
        statement
            .query_map([], |row| row.get(0))
            .map_err(sql_unavailable)?,
    )?;
    for service in names {
        let metadata = metadata(conn, &service)?.ok_or_else(invalid_data)?;
        read_document(conn, &service, &metadata)?;
    }
    Ok(())
}
