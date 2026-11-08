//! Durable service routing generations; previews never own denial guards.
use super::*;
use crate::imports::{
    IMPORT_MAX_GATEWAY_ROUTE_BYTES, ImportedGatewayRouteCandidate, ImportedGatewayRouteRecord,
};

fn invalid_data() -> ManagedStoreError {
    ManagedStoreError::SchemaInvalid("retained imported gateway routes are invalid".into())
}

pub(super) fn read(
    conn: &Connection,
    service: &str,
) -> Result<Option<ImportedGatewayRouteRecord>, ManagedStoreError> {
    let row: Option<(String, String, i64)> = conn.query_row(
        "SELECT manifest_json,content_hash,generation FROM imported_gateway_routes WHERE service=?1",
        [service], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).optional().map_err(sql_unavailable)?;
    let Some((json, content_hash, generation)) = row else {
        return Ok(None);
    };
    if json.len() > IMPORT_MAX_GATEWAY_ROUTE_BYTES
        || sha256_hex(json.as_bytes()) != content_hash
        || generation <= 0
    {
        return Err(invalid_data());
    }
    let manifest: ImportedGatewayRouteCandidate =
        serde_json::from_str(&json).map_err(|_| invalid_data())?;
    manifest.encoded().map_err(|_| invalid_data())?;
    Ok(Some(ImportedGatewayRouteRecord {
        manifest,
        content_hash,
        generation: generation as u64,
    }))
}

pub(super) fn write(
    conn: &Connection,
    service: &str,
    expected: Option<&ImportedGatewayRouteRecord>,
    candidate: &ImportedGatewayRouteCandidate,
) -> Result<(), ManagedStoreError> {
    let current = read(conn, service)?;
    if current.as_ref() != expected {
        return Err(ManagedStoreError::VersionConflict);
    }
    let next = ImportedGatewayRouteRecord::next(current.as_ref(), candidate.clone())
        .map_err(input_invalid)?;
    let bytes = next.manifest.encoded().map_err(input_invalid)?;
    let json = String::from_utf8(bytes).map_err(|_| invalid_data())?;
    conn.execute(
        "INSERT INTO imported_gateway_routes(service,manifest_json,content_hash,generation) VALUES(?1,?2,?3,?4) ON CONFLICT(service) DO UPDATE SET manifest_json=excluded.manifest_json,content_hash=excluded.content_hash,generation=excluded.generation",
        params![service, json, next.content_hash, next.generation as i64],
    ).map_err(sql_unavailable)?;
    Ok(())
}

pub(super) fn check_rows(conn: &Connection) -> Result<(), ManagedStoreError> {
    let mut statement = conn
        .prepare("SELECT service FROM imported_gateway_routes ORDER BY service")
        .map_err(sql_unavailable)?;
    let names: Vec<String> = collect_rows(
        statement
            .query_map([], |row| row.get(0))
            .map_err(sql_unavailable)?,
    )?;
    for service in names {
        read(conn, &service)?.ok_or_else(invalid_data)?;
    }
    Ok(())
}

pub(super) fn validate_structure(conn: &Connection) -> Result<(), ManagedStoreError> {
    if conn.is_autocommit() {
        let tx = conn.unchecked_transaction().map_err(sql_unavailable)?;
        validate_structure(&tx)?;
        tx.commit().map_err(sql_unavailable)?;
        return Ok(());
    }
    imported_store::validate_structure_through(
        conn,
        MANAGED_STORE_IMPORTED_GATEWAY_ROUTES_VERSION,
    )?;
    super::agent_token_issuance::validate_context_rows(conn)?;
    check_rows(conn)
}
