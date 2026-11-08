//! Offline validation of a hand-authored document; output contains no supplied parameter values.
use agent_access_openapi_common::{
    GatewayAuthenticationSelection, GatewayCompileOptions, compile_gateway_document,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: check-document <JSON-file> <approved-endpoint>".into());
    }
    let bytes = std::fs::read(&args[1])?;
    let result = compile_gateway_document(
        &bytes,
        &GatewayCompileOptions {
            endpoint: args[2].clone(),
            document_base: args[2].clone(),
            authentication: GatewayAuthenticationSelection::Anonymous,
        },
    )?;
    let unsupported = result
        .operations
        .iter()
        .filter(|v| v.unsupported_reason.is_some())
        .count();
    println!(
        "{} operations, {} path guards, {} unsupported operations",
        result.operations.len(),
        result.routes.paths.len(),
        unsupported
    );
    if unsupported != 0 {
        for op in result.operations {
            if let Some(reason) = op.unsupported_reason {
                eprintln!("{reason}");
            }
        }
        return Err("document contains unsupported operations".into());
    }
    Ok(())
}
