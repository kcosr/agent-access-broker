use crate::state::AppState;
use axum::extract::{Path as AxumPath, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use std::path::{Component, Path, PathBuf};

pub(crate) async fn portal_index(State(state): State<AppState>) -> impl IntoResponse {
    serve_portal_path(state, None).await
}

pub(crate) async fn portal_asset(
    State(state): State<AppState>,
    AxumPath(path): AxumPath<String>,
) -> impl IntoResponse {
    serve_portal_path(state, Some(path)).await
}

async fn serve_portal_path(state: AppState, path: Option<String>) -> Response {
    let snapshot = state.reloadable.current();
    let config = &snapshot.runtime.config().portal;
    if !config.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(static_dir) = config.static_dir.as_deref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    serve_static_directory(Path::new(static_dir), path.as_deref()).await
}

async fn serve_static_directory(root: &Path, path: Option<&str>) -> Response {
    // Lexical traversal checks alone do not contain symlinks in a deployed
    // asset tree. Resolve both the root and the selected file before serving.
    let Ok(root) = tokio::fs::canonicalize(root).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let requested = match path {
        None | Some("") => root.join("index.html"),
        Some(path) => match safe_asset_path(&root, path) {
            Some(path) => path,
            None => return StatusCode::NOT_FOUND.into_response(),
        },
    };
    let file = match tokio::fs::canonicalize(&requested).await {
        Ok(file) => {
            if !file.starts_with(&root) {
                return StatusCode::NOT_FOUND.into_response();
            }
            match tokio::fs::metadata(&file).await {
                Ok(metadata) if metadata.is_file() => file,
                Ok(metadata) if metadata.is_dir() => root.join("index.html"),
                _ => return StatusCode::NOT_FOUND.into_response(),
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => root.join("index.html"),
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    // Apply the same boundary to the SPA fallback and index itself.
    let Ok(file) = tokio::fs::canonicalize(&file).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !file.starts_with(&root) {
        return StatusCode::NOT_FOUND.into_response();
    }
    if !tokio::fs::metadata(&file)
        .await
        .is_ok_and(|metadata| metadata.is_file())
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    match tokio::fs::read(&file).await {
        Ok(bytes) => {
            let mime = mime_guess::from_path(&file).first_or_octet_stream();
            let mut response = (StatusCode::OK, bytes).into_response();
            if let Ok(value) = HeaderValue::from_str(mime.as_ref()) {
                response.headers_mut().insert(CONTENT_TYPE, value);
            }
            insert_portal_security_headers(&mut response);
            insert_portal_cache_header(&mut response, &root, &file);
            response
        }
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

fn insert_portal_security_headers(response: &mut Response) {
    let headers = response.headers_mut();
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        ),
    );
}

fn insert_portal_cache_header(response: &mut Response, root: &Path, file: &Path) {
    let value = if file.starts_with(root.join("assets")) {
        HeaderValue::from_static("public, max-age=31536000, immutable")
    } else {
        HeaderValue::from_static("no-store")
    };
    response.headers_mut().insert(CACHE_CONTROL, value);
}

fn safe_asset_path(root: &Path, path: &str) -> Option<PathBuf> {
    if path.starts_with('/') || path.contains('\\') {
        return None;
    }
    let mut resolved = root.to_path_buf();
    for component in Path::new(path).components() {
        match component {
            Component::Normal(part) => resolved.push(part),
            _ => return None,
        }
    }
    Some(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn portal_serves_assets_and_spa_routes_with_security_headers() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("portal");
        std::fs::create_dir_all(root.join("assets")).unwrap();
        std::fs::write(root.join("index.html"), "portal index").unwrap();
        std::fs::write(root.join("assets/app.js"), "portal script").unwrap();
        for (path, content, cache) in [
            (None, "portal index", "no-store"),
            (Some("principals/alice"), "portal index", "no-store"),
            (
                Some("assets/app.js"),
                "portal script",
                "public, max-age=31536000, immutable",
            ),
        ] {
            let response = serve_static_directory(&root, path).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[CACHE_CONTROL], cache);
            assert_eq!(response.headers()["x-content-type-options"], "nosniff");
            assert_eq!(response.headers()["x-frame-options"], "DENY");
            assert!(response.headers().contains_key("content-security-policy"));
            let body = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            assert_eq!(body.as_ref(), content.as_bytes());
        }
        for path in [
            "../secret",
            "/secret",
            "assets/../../secret",
            "assets\\secret",
        ] {
            assert_eq!(
                serve_static_directory(&root, Some(path)).await.status(),
                StatusCode::NOT_FOUND,
                "path {path} must not escape the asset directory",
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn portal_rejects_symlinks_outside_the_asset_directory_including_index() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("portal");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(directory.path().join("secret"), "private credential").unwrap();
        std::fs::write(root.join("index.html"), "portal index").unwrap();
        symlink(directory.path().join("secret"), root.join("linked-file")).unwrap();
        symlink(directory.path(), root.join("linked-directory")).unwrap();
        for path in ["linked-file", "linked-directory/secret", "linked-directory"] {
            assert_eq!(
                serve_static_directory(&root, Some(path)).await.status(),
                StatusCode::NOT_FOUND,
                "external symlink {path} must not expose server files",
            );
        }
        // In-root symlinks remain usable, including a symlinked deployment root.
        symlink(root.join("index.html"), root.join("linked-index")).unwrap();
        let linked_root = directory.path().join("current");
        symlink(&root, &linked_root).unwrap();
        assert_eq!(
            serve_static_directory(&linked_root, Some("linked-index"))
                .await
                .status(),
            StatusCode::OK,
        );
        std::fs::remove_file(root.join("index.html")).unwrap();
        symlink(directory.path().join("secret"), root.join("index.html")).unwrap();
        for path in [None, Some("missing-spa-route")] {
            assert_eq!(
                serve_static_directory(&root, path).await.status(),
                StatusCode::NOT_FOUND,
                "index and SPA fallback must stay inside the asset directory",
            );
        }
    }
}
