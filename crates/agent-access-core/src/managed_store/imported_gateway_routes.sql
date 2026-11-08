CREATE TABLE imported_gateway_routes (
    service TEXT PRIMARY KEY NOT NULL REFERENCES imported_services(service) ON DELETE CASCADE,
    manifest_json TEXT NOT NULL CHECK(typeof(manifest_json) = 'text' AND length(CAST(manifest_json AS BLOB)) BETWEEN 1 AND 4194304),
    content_hash TEXT NOT NULL CHECK(typeof(content_hash) = 'text' AND length(content_hash) = 64 AND content_hash NOT GLOB '*[^0-9a-f]*'),
    generation INTEGER NOT NULL CHECK(typeof(generation) = 'integer' AND generation > 0)
);
