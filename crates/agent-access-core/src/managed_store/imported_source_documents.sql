CREATE TABLE imported_source_documents (
    service TEXT PRIMARY KEY NOT NULL REFERENCES imported_services(service) ON DELETE CASCADE,
    filename TEXT CHECK(filename IS NULL OR (typeof(filename) = 'text' AND length(CAST(filename AS BLOB)) BETWEEN 1 AND 255)),
    byte_length INTEGER NOT NULL CHECK(typeof(byte_length) = 'integer' AND byte_length BETWEEN 1 AND 4194304),
    sha256 TEXT NOT NULL CHECK(typeof(sha256) = 'text' AND length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
    content BLOB NOT NULL CHECK(typeof(content) = 'blob' AND length(content) = byte_length)
);
