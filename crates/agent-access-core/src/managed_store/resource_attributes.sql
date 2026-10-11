CREATE TABLE resource_secret_material (
    resource_id TEXT NOT NULL REFERENCES resources(resource_id) ON DELETE CASCADE,
    attribute_name TEXT NOT NULL CHECK(length(attribute_name) BETWEEN 1 AND 64),
    material_version TEXT NOT NULL CHECK(length(material_version) > 0),
    key_id TEXT NOT NULL CHECK(length(key_id) > 0),
    nonce BLOB NOT NULL CHECK(length(nonce) = 12),
    ciphertext BLOB NOT NULL CHECK(length(ciphertext) >= 16),
    PRIMARY KEY(resource_id, attribute_name)
);
CREATE INDEX resource_secret_material_key_id ON resource_secret_material(key_id);
