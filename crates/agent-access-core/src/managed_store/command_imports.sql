ALTER TABLE imported_services ADD COLUMN accepted_metadata_json TEXT
    CHECK(accepted_metadata_json IS NULL OR length(accepted_metadata_json) <= 262144);
CREATE TABLE imported_secret_material_new (
    service TEXT NOT NULL REFERENCES imported_services(service),
    purpose TEXT NOT NULL CHECK(purpose IN ('execution','discovery','transport')),
    credential_kind TEXT NOT NULL CHECK(credential_kind IN ('bearer_token','basic_api_token')),
    material_version TEXT NOT NULL CHECK(length(material_version) > 0),
    key_id TEXT NOT NULL CHECK(length(key_id) > 0),
    nonce BLOB NOT NULL CHECK(length(nonce) = 12),
    ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 16 AND 32784),
    PRIMARY KEY(service,purpose)
);
INSERT INTO imported_secret_material_new
    (service,purpose,credential_kind,material_version,key_id,nonce,ciphertext)
SELECT service,purpose,credential_kind,material_version,key_id,nonce,ciphertext
FROM imported_secret_material;
DROP TABLE imported_secret_material;
ALTER TABLE imported_secret_material_new RENAME TO imported_secret_material;
CREATE INDEX imported_secret_material_key_id ON imported_secret_material(key_id);
