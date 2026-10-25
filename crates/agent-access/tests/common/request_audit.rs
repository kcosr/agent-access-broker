use serde_json::Value;

/// Match retained caller values independently of provider outcome metadata.
pub fn assert_captured_values(records: &[Value], key: &str, expected: &[Value]) {
    let values = records
        .iter()
        .flat_map(|record| {
            record["requestAudit"]["fields"]
                .as_array()
                .expect("prepared request must retain its declared input audit")
        })
        .filter(|field| field["key"] == key && field["state"] == "captured")
        .map(|field| field["value"].clone())
        .collect::<Vec<_>>();
    assert_eq!(values, expected, "request field {key}");
}
