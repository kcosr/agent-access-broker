use super::*;
use agent_access_core::imports::{BoundedImportSchema, CommandRegistry, ImportedActionAuthority};
use agent_access_provider::{ProviderResult, ProviderResultStreamSource, ReasonCode};
use futures_util::{FutureExt, StreamExt};
use std::time::Duration;

fn action() -> CompiledAction {
    CompiledAction {
        read_only: true,
        download: true,
        input: BoundedImportSchema::compile(&json!({"type": "object"})).unwrap(),
        output: None,
        authority: ImportedActionAuthority::default(),
    }
}

fn document(bytes: &[u8]) -> Value {
    json!({"ok": true, "result": {}, "download": {
        "content": STANDARD.encode(bytes), "filename": "report.bin", "contentType": "application/octet-stream"
    }})
}

fn read_raw(text: &[u8], cap: usize) -> Result<InvokeOutcome, Error> {
    invoke(
        "reports",
        &action(),
        true,
        text,
        &CommandSecrets::new(),
        cap,
        &Control::new(Instant::now() + Duration::from_secs(30)),
    )
}

fn read(document: &Value, cap: usize) -> Result<ProviderResult, Error> {
    read_raw(&serde_json::to_vec(document).unwrap(), cap).map(|outcome| outcome.unwrap())
}

fn violation(error: Error) -> &'static str {
    match error {
        Error::Violation(violation) => violation.category(),
        other => panic!("expected contract violation, got {other:?}"),
    }
}

async fn chunks(result: ProviderResult) -> Vec<Bytes> {
    let ProviderResultStreamSource::Stream(stream) = result.stream.unwrap().source else {
        panic!("buffered command downloads must expose a stream");
    };
    let mut stream = stream.lock().unwrap().take().unwrap();
    let mut chunks = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.unwrap();
        assert!(chunk.len() <= CHUNK_BYTES);
        chunks.push(chunk);
    }
    chunks
}

#[tokio::test]
async fn empty_binary_padding_and_large_files_have_computed_integrity_and_bounded_chunks() {
    for bytes in [
        vec![],
        vec![0],
        vec![0, 255],
        vec![0, 1, 255],
        (0..=255).collect(),
        (0..200_000).map(|index| index as u8).collect(),
    ] {
        let result = read(&document(&bytes), bytes.len()).unwrap();
        assert_eq!(result.result["size"], bytes.len());
        assert_eq!(
            result.result["sha256"],
            format!("{:x}", Sha256::digest(&bytes))
        );
        assert_eq!(result.result["upstreamCommand"], json!({}));
        assert!(result.result.get("download").is_none());
        assert!(result.result.get("content").is_none());
        let collected = chunks(result)
            .await
            .into_iter()
            .flat_map(|chunk| chunk.to_vec())
            .collect::<Vec<_>>();
        assert_eq!(collected, bytes);
    }
}

#[test]
fn declarations_must_be_exact_non_null_and_hash_is_case_insensitive() {
    let mut doc = document(&[0, 1, 2, 3]);
    doc["download"]["size"] = json!(4);
    doc["download"]["sha256"] = json!(format!("{:X}", Sha256::digest([0, 1, 2, 3])));
    assert!(read(&doc, 4).is_ok());
    for value in [
        Value::Null,
        json!(3),
        json!(5),
        json!(-1),
        json!(4.0),
        json!("4"),
    ] {
        doc["download"]["size"] = value;
        assert_eq!(violation(read(&doc, 4).unwrap_err()), "download_size");
    }
    doc["download"].as_object_mut().unwrap().remove("size");
    for value in [
        Value::Null,
        json!("0".repeat(64)),
        json!("g".repeat(64)),
        json!("a".repeat(63)),
        json!(5),
    ] {
        doc["download"]["sha256"] = value;
        assert_eq!(violation(read(&doc, 4).unwrap_err()), "download_sha256");
    }
}

#[test]
fn strict_base64_rejects_missing_excess_and_noncanonical_padding_or_alphabet() {
    for content in [
        "A",
        "AA",
        "AAA",
        "A===",
        "====",
        "AA===",
        "AA== ",
        " A==",
        "AA\n=",
        "AA-_",
        "AA?=",
        "AB==",
        "AAB=",
        "AA==AAAA",
        "AAAAAA==AAAA",
    ] {
        let mut doc = document(&[]);
        doc["download"]["content"] = json!(content);
        assert!(read(&doc, 1024).is_err(), "accepted {content:?}");
    }
    // A complete padded quartet at a decoder chunk boundary cannot start
    // another independently padded base64 document.
    let mut doc = document(&[]);
    doc["download"]["content"] = json!(format!("{}AA==AAAA", "AAAA".repeat(CHUNK_BYTES / 4 - 1)));
    assert!(read(&doc, CHUNK_BYTES).is_err());
    let raw = br#"{"ok":true,"result":{},"download":{"content":"\u0041A==","filename":"a","contentType":"text/plain"}}"#;
    assert_eq!(
        violation(read_raw(raw, 10).unwrap_err()),
        "download_content"
    );
    for content in [Value::Null, json!(false), json!(42), json!({}), json!([])] {
        doc["download"]["content"] = content;
        assert!(read(&doc, CHUNK_BYTES).is_err());
    }
}

#[test]
fn decoded_and_envelope_limits_are_independent_and_exact() {
    assert!(read(&document(&[1, 2, 3]), 3).is_ok());
    assert_eq!(
        violation(read(&document(&[1, 2, 3]), 2).unwrap_err()),
        "download_limit"
    );
    let raw = document(&[1]).to_string();
    let mut exact = " ".repeat(OVERHEAD + 4 - raw.len());
    exact.push_str(&raw);
    assert!(read_raw(exact.as_bytes(), 1).is_ok());
    exact.push(' ');
    assert_eq!(
        violation(read_raw(exact.as_bytes(), 1).unwrap_err()),
        "download_envelope_limit"
    );
    // Error documents have no encoded payload allowance.
    let error = r#"{"ok":false,"error":{"code":"resource_not_found","message":"missing"}}"#;
    let oversized = format!("{}{}", " ".repeat(OVERHEAD - error.len() + 1), error);
    assert_eq!(
        violation(read_raw(oversized.as_bytes(), 1).unwrap_err()),
        "download_envelope_limit"
    );
}

#[test]
fn protocol_objects_reject_unknown_duplicate_missing_and_wrong_shaped_fields() {
    let valid = r#"{"ok":true,"result":{},"download":{"content":"AA==","filename":"a","contentType":"text/plain"}}"#;
    let bad = [
        valid.replace("\"ok\":true", "\"ok\":true,\"ok\":true"),
        valid.replace("\"result\":{}", "\"result\":{},\"result\":{}"),
        valid.replace("\"content\":\"AA==\"", "\"content\":\"AA==\",\"content\":\"AA==\""),
        valid.replace("\"filename\":\"a\"", "\"filename\":\"a\",\"filename\":\"b\""),
        valid.replace("\"ok\":true", "\"ok\":true,\"extra\":42"),
        valid.replace("\"content\":\"AA==\"", "\"content\":\"AA==\",\"extra\":42"),
        valid.replace("\"result\":{},", ""),
        valid.replace("\"content\":\"AA==\",", ""),
        valid.replace("\"filename\":\"a\",", ""),
        valid.replace("\"ok\":true", "\"ok\":false"),
        valid.replace("\"ok\":true", "\"ok\":null"),
        format!("{valid}{{}}"),
        format!("[{valid}]"),
        r#"{"ok":true,"result":{},"download":"AA=="}"#.into(),
        r#"{"ok":true,"result":{}}"#.into(),
        r#"{"ok":false,"error":{"code":"resource_not_found","code":"conflict","message":"missing"}}"#.into(),
        r#"{"ok":false,"error":{"code":"resource_not_found","message":"missing","extra":5}}"#.into(),
        r#"{"ok":false,"error":{"code":"resource_not_found","message":"missing"},"receipt":{"mutationStatus":"unknown","mutationStatus":"unknown"}}"#.into(),
    ];
    for raw in bad {
        assert!(read_raw(raw.as_bytes(), 10).is_err(), "accepted {raw}");
    }
}

#[test]
fn metadata_bounds_cover_raw_length_compact_length_strings_members_and_depth() {
    let mut doc = document(&[]);
    doc["result"] = json!({"warning": "x".repeat(STRING_BYTES)});
    assert!(read(&doc, 1).is_ok());
    doc["result"] = json!({"warning": "x".repeat(STRING_BYTES + 1)});
    assert_eq!(
        violation(read(&doc, 1).unwrap_err()),
        "download_result_limit"
    );
    doc["result"] = json!({"x".repeat(STRING_BYTES + 1): 1});
    assert!(read(&doc, 1).is_err());
    doc["result"] = json!({"items": vec![0; ELEMENTS - 1]});
    assert!(read(&doc, 1).is_ok());
    doc["result"] = json!({"items": vec![0; ELEMENTS]});
    assert_eq!(
        violation(read(&doc, 1).unwrap_err()),
        "download_result_limit"
    );
    doc["result"] = json!({});
    for _ in 1..DEPTH {
        doc["result"] = json!({"child": doc["result"]});
    }
    assert!(read(&doc, 1).is_ok());
    doc["result"] = json!({"child": doc["result"]});
    assert_eq!(
        violation(read(&doc, 1).unwrap_err()),
        "download_result_limit"
    );
    doc["result"] = json!(0);
    for _ in 0..DEPTH {
        doc["result"] = json!({"child": doc["result"]});
    }
    assert!(
        read(&doc, 1).is_ok(),
        "scalar leaves do not add container nesting"
    );
    let raw = document(&[]).to_string();
    let exact = raw.replace(
        "\"result\":{}",
        &format!("\"result\":{{{}}}", " ".repeat(RESULT_BYTES - 2)),
    );
    assert!(read_raw(exact.as_bytes(), 1).is_ok());
    let oversized = raw.replace(
        "\"result\":{}",
        &format!("\"result\":{{{}}}", " ".repeat(RESULT_BYTES - 1)),
    );
    assert_eq!(
        violation(read_raw(oversized.as_bytes(), 1).unwrap_err()),
        "download_result_limit"
    );
    for value in [json!(null), json!([]), json!("text"), json!(true)] {
        doc["result"] = value;
        assert_eq!(
            violation(read(&doc, 1).unwrap_err()),
            "download_result_shape"
        );
    }
}

#[test]
fn output_schema_checks_metadata_and_read_write_receipts_keep_their_semantics() {
    let control = Control::new(Instant::now() + Duration::from_secs(30));
    let mut action = action();
    action.output = Some(
        BoundedImportSchema::compile(&json!({"type":"object","required":["warnings"]})).unwrap(),
    );
    let mut doc = document(&[]);
    let call = |doc: &Value, read_only| {
        invoke(
            "reports",
            &action,
            read_only,
            &serde_json::to_vec(doc).unwrap(),
            &CommandSecrets::new(),
            1,
            &control,
        )
    };
    assert_eq!(violation(call(&doc, true).unwrap_err()), "output_schema");
    doc["result"] = json!({"warnings": []});
    assert!(call(&doc, true).unwrap().is_ok());
    doc["receipt"] = json!({"safeLocators": {"report": "R-1"}});
    assert_eq!(violation(call(&doc, true).unwrap_err()), "receipt_on_read");
    let result = call(&doc, false).unwrap().unwrap();
    assert_eq!(result.result["mutationStatus"], "applied_unverified");
    assert_eq!(result.result["retrySafe"], false);
    assert_eq!(result.result["safeLocators"], json!({"report": "R-1"}));
    assert_eq!(result.result["size"], 0);
    let error = json!({"ok":false,"error":{"code":"resource_not_found","message":"missing"}});
    let result = call(&error, true).unwrap().unwrap_err();
    assert_eq!(result.reason_code(), ReasonCode::ResourceNotFound);
    assert_eq!(result.message, "missing");
    assert!(result.result.is_none());
    assert_eq!(
        call(&error, false).unwrap().unwrap_err().result.unwrap()["mutationStatus"],
        "unknown"
    );
    let mut error = error;
    error["receipt"] = json!({"mutationStatus":"not_applied"});
    assert_eq!(
        call(&error, false).unwrap().unwrap_err().result.unwrap()["retrySafe"],
        true
    );
    error["result"] = json!({});
    assert!(call(&error, false).is_err());
}

#[test]
fn filenames_media_types_and_supplied_secrets_are_validated_without_content_sniffing() {
    let mut doc = document(&[0xff]);
    for filename in ["", ".", "..", "a/b", "a\\b", "a\n", "a\u{7f}"] {
        doc["download"]["filename"] = json!(filename);
        assert_eq!(violation(read(&doc, 1).unwrap_err()), "download_filename");
    }
    doc["download"]["filename"] = json!("é".repeat(128));
    assert!(read(&doc, 1).is_err());
    doc["download"]["filename"] = json!("é".repeat(127));
    assert!(read(&doc, 1).is_ok());
    doc["download"]["filename"] = json!("report.txt");
    for content_type in [
        "",
        "plain",
        "text/plain\r\nX-Evil: 1",
        "téxt/plain",
        "text/",
        "/plain",
        "/",
        "text//plain",
        "text /plain",
        "text/ plain",
        "text/plain, application/json",
        "text/plain; charset=",
        "text/plain; charset=; next=value",
        "text/plain; =utf-8",
        "text/plain; charset =utf-8",
        "text/plain; charset= utf-8",
        "text/plain; charset",
        "text/plain; charset=\"unterminated",
        "text/plain; charset=\"escaped-end\\\"",
        "text/plain; charset=\"valid\"junk",
        "text/plain\t",
    ] {
        doc["download"]["contentType"] = json!(content_type);
        let error = match read(&doc, 1) {
            Err(error) => error,
            Ok(_) => panic!("accepted invalid media type {content_type:?}"),
        };
        assert_eq!(violation(error), "download_content_type");
    }
    for content_type in [
        "text/plain; charset=utf-8",
        "application/vnd.example.report+json; version=2",
        "Text/Plain ; charset=\"UTF-8\"; note=\"a;b=c\"",
        "text/plain; note=\"\"",
        "text/plain; note=\"quote\\\" and slash\\\\\"",
        "text/plain; ; charset=utf-8;",
    ] {
        doc["download"]["contentType"] = json!(content_type);
        assert!(
            read(&doc, 1).is_ok(),
            "rejected valid media type {content_type:?}"
        );
    }
    let mut secrets = CommandSecrets::new();
    secrets.insert("secret-token");
    for (field, value) in [
        ("filename", "secret-token.txt"),
        ("contentType", "application/secret-token"),
    ] {
        let mut doc = document(&[0]);
        doc["download"][field] = json!(value);
        let error = invoke(
            "reports",
            &action(),
            true,
            &serde_json::to_vec(&doc).unwrap(),
            &secrets,
            1,
            &Control::new(Instant::now() + Duration::from_secs(30)),
        )
        .unwrap_err();
        assert_eq!(violation(error), "secret_in_download_metadata");
    }
}

#[test]
fn raw_tokens_borrow_even_escaped_contents_and_bad_keys_produce_only_static_errors() {
    let raw = r#"{"content":"\u0041A=="}"#;
    let fields = raw_object(raw, &["content"]).unwrap();
    let content = fields.required("content").unwrap().get();
    assert_eq!(content, r#""\u0041A==""#);
    assert!(content.as_ptr() >= raw.as_ptr());
    assert!(content.as_ptr() < raw.as_ptr().wrapping_add(raw.len()));
    let bad = format!("{{\"{}\":0}}", "\\u0000".repeat(50_000));
    assert_eq!(
        violation(read_raw(bad.as_bytes(), 300_000).unwrap_err()),
        "response_shape"
    );
    let wrong_shape = format!("\"{}\"", "\\u0000".repeat(50_000));
    assert_eq!(
        violation(read_raw(wrong_shape.as_bytes(), 300_000).unwrap_err()),
        "response_shape"
    );
}

#[test]
fn preflight_limits_parser_scratch_without_rejecting_large_file_tokens() {
    let long_content = format!("{{\"content\":\"{}\"}}", "A".repeat(2 * RAW_KEY_BYTES));
    assert!(preflight(long_content.as_bytes()).is_ok());
    let escaped_key = format!("{{\"{}\":0}}", "\\u0061".repeat(STRING_BYTES));
    assert!(preflight(escaped_key.as_bytes()).is_ok());
    let oversized_key = format!("{{\"{}a\":0}}", "\\u0061".repeat(STRING_BYTES));
    assert!(preflight(oversized_key.as_bytes()).is_err());
    let missing_colon = format!("{{\"{}\",0}}", "\\u0061".repeat(STRING_BYTES + 1));
    assert!(preflight(missing_colon.as_bytes()).is_err());
    let unterminated = format!("{{\"{}", "\\u0061".repeat(STRING_BYTES + 1));
    assert!(preflight(unterminated.as_bytes()).is_err());
    let nesting = format!("{}0{}", "[".repeat(SCAN_DEPTH), "]".repeat(SCAN_DEPTH));
    assert!(preflight(nesting.as_bytes()).is_ok());
    let too_deep = format!("[{nesting}]");
    assert!(preflight(too_deep.as_bytes()).is_err());
    assert!(preflight(br#"{"content":"\"[{}]\""}"#).is_ok());
}

#[tokio::test]
async fn timeout_keeps_the_slot_until_the_real_worker_exits_and_never_delivers_its_result() {
    let registry = CommandRegistry::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    let permit = registry.acquire("reports", 1, deadline).await.unwrap();
    let lease = permit.retain_budget();
    drop(permit);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let stopped = Arc::new(AtomicBool::new(false));
    let worker_stopped = stopped.clone();
    let waiter = tokio::spawn(run_worker(lease, deadline, move |control| {
        let _ = started_tx.send(());
        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        worker_stopped.store(control.check().is_err(), Ordering::SeqCst);
        Ok(())
    }));
    started_rx.await.unwrap();
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(31)).await;
    assert!(matches!(waiter.await.unwrap(), Err(Error::Stopped)));
    tokio::time::resume();
    assert_eq!(registry.in_use("reports"), 1);
    assert_eq!(registry.live_processes(), 0);
    assert!(
        registry
            .acquire("reports", 1, Instant::now() + Duration::from_secs(30))
            .now_or_never()
            .is_none()
    );
    release_tx.send(()).unwrap();
    let next = registry
        .acquire("reports", 1, Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    assert!(stopped.load(Ordering::SeqCst));
    drop(next);
    assert_eq!(registry.in_use("reports"), 0);
}

#[tokio::test]
async fn abandoning_the_waiter_cancels_processing_without_freeing_a_running_workers_slot() {
    let registry = CommandRegistry::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    let permit = registry.acquire("reports", 1, deadline).await.unwrap();
    let lease = permit.retain_budget();
    drop(permit);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let stopped = Arc::new(AtomicBool::new(false));
    let worker_stopped = stopped.clone();
    let waiter = tokio::spawn(run_worker(lease, deadline, move |control| {
        let _ = started_tx.send(());
        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        worker_stopped.store(control.check().is_err(), Ordering::SeqCst);
        Ok(())
    }));
    started_rx.await.unwrap();
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    assert_eq!(registry.in_use("reports"), 1);
    release_tx.send(()).unwrap();
    let next = registry
        .acquire("reports", 1, Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    assert!(stopped.load(Ordering::SeqCst));
    drop(next);
}

#[tokio::test]
async fn successful_worker_releases_command_budget_before_delivery_and_byte_slices_own_storage() {
    let registry = CommandRegistry::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    let permit = registry.acquire("reports", 1, deadline).await.unwrap();
    let lease = permit.retain_budget();
    drop(permit);
    let result = run_worker(lease, deadline, |_| {
        read(&document(&vec![42; CHUNK_BYTES + 1]), CHUNK_BYTES + 1)
    })
    .await
    .unwrap();
    assert_eq!(registry.in_use("reports"), 0);
    let pieces = chunks(result).await;
    assert_eq!(pieces.len(), 2);
    let retained = pieces[0].slice(1..3);
    drop(pieces);
    assert_eq!(&retained[..], [42, 42]);
    assert_eq!(registry.in_use("reports"), 0);
}
