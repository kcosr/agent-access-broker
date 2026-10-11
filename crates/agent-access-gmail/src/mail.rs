//! Bounded projection of Gmail's parsed MIME tree. Text/HTML is returned as
//! untrusted data; nothing here renders HTML, follows links or loads images.
use crate::{protocol, valid_id};
use agent_access_provider::ProviderError;
use base64::{
    Engine,
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};
use serde_json::{Value, json};
use std::collections::BTreeSet;

const MAX_PARTS: usize = 100;
const MAX_DEPTH: usize = 16;
const MAX_TEXT: usize = 256 * 1024;

#[derive(Default)]
struct Budget {
    parts: usize,
    text: usize,
    omissions: BTreeSet<&'static str>,
}

pub(super) fn message(value: &Value, body: bool) -> Result<Value, ProviderError> {
    project(value, body, &mut Budget::default())
}
pub(super) fn thread(value: &Value) -> Result<Value, ProviderError> {
    let messages = value["messages"].as_array().ok_or_else(protocol)?;
    if messages.len() > 100 {
        return Err(protocol());
    }
    let mut budget = Budget::default();
    Ok(
        json!({"id":id(value,"id")?,"historyId":value["historyId"],"messages":messages.iter().map(|m| project(m,true,&mut budget)).collect::<Result<Vec<_>,_>>()?,"contentTrust":"untrusted"}),
    )
}
fn id<'a>(value: &'a Value, key: &str) -> Result<&'a str, ProviderError> {
    value[key]
        .as_str()
        .filter(|s| valid_id(s))
        .ok_or_else(protocol)
}
fn project(value: &Value, body: bool, budget: &mut Budget) -> Result<Value, ProviderError> {
    // Part/depth bounds apply to each message; decoded text is shared by a thread.
    budget.parts = 0;
    budget.omissions.clear();
    let mut headers_truncated = false;
    let mut texts = Vec::new();
    let mut attachments = Vec::new();
    let mut headers = Vec::new();
    if let Some(payload) = value.get("payload") {
        if let Some(raw) = payload.get("headers") {
            let raw = raw.as_array().ok_or_else(protocol)?;
            for header in raw {
                let name = header["name"].as_str().ok_or_else(protocol)?;
                if [
                    "from",
                    "to",
                    "cc",
                    "bcc",
                    "subject",
                    "date",
                    "message-id",
                    "reply-to",
                ]
                .contains(&name.to_ascii_lowercase().as_str())
                {
                    if headers.len() == 200 {
                        headers_truncated = true;
                        continue;
                    }
                    let content = header["value"].as_str().ok_or_else(protocol)?;
                    let mut end = content.len().min(16384);
                    while !content.is_char_boundary(end) {
                        end -= 1;
                    }
                    headers_truncated |= end < content.len();
                    headers.push(json!({"name":name,"value":&content[..end]}));
                }
            }
        }
        if body {
            part(payload, 0, budget, &mut texts, &mut attachments)?;
        }
    }
    Ok(
        json!({"id":id(value,"id")?,"threadId":id(value,"threadId")?,"labelIds":value["labelIds"],"snippet":value["snippet"],"internalDate":value["internalDate"],"sizeEstimate":value["sizeEstimate"],"headers":headers,"headersTruncated":headers_truncated,"textParts":texts,"attachments":attachments,"bodyTruncated":!budget.omissions.is_empty(),"bodyOmissions":budget.omissions,"contentTrust":"untrusted"}),
    )
}
fn part(
    value: &Value,
    depth: usize,
    budget: &mut Budget,
    texts: &mut Vec<Value>,
    attachments: &mut Vec<Value>,
) -> Result<(), ProviderError> {
    if depth > MAX_DEPTH || budget.parts >= MAX_PARTS {
        budget.omissions.insert(if depth > MAX_DEPTH {
            "depth_limit"
        } else {
            "part_limit"
        });
        return Ok(());
    }
    budget.parts += 1;
    let mime = value["mimeType"].as_str().unwrap_or("");
    let filename = value["filename"].as_str().unwrap_or("");
    if mime.len() > 256 {
        budget.omissions.insert("part_metadata_limit");
        return Ok(());
    }
    let mut filename_end = filename.len().min(4096);
    while !filename.is_char_boundary(filename_end) {
        filename_end -= 1;
    }
    let filename_truncated = filename_end < filename.len();
    let filename = &filename[..filename_end];
    let attachment = value.pointer("/body/attachmentId").and_then(Value::as_str);
    if !filename.is_empty() || attachment.is_some() {
        attachments.push(json!({"filename":filename,"filenameTruncated":filename_truncated,"mimeType":mime,"size":value.pointer("/body/size"),"downloadAvailable":false}));
    } else if matches!(mime, "text/plain" | "text/html")
        && let Some(data) = value.pointer("/body/data")
    {
        let encoded = data.as_str().ok_or_else(protocol)?;
        if encoded.len() > MAX_TEXT * 4 / 3 + 4 || budget.text == MAX_TEXT {
            budget.omissions.insert("text_limit");
            return Ok(());
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .or_else(|_| URL_SAFE.decode(encoded))
            .map_err(|_| protocol())?;
        let charset = value["headers"]
            .as_array()
            .and_then(|a| {
                a.iter().find(|h| {
                    h["name"]
                        .as_str()
                        .is_some_and(|n| n.eq_ignore_ascii_case("content-type"))
                })
            })
            .and_then(|h| h["value"].as_str())
            .and_then(|ct| {
                ct.split(';').skip(1).find_map(|parameter| {
                    let (key, value) = parameter.trim().split_once('=')?;
                    key.trim()
                        .eq_ignore_ascii_case("charset")
                        .then(|| value.trim().trim_matches('"'))
                })
            })
            .unwrap_or("utf-8");
        let encoding = encoding_rs::Encoding::for_label(charset.as_bytes());
        let (text, _, had_errors) = encoding.unwrap_or(encoding_rs::UTF_8).decode(&bytes);
        if text.len() > MAX_TEXT - budget.text {
            budget.omissions.insert("text_limit");
        } else {
            budget.text += text.len();
            texts.push(json!({"mimeType":mime,"text":text,"charsetFallback":encoding.is_none(),"decodeErrors":had_errors}));
        }
    }
    if let Some(parts) = value.get("parts") {
        let parts = parts.as_array().ok_or_else(protocol)?;
        for child in parts {
            if budget.parts >= MAX_PARTS {
                budget.omissions.insert("part_limit");
                break;
            }
            part(child, depth + 1, budget, texts, attachments)?;
        }
    }
    Ok(())
}
