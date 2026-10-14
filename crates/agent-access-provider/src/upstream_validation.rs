//! Bounded, sanitized extraction of upstream validation messages.
use serde_json::Value;

const VALIDATION_BODY_MAX_BYTES: usize = 16 * 1024;

pub const VALIDATION_MESSAGE_MAX_BYTES: usize = 768;

pub const VALIDATION_FRAGMENT_MAX_BYTES: usize = 256;

pub const VALIDATION_FIELD_MAX_BYTES: usize = 64;

pub const VALIDATION_MESSAGE_MAX_PARTS: usize = 4;

pub fn response_has_json_content_type(response: &reqwest::Response) -> bool {
    response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .is_some_and(|value| {
            value.eq_ignore_ascii_case("application/json")
                || value.to_ascii_lowercase().ends_with("+json")
        })
}

pub async fn read_validation_json(
    response: reqwest::Response,
    configured_byte_cap: u64,
) -> Option<Value> {
    let byte_cap = configured_byte_cap.min(VALIDATION_BODY_MAX_BYTES as u64);
    let bytes = crate::read_bounded_body(response, byte_cap, None)
        .await
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub fn push_message_part(parts: &mut Vec<String>, field: Option<String>, message: Option<&str>) {
    if parts.len() >= VALIDATION_MESSAGE_MAX_PARTS {
        return;
    }
    let Some(message) = message.and_then(sanitize_fragment) else {
        return;
    };
    let part = field.map_or(message.clone(), |field| format!("{field}: {message}"));
    let part = truncate_to_bytes(&part, VALIDATION_FRAGMENT_MAX_BYTES);
    if !parts.contains(&part) {
        parts.push(part);
    }
}

pub fn join_message_parts(parts: Vec<String>) -> Option<String> {
    let mut message = String::new();
    for part in parts {
        let separator = if message.is_empty() { "" } else { "; " };
        if message
            .len()
            .saturating_add(separator.len())
            .saturating_add(part.len())
            > VALIDATION_MESSAGE_MAX_BYTES
        {
            break;
        }
        message.push_str(separator);
        message.push_str(&part);
    }
    (!message.is_empty()).then_some(message)
}

pub fn sanitize_fragment(value: &str) -> Option<String> {
    let mut sanitized = String::new();
    let mut pending_space = false;
    let mut in_markup = false;
    let mut in_ansi_escape = false;
    for character in value.trim().chars() {
        if in_markup {
            if character == '>' {
                in_markup = false;
                pending_space = !sanitized.is_empty();
            }
            continue;
        }
        if in_ansi_escape {
            if character.is_ascii_alphabetic() {
                in_ansi_escape = false;
            }
            continue;
        }
        if character == '<' {
            in_markup = true;
            pending_space = !sanitized.is_empty();
            continue;
        }
        if character == '\u{1b}' {
            in_ansi_escape = true;
            pending_space = !sanitized.is_empty();
            continue;
        }
        if character.is_control()
            || character.is_whitespace()
            || character == '>'
            || is_disallowed_format_character(character)
        {
            pending_space = !sanitized.is_empty();
            continue;
        }
        if pending_space {
            if sanitized.len() + 1 > VALIDATION_FRAGMENT_MAX_BYTES {
                break;
            }
            sanitized.push(' ');
            pending_space = false;
        }
        if sanitized.len() + character.len_utf8() > VALIDATION_FRAGMENT_MAX_BYTES {
            break;
        }
        sanitized.push(character);
    }
    (!sanitized.is_empty()).then_some(sanitized)
}

fn is_disallowed_format_character(character: char) -> bool {
    matches!(
        character,
        '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}'
    )
}

fn truncate_to_bytes(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].trim_end().to_string()
}

pub fn sanitize_field(value: &str) -> Option<String> {
    if value.is_empty()
        || value.len() > VALIDATION_FIELD_MAX_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return None;
    }
    Some(value.to_string())
}
