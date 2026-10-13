//! Bounded consoleText reads. Source positions always count entity bytes,
//! never UTF-8 replacement bytes or Jenkins' annotated progressive-log offsets.
use super::*;
use agent_access_provider::{
    ContinuationBinding, ContinuationError, ContinuationFamily, ContinuationLifetime,
    ContinuationSigner,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;

/// Head and search continuations. They carry the next source position and a
/// keyed commitment to the consumed prefix, and expire after 15 minutes;
/// without a configured stable key a reload or restart invalidates them.
const LOG_CURSORS: ContinuationFamily = ContinuationFamily::new(
    "cloudbees_ci",
    "build-log-cursor",
    3,
    ContinuationLifetime::StableWhenConfigured,
    CURSOR_PAYLOAD_BYTES,
)
.expires_after(Duration::from_secs(900));
/// An 8-byte source position and a 32-byte prefix commitment.
const CURSOR_PAYLOAD_BYTES: usize = 8 + 32;
const CURSOR_MAX_BYTES: usize = LOG_CURSORS.max_token_bytes();
const PREFIX_COMMITMENT: &str = "consumedPrefix";
const CONTEXT_BYTES: u64 = 256;

pub(super) fn default_scan_limit() -> u64 {
    16 * 1024 * 1024
}

pub(super) fn fingerprint(config: &CloudbeesCiProviderConfig, limits: &ProviderLimits) -> String {
    // Configuration only, never credentials or log content.
    let controllers: BTreeMap<_, _> = config
        .controllers
        .iter()
        .map(|(name, c)| (name, (&c.base_url, &c.web_base_url)))
        .collect();
    hash(
        &json!({"controllers":controllers,"scan":config.max_log_scan_bytes,
        "allowlist":config.allowed_upstream_hosts,"proxy":config.egress_proxy.as_ref().map(|p| (&p.url, &p.username_ref, &p.password_ref)),
        "requestTimeout":limits.request_timeout_ms,"idleTimeout":limits.streaming_idle_timeout_ms,
        "responseLimit":limits.max_upstream_response_bytes}),
    )
}

pub(super) fn input_properties() -> serde_json::Map<String, Value> {
    json!({
        "mode":{"type":"string","enum":["head","tail","search"],"default":"tail"},
        "maxBytes":{"type":"integer","minimum":1024,"maximum":65536,"default":16384,
            "description":"Returned UTF-8 text budget, independent of the provider scan ceiling."},
        "cursor":{"type":"string","minLength":1,"maxLength":CURSOR_MAX_BYTES,
            "description":"Opaque head/search continuation. Keep mode, query and output settings unchanged; each page rescans its prefix."},
        "query":{"type":"string","minLength":1,"maxLength":256,
            "description":"Search only: case-sensitive literal, at most 256 UTF-8 bytes. No regular expressions."},
        "maxMatches":{"type":"integer","minimum":1,"maximum":100,"default":20,
            "description":"Search only."}
    }).as_object().unwrap().clone()
}

#[derive(Debug)]
pub(super) struct LogInput<'a> {
    mode: &'a str,
    max_bytes: usize,
    cursor: Option<&'a str>,
    query: Option<&'a str>,
    max_matches: usize,
}
impl<'a> LogInput<'a> {
    pub(super) fn parse(object: &'a serde_json::Map<String, Value>) -> Result<Self, ProviderError> {
        let optional_string = |key: &'static str| {
            object
                .get(key)
                .map(|v| {
                    v.as_str().ok_or_else(|| {
                        input_error(
                            "value_invalid",
                            Some(key),
                            format!("{key} must be a string"),
                        )
                    })
                })
                .transpose()
        };
        let mode = optional_string("mode")?.unwrap_or("tail");
        if !matches!(mode, "head" | "tail" | "search") {
            return Err(input_error(
                "value_invalid",
                Some("mode"),
                "mode must be head, tail, or search",
            ));
        }
        let number = |key: &'static str, default, min, max| match object.get(key) {
            None => Ok(default),
            Some(value) => value
                .as_u64()
                .filter(|n| (min..=max).contains(n))
                .map(|n| n as usize)
                .ok_or_else(|| {
                    input_error(
                        "value_invalid",
                        Some(key),
                        format!("{key} must be an integer from {min} to {max}"),
                    )
                }),
        };
        let cursor = optional_string("cursor")?;
        let query = optional_string("query")?;
        if cursor.is_some_and(|c| c.is_empty() || c.len() > CURSOR_MAX_BYTES) {
            return Err(input_error(
                "value_invalid",
                Some("cursor"),
                "cursor must be the nextCursor value from a previous head or search read",
            ));
        }
        if mode == "tail" && cursor.is_some() {
            return Err(input_error(
                "option_conflict",
                Some("cursor"),
                "tail reads have no cursor; continue a head or search read with the same mode",
            ));
        }
        if mode == "search" {
            if !query.is_some_and(|q| !q.is_empty() && q.len() <= 256) {
                return Err(input_error(
                    "value_invalid",
                    Some("query"),
                    "mode search needs a nonempty literal query of at most 256 UTF-8 bytes",
                ));
            }
        } else if let Some(field) = ["query", "maxMatches"]
            .into_iter()
            .find(|field| object.contains_key(*field))
        {
            return Err(input_error(
                "option_conflict",
                Some(field),
                format!("{field} applies only to mode search"),
            ));
        }
        Ok(Self {
            mode,
            max_bytes: number("maxBytes", 16384, 1024, 65536)?,
            cursor,
            query,
            max_matches: number("maxMatches", 20, 1, 100)?,
        })
    }
}

struct Cursor {
    position: u64,
    prefix: [u8; 32],
}
fn hash(value: &impl Serialize) -> String {
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).expect("serializable log binding"))
    )
}
fn cursor_error() -> ProviderError {
    ProviderError::deny(
        ReasonCode::InputInvalid,
        "Invalid or expired log cursor, changed request context, or rewritten/truncated log prefix; start a new read without the cursor",
    )
}
fn signing_error() -> ProviderError {
    ProviderError::error(
        ReasonCode::CursorSigningUnavailable,
        "Broker log cursor signing key is unavailable",
    )
}
fn cursor_failure(error: ContinuationError) -> ProviderError {
    match error {
        _ if error.is_token_rejection() => cursor_error(),
        ContinuationError::SigningUnavailable | ContinuationError::DurableKeyUnavailable => {
            signing_error()
        }
        _ => ProviderError::error(
            ReasonCode::OperationFailed,
            "Broker could not encode the log cursor",
        ),
    }
}

/// Binds a cursor to the admitted context and configuration, the numeric
/// build and every read setting. The binding enters only the MACs, and the
/// prefix commitment shares it, so a commitment never correlates across
/// requests.
fn cursor_binding(
    request: &ProviderInvocation,
    configuration: &str,
    input: &JobInput<'_>,
    options: &LogInput<'_>,
) -> ContinuationBinding {
    LOG_CURSORS
        .bind(request.context(), configuration)
        .text("controller", &input.controller)
        .text("job", &input.job)
        .optional_number("build", input.build_number)
        .text("mode", options.mode)
        .optional_text("query", options.query)
        .number("maxBytes", options.max_bytes as u64)
        .number("maxMatches", options.max_matches as u64)
}

fn verify_prefix(
    signer: &ContinuationSigner,
    binding: &ContinuationBinding,
    digest: &[u8; 32],
    prefix: &[u8; 32],
) -> Result<(), ProviderError> {
    signer
        .verify_commitment(binding, PREFIX_COMMITMENT, digest, prefix)
        .map_err(cursor_failure)
}

fn decode_cursor(
    signer: &ContinuationSigner,
    value: &str,
    binding: &ContinuationBinding,
    cap: u64,
) -> Result<Cursor, ProviderError> {
    let payload = signer.open(binding, value).map_err(cursor_failure)?;
    let (position, prefix) = payload.split_first_chunk::<8>().ok_or_else(cursor_error)?;
    let position = u64::from_be_bytes(*position);
    let prefix = <[u8; 32]>::try_from(prefix).map_err(|_| cursor_error())?;
    if position == 0 || position >= cap {
        return Err(cursor_error());
    }
    Ok(Cursor { position, prefix })
}
fn encode_cursor(
    signer: &ContinuationSigner,
    binding: &ContinuationBinding,
    position: u64,
    digest: &[u8; 32],
) -> Result<String, ProviderError> {
    let prefix = signer
        .commit(binding, PREFIX_COMMITMENT, digest)
        .map_err(cursor_failure)?;
    let mut payload = Vec::with_capacity(CURSOR_PAYLOAD_BYTES);
    payload.extend_from_slice(&position.to_be_bytes());
    payload.extend_from_slice(&prefix);
    signer.seal(binding, &payload).map_err(cursor_failure)
}

#[derive(Clone)]
struct Unit {
    start: u64,
    raw: [u8; 4],
    len: u8,
    text: char,
}
impl Unit {
    fn end(&self) -> u64 {
        self.start + u64::from(self.len)
    }
    fn raw(&self) -> &[u8] {
        &self.raw[..usize::from(self.len)]
    }
}

/// Keeps at most one transport chunk and four decoder bytes. Incomplete final
/// UTF-8 is withheld; definitively malformed sequences use one replacement.
struct Decoder {
    response: reqwest::Response,
    chunk: bytes::Bytes,
    chunk_offset: usize,
    scan_cap: u64,
    expected_length: Option<u64>,
    scanned: u64,
    eof: bool,
    limited: bool,
    bytes: VecDeque<u8>,
    position: u64,
    idle: Duration,
    deadline: tokio::time::Instant,
}
impl Decoder {
    async fn byte(&mut self) -> Result<Option<u8>, ProviderError> {
        if self.scanned == self.scan_cap {
            // A known complete response can reach EOF exactly at the ceiling.
            if self.chunk_offset == self.chunk.len() && self.expected_length == Some(self.scanned) {
                self.eof = true;
            } else {
                self.limited = true;
            }
            return Ok(None);
        }
        if self.scanned.is_multiple_of(65_536) {
            tokio::task::yield_now().await;
            if tokio::time::Instant::now() >= self.deadline {
                return Err(timeout_error());
            }
        }
        while self.chunk_offset == self.chunk.len() {
            let chunk = tokio::time::timeout_at(
                self.deadline.min(tokio::time::Instant::now() + self.idle),
                self.response.chunk(),
            )
            .await
            .map_err(|_| timeout_error())?
            .map_err(|e| {
                ProviderError::error(
                    if e.is_timeout() {
                        ReasonCode::UpstreamTimeout
                    } else {
                        ReasonCode::UpstreamConnectionFailed
                    },
                    "CloudBees CI console response failed",
                )
            })?;
            let Some(chunk) = chunk else {
                self.eof = true;
                return Ok(None);
            };
            self.chunk = chunk;
            self.chunk_offset = 0;
        }
        let byte = self.chunk[self.chunk_offset];
        self.chunk_offset += 1;
        self.scanned += 1;
        Ok(Some(byte))
    }
    async fn next(&mut self) -> Result<Option<Unit>, ProviderError> {
        loop {
            if !self.bytes.is_empty() {
                let mut raw = [0; 4];
                for (slot, byte) in raw.iter_mut().zip(&self.bytes) {
                    *slot = *byte;
                }
                let bytes = &raw[..self.bytes.len()];
                let (size, text) = match std::str::from_utf8(bytes) {
                    Ok(text) => {
                        let c = text.chars().next().unwrap();
                        (c.len_utf8(), c)
                    }
                    Err(e) if e.valid_up_to() > 0 => {
                        let c = std::str::from_utf8(&bytes[..e.valid_up_to()])
                            .unwrap()
                            .chars()
                            .next()
                            .unwrap();
                        (c.len_utf8(), c)
                    }
                    Err(e) => match e.error_len() {
                        Some(n) => (n, '\u{fffd}'),
                        None => (0, '\0'),
                    },
                };
                if size > 0 {
                    self.bytes.drain(..size);
                    let unit = Unit {
                        start: self.position,
                        raw,
                        len: size as u8,
                        text,
                    };
                    self.position = unit.end();
                    return Ok(Some(unit));
                }
            }
            match self.byte().await? {
                Some(b) => self.bytes.push_back(b),
                None => return Ok(None),
            }
        }
    }
}

struct Scan {
    decoder: Decoder,
    ahead: VecDeque<Unit>,
    history: VecDeque<Unit>,
    digest: Sha256,
    position: u64,
}
impl Scan {
    async fn peek(&mut self) -> Result<Option<&Unit>, ProviderError> {
        if self.ahead.is_empty()
            && let Some(unit) = self.decoder.next().await?
        {
            self.ahead.push_back(unit);
        }
        Ok(self.ahead.front())
    }
    async fn pop(&mut self) -> Result<Option<Unit>, ProviderError> {
        self.peek().await?;
        let Some(unit) = self.ahead.pop_front() else {
            return Ok(None);
        };
        self.digest.update(unit.raw());
        self.position = unit.end();
        self.history.push_back(unit.clone());
        while self
            .history
            .front()
            .is_some_and(|first| self.position - first.start > 512)
        {
            self.history.pop_front();
        }
        Ok(Some(unit))
    }
    async fn context_after(&mut self) -> Result<(), ProviderError> {
        while self
            .ahead
            .back()
            .map_or(0, |unit| unit.end() - self.position)
            < CONTEXT_BYTES
        {
            let Some(unit) = self.decoder.next().await? else {
                break;
            };
            self.ahead.push_back(unit);
        }
        Ok(())
    }
    fn prefix_digest(&self) -> [u8; 32] {
        self.digest.clone().finalize().into()
    }
    fn end_reason(&self) -> &'static str {
        if self.decoder.limited {
            "scan_limit"
        } else if !self.decoder.bytes.is_empty() {
            "pending_text"
        } else {
            "eof"
        }
    }
}
fn timeout_error() -> ProviderError {
    ProviderError::error(
        ReasonCode::UpstreamTimeout,
        "CloudBees CI log read exceeded its total or streaming idle deadline",
    )
}

impl CloudbeesCiProvider {
    pub(super) async fn read_log(
        &self,
        request: &ProviderInvocation,
        input: &JobInput<'_>,
        controller: &Controller,
        credential: &ExecutionCredential,
        job_url: Url,
    ) -> Result<ProviderResult, ProviderError> {
        let deadline =
            tokio::time::Instant::now() + self.request_timeout.min(Duration::from_secs(20));
        tokio::time::timeout_at(
            deadline,
            self.read_log_inner(request, input, controller, credential, job_url, deadline),
        )
        .await
        .map_err(|_| timeout_error())?
    }

    #[allow(clippy::too_many_arguments)]
    async fn read_log_inner(
        &self,
        request: &ProviderInvocation,
        input: &JobInput<'_>,
        controller: &Controller,
        credential: &ExecutionCredential,
        job_url: Url,
        deadline: tokio::time::Instant,
    ) -> Result<ProviderResult, ProviderError> {
        let options = input.log.as_ref().expect("parsed log input");
        let binding = cursor_binding(request, &self.log_fingerprint, input, options);
        let cursor = options
            .cursor
            .map(|c| decode_cursor(&self.log_signer, c, &binding, self.log_scan_limit))
            .transpose()?;
        let (username, token) = basic_material(credential)?;
        let number = input.build_number.expect("required build");
        let url = Self::append(job_url, &[&number.to_string(), "consoleText"]);
        let started = Instant::now();
        let mut response = controller
            .download_client
            .get_following_redirects(
                url.clone(),
                RedirectRules {
                    max_redirects: 0,
                    deadline: deadline.saturating_duration_since(tokio::time::Instant::now()),
                    correlate_other_origins: false,
                    vet: &|candidate| *candidate == url,
                    decorate: &|r| r.header(reqwest::header::ACCEPT_ENCODING, "identity"),
                    authorize: &|r| r.basic_auth(username, Some(token)),
                },
                "build.log.read",
            )
            .await
            .map_err(|e| {
                ProviderError::error(e.reason_code(), "CloudBees CI log request failed")
            })?;
        complete_upstream_trace(&mut response, None);
        match response.status() {
            StatusCode::OK => {}
            StatusCode::UNAUTHORIZED => {
                return Err(ProviderError::error(
                    ReasonCode::UpstreamUnauthorized,
                    "CloudBees CI rejected the credential",
                ));
            }
            StatusCode::FORBIDDEN => {
                return Err(ProviderError::error(
                    ReasonCode::UpstreamForbidden,
                    "CloudBees CI denied log access",
                ));
            }
            StatusCode::NOT_FOUND => {
                return Err(upstream_not_found("CloudBees CI log was not found"));
            }
            StatusCode::TOO_MANY_REQUESTS => return Err(rate_limited(response.headers())),
            status if !status.is_success() && !status.is_redirection() => {
                return Err(ProviderError::error(
                    ReasonCode::UpstreamFailed,
                    "CloudBees CI returned an unexpected status",
                ));
            }
            _ => return Err(protocol_error()),
        }
        // This client intentionally has no implicit compression codecs. Require
        // the plain entity so byte positions and prefix digests have one meaning.
        if response
            .headers()
            .get_all(reqwest::header::CONTENT_ENCODING)
            .iter()
            .any(|value| {
                !value
                    .to_str()
                    .is_ok_and(|v| v.trim().eq_ignore_ascii_case("identity"))
            })
        {
            return Err(protocol_error());
        }
        if !response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(';')
                    .next()
                    .is_some_and(|v| v.trim().eq_ignore_ascii_case("text/plain"))
            })
        {
            return Err(protocol_error());
        }
        let expected_length = response.content_length();
        let mut scan = Scan {
            decoder: Decoder {
                response,
                expected_length,
                chunk: bytes::Bytes::new(),
                chunk_offset: 0,
                scan_cap: self.log_scan_limit,
                scanned: 0,
                eof: false,
                limited: false,
                bytes: VecDeque::new(),
                position: 0,
                idle: self.download_idle_timeout,
                deadline,
            },
            ahead: VecDeque::new(),
            history: VecDeque::new(),
            digest: Sha256::new(),
            position: 0,
        };
        let start = cursor.as_ref().map_or(0, |c| c.position);
        while scan.position < start {
            if scan.pop().await?.is_none() || scan.position > start {
                return Err(cursor_error());
            }
        }
        if let Some(cursor) = &cursor {
            verify_prefix(
                &self.log_signer,
                &binding,
                &scan.prefix_digest(),
                &cursor.prefix,
            )?;
        }
        let (mut result, stop) = match options.mode {
            "head" => head(&mut scan, options.max_bytes).await?,
            "tail" => tail(&mut scan, options.max_bytes).await?,
            "search" => search(&mut scan, options).await?,
            _ => unreachable!(),
        };
        if options.mode == "tail" && scan.decoder.limited {
            return Err(ProviderError::domain(&CLOUDBEES_CI_LOG_SCAN_EXCEEDED,
                "The scan ceiling prevented reaching the log end; increasing maxBytes cannot help. Use head, an applicable Pipeline step log, an operator-adjusted scan ceiling, or a separately authorized download")
                .with_result(json!({"stopReason":"scan_limit","scannedBytes":scan.decoder.scanned,"maxLogScanBytes":self.log_scan_limit,"reachedEnd":false})));
        }
        let pending_width = match scan.decoder.bytes.front() {
            Some(0xc2..=0xdf) => 2,
            Some(0xe0..=0xef) => 3,
            Some(0xf0..=0xf4) => 4,
            _ => 0,
        };
        let pending_can_fit = stop != "pending_text"
            || scan.decoder.position.saturating_add(pending_width) <= self.log_scan_limit;
        let next_cursor = if options.mode != "tail"
            && pending_can_fit
            && matches!(stop, "output_limit" | "match_limit" | "pending_text")
            && scan.position > start
            && scan.position < self.log_scan_limit
        {
            Some(encode_cursor(
                &self.log_signer,
                &binding,
                scan.position,
                &scan.prefix_digest(),
            )?)
        } else {
            None
        };
        let object = result.as_object_mut().expect("log result");
        object.extend(json!({"controller":input.controller,"job":input.job,"buildNumber":number,"mode":options.mode,
            "scannedBytes":scan.decoder.scanned,"reachedEnd":scan.decoder.eof,"stopReason":stop,
            "nextCursor":next_cursor,"pendingUtf8Bytes":if scan.decoder.eof { scan.decoder.bytes.len() } else { 0 },
            "maxLogScanBytes":self.log_scan_limit}).as_object().unwrap().clone());
        let reply = Reply {
            status: StatusCode::OK,
            bytes: Vec::new(),
            content_type: None,
            location: None,
            duration_ms: started.elapsed().as_millis() as u64,
        };
        Ok(self.result(
            "build.log.read",
            input,
            result,
            &reply,
            controller.download_client.egress_route(),
        ))
    }
}

async fn head(scan: &mut Scan, budget: usize) -> Result<(Value, &'static str), ProviderError> {
    let start = scan.position;
    let mut text = String::new();
    let stop = loop {
        let Some(unit) = scan.peek().await? else {
            break scan.end_reason();
        };
        if text.len() + unit.text.len_utf8() > budget {
            break "output_limit";
        }
        let unit = scan.pop().await?.unwrap();
        text.push(unit.text);
    };
    Ok((
        json!({"text":text,"sourceStart":start,"sourceEnd":scan.position,"leadingTextOmitted":start > 0}),
        stop,
    ))
}
async fn tail(scan: &mut Scan, budget: usize) -> Result<(Value, &'static str), ProviderError> {
    let mut units = VecDeque::new();
    let mut size = 0;
    while let Some(unit) = scan.pop().await? {
        size += unit.text.len_utf8();
        units.push_back(unit);
        while size > budget {
            size -= units.pop_front().unwrap().text.len_utf8();
        }
    }
    let start = units.front().map_or(scan.position, |unit| unit.start);
    let text: String = units.iter().map(|unit| unit.text).collect();
    Ok((
        json!({"text":text,"sourceStart":start,"sourceEnd":scan.position,"leadingTextOmitted":start > 0}),
        scan.end_reason(),
    ))
}

fn prefix_table(query: &[u8]) -> Vec<usize> {
    let mut table = vec![0; query.len()];
    let mut matched = 0;
    for i in 1..query.len() {
        while matched > 0 && query[i] != query[matched] {
            matched = table[matched - 1];
        }
        if query[i] == query[matched] {
            matched += 1;
        }
        table[i] = matched;
    }
    table
}
async fn search(
    scan: &mut Scan,
    options: &LogInput<'_>,
) -> Result<(Value, &'static str), ProviderError> {
    let query = options.query.expect("search query");
    let needle = query.as_bytes();
    let table = prefix_table(needle);
    let mut matched = 0;
    let source_start = scan.position;
    let mut safe_position = scan.position;
    let mut safe_digest = scan.digest.clone();
    let mut matches = Vec::new();
    let mut remaining = options.max_bytes;
    let stop = loop {
        if scan.ahead.is_empty() && (scan.decoder.eof || scan.decoder.limited) {
            break scan.end_reason();
        }
        if matches.len() == options.max_matches {
            break "match_limit";
        }
        if remaining < query.len() {
            break "output_limit";
        }
        if matched == 0 {
            safe_position = scan.position;
            safe_digest = scan.digest.clone();
        }
        let Some(unit) = scan.pop().await? else {
            break scan.end_reason();
        };
        for byte in unit.raw() {
            while matched > 0 && *byte != needle[matched] {
                matched = table[matched - 1];
            }
            if *byte == needle[matched] {
                matched += 1;
            }
            if matched == needle.len() {
                break;
            }
        }
        if matched != needle.len() {
            continue;
        }
        matched = 0; // Non-overlapping occurrences.
        let end = scan.position;
        let start = end - needle.len() as u64;
        scan.context_after().await?;
        let before: Vec<_> = scan
            .history
            .iter()
            .filter(|u| u.end() <= start && start - u.start <= CONTEXT_BYTES)
            .collect();
        let after: Vec<_> = scan
            .ahead
            .iter()
            .take_while(|u| u.end() - end <= CONTEXT_BYTES)
            .collect();
        let mut before_size = 0;
        let mut begin = before.len();
        let available = remaining - query.len();
        // Reserve half for following text; use spare space for preceding text.
        let after_available: usize = after.iter().map(|u| u.text.len_utf8()).sum();
        let before_budget = available.saturating_sub(after_available.min(available.div_ceil(2)));
        while begin > 0 && before_size + before[begin - 1].text.len_utf8() <= before_budget {
            begin -= 1;
            before_size += before[begin].text.len_utf8();
        }
        let mut text: String = before[begin..].iter().map(|u| u.text).collect();
        text.push_str(query);
        let mut after_end = end;
        for u in &after {
            if text.len() + u.text.len_utf8() > remaining {
                break;
            }
            text.push(u.text);
            after_end = u.end();
        }
        let source_start = before.get(begin).map_or(start, |u| u.start);
        remaining -= text.len();
        matches.push(json!({"text":text,"sourceStart":source_start,"sourceEnd":after_end,
            "matchStart":start,"matchEnd":end,"contextBeforeClipped":source_start > start.saturating_sub(CONTEXT_BYTES),
            "contextAfterClipped":after_end < end.saturating_add(CONTEXT_BYTES) && !(scan.decoder.eof && after_end == scan.decoder.position)}));
    };
    // A growing final character may complete a literal whose valid prefix was
    // already scanned. Resume before that candidate, never after it. Replaying
    // nonmatching candidate bytes is safe; disclosed matches precede this point.
    if stop == "pending_text" && matched > 0 {
        scan.position = safe_position;
        scan.digest = safe_digest;
    }
    Ok((
        json!({"matches":matches,"sourceStart":source_start,"sourceEnd":scan.position}),
        stop,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{invocation, provider};
    use agent_access_provider::CredentialMode;
    use agent_access_provider::test_support::InvocationBuilder;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn inputs(mode: &str) -> Value {
        json!({"controller":"team-ci","job":"payments/build-api","buildNumber":42,"mode":mode,"maxBytes":1024})
    }
    async fn body(server: &MockServer, bytes: Vec<u8>) {
        Mock::given(method("GET"))
            .and(path("/team-ci/job/payments/job/build-api/42/consoleText"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(bytes)
                    .insert_header("Content-Type", "text/plain;charset=UTF-8"),
            )
            .mount(server)
            .await;
    }
    async fn read(ci: &CloudbeesCiProvider, input: Value) -> Result<Value, ProviderError> {
        Ok(ci.invoke(invocation("build.log.read", input)).await?.result)
    }

    #[tokio::test]
    async fn head_reassembles_large_log_with_codepoint_safe_cursors() {
        let server = MockServer::start().await;
        let expected = "a🙂é\n".repeat(10_000);
        body(&server, expected.as_bytes().to_vec()).await;
        let ci = provider(&server);
        let mut input = inputs("head");
        let mut actual = String::new();
        let mut previous_end = 0;
        loop {
            let page = read(&ci, input.clone()).await.unwrap();
            assert_eq!(page["sourceStart"], previous_end);
            let text = page["text"].as_str().unwrap();
            assert!(text.len() <= 1024);
            actual.push_str(text);
            previous_end = page["sourceEnd"].as_u64().unwrap();
            if page["nextCursor"].is_null() {
                assert_eq!(page["stopReason"], "eof");
                break;
            }
            input["cursor"] = page["nextCursor"].clone();
        }
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn ansi_and_console_note_bytes_survive_paging_and_search_literally() {
        let server = MockServer::start().await;
        // consoleText is already Jenkins' plain projection. If escape or note
        // markers remain, the broker preserves them; it never strips codes or
        // interprets/decodes the base64 payload as additional searchable text.
        let line = "\x1b[31mFAIL\x1b[0m next 🙂 \x1b[8mha:c2VjcmV0LW5vdGU=\x1b[0m\n";
        let expected = line.repeat(1500);
        assert!(expected.len() > 65_536);
        body(&server, expected.as_bytes().to_vec()).await;
        let ci = provider(&server);
        let mut input = inputs("head");
        let mut actual = String::new();
        let mut source_end = 0;
        loop {
            let page = read(&ci, input.clone()).await.unwrap();
            assert_eq!(page["sourceStart"], source_end);
            actual.push_str(page["text"].as_str().unwrap());
            source_end = page["sourceEnd"].as_u64().unwrap();
            if page["nextCursor"].is_null() {
                break;
            }
            input["cursor"] = page["nextCursor"].clone();
        }
        assert_eq!(actual, expected);
        assert_eq!(source_end as usize, expected.len());

        server.reset().await;
        let text = line.repeat(10);
        body(&server, text.as_bytes().to_vec()).await;
        for query in [
            "FAIL",
            "IL\x1b[0m next",
            "\x1b[8mha:",
            "c2VjcmV0LW5vdGU=",
            "secret-note",
            "FAIL next",
        ] {
            let mut expected = Vec::new();
            let mut offset = 0;
            while offset + query.len() <= text.len() {
                if &text.as_bytes()[offset..offset + query.len()] == query.as_bytes() {
                    expected.push(offset as u64);
                    offset += query.len();
                } else {
                    offset += 1;
                }
            }
            let mut input = inputs("search");
            input["query"] = json!(query);
            input["maxMatches"] = json!(2);
            let mut actual = Vec::new();
            loop {
                let page = read(&ci, input.clone()).await.unwrap();
                for found in page["matches"].as_array().unwrap() {
                    let start = found["matchStart"].as_u64().unwrap();
                    assert_eq!(found["matchEnd"], start + query.len() as u64);
                    actual.push(start);
                }
                if page["nextCursor"].is_null() {
                    break;
                }
                input["cursor"] = page["nextCursor"].clone();
            }
            assert_eq!(actual, expected, "literal query {query:?}");
        }
    }

    #[tokio::test]
    async fn reported_large_log_tail_succeeds_with_small_text_budget() {
        let server = MockServer::start().await;
        let mut log = vec![b'x'; 4_590_015];
        let end = b"BUILD FAILED\n";
        let offset = log.len() - end.len();
        log[offset..].copy_from_slice(end);
        body(&server, log).await;
        let result = read(&provider(&server), inputs("tail")).await.unwrap();
        assert!(result["text"].as_str().unwrap().ends_with("BUILD FAILED\n"));
        assert_eq!(result["sourceStart"], 4_590_015 - 1024);
        assert_eq!(result["sourceEnd"], 4_590_015);
        assert_eq!(result["scannedBytes"], 4_590_015);
        assert_eq!(result["reachedEnd"], true);
        assert_eq!(result["stopReason"], "eof");
    }

    #[tokio::test]
    async fn scan_limit_is_partial_for_head_search_and_honest_tail_error() {
        let server = MockServer::start().await;
        body(&server, vec![b'x'; 5000]).await;
        let mut ci = provider(&server);
        ci.log_scan_limit = 2000;
        let mut input = inputs("head");
        input["maxBytes"] = json!(3000);
        let head = read(&ci, input).await.unwrap();
        assert_eq!(head["text"].as_str().unwrap().len(), 2000);
        assert_eq!(head["stopReason"], "scan_limit");
        assert_eq!(head["reachedEnd"], false);
        assert!(head["nextCursor"].is_null());
        let mut input = inputs("search");
        input["query"] = json!("no match");
        let search = read(&ci, input).await.unwrap();
        assert_eq!(search["matches"], json!([]));
        assert_eq!(search["stopReason"], "scan_limit");
        let tail = read(&ci, inputs("tail")).await.unwrap_err();
        assert_eq!(
            tail.reason_code(),
            agent_access_provider::ProviderReason::from(&CLOUDBEES_CI_LOG_SCAN_EXCEEDED)
        );
        assert_eq!(tail.decision(), agent_access_provider::Decision::Deny);
        assert_eq!(tail.reason_code().http_status(), 413);
        assert!(!tail.message.contains("xxxxx"));
    }

    #[tokio::test]
    async fn scan_ceiling_at_known_eof_and_empty_logs_are_complete() {
        let server = MockServer::start().await;
        body(&server, vec![b'a'; 1024]).await;
        let mut ci = provider(&server);
        ci.log_scan_limit = 1024;
        assert_eq!(
            read(&ci, inputs("tail")).await.unwrap()["stopReason"],
            "eof"
        );
        server.reset().await;
        body(&server, vec![]).await;
        let empty = read(&ci, inputs("head")).await.unwrap();
        assert_eq!(empty["text"], "");
        assert_eq!(empty["sourceEnd"], 0);
        assert_eq!(empty["reachedEnd"], true);
        assert!(empty["nextCursor"].is_null());
    }

    #[tokio::test]
    async fn search_context_lookahead_never_skips_or_duplicates_matches() {
        let server = MockServer::start().await;
        body(&server, b"aaa aba aba\n".repeat(100)).await;
        let ci = provider(&server);
        let mut input = inputs("search");
        input["query"] = json!("aa");
        input["maxMatches"] = json!(2);
        let mut positions = Vec::new();
        loop {
            let result = read(&ci, input.clone()).await.unwrap();
            let matches = result["matches"].as_array().unwrap();
            assert!(
                matches
                    .iter()
                    .map(|m| m["text"].as_str().unwrap().len())
                    .sum::<usize>()
                    <= 1024
            );
            for m in matches {
                positions.push(m["matchStart"].as_u64().unwrap());
            }
            if result["nextCursor"].is_null() {
                break;
            }
            input["cursor"] = result["nextCursor"].clone();
        }
        assert_eq!(positions, (0..100).map(|n| n * 12).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn paged_search_matches_reference_for_adjacent_unicode_and_binary_input() {
        let server = MockServer::start().await;
        let log = [
            "abaaba🙂🙂aa�".as_bytes(),
            &[0xff, 0x80, 0],
            "aba🙂".as_bytes(),
        ]
        .concat()
        .repeat(80);
        body(&server, log.clone()).await;
        let ci = provider(&server);
        for query in ["aba", "🙂", "aa", "�", "\0aba", "🙂🙂"] {
            let mut expected = Vec::new();
            let mut pos = 0;
            while pos + query.len() <= log.len() {
                if &log[pos..pos + query.len()] == query.as_bytes() {
                    expected.push(pos as u64);
                    pos += query.len();
                } else {
                    pos += 1;
                }
            }
            let mut input = inputs("search");
            input["query"] = json!(query);
            input["maxMatches"] = json!(3);
            let mut actual = Vec::new();
            loop {
                let result = read(&ci, input.clone()).await.unwrap();
                for item in result["matches"].as_array().unwrap() {
                    actual.push(item["matchStart"].as_u64().unwrap());
                    assert!(item["text"].as_str().unwrap().contains(query));
                }
                if result["nextCursor"].is_null() {
                    break;
                }
                input["cursor"] = result["nextCursor"].clone();
            }
            assert_eq!(actual, expected, "query {query:?}");
        }
    }

    #[tokio::test]
    async fn old_offset_and_invalid_mode_combinations_fail_before_network() {
        let server = MockServer::start().await;
        let ci = provider(&server);
        let mut value = inputs("head");
        value["offset"] = json!(0);
        assert_eq!(
            ci.local_scopes("build.log.read", &value)
                .unwrap_err()
                .reason_code(),
            ReasonCode::InputInvalid
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn malformed_input_expansion_is_bounded_and_does_not_create_matches() {
        let server = MockServer::start().await;
        let mut data = vec![0xff; 2000];
        data.extend_from_slice("replacement:�".as_bytes());
        body(&server, data).await;
        let ci = provider(&server);
        let head = read(&ci, inputs("head")).await.unwrap();
        assert_eq!(head["text"].as_str().unwrap().len(), 1023);
        assert_eq!(head["sourceEnd"], 341);
        let mut input = inputs("search");
        input["query"] = json!("�");
        let result = read(&ci, input).await.unwrap();
        let matches = result["matches"].as_array().unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0]["matchStart"], 2012);
    }

    #[tokio::test]
    async fn incomplete_trailing_utf8_is_pending_and_append_continues_head() {
        let server = MockServer::start().await;
        body(&server, vec![b'a', 0xf0, 0x9f]).await;
        let ci = provider(&server);
        let first = read(&ci, inputs("head")).await.unwrap();
        assert_eq!(first["text"], "a");
        assert_eq!(first["pendingUtf8Bytes"], 2);
        assert_eq!(first["stopReason"], "pending_text");
        assert_eq!(first["reachedEnd"], true);
        server.reset().await;
        body(&server, "a🙂b".as_bytes().to_vec()).await;
        let mut input = inputs("head");
        input["cursor"] = first["nextCursor"].clone();
        assert_eq!(read(&ci, input).await.unwrap()["text"], "🙂b");
        server.reset().await;
        body(&server, vec![0xf0, 0x9f]).await;
        let pending = read(&ci, inputs("head")).await.unwrap();
        assert!(pending["nextCursor"].is_null());
        assert_eq!(pending["sourceEnd"], 0);
        assert_eq!(
            read(&ci, inputs("tail")).await.unwrap()["pendingUtf8Bytes"],
            2
        );
    }

    #[tokio::test]
    async fn search_pending_literal_resumes_before_undisclosed_prefix() {
        let server = MockServer::start().await;
        body(&server, [b"prefix a".as_slice(), &[0xe2, 0x82]].concat()).await;
        let ci = provider(&server);
        let mut input = inputs("search");
        input["query"] = json!("a€");
        let first = read(&ci, input.clone()).await.unwrap();
        assert_eq!(first["stopReason"], "pending_text");
        assert_eq!(first["sourceEnd"], 7);
        assert!(first["matches"].as_array().unwrap().is_empty());
        server.reset().await;
        body(&server, "prefix a€ done".as_bytes().to_vec()).await;
        input["cursor"] = first["nextCursor"].clone();
        let next = read(&ci, input).await.unwrap();
        assert_eq!(next["matches"][0]["matchStart"], 7);
        assert_eq!(next["matches"][0]["matchEnd"], 11);
    }

    #[tokio::test]
    async fn split_network_utf8_is_preserved() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let serve = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(socket.read_u8().await.unwrap());
            }
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").await.unwrap();
            for byte in "ab🙂éZ".as_bytes() {
                socket
                    .write_all(&[b'1', b'\r', b'\n', *byte, b'\r', b'\n'])
                    .await
                    .unwrap();
                tokio::task::yield_now().await;
            }
            socket.write_all(b"0\r\n\r\n").await.unwrap();
        });
        // Build with the local raw HTTP endpoint so allowlisting still applies.
        let config = CloudbeesCiProviderConfig {
            max_log_scan_bytes: default_scan_limit(),
            controllers: BTreeMap::from([(
                "team-ci".into(),
                CloudbeesCiControllerConfig {
                    base_url: format!("{origin}/team-ci/"),
                    web_base_url: None,
                },
            )]),
            egress_proxy: None,
            allowed_upstream_hosts: vec![format!("{origin}/team-ci/**")],
        };
        let ci = CloudbeesCiProvider::for_tests(config, ProviderLimits::default()).unwrap();
        assert_eq!(read(&ci, inputs("tail")).await.unwrap()["text"], "ab🙂éZ");
        serve.await.unwrap();
    }

    #[tokio::test]
    async fn log_idle_and_total_deadlines_cover_body_stalls() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for (idle, total) in [(25, 1000), (1000, 25)] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            let serve = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(socket.read_u8().await.unwrap());
                }
                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 100\r\nConnection: close\r\n\r\nx").await.unwrap();
                std::future::pending::<()>().await;
            });
            let ci = CloudbeesCiProvider::for_tests(
                CloudbeesCiProviderConfig {
                    max_log_scan_bytes: default_scan_limit(),
                    controllers: BTreeMap::from([(
                        "team-ci".into(),
                        CloudbeesCiControllerConfig {
                            base_url: format!("{origin}/team-ci/"),
                            web_base_url: None,
                        },
                    )]),
                    egress_proxy: None,
                    allowed_upstream_hosts: vec![format!("{origin}/team-ci/**")],
                },
                ProviderLimits {
                    request_timeout_ms: total,
                    streaming_idle_timeout_ms: idle,
                    ..ProviderLimits::default()
                },
            )
            .unwrap();
            let error = read(&ci, inputs("tail")).await.unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::UpstreamTimeout);
            serve.abort();
        }
    }

    #[tokio::test]
    async fn pending_character_that_cannot_fit_scan_ceiling_has_no_cursor() {
        let server = MockServer::start().await;
        body(&server, [b"12345678".as_slice(), &[0xe2]].concat()).await;
        let mut ci = provider(&server);
        ci.log_scan_limit = 10;
        let result = read(&ci, inputs("head")).await.unwrap();
        assert_eq!(result["text"], "12345678");
        assert_eq!(result["stopReason"], "pending_text");
        assert!(result["nextCursor"].is_null());
    }

    #[tokio::test]
    async fn cursor_rejects_rewrite_truncation_tampering_and_context_changes() {
        let server = MockServer::start().await;
        body(&server, vec![b'a'; 3000]).await;
        let ci = provider(&server);
        let first = read(&ci, inputs("head")).await.unwrap();
        let token = first["nextCursor"].as_str().unwrap();
        let mut input = inputs("head");
        input["cursor"] = json!(token);
        let mut wrong = invocation("build.log.read", input.clone());
        wrong = InvocationBuilder::from(wrong).principal("other").build();
        assert_eq!(
            ci.invoke(wrong).await.unwrap_err().reason_code(),
            ReasonCode::InputInvalid
        );
        let mut wrong = invocation("build.log.read", input.clone());
        wrong = InvocationBuilder::from(wrong)
            .execution_context("external")
            .build();
        assert_eq!(
            ci.invoke(wrong).await.unwrap_err().reason_code(),
            ReasonCode::InputInvalid
        );
        let mut wrong = input.clone();
        wrong["maxBytes"] = json!(2048);
        assert!(read(&ci, wrong).await.is_err());
        let mut wrong = input.clone();
        wrong["cursor"] = json!(format!("{token}x"));
        assert!(read(&ci, wrong).await.is_err());
        server.reset().await;
        body(&server, vec![b'b'; 3000]).await;
        assert!(read(&ci, input.clone()).await.is_err());
        server.reset().await;
        body(&server, vec![b'a'; 100]).await;
        assert!(read(&ci, input).await.is_err());
    }

    #[tokio::test]
    async fn cursor_resource_credential_and_config_bindings_reject_without_upstream_calls() {
        let server = MockServer::start().await;
        body(&server, vec![b'a'; 3000]).await;
        let mut ci = provider(&server);
        let first = read(&ci, inputs("head")).await.unwrap();
        let mut input = inputs("head");
        input["cursor"] = first["nextCursor"].clone();
        let requests = server.received_requests().await.unwrap().len();
        for (key, value) in [("buildNumber", json!(43)), ("job", json!("other/job"))] {
            let mut wrong = input.clone();
            wrong[key] = value;
            assert_eq!(
                read(&ci, wrong).await.unwrap_err().reason_code(),
                ReasonCode::InputInvalid
            );
        }
        let mut wrong = invocation("build.log.read", input.clone());
        wrong = InvocationBuilder::from(wrong)
            .credential_mode(CredentialMode::PerUser)
            .build();
        assert_eq!(
            ci.invoke(wrong).await.unwrap_err().reason_code(),
            ReasonCode::InputInvalid
        );
        ci.log_fingerprint = hash(&"different provider configuration");
        assert_eq!(
            read(&ci, input).await.unwrap_err().reason_code(),
            ReasonCode::InputInvalid
        );
        assert_eq!(server.received_requests().await.unwrap().len(), requests);
    }

    #[tokio::test]
    async fn cancelled_log_read_drops_the_upstream_body() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let (sent, headers) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(socket.read_u8().await.unwrap());
            }
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 100\r\nConnection: close\r\n\r\nx").await.unwrap();
            sent.send(()).unwrap();
            let mut byte = [0];
            socket.read(&mut byte).await.unwrap_or(0)
        });
        let ci = CloudbeesCiProvider::for_tests(
            CloudbeesCiProviderConfig {
                max_log_scan_bytes: default_scan_limit(),
                controllers: BTreeMap::from([(
                    "team-ci".into(),
                    CloudbeesCiControllerConfig {
                        base_url: format!("{origin}/team-ci/"),
                        web_base_url: None,
                    },
                )]),
                egress_proxy: None,
                allowed_upstream_hosts: vec![format!("{origin}/team-ci/**")],
            },
            ProviderLimits::default(),
        )
        .unwrap();
        let task = tokio::spawn(async move { read(&ci, inputs("tail")).await });
        headers.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), server)
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }

    #[test]
    fn input_contract_rejects_legacy_and_incompatible_fields() {
        for value in [
            json!({"mode":"search"}),
            json!({"query":"oops"}),
            json!({"mode":"tail","cursor":"x"}),
            json!({"maxBytes":1}),
            json!({"mode":"head","maxMatches":2}),
            json!({"mode":"search","query":"🙂".repeat(65)}),
        ] {
            assert!(LogInput::parse(value.as_object().unwrap()).is_err());
        }
    }

    #[tokio::test]
    async fn new_log_path_rejects_redirects_compression_and_bad_media_types() {
        let server = MockServer::start().await;
        let ci = provider(&server);
        for response in [
            ResponseTemplate::new(302).insert_header("Location", "/login"),
            ResponseTemplate::new(200).set_body_raw("private", "text/html"),
            ResponseTemplate::new(200)
                .set_body_raw(vec![0x1f, 0x8b], "text/plain")
                .insert_header("Content-Encoding", "gzip"),
        ] {
            server.reset().await;
            Mock::given(method("GET"))
                .respond_with(response)
                .mount(&server)
                .await;
            assert!(read(&ci, inputs("head")).await.is_err());
            let requests = server.received_requests().await.unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(
                requests[0].headers.get("accept-encoding").unwrap(),
                "identity"
            );
        }
        for (status, reason) in [
            (401, ReasonCode::UpstreamUnauthorized),
            (403, ReasonCode::UpstreamForbidden),
            (404, ReasonCode::ResourceNotFound),
            (429, ReasonCode::UpstreamRateLimited),
            (500, ReasonCode::UpstreamFailed),
            (503, ReasonCode::UpstreamFailed),
        ] {
            server.reset().await;
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(status))
                .mount(&server)
                .await;
            assert_eq!(
                read(&ci, inputs("head")).await.unwrap_err().reason_code(),
                reason
            );
        }
    }

    #[tokio::test]
    async fn search_last_match_at_observed_eof_does_not_issue_empty_continuation() {
        let server = MockServer::start().await;
        body(&server, b"match".to_vec()).await;
        let mut input = inputs("search");
        input["query"] = json!("match");
        input["maxMatches"] = json!(1);
        let result = read(&provider(&server), input).await.unwrap();
        assert_eq!(result["matches"].as_array().unwrap().len(), 1);
        assert_eq!(result["stopReason"], "eof");
        assert!(result["nextCursor"].is_null());
    }

    /// A stable key that signs `successes` times, then fails.
    struct FailingSigningKey {
        inner: Arc<dyn agent_access_provider::StableSigningKey>,
        successes: std::sync::atomic::AtomicUsize,
    }
    impl agent_access_provider::StableSigningKey for FailingSigningKey {
        fn hmac_base64url(
            &self,
            context: &[u8],
            payload: &[u8],
        ) -> Result<String, agent_access_provider::SigningError> {
            use std::sync::atomic::Ordering;
            self.successes
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .map_err(|_| agent_access_provider::SigningError)?;
            self.inner.hmac_base64url(context, payload)
        }
    }
    fn failing_signer(successes: usize) -> ContinuationSigner {
        ContinuationSigner::new(Some(Arc::new(FailingSigningKey {
            inner: agent_access_provider::test_support::test_signing_key(7),
            successes: successes.into(),
        })))
    }

    fn test_binding(family: &ContinuationFamily) -> ContinuationBinding {
        family.bind(
            invocation("build.log.read", inputs("head")).context(),
            "fingerprint",
        )
    }

    #[test]
    fn unavailable_signing_keys_are_broker_errors_for_all_cursor_mac_paths() {
        let signer = failing_signer(usize::MAX);
        let binding = test_binding(&LOG_CURSORS);
        let digest: [u8; 32] = Sha256::digest(b"prefix").into();
        let cursor = encode_cursor(&signer, &binding, 1, &digest).unwrap();
        let decoded = decode_cursor(&signer, &cursor, &binding, 100).unwrap();
        // Encoding commits to the prefix, then seals; decoding opens, and
        // the prefix is verified after the rescan.
        for error in [
            encode_cursor(&failing_signer(0), &binding, 1, &digest).unwrap_err(),
            encode_cursor(&failing_signer(1), &binding, 1, &digest).unwrap_err(),
            decode_cursor(&failing_signer(0), &cursor, &binding, 100)
                .err()
                .unwrap(),
            verify_prefix(&failing_signer(0), &binding, &digest, &decoded.prefix).unwrap_err(),
        ] {
            assert_eq!(error.reason_code(), ReasonCode::CursorSigningUnavailable);
            assert_eq!(error.decision(), agent_access_provider::Decision::Error);
            assert_eq!(
                error.message,
                "Broker log cursor signing key is unavailable"
            );
        }
        let other_digest: [u8; 32] = Sha256::digest(b"rewritten prefix").into();
        assert_eq!(
            verify_prefix(&signer, &binding, &other_digest, &decoded.prefix)
                .unwrap_err()
                .reason_code(),
            ReasonCode::InputInvalid
        );
    }

    #[tokio::test]
    async fn cursor_exposes_neither_source_digest_nor_request_binding() {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let server = MockServer::start().await;
        let ci = provider(&server);
        let signer = ContinuationSigner::new(None);
        let digest: [u8; 32] = Sha256::digest(b"guessable secret prefix").into();
        let request = InvocationBuilder::from(invocation("build.log.read", inputs("search")))
            .principal("private-principal")
            .execution_context("private-context")
            .build();
        let mut search = inputs("search");
        search["query"] = json!("guessable private query");
        let job = ci.parse("build.log.read", &search).unwrap();
        let binding = cursor_binding(
            &request,
            "private-configuration",
            &job,
            job.log.as_ref().unwrap(),
        );
        let token = encode_cursor(&signer, &binding, 10, &digest).unwrap();
        let raw = URL_SAFE_NO_PAD.decode(&token).unwrap();
        // Version, expiry, position, prefix commitment and MAC only.
        assert_eq!(raw.len(), 1 + 8 + CURSOR_PAYLOAD_BYTES + 32);
        assert_eq!(token.len(), CURSOR_MAX_BYTES);
        let contains = |needle: &[u8]| raw.windows(needle.len()).any(|w| w == needle);
        assert!(!contains(&digest));
        for private in [
            "guessable private query",
            "private-principal",
            "private-context",
            "private-configuration",
            "payments/build-api",
        ] {
            assert!(!contains(private.as_bytes()), "{private}");
        }
        let source_hex = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert!(!token.contains(&source_hex));
        assert!(!token.contains(&URL_SAFE_NO_PAD.encode(digest)));
        let decoded = decode_cursor(&signer, &token, &binding, 100).unwrap();
        verify_prefix(&signer, &binding, &digest, &decoded.prefix).unwrap();
        // The same prefix commits differently under another binding.
        let other = test_binding(&LOG_CURSORS);
        let other = encode_cursor(&signer, &other, 10, &digest).unwrap();
        let other = decode_cursor(&signer, &other, &test_binding(&LOG_CURSORS), 100).unwrap();
        assert_ne!(decoded.prefix, other.prefix);
    }

    #[test]
    fn cursors_expire_and_bind_configuration_without_plaintext_content() {
        let signer = ContinuationSigner::new(None);
        let binding = test_binding(&LOG_CURSORS);
        let digest: [u8; 32] = Sha256::digest(b"prefix").into();
        let prefix = signer.commit(&binding, PREFIX_COMMITMENT, &digest).unwrap();
        let payload = [1_u64.to_be_bytes().as_slice(), &prefix].concat();
        let expired = signer
            .seal_at(
                &binding,
                &payload,
                std::time::SystemTime::now() - Duration::from_secs(901),
            )
            .unwrap();
        let error = decode_cursor(&signer, &expired, &binding, 100)
            .err()
            .unwrap();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
        assert_eq!(error.decision(), agent_access_provider::Decision::Deny);
        let valid = encode_cursor(&signer, &binding, 1, &digest).unwrap();
        let other = LOG_CURSORS.bind(
            invocation("build.log.read", inputs("head")).context(),
            "other fingerprint",
        );
        assert!(decode_cursor(&signer, &valid, &other, 100).is_err());
        assert!(decode_cursor(&signer, &valid, &binding, 1).is_err());
    }

    #[test]
    fn obsolete_versions_other_purposes_and_oversized_cursors_are_rejected() {
        let signer = ContinuationSigner::new(None);
        let digest: [u8; 32] = Sha256::digest(b"prefix").into();
        let current = test_binding(&LOG_CURSORS);
        for family in [
            ContinuationFamily::new(
                "cloudbees_ci",
                "build-log-cursor",
                2,
                ContinuationLifetime::StableWhenConfigured,
                CURSOR_PAYLOAD_BYTES,
            )
            .expires_after(Duration::from_secs(900)),
            ContinuationFamily::new(
                "cloudbees_ci",
                "build-artifact-cursor",
                3,
                ContinuationLifetime::StableWhenConfigured,
                CURSOR_PAYLOAD_BYTES,
            )
            .expires_after(Duration::from_secs(900)),
        ] {
            let foreign = encode_cursor(&signer, &test_binding(&family), 1, &digest).unwrap();
            let error = decode_cursor(&signer, &foreign, &current, 100)
                .err()
                .unwrap();
            assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
            assert_eq!(error.decision(), agent_access_provider::Decision::Deny);
        }
        // The schema and input bounds equal the exact encoded cursor size.
        assert_eq!(input_properties()["cursor"]["maxLength"], CURSOR_MAX_BYTES);
        assert_eq!(CURSOR_MAX_BYTES, 108);
        let cursor = encode_cursor(&signer, &current, 1, &digest).unwrap();
        assert_eq!(cursor.len(), CURSOR_MAX_BYTES);
        for oversized in [format!("{cursor}A"), "A".repeat(2048)] {
            let input = json!({"mode":"head","cursor":oversized});
            assert!(LogInput::parse(input.as_object().unwrap()).is_err());
            assert_eq!(
                decode_cursor(&signer, &oversized, &current, 100)
                    .err()
                    .unwrap()
                    .reason_code(),
                ReasonCode::InputInvalid
            );
        }
    }
}
