//! Response presentation: read-content normalization of embedded upstream
//! bodies and whole-result Markdown rendering, bounded by a shared budget.
//!
//! Backends attach an [`ActionPresentation`] to each action descriptor; the
//! broker runs [`present_result`] on provider results. The helpers here are
//! the building blocks backend renderers use. Every presentation item is
//! reachable only through this module.
use crate::{ProviderError, ReasonCode};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::io::{self, Write};
use thiserror::Error;
use url::Url;

pub const READ_CONTENT_FORMATS: &[&str] = &["native", "markdown", "text"];
pub const RESPONSE_FORMATS: &[&str] = &["json", "markdown"];
pub const MAX_PRESENTATION_WORK_UNITS: usize = 1_048_576;
const FENCED_LITERAL_WORK_CHUNK_BYTES: usize = 4_096;
pub const RENDER_FAILURE_MESSAGE: &str = "provider response content could not be rendered safely";

const MAX_REQUEST_RENDER_NODES: usize = 131_072;
const MAX_REQUEST_RENDER_WORK_UNITS: usize = 524_288;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReadContentFormat {
    #[default]
    Native,
    Markdown,
    Text,
}

impl ReadContentFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Markdown => "markdown",
            Self::Text => "text",
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RenderedBody {
    pub format: ReadContentFormat,
    pub value: String,
}

/// Shared defensive accounting for every rich-content field rendered by one request.
///
/// Individual documents retain their tighter per-document limits. Keeping this
/// budget separate prevents a collection of individually-valid documents from
/// multiplying traversal cost without bound.
#[derive(Debug)]
pub struct RenderBudget {
    remaining_nodes: usize,
    remaining_work_units: usize,
}

impl Default for RenderBudget {
    fn default() -> Self {
        Self {
            remaining_nodes: MAX_REQUEST_RENDER_NODES,
            remaining_work_units: MAX_REQUEST_RENDER_WORK_UNITS,
        }
    }
}

impl RenderBudget {
    /// A budget with explicit allowances instead of the per-request defaults.
    pub fn with_limits(nodes: usize, work_units: usize) -> Self {
        Self {
            remaining_nodes: nodes,
            remaining_work_units: work_units,
        }
    }

    pub fn remaining_nodes(&self) -> usize {
        self.remaining_nodes
    }

    pub fn remaining_work_units(&self) -> usize {
        self.remaining_work_units
    }

    pub fn charge_node(&mut self) -> Result<(), RenderBudgetExhausted> {
        self.remaining_nodes = self
            .remaining_nodes
            .checked_sub(1)
            .ok_or(RenderBudgetExhausted::Nodes)?;
        Ok(())
    }

    pub fn charge_work(&mut self, units: usize) -> Result<(), RenderBudgetExhausted> {
        self.remaining_work_units = self
            .remaining_work_units
            .checked_sub(units)
            .ok_or(RenderBudgetExhausted::WorkUnits)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseFormat {
    #[default]
    Json,
    Markdown,
}

impl ResponseFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Markdown => "markdown",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ResponseOptions {
    #[serde(default)]
    pub read_content_format: ReadContentFormat,
    #[serde(default)]
    pub response_format: ResponseFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseCapabilities {
    pub read_content_formats: Option<&'static [&'static str]>,
    pub response_formats: Option<&'static [&'static str]>,
}

impl ResponseCapabilities {
    pub fn supports_read_content(self) -> bool {
        self.read_content_formats.is_some()
    }

    pub fn supports_markdown_response(self) -> bool {
        self.response_formats.is_some()
    }
}

/// Why a presentation step failed. Callers report every failure the same
/// way, so no rendered or native content leaks through error details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("provider response content could not be rendered safely")]
pub struct RenderError;

/// A shared render budget ran out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RenderBudgetExhausted {
    #[error("rich-content node budget exhausted")]
    Nodes,
    #[error("rich-content work budget exhausted")]
    WorkUnits,
}

/// How a backend presents one action's JSON result: embedded upstream
/// bodies that `readContentFormat` normalizes, and an optional whole-result
/// Markdown renderer for `responseFormat = "markdown"`.
#[derive(Clone, Copy)]
pub struct ActionPresentation {
    pub embedded_bodies: &'static [EmbeddedBody],
    pub whole: Option<&'static dyn WholeResultRenderer>,
}

impl ActionPresentation {
    pub fn capabilities(&self) -> ResponseCapabilities {
        ResponseCapabilities {
            read_content_formats: (!self.embedded_bodies.is_empty())
                .then_some(READ_CONTENT_FORMATS),
            response_formats: self.whole.is_some().then_some(RESPONSE_FORMATS),
        }
    }
}

impl std::fmt::Debug for ActionPresentation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ActionPresentation")
            .field("embedded_bodies", &self.embedded_bodies)
            .field("whole", &self.whole.is_some())
            .finish()
    }
}

/// Presentations are static: two are equal when they name the same bodies
/// and the same renderer.
impl PartialEq for ActionPresentation {
    fn eq(&self, other: &Self) -> bool {
        self.embedded_bodies == other.embedded_bodies
            && match (self.whole, other.whole) {
                (Some(left), Some(right)) => std::ptr::addr_eq(left, right),
                (None, None) => true,
                _ => false,
            }
    }
}

/// An upstream body embedded in the result: where its owner objects are,
/// and how to render the native body each owner carries.
#[derive(Clone, Copy)]
pub struct EmbeddedBody {
    pub owner_path: &'static [BodyPathSegment],
    pub codec: &'static dyn EmbeddedBodyCodec,
}

impl EmbeddedBody {
    /// Where the owners are, as a JSON pointer into the provider result in
    /// which a `*` segment matches every element of an array.
    pub fn owner_pointer(&self) -> String {
        self.owner_path
            .iter()
            .map(|segment| match segment {
                BodyPathSegment::Field(field) => {
                    format!("/{}", field.replace('~', "~0").replace('/', "~1"))
                }
                BodyPathSegment::Each => "/*".to_string(),
            })
            .collect()
    }
}

impl std::fmt::Debug for EmbeddedBody {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EmbeddedBody")
            .field("owner_path", &self.owner_path)
            .finish_non_exhaustive()
    }
}

impl PartialEq for EmbeddedBody {
    fn eq(&self, other: &Self) -> bool {
        self.owner_path == other.owner_path && std::ptr::addr_eq(self.codec, other.codec)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyPathSegment {
    Field(&'static str),
    Each,
}

/// Renders the native body one owner object carries.
pub trait EmbeddedBodyCodec: Sync {
    /// The rendered companion, or `None` when the owner has no native body.
    /// For [`ReadContentFormat::Native`] the codec still validates the body
    /// within the budget but returns `None`: native results carry no
    /// companion.
    fn render(
        &self,
        owner: &Map<String, Value>,
        format: ReadContentFormat,
        max_body_bytes: u64,
        budget: &mut RenderBudget,
    ) -> Result<Option<RenderedBody>, RenderError>;
}

/// Renders a whole result as Markdown.
pub trait WholeResultRenderer: Sync {
    fn render(&self, result: &Value, context: &mut RenderContext) -> Result<(), RenderError>;
}

impl<F> WholeResultRenderer for F
where
    F: Fn(&Value, &mut RenderContext) -> Result<(), RenderError> + Sync,
{
    fn render(&self, result: &Value, context: &mut RenderContext) -> Result<(), RenderError> {
        self(result, context)
    }
}

/// Output and limits for one whole-result render.
pub struct RenderContext {
    pub out: MarkdownWriter,
    /// Largest embedded upstream body the service renders.
    pub max_body_bytes: u64,
    pub budget: PresentationBudget,
}

/// Capabilities an action advertises: none without a presentation.
pub fn response_capabilities(presentation: Option<&ActionPresentation>) -> ResponseCapabilities {
    presentation
        .map(ActionPresentation::capabilities)
        .unwrap_or(ResponseCapabilities {
            read_content_formats: None,
            response_formats: None,
        })
}

/// Rejects response options the action cannot honor.
pub fn validate_response_options(
    presentation: Option<&ActionPresentation>,
    options: ResponseOptions,
) -> Result<(), ProviderError> {
    if options.response_format == ResponseFormat::Markdown
        && options.read_content_format != ReadContentFormat::Native
    {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "responseFormat markdown cannot be combined with non-native readContentFormat",
        ));
    }
    let capabilities = response_capabilities(presentation);
    if options.read_content_format != ReadContentFormat::Native
        && capabilities.read_content_formats.is_none()
    {
        return Err(unsupported());
    }
    if options.response_format != ResponseFormat::Json && capabilities.response_formats.is_none() {
        return Err(unsupported());
    }
    Ok(())
}

/// Applies the requested presentation to a provider result in place and
/// bounds the serialized result.
pub fn present_result(
    presentation: Option<&ActionPresentation>,
    result: &mut Value,
    options: ResponseOptions,
    max_body_bytes: u64,
    max_result_bytes: u64,
) -> Result<(), ProviderError> {
    validate_response_options(presentation, options)?;
    let Some(presentation) = presentation else {
        return enforce_serialized_bound(result, max_result_bytes).map_err(|_| render_failure());
    };
    let mut budget = PresentationBudget::new(max_result_bytes);

    if options.response_format == ResponseFormat::Markdown {
        let renderer = presentation.whole.ok_or_else(unsupported)?;
        let mut context = RenderContext {
            out: MarkdownWriter::new(max_result_bytes),
            max_body_bytes,
            budget,
        };
        let markdown =
            render_whole(renderer, result, &mut context).map_err(|_| render_failure())?;
        *result = json!({ "format": "markdown", "value": markdown });
    } else {
        for body in presentation.embedded_bodies {
            normalize_embedded_body(
                result,
                body,
                options.read_content_format,
                max_body_bytes,
                &mut budget,
            )
            .map_err(|_| render_failure())?;
        }
    }

    enforce_serialized_bound(result, max_result_bytes).map_err(|_| render_failure())
}

fn render_whole(
    renderer: &dyn WholeResultRenderer,
    result: &Value,
    context: &mut RenderContext,
) -> Result<String, RenderError> {
    renderer.render(result, context)?;
    context.out.normalize_terminal_lf()?;
    context.budget.charge_rendered(context.out.len())?;
    Ok(std::mem::replace(&mut context.out, MarkdownWriter::new(0)).finish())
}

fn normalize_embedded_body(
    root: &mut Value,
    body: &EmbeddedBody,
    format: ReadContentFormat,
    max_body_bytes: u64,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    visit_owners_mut(root, body.owner_path, &mut |owner| {
        let owner = owner.as_object_mut().ok_or(RenderError)?;
        if owner.contains_key("renderedBody") {
            return Err(RenderError);
        }
        let rendered =
            body.codec
                .render(owner, format, max_body_bytes, &mut budget.rich_content)?;
        if let Some(rendered) = rendered {
            budget.charge_rendered(rendered.value.len())?;
            owner.insert(
                "renderedBody".to_string(),
                serde_json::to_value(rendered).map_err(|_| RenderError)?,
            );
        }
        Ok(())
    })
}

#[derive(Debug)]
pub struct PresentationBudget {
    /// Shared budget for every rich-content document rendered in the result.
    pub rich_content: RenderBudget,
    remaining_rendered_bytes: u64,
    remaining_work_units: usize,
}

impl PresentationBudget {
    pub fn new(max_rendered_bytes: u64) -> Self {
        Self {
            rich_content: RenderBudget::default(),
            remaining_rendered_bytes: max_rendered_bytes,
            remaining_work_units: MAX_PRESENTATION_WORK_UNITS,
        }
    }

    pub fn charge_rendered(&mut self, bytes: usize) -> Result<(), RenderError> {
        self.remaining_rendered_bytes = self
            .remaining_rendered_bytes
            .checked_sub(bytes as u64)
            .ok_or(RenderError)?;
        Ok(())
    }

    pub fn charge_work(&mut self, units: usize) -> Result<(), RenderError> {
        self.remaining_work_units = self
            .remaining_work_units
            .checked_sub(units)
            .ok_or(RenderError)?;
        Ok(())
    }

    pub fn charge_fenced_literal_work(&mut self, bytes: usize) -> Result<(), RenderError> {
        self.charge_work(bytes.div_ceil(FENCED_LITERAL_WORK_CHUNK_BYTES).max(1))
    }
}

fn visit_owners_mut(
    value: &mut Value,
    path: &[BodyPathSegment],
    visitor: &mut impl FnMut(&mut Value) -> Result<(), RenderError>,
) -> Result<(), RenderError> {
    let Some((segment, rest)) = path.split_first() else {
        return visitor(value);
    };
    match segment {
        BodyPathSegment::Field(field) => {
            let child = value
                .as_object_mut()
                .and_then(|value| value.get_mut(*field))
                .ok_or(RenderError)?;
            visit_owners_mut(child, rest, visitor)
        }
        BodyPathSegment::Each => {
            for child in value.as_array_mut().ok_or(RenderError)? {
                visit_owners_mut(child, rest, visitor)?;
            }
            Ok(())
        }
    }
}

fn unsupported() -> ProviderError {
    ProviderError::deny(
        ReasonCode::ResponseFormatUnsupported,
        "requested response format is not supported for this action",
    )
}

fn render_failure() -> ProviderError {
    ProviderError::error(ReasonCode::UpstreamProtocolFailed, RENDER_FAILURE_MESSAGE)
}

pub struct MarkdownWriter {
    value: String,
    max_bytes: u64,
}

impl MarkdownWriter {
    pub fn new(max_bytes: u64) -> Self {
        Self {
            value: String::new(),
            max_bytes,
        }
    }

    pub fn push(&mut self, value: &str) -> Result<(), RenderError> {
        let next = (self.value.len() as u64)
            .checked_add(value.len() as u64)
            .ok_or(RenderError)?;
        if next > self.max_bytes {
            return Err(RenderError);
        }
        self.value.push_str(value);
        Ok(())
    }

    pub fn push_escaped(&mut self, value: &str) -> Result<(), RenderError> {
        for character in neutralize_controls(value).chars() {
            if matches!(character, '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>') {
                self.push("\\")?;
            }
            let mut bytes = [0; 4];
            self.push(character.encode_utf8(&mut bytes))?;
        }
        Ok(())
    }

    pub fn push_heading_text(&mut self, value: &str) -> Result<(), RenderError> {
        let value = neutralize_controls(value);
        let closing_end = value.trim_end_matches(' ').len();
        let hash_start = value[..closing_end].trim_end_matches('#').len();
        let closing_hashes = hash_start < closing_end
            && value[..hash_start]
                .chars()
                .last()
                .is_none_or(char::is_whitespace);
        if !closing_hashes {
            return self.push_escaped(&value);
        }
        self.push_escaped(&value[..hash_start])?;
        for _ in hash_start..closing_end {
            self.push("\\#")?;
        }
        self.push_escaped(&value[closing_end..])
    }

    pub fn push_code(&mut self, value: &str) -> Result<(), RenderError> {
        self.push(&code_span(value))
    }

    pub fn push_url(&mut self, value: &str) -> Result<(), RenderError> {
        if let Some(link) = safe_autolink(value) {
            self.push(&link)
        } else {
            self.push_code(value)
        }
    }

    pub fn len(&self) -> usize {
        self.value.len()
    }

    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    pub fn remaining(&self) -> u64 {
        self.max_bytes.saturating_sub(self.value.len() as u64)
    }

    pub fn normalize_terminal_lf(&mut self) -> Result<(), RenderError> {
        while self.value.ends_with('\n') {
            self.value.pop();
        }
        self.push("\n")
    }

    pub fn finish(self) -> String {
        self.value
    }
}

pub fn fields(
    out: &mut MarkdownWriter,
    values: &[(&str, Option<&str>)],
) -> Result<(), RenderError> {
    for (label, value) in values {
        if let Some(value) = value {
            field(out, label, value)?;
        }
    }
    Ok(())
}

pub fn code_fields(
    out: &mut MarkdownWriter,
    values: &[(&str, Option<&str>)],
) -> Result<(), RenderError> {
    for (label, value) in values {
        if let Some(value) = value {
            field_code(out, label, value)?;
        }
    }
    Ok(())
}

pub fn field(out: &mut MarkdownWriter, label: &str, value: &str) -> Result<(), RenderError> {
    out.push("- ")?;
    out.push(label)?;
    out.push(": ")?;
    out.push_escaped(value)?;
    out.push("\n")
}

pub fn field_code(out: &mut MarkdownWriter, label: &str, value: &str) -> Result<(), RenderError> {
    out.push("- ")?;
    out.push(label)?;
    out.push(": ")?;
    out.push_code(value)?;
    out.push("\n")
}

pub fn field_url(out: &mut MarkdownWriter, label: &str, value: &str) -> Result<(), RenderError> {
    out.push("- ")?;
    out.push(label)?;
    out.push(": ")?;
    out.push_url(value)?;
    out.push("\n")
}

pub fn field_raw(out: &mut MarkdownWriter, label: &str, value: &str) -> Result<(), RenderError> {
    out.push("- ")?;
    out.push(label)?;
    out.push(": ")?;
    out.push(value)?;
    out.push("\n")
}

pub fn as_object(value: &Value) -> Result<&Map<String, Value>, RenderError> {
    value.as_object().ok_or(RenderError)
}

pub fn array(value: &Value) -> Result<&[Value], RenderError> {
    value.as_array().map(Vec::as_slice).ok_or(RenderError)
}

pub fn required<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a Value, RenderError> {
    object
        .get(key)
        .filter(|value| !value.is_null())
        .ok_or(RenderError)
}

pub fn required_scalar<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, RenderError> {
    scalar(required(object, key)?)
}

pub fn optional_scalar<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, RenderError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => scalar(value).map(Some),
    }
}

pub fn optional_display(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<String>, RenderError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(Value::Number(value)) => Ok(Some(value.to_string())),
        Some(Value::Bool(value)) => Ok(Some(value.to_string())),
        Some(_) => Err(RenderError),
    }
}

pub fn scalar(value: &Value) -> Result<&str, RenderError> {
    value.as_str().ok_or(RenderError)
}

pub fn code_span(value: &str) -> String {
    let value = neutralize_controls(value);
    let width = longest_run(value.as_bytes(), b'`').saturating_add(1).max(1);
    let fence = "`".repeat(width);
    let padding = value.is_empty()
        || value.chars().all(char::is_whitespace)
        || value.starts_with([' ', '`'])
        || value.ends_with([' ', '`']);
    if padding {
        format!("{fence} {value} {fence}")
    } else {
        format!("{fence}{value}{fence}")
    }
}

pub fn safe_autolink(value: &str) -> Option<String> {
    if value
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
        || value.contains('<')
        || value.contains('>')
    {
        return None;
    }
    let parsed = Url::parse(value).ok()?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return None;
    }
    Some(format!("<{value}>"))
}

fn neutralize_controls(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            if !output.ends_with(' ') {
                output.push(' ');
            }
        } else {
            output.push(character);
        }
    }
    output
}

pub fn normalize_fenced_text_literal(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\r' => {
                if characters.peek() == Some(&'\n') {
                    characters.next();
                }
                output.push('\n');
            }
            '\n' | '\t' => output.push(character),
            character if character.is_control() => output.push(' '),
            character => output.push(character),
        }
    }
    output
}

pub fn escaped(value: &str) -> String {
    let mut output = MarkdownWriter::new(u64::MAX);
    output
        .push_escaped(value)
        .expect("an unbounded writer cannot overflow");
    output.finish()
}

pub fn fence_for(value: &str, delimiter: char) -> String {
    let width = longest_run(value.as_bytes(), delimiter as u8)
        .saturating_add(1)
        .max(3);
    delimiter.to_string().repeat(width)
}

fn longest_run(bytes: &[u8], needle: u8) -> usize {
    let mut longest = 0;
    let mut current = 0;
    for byte in bytes {
        if *byte == needle {
            current += 1;
            longest = longest.max(current);
        } else {
            current = 0;
        }
    }
    longest
}

pub fn serialize_json_pretty_bounded(value: &Value, max_bytes: u64) -> Result<String, RenderError> {
    struct BoundedBuffer {
        bytes: Vec<u8>,
        max_bytes: u64,
    }

    impl Write for BoundedBuffer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let next = (self.bytes.len() as u64)
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| io::Error::other("serialized JSON limit exceeded"))?;
            if next > self.max_bytes {
                return Err(io::Error::other("serialized JSON limit exceeded"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut buffer = BoundedBuffer {
        bytes: Vec::new(),
        max_bytes,
    };
    serde_json::to_writer_pretty(&mut buffer, value).map_err(|_| RenderError)?;
    String::from_utf8(buffer.bytes).map_err(|_| RenderError)
}

pub fn enforce_serialized_bound(value: &Value, max_bytes: u64) -> Result<(), RenderError> {
    struct LimitWriter {
        written: u64,
        max_bytes: u64,
    }
    impl Write for LimitWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.written = self
                .written
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| io::Error::other("serialized result limit exceeded"))?;
            if self.written > self.max_bytes {
                return Err(io::Error::other("serialized result limit exceeded"));
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(
        LimitWriter {
            written: 0,
            max_bytes,
        },
        value,
    )
    .map_err(|_| RenderError)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Upper-cases the owner's `text` field.
    struct ShoutCodec;

    impl EmbeddedBodyCodec for ShoutCodec {
        fn render(
            &self,
            owner: &Map<String, Value>,
            format: ReadContentFormat,
            _max_body_bytes: u64,
            budget: &mut RenderBudget,
        ) -> Result<Option<RenderedBody>, RenderError> {
            let Some(text) = owner.get("text").and_then(Value::as_str) else {
                return Ok(None);
            };
            budget.charge_node().map_err(|_| RenderError)?;
            if format == ReadContentFormat::Native {
                return Ok(None);
            }
            Ok(Some(RenderedBody {
                format,
                value: text.to_uppercase(),
            }))
        }
    }

    fn heading(result: &Value, context: &mut RenderContext) -> Result<(), RenderError> {
        context.out.push("# ")?;
        context
            .out
            .push_heading_text(required_scalar(as_object(result)?, "title")?)?;
        context.out.push("\n\n\n")
    }

    const BODIES: &[EmbeddedBody] = &[EmbeddedBody {
        owner_path: &[BodyPathSegment::Field("items"), BodyPathSegment::Each],
        codec: &ShoutCodec,
    }];
    const EMBEDDED: ActionPresentation = ActionPresentation {
        embedded_bodies: BODIES,
        whole: None,
    };
    const WHOLE: ActionPresentation = ActionPresentation {
        embedded_bodies: &[],
        whole: Some(&heading),
    };

    fn options(read: ReadContentFormat, response: ResponseFormat) -> ResponseOptions {
        ResponseOptions {
            read_content_format: read,
            response_format: response,
        }
    }

    #[test]
    fn owner_pointers_escape_fields_and_mark_array_elements() {
        assert_eq!(BODIES[0].owner_pointer(), "/items/*");
        let root = EmbeddedBody {
            owner_path: &[],
            codec: &ShoutCodec,
        };
        assert_eq!(root.owner_pointer(), "");
        let escaped = EmbeddedBody {
            owner_path: &[BodyPathSegment::Field("a/b~c"), BodyPathSegment::Each],
            codec: &ShoutCodec,
        };
        assert_eq!(escaped.owner_pointer(), "/a~1b~0c/*");
    }

    #[test]
    fn capabilities_follow_the_declared_presentation() {
        assert_eq!(
            response_capabilities(Some(&EMBEDDED)),
            ResponseCapabilities {
                read_content_formats: Some(READ_CONTENT_FORMATS),
                response_formats: None,
            }
        );
        assert_eq!(
            response_capabilities(Some(&WHOLE)),
            ResponseCapabilities {
                read_content_formats: None,
                response_formats: Some(RESPONSE_FORMATS),
            }
        );
        let none = response_capabilities(None);
        assert!(!none.supports_read_content() && !none.supports_markdown_response());
    }

    #[test]
    fn unsupported_and_conflicting_options_are_rejected_before_rendering() {
        let conflict = validate_response_options(
            Some(&WHOLE),
            options(ReadContentFormat::Markdown, ResponseFormat::Markdown),
        )
        .unwrap_err();
        assert_eq!(conflict.reason_code, ReasonCode::InputInvalid);
        for (presentation, requested) in [
            (
                Some(&WHOLE),
                options(ReadContentFormat::Text, ResponseFormat::Json),
            ),
            (
                Some(&EMBEDDED),
                options(ReadContentFormat::Native, ResponseFormat::Markdown),
            ),
            (
                None,
                options(ReadContentFormat::Markdown, ResponseFormat::Json),
            ),
        ] {
            let error = validate_response_options(presentation, requested).unwrap_err();
            assert_eq!(error.reason_code, ReasonCode::ResponseFormatUnsupported);
        }
        validate_response_options(None, ResponseOptions::default()).unwrap();
    }

    #[test]
    fn embedded_bodies_render_beside_each_owner_and_keep_the_native_body() {
        let mut result = json!({"items": [{"text": "one"}, {"other": true}, {"text": "two"}]});
        present_result(
            Some(&EMBEDDED),
            &mut result,
            options(ReadContentFormat::Text, ResponseFormat::Json),
            1024,
            1024,
        )
        .unwrap();
        assert_eq!(
            result,
            json!({"items": [
                {"text": "one", "renderedBody": {"format": "text", "value": "ONE"}},
                {"other": true},
                {"text": "two", "renderedBody": {"format": "text", "value": "TWO"}}
            ]})
        );

        let mut native = json!({"items": [{"text": "one"}]});
        present_result(
            Some(&EMBEDDED),
            &mut native,
            ResponseOptions::default(),
            1024,
            1024,
        )
        .unwrap();
        assert_eq!(native, json!({"items": [{"text": "one"}]}));
    }

    #[test]
    fn embedded_rendering_fails_closed_on_shape_collisions_and_bounds() {
        for mut result in [
            json!({"items": [{"text": "one", "renderedBody": "provider supplied"}]}),
            json!({"elements": []}),
            json!({"items": {"text": "not an array"}}),
        ] {
            let error = present_result(
                Some(&EMBEDDED),
                &mut result,
                options(ReadContentFormat::Markdown, ResponseFormat::Json),
                1024,
                1024,
            )
            .unwrap_err();
            assert_eq!(error.reason_code, ReasonCode::UpstreamProtocolFailed);
            assert_eq!(error.message, RENDER_FAILURE_MESSAGE);
        }
        let mut large = json!({"items": [{"text": "x".repeat(64)}]});
        assert!(
            present_result(
                Some(&EMBEDDED),
                &mut large,
                options(ReadContentFormat::Markdown, ResponseFormat::Json),
                1024,
                96,
            )
            .is_err()
        );
    }

    #[test]
    fn whole_results_become_bounded_markdown_with_one_terminal_newline() {
        let mut result = json!({"title": "Release *notes* #"});
        present_result(
            Some(&WHOLE),
            &mut result,
            options(ReadContentFormat::Native, ResponseFormat::Markdown),
            1024,
            1024,
        )
        .unwrap();
        assert_eq!(
            result,
            json!({"format": "markdown", "value": "# Release \\*notes\\* \\#\n"})
        );

        let mut too_large = json!({"title": "x".repeat(64)});
        assert!(
            present_result(
                Some(&WHOLE),
                &mut too_large,
                options(ReadContentFormat::Native, ResponseFormat::Markdown),
                1024,
                32,
            )
            .is_err()
        );
    }

    #[test]
    fn results_without_a_presentation_are_only_bounded() {
        let mut result = json!({"value": "x".repeat(32)});
        present_result(None, &mut result, ResponseOptions::default(), 16, 1024).unwrap();
        assert!(present_result(None, &mut result, ResponseOptions::default(), 16, 16).is_err());
    }
}
