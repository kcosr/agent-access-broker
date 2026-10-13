use agent_access_provider::presentation::{
    ReadContentFormat, RenderBudget, RenderBudgetExhausted, RenderedBody,
};
use html5ever::{QualName, local_name, ns, parse_fragment, tendril::TendrilSink};
use markup5ever_rcdom::{Handle, NodeData, RcDom};
use pulldown_cmark::{CowStr, Event, Options, Parser, Tag, TagEnd, html::write_html_io};
use serde_json::{Map, Value};
use std::io::{self, Write};
use thiserror::Error;
use url::Url;

const MAX_ADF_RENDER_DEPTH: usize = 128;
const MAX_ADF_RENDER_NODES: usize = 65_536;
const MAX_ADF_RENDER_WORK_UNITS: usize = 262_144;
// `pulldown_cmark` emits bounded structural markup per event in addition to
// escaping source bytes. The intermediate cap accounts for both components;
// source entities may expand by up to six bytes per input byte.
const GITLAB_INTERMEDIATE_HTML_BYTES_PER_NODE: u64 = 64;
const GITLAB_INTERMEDIATE_HTML_BYTES_PER_WORK_UNIT: u64 = 16;
const GITLAB_INTERMEDIATE_HTML_SOURCE_EXPANSION: u64 = 6;

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ContentRenderError {
    #[error("ADF document is malformed")]
    MalformedDocument,
    #[error("ADF document nesting exceeded the render limit")]
    NestingLimitExceeded,
    #[error("ADF document exceeded the node render limit")]
    NodeLimitExceeded,
    #[error("ADF document exceeded the render work limit")]
    WorkLimitExceeded,
    #[error("rendered content exceeded the {max_bytes}-byte limit")]
    OutputTooLarge { max_bytes: u64 },
    #[error("native content exceeded the {max_bytes}-byte limit")]
    SourceTooLarge { max_bytes: u64 },
}

impl From<RenderBudgetExhausted> for ContentRenderError {
    fn from(exhausted: RenderBudgetExhausted) -> Self {
        match exhausted {
            RenderBudgetExhausted::Nodes => Self::NodeLimitExceeded,
            RenderBudgetExhausted::WorkUnits => Self::WorkLimitExceeded,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct RenderLimits {
    max_depth: usize,
    max_nodes: usize,
    max_work_units: usize,
}

const DEFAULT_RENDER_LIMITS: RenderLimits = RenderLimits {
    max_depth: MAX_ADF_RENDER_DEPTH,
    max_nodes: MAX_ADF_RENDER_NODES,
    max_work_units: MAX_ADF_RENDER_WORK_UNITS,
};

#[cfg(test)]
pub fn render_adf_bounded(
    document: &Value,
    format: ReadContentFormat,
    max_output_bytes: u64,
) -> Result<Option<RenderedBody>, ContentRenderError> {
    let mut budget = RenderBudget::default();
    render_adf_bounded_with_budget(document, format, u64::MAX, max_output_bytes, &mut budget)
}

pub fn render_adf_bounded_with_budget(
    document: &Value,
    format: ReadContentFormat,
    max_source_bytes: u64,
    max_output_bytes: u64,
    budget: &mut RenderBudget,
) -> Result<Option<RenderedBody>, ContentRenderError> {
    render_adf_with_limits(
        document,
        format,
        max_source_bytes,
        max_output_bytes,
        DEFAULT_RENDER_LIMITS,
        budget,
    )
}

#[cfg(test)]
pub fn render_confluence_storage_bounded(
    source: &str,
    format: ReadContentFormat,
    max_output_bytes: u64,
) -> Result<Option<RenderedBody>, ContentRenderError> {
    let mut budget = RenderBudget::default();
    render_confluence_storage_bounded_with_budget(
        source,
        format,
        u64::MAX,
        max_output_bytes,
        &mut budget,
    )
}

pub fn render_confluence_storage_bounded_with_budget(
    source: &str,
    format: ReadContentFormat,
    max_source_bytes: u64,
    max_output_bytes: u64,
    budget: &mut RenderBudget,
) -> Result<Option<RenderedBody>, ContentRenderError> {
    render_confluence_storage_with_limits_and_budget(
        source,
        format,
        max_source_bytes,
        max_output_bytes,
        DEFAULT_RENDER_LIMITS,
        budget,
    )
}

pub fn render_confluence_adf_bounded_with_budget(
    source: &str,
    format: ReadContentFormat,
    max_source_bytes: u64,
    max_output_bytes: u64,
    budget: &mut RenderBudget,
) -> Result<Option<RenderedBody>, ContentRenderError> {
    validate_string_source_size(source, max_source_bytes)?;
    let document: Value =
        serde_json::from_str(source).map_err(|_| ContentRenderError::MalformedDocument)?;
    // The original serialized representation was bounded before parsing. The
    // shared ADF traversal performs the same structural and work validation as
    // Jira without reparsing the document.
    render_adf_with_limits(
        &document,
        format,
        u64::MAX,
        max_output_bytes,
        DEFAULT_RENDER_LIMITS,
        budget,
    )
}

/// Render one GitLab-native Markdown body for an embedded structured result.
///
/// GitLab's native representation is already Markdown, so `markdown` preserves
/// the source byte-for-byte. All modes still parse the complete bounded source
/// and consume the same structural request budget before returning it.
pub fn render_gitlab_markdown_bounded_with_budget(
    source: &str,
    format: ReadContentFormat,
    max_source_bytes: u64,
    max_output_bytes: u64,
    budget: &mut RenderBudget,
) -> Result<Option<RenderedBody>, ContentRenderError> {
    validate_string_source_size(source, max_source_bytes)?;
    match format {
        ReadContentFormat::Native => {
            validate_gitlab_markdown_with_limits(source, DEFAULT_RENDER_LIMITS, budget)?;
            Ok(None)
        }
        ReadContentFormat::Markdown => {
            validate_gitlab_markdown_with_limits(source, DEFAULT_RENDER_LIMITS, budget)?;
            let value = BoundedString::from_str(source, max_output_bytes)?.into_string();
            Ok(Some(RenderedBody::new(format, value)))
        }
        ReadContentFormat::Text => {
            let text = render_gitlab_text_with_limits(
                source,
                max_output_bytes,
                DEFAULT_RENDER_LIMITS,
                budget,
            )?;
            Ok(Some(RenderedBody::new(format, text.into_string())))
        }
    }
}

/// Produce a composition-safe Markdown fragment from a GitLab body.
///
/// Supported CommonMark/GFM structures are parsed and deterministically
/// re-emitted through the shared bounded HTML traversal. This closes hostile or
/// unbalanced source constructs before trusted metadata is appended while
/// retaining headings, lists, task states, tables, code, safe links, link
/// labels, and image alternatives. Raw HTML is interpreted only by the inert
/// HTML parser used for the final bounded traversal.
pub fn render_gitlab_markdown_fragment_bounded_with_budget(
    source: &str,
    max_source_bytes: u64,
    max_output_bytes: u64,
    budget: &mut RenderBudget,
    heading_level_offset: usize,
) -> Result<String, ContentRenderError> {
    validate_string_source_size(source, max_source_bytes)?;
    if source.trim().is_empty() {
        return Ok(String::new());
    }
    let events = collect_gitlab_composition_events(source, DEFAULT_RENDER_LIMITS, budget)?;
    // CommonMark-to-HTML expansion is independently bounded by the source cap
    // plus the same structural limits that bounded the event stream. HTML
    // entity serialization can expand one source byte to at most six bytes.
    let max_html_bytes = gitlab_intermediate_html_byte_limit(
        source.len() as u64,
        max_source_bytes,
        DEFAULT_RENDER_LIMITS,
    );
    let mut html = BoundedIoString::new(max_html_bytes);
    if write_html_io(&mut html, events.into_iter()).is_err() {
        return if html.exceeded {
            Err(ContentRenderError::OutputTooLarge {
                max_bytes: max_html_bytes,
            })
        } else {
            Err(ContentRenderError::MalformedDocument)
        };
    }
    let html = html.into_string();
    if html.trim().is_empty() {
        return Ok(String::new());
    }
    render_gitlab_html_fragment_with_limits_and_budget(
        &html,
        ReadContentFormat::Markdown,
        max_output_bytes,
        DEFAULT_RENDER_LIMITS,
        budget,
        heading_level_offset,
    )?
    .map(|rendered| rendered.value)
    .ok_or(ContentRenderError::MalformedDocument)
}

fn gitlab_intermediate_html_byte_limit(
    source_bytes: u64,
    max_source_bytes: u64,
    limits: RenderLimits,
) -> u64 {
    let bounded_source_bytes = source_bytes.min(max_source_bytes);
    let source_expansion =
        bounded_source_bytes.saturating_mul(GITLAB_INTERMEDIATE_HTML_SOURCE_EXPANSION);
    let structural_expansion = (limits.max_nodes as u64)
        .saturating_mul(GITLAB_INTERMEDIATE_HTML_BYTES_PER_NODE)
        .saturating_add(
            (limits.max_work_units as u64)
                .saturating_mul(GITLAB_INTERMEDIATE_HTML_BYTES_PER_WORK_UNIT),
        );
    source_expansion.saturating_add(structural_expansion)
}

fn collect_gitlab_composition_events<'a>(
    source: &'a str,
    limits: RenderLimits,
    budget: &mut RenderBudget,
) -> Result<Vec<Event<'a>>, ContentRenderError> {
    let options = Options::ENABLE_TABLES
        | Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_TASKLISTS
        | Options::ENABLE_FOOTNOTES;
    let mut output = Vec::new();
    let mut depth = 0usize;
    let mut nodes = 0usize;
    let mut work_units = 0usize;
    for event in Parser::new_ext(source, options) {
        nodes = nodes
            .checked_add(1)
            .ok_or(ContentRenderError::NodeLimitExceeded)?;
        if nodes > limits.max_nodes {
            return Err(ContentRenderError::NodeLimitExceeded);
        }
        let work = event_work(&event);
        work_units = work_units
            .checked_add(work)
            .ok_or(ContentRenderError::WorkLimitExceeded)?;
        if work_units > limits.max_work_units {
            return Err(ContentRenderError::WorkLimitExceeded);
        }
        budget.charge_node()?;
        budget.charge_work(work)?;

        match &event {
            Event::Start(_) => {
                depth = depth
                    .checked_add(1)
                    .ok_or(ContentRenderError::NestingLimitExceeded)?;
                if depth > limits.max_depth {
                    return Err(ContentRenderError::NestingLimitExceeded);
                }
            }
            Event::End(_) => {
                depth = depth
                    .checked_sub(1)
                    .ok_or(ContentRenderError::MalformedDocument)?;
            }
            _ => {}
        }

        match event {
            // A Unicode checkbox remains readable after the inert HTML-to-
            // Markdown traversal without becoming an executable HTML input.
            Event::TaskListMarker(checked) => {
                output.push(Event::Text(CowStr::Borrowed(if checked {
                    "☑ "
                } else {
                    "☐ "
                })));
            }
            other => output.push(other),
        }
    }
    if depth != 0 {
        return Err(ContentRenderError::MalformedDocument);
    }
    Ok(output)
}

struct BoundedIoString {
    value: String,
    max_bytes: u64,
    exceeded: bool,
}

impl BoundedIoString {
    fn new(max_bytes: u64) -> Self {
        Self {
            value: String::new(),
            max_bytes,
            exceeded: false,
        }
    }

    fn into_string(self) -> String {
        self.value
    }
}

impl Write for BoundedIoString {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = (self.value.len() as u64).saturating_add(bytes.len() as u64);
        if next > self.max_bytes {
            self.exceeded = true;
            return Err(io::Error::other("intermediate render size limit exceeded"));
        }
        let value = std::str::from_utf8(bytes)
            .map_err(|_| io::Error::other("intermediate render was not UTF-8"))?;
        self.value.push_str(value);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
fn render_gitlab_markdown_bounded(
    source: &str,
    format: ReadContentFormat,
    max_output_bytes: u64,
) -> Result<Option<RenderedBody>, ContentRenderError> {
    render_gitlab_markdown_bounded_with_budget(
        source,
        format,
        u64::MAX,
        max_output_bytes,
        &mut RenderBudget::default(),
    )
}

#[derive(Debug)]
struct MarkdownListState {
    next: Option<u64>,
    fresh_item: bool,
}

fn validate_gitlab_markdown_with_limits(
    source: &str,
    limits: RenderLimits,
    budget: &mut RenderBudget,
) -> Result<(), ContentRenderError> {
    let options = Options::ENABLE_TABLES
        | Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_TASKLISTS
        | Options::ENABLE_FOOTNOTES;
    let mut depth = 0usize;
    let mut nodes = 0usize;
    let mut work_units = 0usize;
    let mut active_html = Vec::new();
    for event in Parser::new_ext(source, options) {
        nodes = nodes
            .checked_add(1)
            .ok_or(ContentRenderError::NodeLimitExceeded)?;
        if nodes > limits.max_nodes {
            return Err(ContentRenderError::NodeLimitExceeded);
        }
        let work = event_work(&event);
        work_units = work_units
            .checked_add(work)
            .ok_or(ContentRenderError::WorkLimitExceeded)?;
        if work_units > limits.max_work_units {
            return Err(ContentRenderError::WorkLimitExceeded);
        }
        budget.charge_node()?;
        budget.charge_work(work)?;

        match event {
            Event::Start(_) => {
                depth = depth
                    .checked_add(1)
                    .ok_or(ContentRenderError::NestingLimitExceeded)?;
                if depth > limits.max_depth {
                    return Err(ContentRenderError::NestingLimitExceeded);
                }
            }
            Event::End(_) => {
                depth = depth
                    .checked_sub(1)
                    .ok_or(ContentRenderError::MalformedDocument)?;
            }
            Event::Html(fragment) | Event::InlineHtml(fragment) => {
                update_active_html_stack(
                    &fragment,
                    &mut active_html,
                    limits.max_depth.saturating_sub(depth),
                )?;
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(ContentRenderError::MalformedDocument);
    }
    Ok(())
}

struct GitlabTextRenderer<'a> {
    output: BoundedString,
    max_output_bytes: u64,
    limits: RenderLimits,
    depth: usize,
    events: usize,
    work_units: usize,
    lists: Vec<MarkdownListState>,
    in_code_block: usize,
    in_table: usize,
    table_cell_index: usize,
    active_html: Vec<String>,
    pending_space: bool,
    pending_newlines: usize,
    budget: &'a mut RenderBudget,
}

fn render_gitlab_text_with_limits(
    source: &str,
    max_output_bytes: u64,
    limits: RenderLimits,
    budget: &mut RenderBudget,
) -> Result<BoundedString, ContentRenderError> {
    let options = Options::ENABLE_TABLES
        | Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_TASKLISTS
        | Options::ENABLE_FOOTNOTES;
    let mut renderer = GitlabTextRenderer::new(max_output_bytes, limits, budget)?;
    for event in Parser::new_ext(source, options) {
        renderer.render_event(event)?;
    }
    renderer.finish()
}

impl<'a> GitlabTextRenderer<'a> {
    fn new(
        max_output_bytes: u64,
        limits: RenderLimits,
        budget: &'a mut RenderBudget,
    ) -> Result<Self, ContentRenderError> {
        Ok(Self {
            output: BoundedString::from_str("", max_output_bytes)?,
            max_output_bytes,
            limits,
            depth: 0,
            events: 0,
            work_units: 0,
            lists: Vec::new(),
            in_code_block: 0,
            in_table: 0,
            table_cell_index: 0,
            active_html: Vec::new(),
            pending_space: false,
            pending_newlines: 0,
            budget,
        })
    }

    fn render_event(&mut self, event: Event<'_>) -> Result<(), ContentRenderError> {
        self.charge_event(event_work(&event))?;
        match event {
            Event::Start(tag) => self.start_tag(tag),
            Event::End(tag) => self.end_tag(tag),
            Event::Text(value) => {
                if !self.active_html.is_empty() {
                    Ok(())
                } else if self.in_code_block != 0 {
                    self.push_output(&value)
                } else {
                    self.push_collapsed_text(&value)
                }
            }
            Event::Code(value) | Event::InlineMath(value) => {
                if self.active_html.is_empty() {
                    self.push_output(&value)
                } else {
                    Ok(())
                }
            }
            Event::DisplayMath(value) => {
                if self.active_html.is_empty() {
                    self.ensure_block_break()?;
                    self.push_output(&value)?;
                    self.ensure_block_break()
                } else {
                    Ok(())
                }
            }
            Event::Html(value) | Event::InlineHtml(value) => self.render_raw_html(&value),
            Event::FootnoteReference(label) => {
                if self.active_html.is_empty() {
                    self.push_output("[^")?;
                    self.push_output(&label)?;
                    self.push_output("]")
                } else {
                    Ok(())
                }
            }
            Event::SoftBreak => {
                if self.active_html.is_empty() {
                    self.ensure_space()
                } else {
                    Ok(())
                }
            }
            Event::HardBreak => {
                if self.active_html.is_empty() {
                    self.ensure_line_break()
                } else {
                    Ok(())
                }
            }
            Event::Rule => {
                if !self.active_html.is_empty() {
                    return Ok(());
                }
                self.ensure_block_break()?;
                self.push_output("—")?;
                self.ensure_block_break()
            }
            Event::TaskListMarker(checked) => {
                if self.active_html.is_empty() {
                    self.push_output(if checked { "[x] " } else { "[ ] " })
                } else {
                    Ok(())
                }
            }
        }
    }

    fn start_tag(&mut self, tag: Tag<'_>) -> Result<(), ContentRenderError> {
        self.depth = self
            .depth
            .checked_add(1)
            .ok_or(ContentRenderError::NestingLimitExceeded)?;
        if self.depth > self.limits.max_depth {
            return Err(ContentRenderError::NestingLimitExceeded);
        }
        let emit = self.active_html.is_empty();
        match tag {
            Tag::Paragraph => {
                if self.in_table == 0 {
                    if let Some(list) = self.lists.last_mut()
                        && list.fresh_item
                    {
                        list.fresh_item = false;
                    } else if emit && self.lists.is_empty() {
                        self.ensure_block_break()?;
                    } else if emit {
                        self.ensure_line_break()?;
                    }
                }
            }
            Tag::Heading { .. } | Tag::BlockQuote(_) | Tag::CodeBlock(_) => {
                if emit {
                    self.ensure_block_break()?;
                }
                if matches!(tag, Tag::CodeBlock(_)) {
                    self.in_code_block = self.in_code_block.saturating_add(1);
                }
            }
            Tag::HtmlBlock if emit => self.ensure_block_break()?,
            Tag::HtmlBlock => {}
            Tag::List(start) => {
                if emit {
                    if self.lists.is_empty() {
                        self.ensure_block_break()?;
                    } else {
                        self.ensure_line_break()?;
                    }
                }
                self.lists.push(MarkdownListState {
                    next: start,
                    fresh_item: false,
                });
            }
            Tag::Item => {
                if emit {
                    self.ensure_line_break()?;
                }
                let nesting = self.lists.len().saturating_sub(1);
                let marker = {
                    let list = self
                        .lists
                        .last_mut()
                        .ok_or(ContentRenderError::MalformedDocument)?;
                    list.fresh_item = true;
                    if let Some(next) = list.next.as_mut() {
                        let marker = format!("{next}. ");
                        *next = next.saturating_add(1);
                        marker
                    } else {
                        "- ".to_string()
                    }
                };
                if emit {
                    self.push_output_repeat(' ', nesting.saturating_mul(2))?;
                    self.push_output(&marker)?;
                }
            }
            Tag::FootnoteDefinition(label) if emit => {
                self.ensure_block_break()?;
                self.push_output("[^")?;
                self.push_output(&label)?;
                self.push_output("]: ")?;
            }
            Tag::FootnoteDefinition(_) => {}
            Tag::DefinitionList if emit => self.ensure_block_break()?,
            Tag::DefinitionList => {}
            Tag::DefinitionListTitle => {}
            Tag::DefinitionListDefinition if emit => {
                self.ensure_line_break()?;
                self.push_output("  ")?;
            }
            Tag::DefinitionListDefinition => {}
            Tag::Table(_) => {
                if emit {
                    self.ensure_block_break()?;
                }
                self.in_table = self.in_table.saturating_add(1);
            }
            Tag::TableHead | Tag::TableRow => self.table_cell_index = 0,
            Tag::TableCell => {
                if emit && self.table_cell_index != 0 {
                    self.push_output(" | ")?;
                }
                self.table_cell_index = self.table_cell_index.saturating_add(1);
            }
            Tag::Emphasis
            | Tag::Strong
            | Tag::Strikethrough
            | Tag::Superscript
            | Tag::Subscript
            | Tag::Link { .. }
            | Tag::Image { .. }
            | Tag::MetadataBlock(_) => {}
        }
        Ok(())
    }

    fn end_tag(&mut self, tag: TagEnd) -> Result<(), ContentRenderError> {
        if self.depth == 0 {
            return Err(ContentRenderError::MalformedDocument);
        }
        self.depth -= 1;
        let emit = self.active_html.is_empty();
        match tag {
            TagEnd::Paragraph => {
                if emit && self.in_table == 0 {
                    if self.lists.is_empty() {
                        self.ensure_block_break()?;
                    } else {
                        self.ensure_line_break()?;
                    }
                }
            }
            TagEnd::Heading(_) | TagEnd::BlockQuote(_) | TagEnd::HtmlBlock if emit => {
                self.ensure_block_break()?
            }
            TagEnd::Heading(_) | TagEnd::BlockQuote(_) | TagEnd::HtmlBlock => {}
            TagEnd::CodeBlock => {
                self.in_code_block = self
                    .in_code_block
                    .checked_sub(1)
                    .ok_or(ContentRenderError::MalformedDocument)?;
                if emit {
                    self.ensure_block_break()?;
                }
            }
            TagEnd::List(_) => {
                self.lists
                    .pop()
                    .ok_or(ContentRenderError::MalformedDocument)?;
                if emit {
                    if self.lists.is_empty() {
                        self.ensure_block_break()?;
                    } else {
                        self.ensure_line_break()?;
                    }
                }
            }
            TagEnd::Item if emit => self.ensure_line_break()?,
            TagEnd::Item => {}
            TagEnd::FootnoteDefinition | TagEnd::DefinitionList if emit => {
                self.ensure_block_break()?
            }
            TagEnd::FootnoteDefinition | TagEnd::DefinitionList => {}
            TagEnd::DefinitionListTitle | TagEnd::DefinitionListDefinition if emit => {
                self.ensure_line_break()?
            }
            TagEnd::DefinitionListTitle | TagEnd::DefinitionListDefinition => {}
            TagEnd::Table => {
                self.in_table = self
                    .in_table
                    .checked_sub(1)
                    .ok_or(ContentRenderError::MalformedDocument)?;
                if emit {
                    self.ensure_block_break()?;
                }
            }
            TagEnd::TableHead | TagEnd::TableRow if emit => self.ensure_line_break()?,
            TagEnd::TableHead | TagEnd::TableRow => {}
            TagEnd::TableCell
            | TagEnd::Emphasis
            | TagEnd::Strong
            | TagEnd::Strikethrough
            | TagEnd::Superscript
            | TagEnd::Subscript
            | TagEnd::Link
            | TagEnd::Image
            | TagEnd::MetadataBlock(_) => {}
        }
        Ok(())
    }

    fn render_raw_html(&mut self, fragment: &str) -> Result<(), ContentRenderError> {
        let was_active = !self.active_html.is_empty();
        update_active_html_stack(
            fragment,
            &mut self.active_html,
            self.limits.max_depth.saturating_sub(self.depth),
        )?;
        if was_active || !self.active_html.is_empty() {
            return Ok(());
        }
        let context = QualName::new(None, ns!(html), local_name!("div"));
        let dom = parse_fragment(
            RcDom::default(),
            Default::default(),
            context,
            Vec::new(),
            false,
        )
        .one(fragment);
        let before_nodes = self.budget.remaining_nodes();
        let before_work = self.budget.remaining_work_units();
        let mut renderer = StorageRenderer {
            format: ReadContentFormat::Text,
            max_output_bytes: self.max_output_bytes,
            heading_level_offset: 0,
            limits: RenderLimits {
                max_depth: self.limits.max_depth.saturating_sub(self.depth),
                ..self.limits
            },
            nodes: 0,
            work_units: 0,
            budget: self.budget,
        };
        let text = renderer.collect_plain_descendants(&dom.document, 0)?;
        let used_nodes = before_nodes.saturating_sub(renderer.budget.remaining_nodes());
        let used_work = before_work.saturating_sub(renderer.budget.remaining_work_units());
        self.events = self.events.saturating_add(used_nodes);
        self.work_units = self.work_units.saturating_add(used_work);
        if self.events > self.limits.max_nodes {
            return Err(ContentRenderError::NodeLimitExceeded);
        }
        if self.work_units > self.limits.max_work_units {
            return Err(ContentRenderError::WorkLimitExceeded);
        }
        self.push_collapsed_text(text.as_str())
    }

    fn charge_event(&mut self, work: usize) -> Result<(), ContentRenderError> {
        self.events = self
            .events
            .checked_add(1)
            .ok_or(ContentRenderError::NodeLimitExceeded)?;
        if self.events > self.limits.max_nodes {
            return Err(ContentRenderError::NodeLimitExceeded);
        }
        self.work_units = self
            .work_units
            .checked_add(work)
            .ok_or(ContentRenderError::WorkLimitExceeded)?;
        if self.work_units > self.limits.max_work_units {
            return Err(ContentRenderError::WorkLimitExceeded);
        }
        self.budget.charge_node()?;
        Ok(self.budget.charge_work(work)?)
    }

    fn push_collapsed_text(&mut self, value: &str) -> Result<(), ContentRenderError> {
        let mut text = BoundedString::from_str("", self.max_output_bytes)?;
        text.push_collapsed_html_text(value)?;
        self.flush_pending()?;
        self.output.push_inline_fragment(text.as_str())
    }

    fn ensure_space(&mut self) -> Result<(), ContentRenderError> {
        if !self.output.is_empty() && self.pending_newlines == 0 {
            self.pending_space = true;
        }
        Ok(())
    }

    fn ensure_line_break(&mut self) -> Result<(), ContentRenderError> {
        while self.output.as_str().ends_with(' ') {
            self.output.value.pop();
        }
        if !self.output.is_empty() {
            self.pending_space = false;
            self.pending_newlines = self.pending_newlines.max(1);
        }
        Ok(())
    }

    fn ensure_block_break(&mut self) -> Result<(), ContentRenderError> {
        if !self.output.is_empty() {
            self.pending_space = false;
            self.pending_newlines = self.pending_newlines.max(2);
        }
        Ok(())
    }

    fn push_output(&mut self, value: &str) -> Result<(), ContentRenderError> {
        self.flush_pending()?;
        self.output.push_str(value)
    }

    fn push_output_repeat(
        &mut self,
        character: char,
        count: usize,
    ) -> Result<(), ContentRenderError> {
        self.flush_pending()?;
        self.output.push_repeat(character, count)
    }

    fn flush_pending(&mut self) -> Result<(), ContentRenderError> {
        if self.output.is_empty() {
            self.pending_space = false;
            self.pending_newlines = 0;
            return Ok(());
        }
        if self.pending_newlines != 0 {
            while self.output.as_str().ends_with(' ') {
                self.output.value.pop();
            }
            let existing = self
                .output
                .as_str()
                .as_bytes()
                .iter()
                .rev()
                .take_while(|byte| **byte == b'\n')
                .count();
            self.output
                .push_repeat('\n', self.pending_newlines.saturating_sub(existing))?;
        } else if self.pending_space
            && !self
                .output
                .as_str()
                .chars()
                .next_back()
                .is_some_and(char::is_whitespace)
        {
            self.output.push_str(" ")?;
        }
        self.pending_space = false;
        self.pending_newlines = 0;
        Ok(())
    }

    fn finish(mut self) -> Result<BoundedString, ContentRenderError> {
        if self.depth != 0
            || !self.lists.is_empty()
            || self.in_code_block != 0
            || self.in_table != 0
        {
            return Err(ContentRenderError::MalformedDocument);
        }
        let trimmed = self.output.as_str().trim_end().len();
        self.output.value.truncate(trimmed);
        Ok(self.output)
    }
}

fn event_work(event: &Event<'_>) -> usize {
    match event {
        Event::Start(Tag::Link {
            dest_url, title, ..
        })
        | Event::Start(Tag::Image {
            dest_url, title, ..
        }) => dest_url.len().saturating_add(title.len()).max(1),
        _ => 1,
    }
}

fn update_active_html_stack(
    fragment: &str,
    active: &mut Vec<String>,
    max_depth: usize,
) -> Result<(), ContentRenderError> {
    let bytes = fragment.as_bytes();
    let mut cursor = 0;
    while cursor < bytes.len() {
        // HTML raw-text/RCDATA elements do not recognize nested start tags.
        // Treat everything up to their matching close as text so repeated
        // `<script>`/`<style>` spellings cannot grow the active stack.
        if let Some(raw_text_name) = active
            .last()
            .filter(|name| is_raw_text_storage_element(name))
            .cloned()
        {
            let Some(close_start) = find_raw_text_close(bytes, cursor, &raw_text_name) else {
                return Ok(());
            };
            let close_name_end = close_start + 2 + raw_text_name.len();
            let Ok(close_end) = storage_tag_end(bytes, close_name_end) else {
                // A possible raw-text close is still text until its terminating
                // `>` arrives. Keep the element active across parser events.
                return Ok(());
            };
            active.pop();
            cursor = close_end.saturating_add(1);
            continue;
        }
        let Some(relative) = fragment[cursor..].find('<') else {
            break;
        };
        cursor += relative;
        if fragment[cursor..].starts_with("<!--") {
            cursor = fragment[cursor + 4..]
                .find("-->")
                .map(|end| cursor + 4 + end + 3)
                .unwrap_or(bytes.len());
            continue;
        }
        let closing = bytes.get(cursor + 1) == Some(&b'/');
        let name_start = cursor + if closing { 2 } else { 1 };
        let name_end = storage_tag_name_end(bytes, name_start);
        if name_end == name_start {
            cursor += 1;
            continue;
        }
        let name = &fragment[name_start..name_end];
        let normalized_name = name.to_ascii_lowercase();
        let end = match storage_tag_end(bytes, name_end) {
            Ok(end) => end,
            Err(_) => {
                if is_active_storage_element(&normalized_name)
                    && !is_active_html_void_element(&normalized_name)
                    && !closing
                {
                    active.push(normalized_name);
                    if active.len() > max_depth {
                        return Err(ContentRenderError::NestingLimitExceeded);
                    }
                }
                break;
            }
        };
        let self_closing = fragment[name_end..=end].trim_end().ends_with("/>");
        if is_active_storage_element(&normalized_name) {
            if closing {
                if let Some(index) = active
                    .iter()
                    .rposition(|open| open.eq_ignore_ascii_case(name))
                {
                    active.truncate(index);
                }
            } else if !(is_active_html_void_element(&normalized_name)
                || self_closing && is_foreign_html_root(&normalized_name))
            {
                active.push(normalized_name);
                if active.len() > max_depth {
                    return Err(ContentRenderError::NestingLimitExceeded);
                }
            }
        }
        cursor = end.saturating_add(1);
    }
    Ok(())
}

fn is_active_html_void_element(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "area"
            | "base"
            | "br"
            | "col"
            | "embed"
            | "hr"
            | "img"
            | "input"
            | "link"
            | "meta"
            | "param"
            | "source"
            | "track"
            | "wbr"
            | "frame"
    )
}

fn is_foreign_html_root(name: &str) -> bool {
    name.eq_ignore_ascii_case("svg") || name.eq_ignore_ascii_case("math")
}

fn render_confluence_storage_with_limits_and_budget(
    source: &str,
    format: ReadContentFormat,
    max_source_bytes: u64,
    max_output_bytes: u64,
    limits: RenderLimits,
    budget: &mut RenderBudget,
) -> Result<Option<RenderedBody>, ContentRenderError> {
    render_confluence_storage_with_limits_and_budget_and_heading_offset(
        source,
        format,
        max_source_bytes,
        max_output_bytes,
        limits,
        budget,
        0,
    )
}

fn render_confluence_storage_with_limits_and_budget_and_heading_offset(
    source: &str,
    format: ReadContentFormat,
    max_source_bytes: u64,
    max_output_bytes: u64,
    limits: RenderLimits,
    budget: &mut RenderBudget,
    heading_level_offset: usize,
) -> Result<Option<RenderedBody>, ContentRenderError> {
    validate_string_source_size(source, max_source_bytes)?;
    let source = preflight_storage_fragment(source, limits, budget)?;
    let context = QualName::new(None, ns!(html), local_name!("div"));
    let dom = parse_fragment(
        RcDom::default(),
        Default::default(),
        context,
        Vec::new(),
        false,
    )
    .one(source);
    let mut renderer = StorageRenderer {
        // Native mode still parses and traverses the complete fragment, but
        // discards the derived text rather than attaching a companion.
        format: if format == ReadContentFormat::Native {
            ReadContentFormat::Text
        } else {
            format
        },
        max_output_bytes,
        heading_level_offset,
        limits,
        nodes: 0,
        work_units: 0,
        budget,
    };
    let rendered = renderer.render_children_block(&dom.document, 0)?;
    if format == ReadContentFormat::Native {
        Ok(None)
    } else {
        Ok(Some(RenderedBody::new(format, rendered.into_string())))
    }
}

/// Render CommonMark-generated HTML using HTML5's tolerant fragment recovery.
///
/// Unlike Confluence storage, valid CommonMark raw HTML need not be a balanced
/// storage fragment. The DOM traversal remains fully bounded and suppresses the
/// same active-content elements as the strict storage path.
fn render_gitlab_html_fragment_with_limits_and_budget(
    source: &str,
    format: ReadContentFormat,
    max_output_bytes: u64,
    limits: RenderLimits,
    budget: &mut RenderBudget,
    heading_level_offset: usize,
) -> Result<Option<RenderedBody>, ContentRenderError> {
    let context = QualName::new(None, ns!(html), local_name!("div"));
    let dom = parse_fragment(
        RcDom::default(),
        Default::default(),
        context,
        Vec::new(),
        false,
    )
    .one(source);
    let mut renderer = StorageRenderer {
        format,
        max_output_bytes,
        heading_level_offset,
        limits,
        nodes: 0,
        work_units: 0,
        budget,
    };
    let rendered = renderer.render_children_block(&dom.document, 0)?;
    Ok(Some(RenderedBody::new(format, rendered.into_string())))
}

#[cfg(test)]
fn render_confluence_storage_with_limits(
    source: &str,
    format: ReadContentFormat,
    max_output_bytes: u64,
    limits: RenderLimits,
) -> Result<Option<RenderedBody>, ContentRenderError> {
    let mut budget = RenderBudget::default();
    render_confluence_storage_with_limits_and_budget(
        source,
        format,
        u64::MAX,
        max_output_bytes,
        limits,
        &mut budget,
    )
}

fn preflight_storage_fragment(
    source: &str,
    limits: RenderLimits,
    budget: &mut RenderBudget,
) -> Result<String, ContentRenderError> {
    let bytes = source.as_bytes();
    let mut output = String::with_capacity(source.len());
    let mut custom_stack: Vec<&str> = Vec::new();
    let mut cursor = 0;
    let mut nodes = 0;
    let mut work_units = 0;
    let mut expansion_bytes: usize = 0;
    while cursor < bytes.len() {
        if source[cursor..].starts_with("<!--") {
            let end = cursor
                + 4
                + source[cursor + 4..]
                    .find("-->")
                    .ok_or(ContentRenderError::MalformedDocument)?
                + 3;
            charge_storage_preflight(&mut nodes, &mut work_units, 1, 1, limits, budget)?;
            output.push_str(&source[cursor..end]);
            cursor = end;
            continue;
        }
        if source[cursor..].starts_with("<![CDATA[") {
            let content_start = cursor + 9;
            let content_end = content_start
                + source[content_start..]
                    .find("]]>")
                    .ok_or(ContentRenderError::MalformedDocument)?;
            let content = &source[content_start..content_end];
            charge_storage_preflight(
                &mut nodes,
                &mut work_units,
                1,
                content.len().max(1),
                limits,
                budget,
            )?;
            push_parse_safe_cdata(
                &mut output,
                content,
                &mut expansion_bytes,
                limits.max_work_units,
            )?;
            let end = content_end + 3;
            cursor = end;
            continue;
        }
        if source[cursor..].starts_with("<!") || source[cursor..].starts_with("<?") {
            let end = storage_tag_end(bytes, cursor + 2)?;
            charge_storage_preflight(&mut nodes, &mut work_units, 1, 1, limits, budget)?;
            output.push_str(&source[cursor..=end]);
            cursor = end + 1;
            continue;
        }
        if bytes[cursor] != b'<' {
            let end = source[cursor..]
                .find('<')
                .map(|relative| cursor + relative)
                .unwrap_or(bytes.len());
            charge_storage_preflight(&mut nodes, &mut work_units, 1, 1, limits, budget)?;
            output.push_str(&source[cursor..end]);
            cursor = end;
            continue;
        }
        if cursor + 1 >= bytes.len() {
            return Err(ContentRenderError::MalformedDocument);
        }
        if bytes[cursor + 1] == b'/' {
            let name_start = cursor + 2;
            let name_end = storage_tag_name_end(bytes, name_start);
            if name_end == name_start {
                return Err(ContentRenderError::MalformedDocument);
            }
            let end = storage_tag_end(bytes, name_end)?;
            if bytes[name_end..end]
                .iter()
                .any(|byte| !byte.is_ascii_whitespace())
            {
                return Err(ContentRenderError::MalformedDocument);
            }
            let name = &source[name_start..name_end];
            charge_storage_preflight(&mut nodes, &mut work_units, 0, 1, limits, budget)?;
            if is_custom_storage_element(name) {
                let open = custom_stack
                    .pop()
                    .ok_or(ContentRenderError::MalformedDocument)?;
                if !open.eq_ignore_ascii_case(name) {
                    return Err(ContentRenderError::MalformedDocument);
                }
            }
            output.push_str(&source[cursor..=end]);
            cursor = end + 1;
            continue;
        }
        if !bytes[cursor + 1].is_ascii_alphabetic() {
            output.push('<');
            cursor += 1;
            continue;
        }
        let name_start = cursor + 1;
        let name_end = storage_tag_name_end(bytes, name_start);
        let name = &source[name_start..name_end];
        let end = storage_tag_end(bytes, name_end)?;
        let attribute_work = storage_attribute_work(bytes, name_end, end)?;
        let mut before_end = end;
        while before_end > name_end && bytes[before_end - 1].is_ascii_whitespace() {
            before_end -= 1;
        }
        let self_closing = before_end > name_end && bytes[before_end - 1] == b'/';
        charge_storage_preflight(
            &mut nodes,
            &mut work_units,
            1,
            attribute_work.saturating_add(1),
            limits,
            budget,
        )?;
        if name.eq_ignore_ascii_case("plaintext") && !self_closing {
            charge_storage_preflight(&mut nodes, &mut work_units, 1, 1, limits, budget)?;
            output.push_str(&source[cursor..]);
            cursor = bytes.len();
            continue;
        }
        if is_raw_text_storage_element(name) && !self_closing {
            let close_start = find_raw_text_close(bytes, end + 1, name)
                .ok_or(ContentRenderError::MalformedDocument)?;
            let close_name_end = close_start + 2 + name.len();
            let close_end = storage_tag_end(bytes, close_name_end)?;
            if bytes[close_name_end..close_end]
                .iter()
                .any(|byte| !byte.is_ascii_whitespace())
            {
                return Err(ContentRenderError::MalformedDocument);
            }
            charge_storage_preflight(&mut nodes, &mut work_units, 1, 2, limits, budget)?;
            output.push_str(&source[cursor..=close_end]);
            cursor = close_end + 1;
            continue;
        }
        if self_closing && !is_html_void_element(name) {
            output.push_str(&source[cursor..before_end - 1]);
            output.push_str(&source[before_end..=end]);
            let expansion = name
                .len()
                .checked_add(3)
                .ok_or(ContentRenderError::WorkLimitExceeded)?;
            expansion_bytes = expansion_bytes
                .checked_add(expansion)
                .ok_or(ContentRenderError::WorkLimitExceeded)?;
            if expansion_bytes > limits.max_work_units {
                return Err(ContentRenderError::WorkLimitExceeded);
            }
            output
                .try_reserve(expansion)
                .map_err(|_| ContentRenderError::WorkLimitExceeded)?;
            output.push_str("</");
            output.push_str(name);
            output.push('>');
        } else {
            output.push_str(&source[cursor..=end]);
            if is_custom_storage_element(name) && !is_html_void_element(name) {
                custom_stack.push(name);
                if custom_stack.len() > limits.max_depth {
                    return Err(ContentRenderError::NestingLimitExceeded);
                }
            }
        }
        cursor = end + 1;
    }
    if !custom_stack.is_empty() {
        return Err(ContentRenderError::MalformedDocument);
    }
    Ok(output)
}

fn charge_storage_preflight(
    nodes: &mut usize,
    work_units: &mut usize,
    added_nodes: usize,
    added_work: usize,
    limits: RenderLimits,
    budget: &mut RenderBudget,
) -> Result<(), ContentRenderError> {
    *nodes = nodes
        .checked_add(added_nodes)
        .ok_or(ContentRenderError::NodeLimitExceeded)?;
    if *nodes > limits.max_nodes {
        return Err(ContentRenderError::NodeLimitExceeded);
    }
    *work_units = work_units
        .checked_add(added_work)
        .ok_or(ContentRenderError::WorkLimitExceeded)?;
    if *work_units > limits.max_work_units {
        return Err(ContentRenderError::WorkLimitExceeded);
    }
    for _ in 0..added_nodes {
        budget.charge_node()?;
    }
    budget.charge_work(added_work)?;
    Ok(())
}

fn push_parse_safe_cdata(
    output: &mut String,
    content: &str,
    expansion_bytes: &mut usize,
    max_expansion_bytes: usize,
) -> Result<(), ContentRenderError> {
    let added_expansion = content.chars().try_fold(0_usize, |total, character| {
        total.checked_add(match character {
            '&' => 4,
            '<' | '>' => 3,
            _ => 0,
        })
    });
    let added_expansion = added_expansion.ok_or(ContentRenderError::WorkLimitExceeded)?;
    *expansion_bytes = expansion_bytes
        .checked_add(added_expansion)
        .ok_or(ContentRenderError::WorkLimitExceeded)?;
    if *expansion_bytes > max_expansion_bytes {
        return Err(ContentRenderError::WorkLimitExceeded);
    }
    output
        .try_reserve(content.len().saturating_add(added_expansion))
        .map_err(|_| ContentRenderError::WorkLimitExceeded)?;
    for character in content.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            _ => output.push(character),
        }
    }
    Ok(())
}

fn storage_tag_name_end(bytes: &[u8], start: usize) -> usize {
    let mut cursor = start;
    while cursor < bytes.len()
        && (bytes[cursor].is_ascii_alphanumeric()
            || matches!(bytes[cursor], b':' | b'-' | b'_' | b'.'))
    {
        cursor += 1;
    }
    cursor
}

fn storage_tag_end(bytes: &[u8], start: usize) -> Result<usize, ContentRenderError> {
    let mut quote = None;
    let mut cursor = start;
    while cursor < bytes.len() {
        match (quote, bytes[cursor]) {
            (None, b'\'' | b'"') => quote = Some(bytes[cursor]),
            (Some(active), byte) if active == byte => quote = None,
            (None, b'>') => return Ok(cursor),
            _ => {}
        }
        cursor += 1;
    }
    Err(ContentRenderError::MalformedDocument)
}

fn storage_attribute_work(
    bytes: &[u8],
    start: usize,
    end: usize,
) -> Result<usize, ContentRenderError> {
    let mut cursor = start;
    let mut attributes = 0_usize;
    while cursor < end {
        while cursor < end && (bytes[cursor].is_ascii_whitespace() || bytes[cursor] == b'/') {
            cursor += 1;
        }
        if cursor == end {
            break;
        }
        attributes = attributes
            .checked_add(1)
            .ok_or(ContentRenderError::WorkLimitExceeded)?;
        let mut quote = None;
        while cursor < end {
            match (quote, bytes[cursor]) {
                (None, b'\'' | b'"') => quote = Some(bytes[cursor]),
                (Some(active), byte) if active == byte => quote = None,
                (None, byte) if byte.is_ascii_whitespace() => break,
                _ => {}
            }
            cursor += 1;
        }
        if quote.is_some() {
            return Err(ContentRenderError::MalformedDocument);
        }
    }
    Ok(attributes)
}

fn is_custom_storage_element(name: &str) -> bool {
    name.contains(':') || name.contains('-')
}

fn is_raw_text_storage_element(name: &str) -> bool {
    [
        "script", "style", "xmp", "iframe", "noembed", "noframes", "textarea", "title",
    ]
    .iter()
    .any(|candidate| name.eq_ignore_ascii_case(candidate))
}

fn is_active_storage_element(name: &str) -> bool {
    matches!(
        name,
        "script"
            | "style"
            | "iframe"
            | "frame"
            | "frameset"
            | "object"
            | "embed"
            | "template"
            | "noscript"
            | "form"
            | "input"
            | "button"
            | "select"
            | "option"
            | "textarea"
            | "title"
            | "xmp"
            | "noembed"
            | "noframes"
            | "plaintext"
            | "svg"
            | "math"
    )
}

fn find_raw_text_close(bytes: &[u8], start: usize, name: &str) -> Option<usize> {
    let name = name.as_bytes();
    let mut cursor = start;
    while cursor + name.len() + 2 <= bytes.len() {
        if bytes[cursor] == b'<'
            && bytes.get(cursor + 1) == Some(&b'/')
            && bytes[cursor + 2..cursor + 2 + name.len()].eq_ignore_ascii_case(name)
            && bytes
                .get(cursor + 2 + name.len())
                .is_some_and(|byte| byte.is_ascii_whitespace() || *byte == b'>')
        {
            return Some(cursor);
        }
        cursor += 1;
    }
    None
}

fn is_html_void_element(name: &str) -> bool {
    [
        "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param",
        "source", "track", "wbr",
    ]
    .iter()
    .any(|candidate| name.eq_ignore_ascii_case(candidate))
}

fn render_adf_with_limits(
    document: &Value,
    format: ReadContentFormat,
    max_source_bytes: u64,
    max_output_bytes: u64,
    limits: RenderLimits,
    budget: &mut RenderBudget,
) -> Result<Option<RenderedBody>, ContentRenderError> {
    validate_serialized_source_size(document, max_source_bytes)?;

    let root = document
        .as_object()
        .ok_or(ContentRenderError::MalformedDocument)?;
    if root.get("type").and_then(Value::as_str) != Some("doc")
        || root.get("version").and_then(Value::as_u64) != Some(1)
        || !root.get("content").is_some_and(Value::is_array)
    {
        return Err(ContentRenderError::MalformedDocument);
    }

    let mut renderer = AdfRenderer {
        // Native mode still traverses and validates the complete structure, but
        // discards the bounded output instead of attaching a companion.
        format: if format == ReadContentFormat::Native {
            ReadContentFormat::Text
        } else {
            format
        },
        max_output_bytes,
        limits,
        nodes: 0,
        work_units: 0,
        budget,
    };
    let rendered = renderer.render_node(document, 0)?;
    if format == ReadContentFormat::Native {
        Ok(None)
    } else {
        Ok(Some(RenderedBody::new(format, rendered.into_string())))
    }
}

struct AdfRenderer<'a> {
    format: ReadContentFormat,
    max_output_bytes: u64,
    limits: RenderLimits,
    nodes: usize,
    work_units: usize,
    budget: &'a mut RenderBudget,
}

impl AdfRenderer<'_> {
    fn render_node(
        &mut self,
        value: &Value,
        depth: usize,
    ) -> Result<BoundedString, ContentRenderError> {
        self.visit_node(depth)?;

        let object = value
            .as_object()
            .ok_or(ContentRenderError::MalformedDocument)?;
        let node_type = object
            .get("type")
            .and_then(Value::as_str)
            .ok_or(ContentRenderError::MalformedDocument)?;
        let attrs = optional_object(object, "attrs")?;
        let children = optional_array(object, "content")?;
        validate_marks_shape(object.get("marks"))?;

        match node_type {
            "doc" => self.render_blocks(children.unwrap_or_default(), depth),
            "paragraph" => self.render_inline(children.unwrap_or_default(), depth),
            "heading" => self.render_heading(attrs, children.unwrap_or_default(), depth),
            "blockquote" => self.render_blockquote(children.unwrap_or_default(), depth),
            "bulletList" => self.render_list(children.unwrap_or_default(), depth, false, attrs),
            "orderedList" => self.render_list(children.unwrap_or_default(), depth, true, attrs),
            "listItem" => self.render_list_item(children.unwrap_or_default(), depth),
            "table" => self.render_table(children.unwrap_or_default(), depth),
            "tableRow" => self.render_table_row(
                children.unwrap_or_default(),
                depth,
                children.unwrap_or_default().len(),
            ),
            "tableHeader" | "tableCell" => self.render_blocks(children.unwrap_or_default(), depth),
            "codeBlock" => self.render_code_block(attrs, children.unwrap_or_default(), depth),
            "text" => self.render_text(object),
            "hardBreak" => self.fragment("\n"),
            "rule" => self.fragment(if self.format == ReadContentFormat::Markdown {
                "---"
            } else {
                "—"
            }),
            "mention" => self.render_mention(attrs),
            "emoji" => self.render_known_attr(attrs, &["text", "shortName"]),
            "status" => self.render_known_attr(attrs, &["text"]),
            "date" => self.render_known_attr(attrs, &["timestamp"]),
            "inlineCard" | "blockCard" => self.render_card(attrs),
            "media" | "mediaInline" => self.render_media(attrs),
            "taskItem" => self.render_check_item(attrs, children.unwrap_or_default(), depth),
            "decisionItem" => self.render_decision_item(attrs, children.unwrap_or_default(), depth),
            "expand" | "nestedExpand" => {
                self.render_expand(attrs, children.unwrap_or_default(), depth)
            }
            // Panels and Atlassian list/group wrappers preserve readable descendants.
            "panel" | "taskList" | "decisionList" | "mediaGroup" | "mediaSingle" => {
                self.render_blocks(children.unwrap_or_default(), depth)
            }
            // Safe fallback: preserve descendants, but never expose unknown leaf attributes.
            _ => match children {
                Some(children) => self.render_blocks(children, depth),
                None => self.fragment("[unsupported content]"),
            },
        }
    }

    fn visit_node(&mut self, depth: usize) -> Result<(), ContentRenderError> {
        if depth > self.limits.max_depth {
            return Err(ContentRenderError::NestingLimitExceeded);
        }
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or(ContentRenderError::NodeLimitExceeded)?;
        if self.nodes > self.limits.max_nodes {
            return Err(ContentRenderError::NodeLimitExceeded);
        }
        self.budget.charge_node()?;
        self.add_work(1)
    }

    fn render_blocks(
        &mut self,
        children: &[Value],
        depth: usize,
    ) -> Result<BoundedString, ContentRenderError> {
        let mut output = self.empty()?;
        for child in children {
            self.add_work(1)?;
            let child = self.render_node(child, depth + 1)?;
            output.push_joined(child.as_str(), "\n\n")?;
        }
        Ok(output)
    }

    fn render_inline(
        &mut self,
        children: &[Value],
        depth: usize,
    ) -> Result<BoundedString, ContentRenderError> {
        let mut output = self.empty()?;
        for child in children {
            self.add_work(1)?;
            let child = self.render_node(child, depth + 1)?;
            output.push_str(child.as_str())?;
        }
        Ok(output)
    }

    fn render_heading(
        &mut self,
        attrs: Option<&Map<String, Value>>,
        children: &[Value],
        depth: usize,
    ) -> Result<BoundedString, ContentRenderError> {
        let content = self.render_inline(children, depth)?;
        if self.format == ReadContentFormat::Text || content.is_empty() {
            return Ok(content);
        }
        let level = attrs
            .and_then(|attrs| attrs.get("level"))
            .and_then(Value::as_u64)
            .filter(|level| (1..=6).contains(level))
            .unwrap_or(1) as usize;
        let mut output = self.empty()?;
        output.push_repeat('#', level)?;
        output.push_str(" ")?;
        output.push_str(content.as_str())?;
        Ok(output)
    }

    fn render_blockquote(
        &mut self,
        children: &[Value],
        depth: usize,
    ) -> Result<BoundedString, ContentRenderError> {
        let content = self.render_blocks(children, depth)?;
        if self.format == ReadContentFormat::Text || content.is_empty() {
            return Ok(content);
        }
        let mut output = self.empty()?;
        for (index, line) in content.as_str().split('\n').enumerate() {
            if index != 0 {
                output.push_str("\n")?;
            }
            output.push_str(if line.is_empty() { ">" } else { "> " })?;
            output.push_str(line)?;
        }
        Ok(output)
    }

    fn render_list(
        &mut self,
        children: &[Value],
        depth: usize,
        ordered: bool,
        attrs: Option<&Map<String, Value>>,
    ) -> Result<BoundedString, ContentRenderError> {
        let start = attrs
            .and_then(|attrs| attrs.get("order"))
            .and_then(Value::as_u64)
            .filter(|order| *order > 0)
            .unwrap_or(1);
        let mut output = self.empty()?;
        for (index, child) in children.iter().enumerate() {
            self.add_work(1)?;
            let item = self.render_node(child, depth + 1)?;
            if item.is_empty() {
                continue;
            }
            if !output.is_empty() {
                output.push_str("\n")?;
            }
            let marker = if ordered {
                let mut marker = start.saturating_add(index as u64).to_string();
                marker.push_str(". ");
                marker
            } else if self.format == ReadContentFormat::Markdown {
                "- ".to_string()
            } else {
                "• ".to_string()
            };
            output.push_str(&marker)?;
            let continuation_width = marker.chars().count();
            for (line_index, line) in item.as_str().split('\n').enumerate() {
                if line_index != 0 {
                    output.push_str("\n")?;
                    output.push_repeat(' ', continuation_width)?;
                }
                output.push_str(line)?;
            }
        }
        Ok(output)
    }

    fn render_table(
        &mut self,
        rows: &[Value],
        depth: usize,
    ) -> Result<BoundedString, ContentRenderError> {
        let mut width = 0;
        for row in rows {
            self.add_work(1)?;
            let row = row
                .as_object()
                .ok_or(ContentRenderError::MalformedDocument)?;
            if row.get("type").and_then(Value::as_str) != Some("tableRow") {
                return Err(ContentRenderError::MalformedDocument);
            }
            width = width.max(optional_array(row, "content")?.unwrap_or_default().len());
        }
        if width == 0 {
            return self.empty();
        }

        let mut output = self.empty()?;
        for (index, row) in rows.iter().enumerate() {
            self.add_work(1)?;
            let row = row
                .as_object()
                .ok_or(ContentRenderError::MalformedDocument)?;
            self.visit_node(depth + 1)?;
            optional_object(row, "attrs")?;
            validate_marks_shape(row.get("marks"))?;
            let cells = optional_array(row, "content")?.unwrap_or_default();
            let rendered = self.render_table_row(cells, depth + 1, width)?;
            output.push_joined(rendered.as_str(), "\n")?;
            if index == 0 && self.format == ReadContentFormat::Markdown {
                let mut separator = self.empty()?;
                separator.push_str("|")?;
                for _ in 0..width {
                    separator.push_str(" --- |")?;
                }
                output.push_joined(separator.as_str(), "\n")?;
            }
        }
        Ok(output)
    }

    fn render_table_row(
        &mut self,
        cells: &[Value],
        depth: usize,
        width: usize,
    ) -> Result<BoundedString, ContentRenderError> {
        let mut output = self.empty()?;
        if self.format == ReadContentFormat::Markdown {
            output.push_str("|")?;
        }
        for index in 0..width {
            if self.format == ReadContentFormat::Markdown {
                output.push_str(" ")?;
            } else if index != 0 {
                output.push_str(" | ")?;
            }
            if let Some(cell) = cells.get(index) {
                self.add_work(1)?;
                let cell = self.render_node(cell, depth + 1)?;
                output.push_flattened(cell.as_str(), self.format == ReadContentFormat::Markdown)?;
            }
            if self.format == ReadContentFormat::Markdown {
                output.push_str(" |")?;
            }
        }
        Ok(output)
    }

    fn render_list_item(
        &mut self,
        children: &[Value],
        depth: usize,
    ) -> Result<BoundedString, ContentRenderError> {
        let mut output = self.empty()?;
        for child in children {
            self.add_work(1)?;
            let child = self.render_node(child, depth + 1)?;
            output.push_joined(child.as_str(), "\n")?;
        }
        Ok(output)
    }

    fn render_code_block(
        &mut self,
        attrs: Option<&Map<String, Value>>,
        children: &[Value],
        depth: usize,
    ) -> Result<BoundedString, ContentRenderError> {
        let content = self.render_plain_descendants(children, depth)?;
        if self.format == ReadContentFormat::Text {
            return Ok(content);
        }
        let longest_run = longest_byte_run(content.as_str().as_bytes(), b'`');
        let fence_width = longest_run.saturating_add(1).max(3);
        let language = attrs
            .and_then(|attrs| attrs.get("language"))
            .and_then(Value::as_str)
            .filter(|value| {
                !value.is_empty()
                    && value.len() <= 32
                    && value.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'+' | b'-')
                    })
            })
            .unwrap_or_default();
        let mut output = self.empty()?;
        output.push_repeat('`', fence_width)?;
        output.push_str(language)?;
        output.push_str("\n")?;
        output.push_str(content.as_str())?;
        output.push_str("\n")?;
        output.push_repeat('`', fence_width)?;
        Ok(output)
    }

    fn render_plain_descendants(
        &mut self,
        children: &[Value],
        depth: usize,
    ) -> Result<BoundedString, ContentRenderError> {
        let mut output = self.empty()?;
        for child in children {
            self.add_work(1)?;
            self.visit_node(depth + 1)?;
            let object = child
                .as_object()
                .ok_or(ContentRenderError::MalformedDocument)?;
            let node_type = object
                .get("type")
                .and_then(Value::as_str)
                .ok_or(ContentRenderError::MalformedDocument)?;
            optional_object(object, "attrs")?;
            validate_marks_shape(object.get("marks"))?;
            if node_type == "text" {
                let text = object
                    .get("text")
                    .and_then(Value::as_str)
                    .ok_or(ContentRenderError::MalformedDocument)?;
                output.push_normalized(text)?;
            } else if node_type == "hardBreak" {
                output.push_str("\n")?;
            } else if let Some(grandchildren) = optional_array(object, "content")? {
                let nested = self.render_plain_descendants(grandchildren, depth + 1)?;
                output.push_str(nested.as_str())?;
            }
        }
        Ok(output)
    }

    fn render_text(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<BoundedString, ContentRenderError> {
        let text = object
            .get("text")
            .and_then(Value::as_str)
            .ok_or(ContentRenderError::MalformedDocument)?;
        if self.format == ReadContentFormat::Text {
            return self.fragment(text);
        }

        let marks = object
            .get("marks")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let mut strong = false;
        let mut emphasis = false;
        let mut strike = false;
        let mut code = false;
        let mut link: Option<Url> = None;
        for mark in marks {
            self.add_work(1)?;
            let mark = mark
                .as_object()
                .ok_or(ContentRenderError::MalformedDocument)?;
            let mark_type = mark
                .get("type")
                .and_then(Value::as_str)
                .ok_or(ContentRenderError::MalformedDocument)?;
            let attrs = optional_object(mark, "attrs")?;
            match mark_type {
                "strong" => strong = true,
                "em" => emphasis = true,
                "strike" => strike = true,
                "code" => code = true,
                "link" if link.is_none() => {
                    link = attrs
                        .and_then(|attrs| attrs.get("href"))
                        .and_then(Value::as_str)
                        .and_then(safe_link);
                }
                _ => {}
            }
        }

        let mut rendered = self.empty()?;
        if link.is_some() {
            rendered.push_str("[")?;
        }
        if strike {
            rendered.push_str("~~")?;
        }
        if emphasis {
            rendered.push_str("_")?;
        }
        if strong {
            rendered.push_str("**")?;
        }
        if code {
            rendered.push_inline_code(text)?;
        } else {
            rendered.push_markdown_escaped(text)?;
        }
        if strong {
            rendered.push_str("**")?;
        }
        if emphasis {
            rendered.push_str("_")?;
        }
        if strike {
            rendered.push_str("~~")?;
        }
        if let Some(href) = link {
            rendered.push_str("](")?;
            rendered.push_markdown_link_destination(href.as_str())?;
            rendered.push_str(")")?;
        }
        Ok(rendered)
    }

    fn render_mention(
        &self,
        attrs: Option<&Map<String, Value>>,
    ) -> Result<BoundedString, ContentRenderError> {
        if let Some(text) = attr_string(attrs, "text") {
            return self.fragment_for_format(text);
        }
        if let Some(name) = attr_string(attrs, "displayName") {
            let mut output = self.empty()?;
            output.push_str("@")?;
            if self.format == ReadContentFormat::Markdown {
                output.push_markdown_escaped(name)?;
            } else {
                output.push_normalized(name)?;
            }
            return Ok(output);
        }
        self.empty()
    }

    fn render_known_attr(
        &self,
        attrs: Option<&Map<String, Value>>,
        names: &[&str],
    ) -> Result<BoundedString, ContentRenderError> {
        for name in names {
            if let Some(value) = attr_string(attrs, name) {
                return self.fragment_for_format(value);
            }
        }
        self.empty()
    }

    fn render_card(
        &self,
        attrs: Option<&Map<String, Value>>,
    ) -> Result<BoundedString, ContentRenderError> {
        let Some(url) = attr_string(attrs, "url").and_then(safe_link) else {
            return self.fragment("[card]");
        };
        let mut output = self.empty()?;
        if self.format == ReadContentFormat::Markdown {
            output.push_str("[card](")?;
            output.push_markdown_link_destination(url.as_str())?;
            output.push_str(")")?;
        } else {
            output.push_str(url.as_str())?;
        }
        Ok(output)
    }

    fn render_media(
        &self,
        attrs: Option<&Map<String, Value>>,
    ) -> Result<BoundedString, ContentRenderError> {
        let mut output = self.empty()?;
        output.push_str("[attachment")?;
        if let Some(alt) = attr_string(attrs, "alt").filter(|alt| !alt.is_empty()) {
            output.push_str(": ")?;
            if self.format == ReadContentFormat::Markdown {
                output.push_markdown_escaped(alt)?;
            } else {
                output.push_normalized(alt)?;
            }
        }
        output.push_str("]")?;
        Ok(output)
    }

    fn render_check_item(
        &mut self,
        attrs: Option<&Map<String, Value>>,
        children: &[Value],
        depth: usize,
    ) -> Result<BoundedString, ContentRenderError> {
        let content = self.render_inline(children, depth)?;
        if content.is_empty() {
            return Ok(content);
        }
        let checked = attrs
            .and_then(|attrs| attrs.get("state"))
            .and_then(Value::as_str)
            .is_some_and(|state| matches!(state, "DONE" | "done" | "checked"));
        let prefix = if self.format == ReadContentFormat::Markdown {
            if checked { "[x] " } else { "[ ] " }
        } else if checked {
            "☑ "
        } else {
            "☐ "
        };
        let mut output = self.empty()?;
        output.push_str(prefix)?;
        output.push_str(content.as_str())?;
        Ok(output)
    }

    fn render_decision_item(
        &mut self,
        attrs: Option<&Map<String, Value>>,
        children: &[Value],
        depth: usize,
    ) -> Result<BoundedString, ContentRenderError> {
        let content = self.render_inline(children, depth)?;
        if content.is_empty() {
            return Ok(content);
        }
        let state = attrs
            .and_then(|attrs| attrs.get("state"))
            .and_then(Value::as_str);
        let label = match state {
            Some("DECIDED") => "Decision (decided)",
            Some("UNDECIDED") => "Decision (undecided)",
            _ => "Decision",
        };
        let mut output = self.empty()?;
        if self.format == ReadContentFormat::Markdown {
            output.push_str("**")?;
            output.push_str(label)?;
            output.push_str(":** ")?;
        } else {
            output.push_str(label)?;
            output.push_str(": ")?;
        }
        output.push_str(content.as_str())?;
        Ok(output)
    }

    fn render_expand(
        &mut self,
        attrs: Option<&Map<String, Value>>,
        children: &[Value],
        depth: usize,
    ) -> Result<BoundedString, ContentRenderError> {
        let mut output = self.empty()?;
        if let Some(title) = attr_string(attrs, "title") {
            if self.format == ReadContentFormat::Markdown {
                output.push_markdown_escaped(title)?;
            } else {
                output.push_normalized(title)?;
            }
        }
        let content = self.render_blocks(children, depth)?;
        output.push_joined(content.as_str(), "\n\n")?;
        Ok(output)
    }

    fn fragment_for_format(&self, value: &str) -> Result<BoundedString, ContentRenderError> {
        let mut output = self.empty()?;
        if self.format == ReadContentFormat::Markdown {
            output.push_markdown_escaped(value)?;
        } else {
            output.push_normalized(value)?;
        }
        Ok(output)
    }

    fn fragment(&self, value: &str) -> Result<BoundedString, ContentRenderError> {
        let mut output = self.empty()?;
        output.push_normalized(value)?;
        Ok(output)
    }

    fn empty(&self) -> Result<BoundedString, ContentRenderError> {
        BoundedString::from_str("", self.max_output_bytes)
    }

    fn add_work(&mut self, units: usize) -> Result<(), ContentRenderError> {
        self.work_units = self
            .work_units
            .checked_add(units)
            .ok_or(ContentRenderError::WorkLimitExceeded)?;
        if self.work_units > self.limits.max_work_units {
            return Err(ContentRenderError::WorkLimitExceeded);
        }
        Ok(self.budget.charge_work(units)?)
    }
}

fn validate_serialized_source_size(
    document: &Value,
    max_bytes: u64,
) -> Result<(), ContentRenderError> {
    struct LimitWriter {
        written: u64,
        max_bytes: u64,
        exceeded: bool,
    }

    impl Write for LimitWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let next = self.written.saturating_add(bytes.len() as u64);
            if next > self.max_bytes {
                self.exceeded = true;
                return Err(io::Error::other("source size limit exceeded"));
            }
            self.written = next;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut writer = LimitWriter {
        written: 0,
        max_bytes,
        exceeded: false,
    };
    if serde_json::to_writer(&mut writer, document).is_err() {
        return if writer.exceeded {
            Err(ContentRenderError::SourceTooLarge { max_bytes })
        } else {
            Err(ContentRenderError::MalformedDocument)
        };
    }
    Ok(())
}

fn validate_string_source_size(source: &str, max_bytes: u64) -> Result<(), ContentRenderError> {
    if source.len() as u64 > max_bytes {
        Err(ContentRenderError::SourceTooLarge { max_bytes })
    } else {
        Ok(())
    }
}

struct StorageRenderer<'a> {
    format: ReadContentFormat,
    max_output_bytes: u64,
    heading_level_offset: usize,
    limits: RenderLimits,
    nodes: usize,
    work_units: usize,
    budget: &'a mut RenderBudget,
}

impl StorageRenderer<'_> {
    fn render_node(
        &mut self,
        node: &Handle,
        depth: usize,
    ) -> Result<BoundedString, ContentRenderError> {
        self.visit_node(depth)?;
        match &node.data {
            NodeData::Document => self.render_children_block(node, depth),
            NodeData::Text { contents } => {
                let mut collapsed = self.empty()?;
                collapsed.push_collapsed_html_text(&contents.borrow())?;
                if self.format == ReadContentFormat::Text {
                    Ok(collapsed)
                } else {
                    let mut output = self.empty()?;
                    output.push_markdown_escaped(collapsed.as_str())?;
                    Ok(output)
                }
            }
            NodeData::Element { name, attrs, .. } => {
                let name = name.local.as_ref();
                let attrs = attrs.borrow();
                match name {
                    "script" | "style" | "iframe" | "frame" | "frameset" | "object" | "embed"
                    | "template" | "noscript" | "form" | "input" | "button" | "select"
                    | "option" | "textarea" | "title" | "xmp" | "noembed" | "noframes"
                    | "plaintext" | "svg" | "math" => self.empty(),
                    "p" => self.render_children_inline(node, depth),
                    "div" | "article" | "section" | "header" | "footer" | "main" | "aside"
                    | "nav" | "ac:rich-text-body" => self.render_children_block(node, depth),
                    "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                        let mut content = self.render_children_inline(node, depth)?;
                        content.trim_spaces();
                        if self.format == ReadContentFormat::Text || content.is_empty() {
                            return Ok(content);
                        }
                        let level = (name.as_bytes()[1].saturating_sub(b'0') as usize)
                            .saturating_add(self.heading_level_offset)
                            .min(6);
                        let mut output = self.empty()?;
                        output.push_repeat('#', level)?;
                        output.push_str(" ")?;
                        output.push_str(content.as_str())?;
                        Ok(output)
                    }
                    "br" => self.fragment("\n"),
                    "hr" => self.fragment(if self.format == ReadContentFormat::Markdown {
                        "---"
                    } else {
                        "—"
                    }),
                    "strong" | "b" => self.render_wrapped_inline(node, depth, "**"),
                    "em" | "i" => self.render_wrapped_inline(node, depth, "_"),
                    "strike" | "s" | "del" => self.render_wrapped_inline(node, depth, "~~"),
                    "code" => {
                        let plain = self.collect_plain_descendants(node, depth)?;
                        if self.format == ReadContentFormat::Text {
                            return Ok(plain);
                        }
                        let mut output = self.empty()?;
                        output.push_inline_code(plain.as_str())?;
                        Ok(output)
                    }
                    "pre" => {
                        let language = html_pre_code_language(node);
                        self.render_storage_code_block(node, depth, language.as_deref())
                    }
                    "blockquote" => self.render_blockquote(node, depth),
                    "ul" => self.render_html_list(node, depth, None),
                    "ol" => {
                        let start = attr_value(&attrs, "start")
                            .filter(|value| {
                                !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
                            })
                            .and_then(|value| value.parse::<u64>().ok())
                            .filter(|value| *value > 0)
                            .unwrap_or(1);
                        self.render_html_list(node, depth, Some(start))
                    }
                    "li" => self.render_html_list_item(node, depth),
                    "table" => self.render_html_table(node, depth),
                    "thead" | "tbody" | "tfoot" | "tr" | "th" | "td" => {
                        self.render_children_block(node, depth)
                    }
                    "a" => self.render_anchor(node, depth, attr_value(&attrs, "href")),
                    "img" => self.render_image(attr_value(&attrs, "alt")),
                    "ac:link" => self.render_confluence_link(node, depth),
                    "ac:image" => self.render_confluence_image(node, depth),
                    "ri:attachment" => self.render_attachment(&attrs),
                    "ri:user" => self.render_user(&attrs),
                    "ri:page" | "ri:blog-post" => self.render_content_reference(&attrs),
                    "ac:structured-macro" | "ac:macro" => {
                        self.render_structured_macro(node, depth, &attrs)
                    }
                    "ac:task-list" => self.render_children_block(node, depth),
                    "ac:task" => self.render_confluence_task(node, depth),
                    // ADF storage wrappers may contain readable block content. Their
                    // attribute/parameter children are provider metadata, not prose.
                    "ac:adf-extension" => self.render_adf_extension(node, depth),
                    "ac:adf-node" | "ac:adf-content" | "ac:adf-fallback" => {
                        self.render_children_block(node, depth)
                    }
                    "ac:plain-text-body" | "ac:plain-text-link-body" => {
                        let plain = self.collect_plain_descendants(node, depth)?;
                        self.format_plain_prose(plain)
                    }
                    "ac:parameter" | "ac:task-id" | "ac:task-uuid" | "ac:task-status"
                    | "ac:adf-attribute" | "ac:adf-parameter" | "ri:space" | "meta" | "link"
                    | "base" => self.empty(),
                    "span" | "small" | "sub" | "sup" | "u" | "mark" | "abbr" | "ac:link-body" => {
                        self.render_children_inline(node, depth)
                    }
                    _ => {
                        if node.children.borrow().is_empty() {
                            self.fragment("[unsupported content]")
                        } else {
                            self.render_children_block(node, depth)
                        }
                    }
                }
            }
            NodeData::Comment { .. }
            | NodeData::Doctype { .. }
            | NodeData::ProcessingInstruction { .. } => self.empty(),
        }
    }

    fn render_children_inline(
        &mut self,
        node: &Handle,
        depth: usize,
    ) -> Result<BoundedString, ContentRenderError> {
        let children = node.children.borrow();
        let mut output = self.empty()?;
        for child in children.iter() {
            self.add_work(1)?;
            let child = self.render_node(child, depth + 1)?;
            output.push_inline_fragment(child.as_str())?;
        }
        Ok(output)
    }

    fn render_children_block(
        &mut self,
        node: &Handle,
        depth: usize,
    ) -> Result<BoundedString, ContentRenderError> {
        let children = node.children.borrow();
        let mut output = self.empty()?;
        for child in children.iter() {
            self.add_work(1)?;
            let mut child = self.render_node(child, depth + 1)?;
            child.trim_spaces();
            output.push_joined(child.as_str(), "\n\n")?;
        }
        output.trim_spaces();
        Ok(output)
    }

    fn render_wrapped_inline(
        &mut self,
        node: &Handle,
        depth: usize,
        marker: &str,
    ) -> Result<BoundedString, ContentRenderError> {
        let content = self.render_children_inline(node, depth)?;
        if self.format == ReadContentFormat::Text || content.is_empty() {
            return Ok(content);
        }
        let mut output = self.empty()?;
        let leading_space = content.as_str().starts_with(' ');
        let trailing_space = content.as_str().ends_with(' ');
        let inner = content.as_str().trim_matches(' ');
        if leading_space {
            output.push_str(" ")?;
        }
        if inner.is_empty() {
            return Ok(output);
        }
        output.push_str(marker)?;
        output.push_str(inner)?;
        output.push_str(marker)?;
        if trailing_space {
            output.push_str(" ")?;
        }
        Ok(output)
    }

    fn render_blockquote(
        &mut self,
        node: &Handle,
        depth: usize,
    ) -> Result<BoundedString, ContentRenderError> {
        let content = self.render_children_block(node, depth)?;
        if self.format == ReadContentFormat::Text || content.is_empty() {
            return Ok(content);
        }
        let mut output = self.empty()?;
        for (index, line) in content.as_str().split('\n').enumerate() {
            if index != 0 {
                output.push_str("\n")?;
            }
            output.push_str(if line.is_empty() { ">" } else { "> " })?;
            output.push_str(line)?;
        }
        Ok(output)
    }

    fn render_html_list(
        &mut self,
        node: &Handle,
        depth: usize,
        ordered_start: Option<u64>,
    ) -> Result<BoundedString, ContentRenderError> {
        let children = node.children.borrow();
        let mut output = self.empty()?;
        let mut item_index = ordered_start.unwrap_or(1);
        for child in children.iter() {
            if !element_named(child, "li") {
                self.add_work(1)?;
                self.visit_node(depth + 1)?;
                continue;
            }
            let marker_index = item_index;
            if ordered_start.is_some() {
                item_index = item_index.saturating_add(1);
            }
            self.add_work(1)?;
            let item = self.render_node(child, depth + 1)?;
            if item.is_empty() {
                continue;
            }
            if !output.is_empty() {
                output.push_str("\n")?;
            }
            let mut marker = self.empty()?;
            if ordered_start.is_some() {
                marker.push_str(&marker_index.to_string())?;
                marker.push_str(". ")?;
            } else if self.format == ReadContentFormat::Markdown {
                marker.push_str("- ")?;
            } else {
                marker.push_str("• ")?;
            }
            output.push_str(marker.as_str())?;
            let continuation = marker.as_str().chars().count();
            for (line_index, line) in item.as_str().split('\n').enumerate() {
                if line_index != 0 {
                    output.push_str("\n")?;
                    output.push_repeat(' ', continuation)?;
                }
                output.push_str(line)?;
            }
        }
        Ok(output)
    }

    fn render_html_list_item(
        &mut self,
        node: &Handle,
        depth: usize,
    ) -> Result<BoundedString, ContentRenderError> {
        let children = node.children.borrow();
        let mut output = self.empty()?;
        let mut previous_was_block = false;
        for child in children.iter() {
            self.add_work(1)?;
            let block = html_list_item_child_is_block(child);
            let mut rendered = self.render_node(child, depth + 1)?;
            if block {
                rendered.trim_spaces();
            }
            if rendered.is_empty() {
                continue;
            }
            if rendered.as_str().chars().all(char::is_whitespace)
                && (previous_was_block || output.is_empty())
            {
                continue;
            }
            if block || previous_was_block {
                output.push_joined(rendered.as_str(), "\n")?;
            } else {
                output.push_inline_fragment(rendered.as_str())?;
            }
            previous_was_block = block;
        }
        Ok(output)
    }

    fn render_storage_code_block(
        &mut self,
        node: &Handle,
        depth: usize,
        language: Option<&str>,
    ) -> Result<BoundedString, ContentRenderError> {
        let mut content = self.collect_plain_descendants(node, depth)?;
        // HTML serializers conventionally retain the line break immediately
        // before `</code></pre>`. The fence writer supplies that delimiter
        // newline itself, so remove exactly one here. Additional trailing line
        // breaks remain meaningful code content.
        if content.as_str().ends_with('\n') {
            content.value.pop();
        }
        self.render_storage_code_content(content, language)
    }

    fn render_storage_code_content(
        &self,
        content: BoundedString,
        language: Option<&str>,
    ) -> Result<BoundedString, ContentRenderError> {
        if self.format == ReadContentFormat::Text {
            return Ok(content);
        }
        let fence_width = longest_byte_run(content.as_str().as_bytes(), b'`')
            .saturating_add(1)
            .max(3);
        let language = language
            .filter(|value| {
                !value.is_empty()
                    && value.len() <= 32
                    && value.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'+' | b'-')
                    })
            })
            .unwrap_or_default();
        let mut output = self.empty()?;
        output.push_repeat('`', fence_width)?;
        output.push_str(language)?;
        output.push_str("\n")?;
        output.push_str(content.as_str())?;
        output.push_str("\n")?;
        output.push_repeat('`', fence_width)?;
        Ok(output)
    }

    fn collect_plain_descendants(
        &mut self,
        node: &Handle,
        depth: usize,
    ) -> Result<BoundedString, ContentRenderError> {
        let children = node.children.borrow();
        let mut output = self.empty()?;
        for child in children.iter() {
            self.add_work(1)?;
            self.visit_node(depth + 1)?;
            match &child.data {
                NodeData::Text { contents } => output.push_normalized(&contents.borrow())?,
                NodeData::Element { name, .. }
                    if is_active_storage_element(name.local.as_ref()) =>
                {
                    // Active content is never surfaced, including from pre/code/plain traversal.
                }
                NodeData::Element { name, .. } if name.local.as_ref() == "br" => {
                    output.push_str("\n")?
                }
                NodeData::Element { .. } | NodeData::Document => {
                    let nested = self.collect_plain_descendants(child, depth + 1)?;
                    output.push_str(nested.as_str())?;
                }
                NodeData::Comment { .. } => {}
                _ => {}
            }
        }
        Ok(output)
    }

    fn render_anchor(
        &mut self,
        node: &Handle,
        depth: usize,
        href: Option<&str>,
    ) -> Result<BoundedString, ContentRenderError> {
        let label = self.render_children_inline(node, depth)?;
        if self.format == ReadContentFormat::Text || label.is_empty() {
            return Ok(label);
        }
        let Some(url) = href.and_then(safe_link) else {
            return Ok(label);
        };
        let leading_space = label.as_str().starts_with(' ');
        let trailing_space = label.as_str().ends_with(' ');
        let inner = label.as_str().trim_matches(' ');
        if inner.is_empty() {
            return Ok(label);
        }
        let mut output = self.empty()?;
        if leading_space {
            output.push_str(" ")?;
        }
        output.push_str("[")?;
        output.push_str(inner)?;
        output.push_str("](")?;
        output.push_markdown_link_destination(url.as_str())?;
        output.push_str(")")?;
        if trailing_space {
            output.push_str(" ")?;
        }
        Ok(output)
    }

    fn render_image(&self, alt: Option<&str>) -> Result<BoundedString, ContentRenderError> {
        self.render_named_fallback("image", alt)
    }

    fn render_attachment(
        &self,
        attrs: &[html5ever::Attribute],
    ) -> Result<BoundedString, ContentRenderError> {
        self.render_named_fallback("attachment", attr_value(attrs, "ri:filename"))
    }

    fn render_user(
        &self,
        attrs: &[html5ever::Attribute],
    ) -> Result<BoundedString, ContentRenderError> {
        self.render_named_fallback("user", attr_value(attrs, "ri:display-name"))
    }

    fn render_content_reference(
        &self,
        attrs: &[html5ever::Attribute],
    ) -> Result<BoundedString, ContentRenderError> {
        self.render_named_fallback("link", attr_value(attrs, "ri:content-title"))
    }

    fn render_named_fallback(
        &self,
        kind: &str,
        label: Option<&str>,
    ) -> Result<BoundedString, ContentRenderError> {
        let mut output = self.empty()?;
        output.push_str("[")?;
        output.push_str(kind)?;
        if let Some(label) = label.filter(|value| !value.is_empty()) {
            output.push_str(": ")?;
            if self.format == ReadContentFormat::Markdown {
                output.push_markdown_escaped(label)?;
            } else {
                output.push_normalized(label)?;
            }
        }
        output.push_str("]")?;
        Ok(output)
    }

    fn render_confluence_link(
        &mut self,
        node: &Handle,
        depth: usize,
    ) -> Result<BoundedString, ContentRenderError> {
        let label_node = self.find_descendant_bounded(
            node,
            &["ac:link-body", "ac:plain-text-link-body"],
            depth,
        )?;
        if let Some(label_node) = label_node {
            if element_named(&label_node, "ac:plain-text-link-body") {
                let plain = self.collect_plain_descendants(&label_node, depth + 1)?;
                return self.format_plain_prose(plain);
            }
            return self.render_children_inline(&label_node, depth + 1);
        }
        if let Some(reference) = self.find_descendant_bounded(
            node,
            &["ri:page", "ri:blog-post", "ri:user", "ri:attachment"],
            depth,
        )? && let NodeData::Element { name, attrs, .. } = &reference.data
        {
            let attrs = attrs.borrow();
            return match name.local.as_ref() {
                "ri:user" => self.render_user(&attrs),
                "ri:attachment" => self.render_attachment(&attrs),
                _ => self.render_content_reference(&attrs),
            };
        }
        self.fragment("[link]")
    }

    fn render_confluence_task(
        &mut self,
        node: &Handle,
        depth: usize,
    ) -> Result<BoundedString, ContentRenderError> {
        let mut checked = false;
        let mut body = None;
        for child in node.children.borrow().iter() {
            self.add_work(1)?;
            self.visit_node(depth + 1)?;
            if element_named(child, "ac:task-status") {
                let status = self.collect_plain_descendants(child, depth + 1)?;
                checked = status.as_str().trim().eq_ignore_ascii_case("complete");
            } else if element_named(child, "ac:task-body") && body.is_none() {
                body = Some(child.clone());
            }
        }

        let Some(body) = body else {
            return self.empty();
        };
        let content = self.render_children_block(&body, depth + 1)?;
        if content.is_empty() {
            return Ok(content);
        }

        let mut output = self.empty()?;
        if self.format == ReadContentFormat::Markdown {
            output.push_str(if checked { "- [x] " } else { "- [ ] " })?;
        } else {
            output.push_str(if checked { "☑ " } else { "☐ " })?;
        }
        for (line_index, line) in content.as_str().split('\n').enumerate() {
            if line_index != 0 {
                output.push_str("\n  ")?;
            }
            output.push_str(line)?;
        }
        Ok(output)
    }

    fn render_adf_extension(
        &mut self,
        node: &Handle,
        depth: usize,
    ) -> Result<BoundedString, ContentRenderError> {
        if self
            .find_adf_primary_content_bounded(node, depth)?
            .is_some()
        {
            return self.render_adf_primary_branches(node, depth);
        }
        if let Some(fallback) = self.find_descendant_bounded(node, &["ac:adf-fallback"], depth)? {
            return self.render_children_block(&fallback, depth + 1);
        }
        self.empty()
    }

    fn render_adf_primary_branches(
        &mut self,
        node: &Handle,
        depth: usize,
    ) -> Result<BoundedString, ContentRenderError> {
        let mut output = self.empty()?;
        for child in node.children.borrow().iter() {
            self.add_work(1)?;
            if element_named(child, "ac:adf-fallback") {
                // The lexical preflight has already validated and charged this
                // alternate branch; do not surface it beside primary content.
                self.visit_node(depth + 1)?;
                continue;
            }
            let mut child = self.render_node(child, depth + 1)?;
            child.trim_spaces();
            output.push_joined(child.as_str(), "\n\n")?;
        }
        output.trim_spaces();
        Ok(output)
    }

    fn find_adf_primary_content_bounded(
        &mut self,
        node: &Handle,
        depth: usize,
    ) -> Result<Option<Handle>, ContentRenderError> {
        for child in node.children.borrow().iter() {
            self.add_work(1)?;
            self.visit_node(depth + 1)?;
            if element_named(child, "ac:adf-content") {
                return Ok(Some(child.clone()));
            }
            // A fallback cannot itself establish the extension's primary branch.
            if !element_named(child, "ac:adf-fallback")
                && let Some(found) = self.find_adf_primary_content_bounded(child, depth + 1)?
            {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }

    fn render_confluence_image(
        &mut self,
        node: &Handle,
        depth: usize,
    ) -> Result<BoundedString, ContentRenderError> {
        if let Some(attachment) = self.find_descendant_bounded(node, &["ri:attachment"], depth)?
            && let NodeData::Element { attrs, .. } = &attachment.data
        {
            return self.render_named_fallback("image", attr_value(&attrs.borrow(), "ri:filename"));
        }
        let attrs = match &node.data {
            NodeData::Element { attrs, .. } => attrs.borrow(),
            _ => return self.fragment("[image]"),
        };
        let _ = depth;
        self.render_image(attr_value(&attrs, "ac:alt"))
    }

    fn render_structured_macro(
        &mut self,
        node: &Handle,
        depth: usize,
        attrs: &[html5ever::Attribute],
    ) -> Result<BoundedString, ContentRenderError> {
        let macro_name = attr_value(attrs, "ac:name").unwrap_or_default();
        if matches!(macro_name, "code" | "noformat") {
            let language = self.find_parameter_bounded(node, "language", depth)?;
            return match self.find_descendant_bounded(node, &["ac:plain-text-body"], depth)? {
                Some(body) => self.render_storage_code_block(&body, depth + 1, language.as_deref()),
                None => {
                    let content = self.empty()?;
                    self.render_storage_code_content(content, language.as_deref())
                }
            };
        }
        if matches!(macro_name, "html" | "html-include" | "widget" | "iframe") {
            return self.fragment("[unsupported content]");
        }
        if let Some(body) =
            self.find_descendant_bounded(node, &["ac:rich-text-body", "ac:plain-text-body"], depth)?
        {
            let content = if element_named(&body, "ac:plain-text-body") {
                let plain = self.collect_plain_descendants(&body, depth + 1)?;
                self.format_plain_prose(plain)?
            } else {
                self.render_children_block(&body, depth + 1)?
            };
            if !content.is_empty() {
                return Ok(content);
            }
        }
        self.fragment("[unsupported content]")
    }

    fn format_plain_prose(
        &self,
        plain: BoundedString,
    ) -> Result<BoundedString, ContentRenderError> {
        if self.format == ReadContentFormat::Text {
            return Ok(plain);
        }
        let mut output = self.empty()?;
        output.push_markdown_escaped(plain.as_str())?;
        Ok(output)
    }

    fn render_html_table(
        &mut self,
        node: &Handle,
        depth: usize,
    ) -> Result<BoundedString, ContentRenderError> {
        let rows = self.collect_table_rows_bounded(node, depth)?;
        let width = rows
            .iter()
            .map(|row| table_cells(row).len())
            .max()
            .unwrap_or(0);
        if width == 0 {
            return self.empty();
        }
        let mut output = self.empty()?;
        for (row_index, row) in rows.iter().enumerate() {
            self.add_work(1)?;
            self.visit_node(depth + 1)?;
            let cells = table_cells(row);
            let mut rendered_row = self.empty()?;
            if self.format == ReadContentFormat::Markdown {
                rendered_row.push_str("|")?;
            }
            for index in 0..width {
                if self.format == ReadContentFormat::Markdown {
                    rendered_row.push_str(" ")?;
                } else if index != 0 {
                    rendered_row.push_str(" | ")?;
                }
                if let Some(cell) = cells.get(index) {
                    self.add_work(1)?;
                    let content = self.render_node(cell, depth + 2)?;
                    rendered_row.push_flattened(
                        content.as_str(),
                        self.format == ReadContentFormat::Markdown,
                    )?;
                }
                if self.format == ReadContentFormat::Markdown {
                    rendered_row.push_str(" |")?;
                }
            }
            output.push_joined(rendered_row.as_str(), "\n")?;
            if row_index == 0 && self.format == ReadContentFormat::Markdown {
                let mut separator = self.empty()?;
                separator.push_str("|")?;
                for _ in 0..width {
                    separator.push_str(" --- |")?;
                }
                output.push_joined(separator.as_str(), "\n")?;
            }
        }
        Ok(output)
    }

    fn find_descendant_bounded(
        &mut self,
        node: &Handle,
        names: &[&str],
        depth: usize,
    ) -> Result<Option<Handle>, ContentRenderError> {
        for child in node.children.borrow().iter() {
            self.add_work(1)?;
            self.visit_node(depth + 1)?;
            if names.iter().any(|name| element_named(child, name)) {
                return Ok(Some(child.clone()));
            }
            if let Some(found) = self.find_descendant_bounded(child, names, depth + 1)? {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }

    fn find_parameter_bounded(
        &mut self,
        node: &Handle,
        parameter_name: &str,
        depth: usize,
    ) -> Result<Option<String>, ContentRenderError> {
        for child in node.children.borrow().iter() {
            self.add_work(1)?;
            self.visit_node(depth + 1)?;
            if let NodeData::Element { name, attrs, .. } = &child.data
                && name.local.as_ref() == "ac:parameter"
                && attr_value(&attrs.borrow(), "ac:name") == Some(parameter_name)
            {
                let value = self.collect_plain_descendants(child, depth + 1)?;
                return Ok((value.as_str().len() <= 32).then(|| value.into_string()));
            }
            if let Some(found) = self.find_parameter_bounded(child, parameter_name, depth + 1)? {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }

    fn collect_table_rows_bounded(
        &mut self,
        node: &Handle,
        depth: usize,
    ) -> Result<Vec<Handle>, ContentRenderError> {
        let mut rows = Vec::new();
        for child in node.children.borrow().iter() {
            self.add_work(1)?;
            self.visit_node(depth + 1)?;
            if element_named(child, "tr") {
                rows.push(child.clone());
            } else if matches!(
                &child.data,
                NodeData::Element { name, .. }
                    if matches!(name.local.as_ref(), "thead" | "tbody" | "tfoot")
            ) {
                rows.extend(self.collect_table_rows_bounded(child, depth + 1)?);
            }
        }
        Ok(rows)
    }

    fn visit_node(&mut self, depth: usize) -> Result<(), ContentRenderError> {
        if depth > self.limits.max_depth {
            return Err(ContentRenderError::NestingLimitExceeded);
        }
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or(ContentRenderError::NodeLimitExceeded)?;
        if self.nodes > self.limits.max_nodes {
            return Err(ContentRenderError::NodeLimitExceeded);
        }
        self.budget.charge_node()?;
        self.add_work(1)
    }

    fn add_work(&mut self, units: usize) -> Result<(), ContentRenderError> {
        self.work_units = self
            .work_units
            .checked_add(units)
            .ok_or(ContentRenderError::WorkLimitExceeded)?;
        if self.work_units > self.limits.max_work_units {
            return Err(ContentRenderError::WorkLimitExceeded);
        }
        Ok(self.budget.charge_work(units)?)
    }

    fn fragment(&self, value: &str) -> Result<BoundedString, ContentRenderError> {
        let mut output = self.empty()?;
        output.push_normalized(value)?;
        Ok(output)
    }

    fn empty(&self) -> Result<BoundedString, ContentRenderError> {
        BoundedString::from_str("", self.max_output_bytes)
    }
}

fn element_named(node: &Handle, expected: &str) -> bool {
    matches!(&node.data, NodeData::Element { name, .. } if name.local.as_ref() == expected)
}

fn attr_value<'a>(attrs: &'a [html5ever::Attribute], expected: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|attr| attr.name.local.as_ref() == expected)
        .map(|attr| attr.value.as_ref())
}

fn table_cells(row: &Handle) -> Vec<Handle> {
    row.children
        .borrow()
        .iter()
        .filter(|child| element_named(child, "th") || element_named(child, "td"))
        .cloned()
        .collect()
}

fn html_list_item_child_is_block(node: &Handle) -> bool {
    match &node.data {
        NodeData::Text { .. } | NodeData::Comment { .. } => false,
        NodeData::Element { name, .. } => !matches!(
            name.local.as_ref(),
            "a" | "abbr"
                | "b"
                | "br"
                | "code"
                | "del"
                | "em"
                | "i"
                | "img"
                | "mark"
                | "s"
                | "small"
                | "span"
                | "strike"
                | "strong"
                | "sub"
                | "sup"
                | "u"
        ),
        _ => true,
    }
}

fn html_pre_code_language(node: &Handle) -> Option<String> {
    let children = node.children.borrow();
    let mut language = None;
    for child in children.iter() {
        let NodeData::Element { name, attrs, .. } = &child.data else {
            continue;
        };
        if name.local.as_ref() != "code" {
            continue;
        }
        if language.is_some() {
            return None;
        }
        let attrs = attrs.borrow();
        let class = attr_value(&attrs, "class")?;
        let mut classes = class.split_whitespace();
        let only = classes.next()?;
        if classes.next().is_some() {
            return None;
        }
        let value = only.strip_prefix("language-")?;
        if value.is_empty()
            || value.len() > 32
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'+' | b'-'))
        {
            return None;
        }
        language = Some(value.to_string());
    }
    language
}

struct BoundedString {
    value: String,
    max_bytes: u64,
}

impl BoundedString {
    fn from_str(value: &str, max_bytes: u64) -> Result<Self, ContentRenderError> {
        if value.len() as u64 > max_bytes {
            return Err(ContentRenderError::OutputTooLarge { max_bytes });
        }
        Ok(Self {
            value: value.to_string(),
            max_bytes,
        })
    }

    fn push_str(&mut self, value: &str) -> Result<(), ContentRenderError> {
        let next = (self.value.len() as u64)
            .checked_add(value.len() as u64)
            .ok_or(ContentRenderError::OutputTooLarge {
                max_bytes: self.max_bytes,
            })?;
        if next > self.max_bytes {
            return Err(ContentRenderError::OutputTooLarge {
                max_bytes: self.max_bytes,
            });
        }
        self.value.push_str(value);
        Ok(())
    }

    fn push_inline_fragment(&mut self, value: &str) -> Result<(), ContentRenderError> {
        if self.value.ends_with(' ') {
            self.push_str(value.trim_start_matches(' '))
        } else {
            self.push_str(value)
        }
    }

    fn push_repeat(&mut self, character: char, count: usize) -> Result<(), ContentRenderError> {
        let bytes =
            character
                .len_utf8()
                .checked_mul(count)
                .ok_or(ContentRenderError::OutputTooLarge {
                    max_bytes: self.max_bytes,
                })?;
        self.ensure_capacity(bytes)?;
        self.value.extend(std::iter::repeat_n(character, count));
        Ok(())
    }

    fn push_normalized(&mut self, value: &str) -> Result<(), ContentRenderError> {
        let mut chars = value.chars().peekable();
        while let Some(character) = chars.next() {
            if character == '\r' {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                self.push_str("\n")?;
            } else {
                let mut bytes = [0; 4];
                self.push_str(character.encode_utf8(&mut bytes))?;
            }
        }
        Ok(())
    }

    fn push_collapsed_html_text(&mut self, value: &str) -> Result<(), ContentRenderError> {
        let mut pending_space = false;
        for character in value.chars() {
            if character.is_whitespace() {
                pending_space = true;
                continue;
            }
            if pending_space {
                self.push_str(" ")?;
                pending_space = false;
            }
            let mut bytes = [0; 4];
            self.push_str(character.encode_utf8(&mut bytes))?;
        }
        if pending_space {
            self.push_str(" ")?;
        }
        Ok(())
    }

    fn push_markdown_escaped(&mut self, value: &str) -> Result<(), ContentRenderError> {
        let mut chars = value.chars().peekable();
        while let Some(character) = chars.next() {
            if character == '\r' {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                self.push_str("\n")?;
                continue;
            }
            if matches!(
                character,
                '\\' | '`'
                    | '*'
                    | '_'
                    | '{'
                    | '}'
                    | '['
                    | ']'
                    | '<'
                    | '>'
                    | '('
                    | ')'
                    | '#'
                    | '+'
                    | '-'
                    | '.'
                    | '!'
                    | '~'
            ) {
                self.push_str("\\")?;
            }
            let mut bytes = [0; 4];
            self.push_str(character.encode_utf8(&mut bytes))?;
        }
        Ok(())
    }

    fn push_markdown_link_destination(&mut self, value: &str) -> Result<(), ContentRenderError> {
        for character in value.chars() {
            match character {
                '(' => self.push_str("%28")?,
                ')' => self.push_str("%29")?,
                '\\' => self.push_str("%5C")?,
                _ => {
                    let mut bytes = [0; 4];
                    self.push_str(character.encode_utf8(&mut bytes))?;
                }
            }
        }
        Ok(())
    }

    fn push_inline_code(&mut self, value: &str) -> Result<(), ContentRenderError> {
        let fence_width = longest_byte_run(value.as_bytes(), b'`')
            .saturating_add(1)
            .max(1);
        let padding = value.is_empty()
            || value.chars().all(char::is_whitespace)
            || value.starts_with([' ', '`'])
            || value.ends_with([' ', '`']);
        self.push_repeat('`', fence_width)?;
        if padding {
            self.push_str(" ")?;
        }
        self.push_normalized(value)?;
        if padding {
            self.push_str(" ")?;
        }
        self.push_repeat('`', fence_width)
    }

    fn push_flattened(
        &mut self,
        value: &str,
        escape_pipes: bool,
    ) -> Result<(), ContentRenderError> {
        let mut pending_space = false;
        let mut wrote = false;
        for character in value.chars() {
            if character.is_whitespace() {
                pending_space = wrote;
                continue;
            }
            if pending_space {
                self.push_str(" ")?;
                pending_space = false;
            }
            if escape_pipes && character == '|' {
                self.push_str("\\")?;
            }
            let mut bytes = [0; 4];
            self.push_str(character.encode_utf8(&mut bytes))?;
            wrote = true;
        }
        Ok(())
    }

    fn ensure_capacity(&self, additional: usize) -> Result<(), ContentRenderError> {
        let next = (self.value.len() as u64)
            .checked_add(additional as u64)
            .ok_or(ContentRenderError::OutputTooLarge {
                max_bytes: self.max_bytes,
            })?;
        if next > self.max_bytes {
            Err(ContentRenderError::OutputTooLarge {
                max_bytes: self.max_bytes,
            })
        } else {
            Ok(())
        }
    }

    fn push_joined(&mut self, value: &str, separator: &str) -> Result<(), ContentRenderError> {
        if value.is_empty() {
            return Ok(());
        }
        if !self.value.is_empty() {
            self.push_str(separator)?;
        }
        self.push_str(value)
    }

    fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    fn trim_spaces(&mut self) {
        let start = self.value.len() - self.value.trim_start_matches(' ').len();
        let end = self.value.trim_end_matches(' ').len();
        if start != 0 {
            self.value.drain(..start);
        }
        self.value.truncate(end.saturating_sub(start));
    }

    fn as_str(&self) -> &str {
        &self.value
    }

    fn into_string(self) -> String {
        self.value
    }
}

fn optional_object<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a Map<String, Value>>, ContentRenderError> {
    object
        .get(key)
        .map(|value| {
            value
                .as_object()
                .ok_or(ContentRenderError::MalformedDocument)
        })
        .transpose()
}

fn optional_array<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a [Value]>, ContentRenderError> {
    object
        .get(key)
        .map(|value| {
            value
                .as_array()
                .map(Vec::as_slice)
                .ok_or(ContentRenderError::MalformedDocument)
        })
        .transpose()
}

fn validate_marks_shape(value: Option<&Value>) -> Result<(), ContentRenderError> {
    let Some(value) = value else {
        return Ok(());
    };
    let marks = value
        .as_array()
        .ok_or(ContentRenderError::MalformedDocument)?;
    for mark in marks {
        let mark = mark
            .as_object()
            .ok_or(ContentRenderError::MalformedDocument)?;
        if !mark.get("type").is_some_and(Value::is_string) {
            return Err(ContentRenderError::MalformedDocument);
        }
        optional_object(mark, "attrs")?;
    }
    Ok(())
}

fn attr_string<'a>(attrs: Option<&'a Map<String, Value>>, key: &str) -> Option<&'a str> {
    attrs?.get(key)?.as_str()
}

fn safe_link(value: &str) -> Option<Url> {
    if value.chars().any(char::is_control) {
        return None;
    }
    let url = Url::parse(value).ok()?;
    match url.scheme() {
        "http" | "https"
            if url.has_host() && url.username().is_empty() && url.password().is_none() =>
        {
            Some(url)
        }
        "mailto" => Some(url),
        _ => None,
    }
}

fn longest_byte_run(bytes: &[u8], needle: u8) -> usize {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn doc(content: Vec<Value>) -> Value {
        json!({ "version": 1, "type": "doc", "content": content })
    }

    fn paragraph(text: &str) -> Value {
        json!({ "type": "paragraph", "content": [{ "type": "text", "text": text }] })
    }

    fn render(document: &Value, format: ReadContentFormat) -> String {
        render_adf_bounded(document, format, 1024 * 1024)
            .unwrap()
            .unwrap()
            .value
    }

    fn render_gitlab(source: &str, format: ReadContentFormat) -> String {
        render_gitlab_markdown_bounded(source, format, 1024 * 1024)
            .unwrap()
            .unwrap()
            .value
    }

    fn render_gitlab_fragment(source: &str) -> String {
        render_gitlab_markdown_fragment_bounded_with_budget(
            source,
            source.len() as u64,
            1024 * 1024,
            &mut RenderBudget::default(),
            0,
        )
        .unwrap()
    }

    #[test]
    fn gitlab_native_validates_and_markdown_is_byte_exact() {
        let source = "# heading\r\n\r\né🙂 <unclosed";
        assert_eq!(
            render_gitlab_markdown_bounded(source, ReadContentFormat::Native, 0).unwrap(),
            None
        );
        assert_eq!(
            render_gitlab_markdown_bounded(
                source,
                ReadContentFormat::Markdown,
                source.len() as u64,
            )
            .unwrap()
            .unwrap()
            .value,
            source
        );
        assert_eq!(
            render_gitlab_markdown_bounded(
                source,
                ReadContentFormat::Markdown,
                source.len() as u64 - 1,
            ),
            Err(ContentRenderError::OutputTooLarge {
                max_bytes: source.len() as u64 - 1
            })
        );

        let mut budget = RenderBudget::default();
        assert_eq!(
            render_gitlab_markdown_bounded_with_budget(
                source,
                ReadContentFormat::Native,
                source.len() as u64 - 1,
                0,
                &mut budget,
            ),
            Err(ContentRenderError::SourceTooLarge {
                max_bytes: source.len() as u64 - 1
            })
        );

        // Plain-text presentation renumbers this ordered list and grows after
        // item nine. Native validation must not materialize that derived form,
        // and Markdown must remain the exact provider string.
        let expanding_projection = "1. x\n".repeat(12);
        assert_eq!(
            render_gitlab_markdown_bounded(&expanding_projection, ReadContentFormat::Native, 0,)
                .unwrap(),
            None
        );
        assert_eq!(
            render_gitlab_markdown_bounded(
                &expanding_projection,
                ReadContentFormat::Markdown,
                expanding_projection.len() as u64,
            )
            .unwrap()
            .unwrap()
            .value,
            expanding_projection
        );
    }

    #[test]
    fn gitlab_text_retains_readable_structure_without_formatting_or_destinations() {
        let source = concat!(
            "# Heading *em* **strong** ~~old~~\n\n",
            "A [safe label](https://example.test/secret) and ",
            "![diagram alt](https://example.test/image-secret). `inline()`\n\n",
            "```rust\nfn main() {\n    println!(\"hi\");\n}\n```\n\n",
            "- [x] done\n- [ ] todo\n  1. nested one\n  2. nested two\n\n",
            "| Name | State |\n| --- | --- |\n| Ada | Ready |\n"
        );
        let rendered = render_gitlab(source, ReadContentFormat::Text);
        assert_eq!(
            rendered,
            concat!(
                "Heading em strong old\n\n",
                "A safe label and diagram alt. inline()\n\n",
                "fn main() {\n    println!(\"hi\");\n}\n\n",
                "- [x] done\n- [ ] todo\n  1. nested one\n  2. nested two\n\n",
                "Name | State\nAda | Ready"
            )
        );
        assert!(!rendered.contains("example.test"));
        assert_eq!(rendered, render_gitlab(source, ReadContentFormat::Text));
    }

    #[test]
    fn gitlab_text_suppresses_active_html_and_keeps_safe_html_text() {
        let source = concat!(
            "before <span>safe &amp; sound</span> ",
            "<script>inline-secret</script> after\n\n",
            "<div>block <b>text</b> &amp; entity</div>\n",
            "<iframe>frame-secret</iframe>\n",
            "<STYLE>style-secret</style>\n"
        );
        let rendered = render_gitlab(source, ReadContentFormat::Text);
        assert_eq!(rendered, "before safe & sound after\n\nblock text & entity");
        for secret in ["inline-secret", "frame-secret", "style-secret"] {
            assert!(!rendered.contains(secret));
        }
    }

    #[test]
    fn gitlab_fragment_neutralizes_unclosed_and_hostile_constructs() {
        let source = concat!(
            "# injected heading\n\n",
            "```rust\nfence content\n```\n",
            "<script>active-secret</script>\n",
            "[label](javascript:alert(1)) **bold"
        );
        let fragment = render_gitlab_fragment(source);
        assert_eq!(
            fragment,
            concat!(
                "# injected heading\n\n",
                "```rust\nfence content\n```\n\n",
                "label \\*\\*bold"
            )
        );
        assert!(!fragment.contains("active-secret"));
        assert!(!fragment.contains("javascript:"));
        assert_eq!(fragment.matches("```").count(), 2);

        let combined = format!("## Body\n\n{fragment}\n\n- Trusted: value\n");
        assert!(combined.ends_with("\n\n- Trusted: value\n"));
        assert_eq!(fragment, render_gitlab_fragment(source));

        let unclosed = render_gitlab_fragment("```rust\nunclosed fence");
        assert_eq!(unclosed, "```rust\nunclosed fence\n```");
        assert_eq!(unclosed.matches("```").count(), 2);
        assert!(format!("{unclosed}\n\n- Trusted: value\n").ends_with("- Trusted: value\n"));
    }

    #[test]
    fn gitlab_fragment_escapes_unicode_lists_tables_code_and_link_labels() {
        let source = concat!(
            "- [x] é🙂\n- item *em*\n\n",
            "| A | B |\n| --- | --- |\n| x | y |\n\n",
            "`a*b` [label](https://example.test/secret)"
        );

        assert_eq!(
            render_gitlab_fragment("42. first\n43. second"),
            "42. first\n43. second"
        );
        assert_eq!(render_gitlab_fragment("42.\n43. visible"), "43. visible");
        assert_eq!(
            render_gitlab_fragment(source),
            concat!(
                "- ☑ é🙂\n- item _em_\n\n",
                "| A | B |\n| --- | --- |\n| x | y |\n\n",
                "`a*b` [label](https://example.test/secret)"
            )
        );
    }

    #[test]
    fn gitlab_text_tracks_structure_while_active_html_crosses_boundaries() {
        let source = concat!(
            "- before\n\n",
            "  <script>\n",
            "  hidden\n\n",
            "  - hidden item\n",
            "  </script>\n\n",
            "- after\n\n",
            "| A | B |\n| --- | --- |\n| kept | visible |\n"
        );
        let rendered = render_gitlab(source, ReadContentFormat::Text);
        assert!(rendered.contains("- before"));
        assert!(rendered.contains("- after"));
        assert!(rendered.contains("kept | visible"));
        assert!(!rendered.contains("hidden"));
    }

    #[test]
    fn gitlab_fragment_inert_html_keeps_safe_descendants_and_suppresses_active_content() {
        let source = concat!(
            "<details><summary>Summary</summary>",
            "<p>Readable <b>body</b></p>",
            "<img alt=\"diagram\" src=\"https://example.test/secret\">",
            "<script>active-secret</script></details>"
        );
        let rendered = render_gitlab_fragment(source);
        assert!(rendered.contains("Summary"));
        assert!(rendered.contains("Readable **body**"));
        assert!(rendered.contains("[image: diagram]"));
        assert!(!rendered.contains("active-secret"));
        assert!(!rendered.contains("example.test"));
    }

    #[test]
    fn gitlab_fragment_tolerates_commonmark_raw_html_recovery_cases() {
        for source in [
            "<script>active-secret",
            "<style>active-secret",
            "<textarea>active-secret",
            "<title>active-secret",
            "<xmp>active-secret",
            "<iframe>active-secret",
            "<!-- unclosed comment",
            "<![CDATA[unclosed cdata",
            "<span title=\"unclosed quote>",
            "before</span extra>after",
            "trailing <",
            "<future-node>unbalanced custom element",
        ] {
            let rendered = render_gitlab_markdown_fragment_bounded_with_budget(
                source,
                source.len() as u64,
                1024,
                &mut RenderBudget::default(),
                0,
            );
            assert!(
                rendered.is_ok(),
                "valid CommonMark raw HTML failed: {source:?}"
            );
            assert!(
                !rendered.unwrap().contains("active-secret"),
                "active raw HTML leaked: {source:?}"
            );
        }
    }

    #[test]
    fn gitlab_intermediate_html_cap_includes_entity_and_structural_expansion() {
        let limits = RenderLimits {
            max_depth: 1,
            max_nodes: 2,
            max_work_units: 3,
        };
        let structural = 2 * GITLAB_INTERMEDIATE_HTML_BYTES_PER_NODE
            + 3 * GITLAB_INTERMEDIATE_HTML_BYTES_PER_WORK_UNIT;
        assert_eq!(
            gitlab_intermediate_html_byte_limit(7, 7, limits),
            7 * GITLAB_INTERMEDIATE_HTML_SOURCE_EXPANSION + structural
        );
        assert_eq!(
            gitlab_intermediate_html_byte_limit(8, 7, limits),
            7 * GITLAB_INTERMEDIATE_HTML_SOURCE_EXPANSION + structural
        );
        assert_eq!(
            gitlab_intermediate_html_byte_limit(u64::MAX, u64::MAX, limits),
            u64::MAX
        );

        // This exceeds the former fixed 8 MiB intermediate cap after
        // `pulldown_cmark` expands each quote to `&quot;`, but remains within
        // the caller's configured source and output bounds.
        let source = "\"".repeat(1_500_000);
        let rendered = render_gitlab_markdown_fragment_bounded_with_budget(
            &source,
            source.len() as u64,
            source.len() as u64,
            &mut RenderBudget::default(),
            0,
        )
        .unwrap();
        assert_eq!(rendered, source);
    }

    #[test]
    fn gitlab_fragment_empty_events_render_empty() {
        for source in [
            "   \n\t",
            "[unused]: https://example.test\n",
            "<!-- comment -->",
        ] {
            assert_eq!(render_gitlab_fragment(source), "", "{source:?}");
        }
    }

    #[test]
    fn gitlab_raw_text_repeated_open_tags_do_not_consume_nesting_depth() {
        let source = format!("<script>{}</script>", "<script>".repeat(256));
        assert_eq!(
            render_gitlab_markdown_bounded(&source, ReadContentFormat::Native, 0).unwrap(),
            None
        );
        assert_eq!(
            render_gitlab_markdown_bounded(
                &source,
                ReadContentFormat::Markdown,
                source.len() as u64,
            )
            .unwrap()
            .unwrap()
            .value,
            source
        );
        assert_eq!(render_gitlab(&source, ReadContentFormat::Text), "");
    }

    #[test]
    fn gitlab_incomplete_raw_text_close_stays_active_without_rejecting_identity_modes() {
        let source = "<script>hidden</script foo";
        assert_eq!(
            render_gitlab_markdown_bounded(source, ReadContentFormat::Native, 0).unwrap(),
            None
        );
        assert_eq!(
            render_gitlab_markdown_bounded(
                source,
                ReadContentFormat::Markdown,
                source.len() as u64,
            )
            .unwrap()
            .unwrap()
            .value,
            source
        );
        assert_eq!(render_gitlab(source, ReadContentFormat::Text), "");
    }

    #[test]
    fn gitlab_fragment_fixed_intermediate_bound_allows_deep_valid_blockquotes() {
        let source = format!("{}deep", ">".repeat(120));
        let rendered = render_gitlab_fragment(&source);
        assert!(rendered.contains("deep"));
        let events = Parser::new_ext(&source, Options::empty());
        let old_source_relative_cap = source.len().saturating_mul(16).saturating_add(1024);
        let mut intermediate = BoundedIoString::new(u64::MAX);
        write_html_io(&mut intermediate, events).unwrap();
        assert!(intermediate.into_string().len() > old_source_relative_cap);
    }

    #[test]
    fn gitlab_fragment_demotes_body_headings_beneath_container_heading() {
        let source = "# One\n\n##### Five\n\n###### Six";
        let rendered = render_gitlab_markdown_fragment_bounded_with_budget(
            source,
            source.len() as u64,
            1024,
            &mut RenderBudget::default(),
            2,
        )
        .unwrap();
        assert_eq!(rendered, "### One\n\n###### Five\n\n###### Six");
    }

    #[test]
    fn gitlab_tasks_and_footnotes_have_deterministic_readable_fallbacks() {
        let source = "- [x] done\n- [ ] todo\n\nClaim[^note].\n\n[^note]: Footnote body.";
        let markdown = render_gitlab_fragment(source);
        assert!(markdown.contains("- ☑ done\n- ☐ todo"));
        assert!(markdown.contains("Footnote body"));

        let text = render_gitlab(source, ReadContentFormat::Text);
        assert!(text.contains("- [x] done\n- [ ] todo"));
        assert!(text.contains("Claim[^note]."));
        assert!(text.contains("[^note]:"));
        assert!(text.contains("Footnote body."));
        assert_eq!(text, render_gitlab(source, ReadContentFormat::Text));
    }

    #[test]
    fn gitlab_enforces_source_output_event_work_depth_and_request_bounds() {
        let source = "é🙂";
        assert_eq!(
            render_gitlab_markdown_bounded(source, ReadContentFormat::Text, 6)
                .unwrap()
                .unwrap()
                .value,
            source
        );
        assert_eq!(
            render_gitlab_markdown_bounded(source, ReadContentFormat::Text, 5),
            Err(ContentRenderError::OutputTooLarge { max_bytes: 5 })
        );

        let limits = RenderLimits {
            max_depth: 128,
            max_nodes: 2,
            max_work_units: 1024,
        };
        assert!(matches!(
            render_gitlab_text_with_limits(
                "one *two* three",
                1024,
                limits,
                &mut RenderBudget::default(),
            ),
            Err(ContentRenderError::NodeLimitExceeded)
        ));
        let limits = RenderLimits {
            max_depth: 128,
            max_nodes: 1024,
            max_work_units: 2,
        };
        assert!(matches!(
            render_gitlab_text_with_limits(
                "[label](https://example.test/long-destination)",
                1024,
                limits,
                &mut RenderBudget::default(),
            ),
            Err(ContentRenderError::WorkLimitExceeded)
        ));

        let nested = format!("{}deep{}", "> ".repeat(129), "\n".repeat(129));
        assert_eq!(
            render_gitlab_markdown_bounded(&nested, ReadContentFormat::Text, 1024),
            Err(ContentRenderError::NestingLimitExceeded)
        );

        let mut exhausted = RenderBudget::with_limits(0, 1);
        assert_eq!(
            render_gitlab_markdown_bounded_with_budget(
                "body",
                ReadContentFormat::Native,
                4,
                0,
                &mut exhausted,
            ),
            Err(ContentRenderError::NodeLimitExceeded)
        );

        let mut budget = RenderBudget::default();
        assert_eq!(
            render_gitlab_markdown_fragment_bounded_with_budget("**bold**", 8, 7, &mut budget, 0,),
            Err(ContentRenderError::OutputTooLarge { max_bytes: 7 })
        );

        let mut exhausted = RenderBudget::with_limits(0, 1);
        assert_eq!(
            render_gitlab_markdown_fragment_bounded_with_budget("body", 4, 1024, &mut exhausted, 0,),
            Err(ContentRenderError::NodeLimitExceeded)
        );
    }

    #[test]
    fn native_returns_none_after_validating_the_document() {
        assert_eq!(
            render_adf_bounded(&doc(vec![]), ReadContentFormat::Native, 1024).unwrap(),
            None
        );
        assert_eq!(
            render_adf_bounded(&json!({ "opaque": true }), ReadContentFormat::Native, 1024),
            Err(ContentRenderError::MalformedDocument)
        );
        assert_eq!(ReadContentFormat::default().as_str(), "native");
    }

    #[test]
    fn renders_blocks_headings_breaks_rules_and_escapes_markdown() {
        let document = doc(vec![
            json!({
                "type": "heading",
                "attrs": { "level": 2 },
                "content": [{ "type": "text", "text": "A *heading*" }]
            }),
            json!({
                "type": "paragraph",
                "content": [
                    { "type": "text", "text": "first" },
                    { "type": "hardBreak" },
                    { "type": "text", "text": "second" }
                ]
            }),
            json!({ "type": "rule" }),
        ]);
        assert_eq!(
            render(&document, ReadContentFormat::Markdown),
            "## A \\*heading\\*\n\nfirst\nsecond\n\n---"
        );
        assert_eq!(
            render(&document, ReadContentFormat::Text),
            "A *heading*\n\nfirst\nsecond\n\n—"
        );
    }

    #[test]
    fn renders_marks_in_canonical_order_independent_of_input_order() {
        let marks = vec![
            json!({ "type": "strike" }),
            json!({ "type": "link", "attrs": { "href": "https://example.test/a" } }),
            json!({ "type": "em" }),
            json!({ "type": "strong" }),
        ];
        let reversed = marks.iter().rev().cloned().collect::<Vec<_>>();
        let with_marks = |marks| {
            doc(vec![json!({
                "type": "paragraph",
                "content": [{ "type": "text", "text": "value", "marks": marks }]
            })])
        };
        let expected = "[~~_**value**_~~](https://example.test/a)";
        assert_eq!(
            render(&with_marks(marks), ReadContentFormat::Markdown),
            expected
        );
        assert_eq!(
            render(&with_marks(reversed), ReadContentFormat::Markdown),
            expected
        );
        assert_eq!(
            render(&with_marks(vec![]), ReadContentFormat::Text),
            "value"
        );
    }

    #[test]
    fn renders_inline_code_with_a_safe_dynamic_fence() {
        let document = doc(vec![json!({
            "type": "paragraph",
            "content": [{
                "type": "text",
                "text": " a`b ",
                "marks": [{ "type": "code" }, { "type": "strong" }]
            }]
        })]);
        assert_eq!(
            render(&document, ReadContentFormat::Markdown),
            "**``  a`b  ``**"
        );
        assert_eq!(render(&document, ReadContentFormat::Text), " a`b ");
    }

    #[test]
    fn renders_nested_lists_blockquotes_and_code_blocks() {
        let document = doc(vec![
            json!({
                "type": "bulletList",
                "content": [{
                    "type": "listItem",
                    "content": [
                        paragraph("outer"),
                        { "type": "orderedList", "attrs": { "order": 3 }, "content": [
                            { "type": "listItem", "content": [paragraph("inner")] }
                        ]}
                    ]
                }]
            }),
            json!({ "type": "blockquote", "content": [paragraph("quoted"), paragraph("again")] }),
            json!({
                "type": "codeBlock",
                "attrs": { "language": "rust" },
                "content": [{ "type": "text", "text": "let ticks = ```;" }]
            }),
        ]);
        assert_eq!(
            render(&document, ReadContentFormat::Markdown),
            "- outer\n  3. inner\n\n> quoted\n>\n> again\n\n````rust\nlet ticks = ```;\n````"
        );
        assert_eq!(
            render(&document, ReadContentFormat::Text),
            "• outer\n  3. inner\n\nquoted\n\nagain\n\nlet ticks = ```;"
        );
    }

    #[test]
    fn accepts_only_safe_absolute_links() {
        let linked = |href: &str| {
            doc(vec![json!({
                "type": "paragraph",
                "content": [{
                    "type": "text",
                    "text": "click",
                    "marks": [{ "type": "link", "attrs": { "href": href } }]
                }]
            })])
        };
        assert_eq!(
            render(
                &linked("https://example.test/a b"),
                ReadContentFormat::Markdown
            ),
            "[click](https://example.test/a%20b)"
        );
        assert_eq!(
            render(
                &linked("mailto:user@example.test"),
                ReadContentFormat::Markdown
            ),
            "[click](mailto:user@example.test)"
        );
        assert_eq!(
            render(
                &linked("https://example.test/a) [injected](https://evil.test/x"),
                ReadContentFormat::Markdown
            ),
            "[click](https://example.test/a%29%20[injected]%28https://evil.test/x)"
        );
        for unsafe_href in [
            "javascript:alert(1)",
            "data:text/html,bad",
            "/relative",
            "https://user:secret@example.test/",
            "https://example.test/a\nb",
        ] {
            assert_eq!(
                render(&linked(unsafe_href), ReadContentFormat::Markdown),
                "click"
            );
        }
    }

    #[test]
    fn renders_known_leaf_fallbacks_without_leaking_opaque_ids() {
        let document = doc(vec![json!({
            "type": "paragraph",
            "content": [
                { "type": "mention", "attrs": { "displayName": "Ada", "id": "secret-user" } },
                { "type": "text", "text": " " },
                { "type": "emoji", "attrs": { "shortName": ":wave:" } },
                { "type": "text", "text": " " },
                { "type": "status", "attrs": { "text": "DONE" } },
                { "type": "text", "text": " " },
                { "type": "date", "attrs": { "timestamp": "1700000000000" } },
                { "type": "text", "text": " " },
                { "type": "inlineCard", "attrs": { "url": "https://example.test/card" } },
                { "type": "media", "attrs": { "id": "secret-media", "alt": "diagram" } },
                { "type": "mediaInline", "attrs": { "id": "secret-inline" } }
            ]
        })]);
        assert_eq!(
            render(&document, ReadContentFormat::Markdown),
            "@Ada :wave: DONE 1700000000000 [card](https://example.test/card)[attachment: diagram][attachment]"
        );
        assert_eq!(
            render(&document, ReadContentFormat::Text),
            "@Ada :wave: DONE 1700000000000 https://example.test/card[attachment: diagram][attachment]"
        );
        let rendered = render(&document, ReadContentFormat::Markdown);
        for secret in ["secret-user", "secret-media", "secret-inline"] {
            assert!(!rendered.contains(secret));
        }

        let block_fallbacks = doc(vec![
            json!({ "type": "blockCard", "attrs": { "url": "https://example.test/block" } }),
            json!({ "type": "mediaSingle", "attrs": { "layout": "center" }, "content": [
                { "type": "media", "attrs": { "id": "secret-single", "alt": "chart" } }
            ]}),
        ]);
        assert_eq!(
            render(&block_fallbacks, ReadContentFormat::Markdown),
            "[card](https://example.test/block)\n\n[attachment: chart]"
        );
        assert!(!render(&block_fallbacks, ReadContentFormat::Text).contains("secret-single"));

        let adversarial_card = doc(vec![json!({
            "type": "blockCard",
            "attrs": { "url": "https://example.test/a) [injected](https://evil.test/x" }
        })]);
        assert_eq!(
            render(&adversarial_card, ReadContentFormat::Markdown),
            "[card](https://example.test/a%29%20[injected]%28https://evil.test/x)"
        );
    }

    #[test]
    fn renders_tasks_expands_and_unknown_container_descendants() {
        let document = doc(vec![
            json!({
                "type": "taskItem",
                "attrs": { "state": "DONE" },
                "content": [{ "type": "text", "text": "ship" }]
            }),
            json!({
                "type": "expand",
                "attrs": { "title": "Details" },
                "content": [paragraph("inside")]
            }),
            json!({ "type": "futureContainer", "content": [paragraph("preserved")] }),
            json!({ "type": "futureLeaf", "attrs": { "text": "not trusted" } }),
        ]);
        assert_eq!(
            render(&document, ReadContentFormat::Markdown),
            "[x] ship\n\nDetails\n\ninside\n\npreserved\n\n[unsupported content]"
        );
        assert_eq!(
            render(&document, ReadContentFormat::Text),
            "☑ ship\n\nDetails\n\ninside\n\npreserved\n\n[unsupported content]"
        );
    }

    #[test]
    fn renders_decision_states_distinctly_from_task_checkboxes() {
        let document = doc(vec![json!({
            "type": "decisionList",
            "content": [
                {
                    "type": "decisionItem",
                    "attrs": { "state": "DECIDED", "localId": "opaque-decided-id" },
                    "content": [{ "type": "text", "text": "Use the broker renderer" }]
                },
                {
                    "type": "decisionItem",
                    "attrs": { "state": "UNDECIDED", "localId": "opaque-pending-id" },
                    "content": [{ "type": "text", "text": "Choose the rollout date" }]
                }
            ]
        })]);

        let markdown = render(&document, ReadContentFormat::Markdown);
        assert_eq!(
            markdown,
            "**Decision (decided):** Use the broker renderer\n\n**Decision (undecided):** Choose the rollout date"
        );
        assert!(!markdown.contains("[x]"));
        assert!(!markdown.contains("[ ]"));
        assert!(!markdown.contains("opaque-"));

        assert_eq!(
            render(&document, ReadContentFormat::Text),
            "Decision (decided): Use the broker renderer\n\nDecision (undecided): Choose the rollout date"
        );
    }

    #[test]
    fn renders_tables_with_normalized_width_flattened_cells_and_escaped_pipes() {
        let document = doc(vec![json!({
            "type": "table",
            "content": [
                { "type": "tableRow", "content": [
                    { "type": "tableHeader", "content": [paragraph("Name")] },
                    { "type": "tableHeader", "content": [paragraph("Value | detail")] }
                ]},
                { "type": "tableRow", "content": [
                    { "type": "tableCell", "content": [paragraph("Ada\r\nLovelace")] }
                ]}
            ]
        })]);
        assert_eq!(
            render(&document, ReadContentFormat::Markdown),
            "| Name | Value \\| detail |\n| --- | --- |\n| Ada Lovelace |  |"
        );
        assert_eq!(
            render(&document, ReadContentFormat::Text),
            "Name | Value | detail\nAda Lovelace | "
        );
    }

    #[test]
    fn normalizes_newlines_and_handles_inline_code_edges() {
        let document = doc(vec![json!({
            "type": "paragraph",
            "content": [
                { "type": "text", "text": "a\r\nb\rc" },
                { "type": "text", "text": "", "marks": [{ "type": "code" }] },
                { "type": "text", "text": "   ", "marks": [{ "type": "code" }] },
                { "type": "text", "text": "`edge`", "marks": [{ "type": "code" }] }
            ]
        })]);
        assert_eq!(
            render(&document, ReadContentFormat::Markdown),
            "a\nb\nc`  ``     ``` `edge` ``"
        );
        assert_eq!(
            render(&document, ReadContentFormat::Text),
            "a\nb\nc   `edge`"
        );
    }

    #[test]
    fn bounds_code_language_and_all_markdown_expansion() {
        let document = doc(vec![json!({
            "type": "codeBlock",
            "attrs": { "language": "abcdefghijklmnopqrstuvwxyz1234567" },
            "content": [{ "type": "text", "text": "x" }]
        })]);
        assert_eq!(
            render(&document, ReadContentFormat::Markdown),
            "```\nx\n```"
        );

        let escaped = doc(vec![paragraph("***")]);
        assert_eq!(
            render_adf_bounded(&escaped, ReadContentFormat::Markdown, 5),
            Err(ContentRenderError::OutputTooLarge { max_bytes: 5 })
        );
        assert_eq!(render(&escaped, ReadContentFormat::Markdown), "\\*\\*\\*");
    }

    fn render_storage(source: &str, format: ReadContentFormat) -> String {
        render_confluence_storage_bounded(source, format, 1024 * 1024)
            .unwrap()
            .unwrap()
            .value
    }

    #[test]
    fn storage_native_returns_none_after_full_validation() {
        assert_eq!(
            render_confluence_storage_bounded("<p>valid</p>", ReadContentFormat::Native, 1024)
                .unwrap(),
            None
        );
        assert_eq!(
            render_confluence_storage_bounded("<ac:link>", ReadContentFormat::Native, 1024),
            Err(ContentRenderError::MalformedDocument)
        );
    }

    #[test]
    fn renders_storage_blocks_marks_entities_links_and_images() {
        let source = concat!(
            "<h2>Plan &amp; scope</h2>",
            "<p>Hello <strong>bold</strong>, <em>careful</em>, ",
            "<s>old</s>, <code>a`b</code> &amp; *literal*.</p>",
            "<blockquote><p>quoted<br>again</p></blockquote>",
            "<p><a href=\"https://example.test/a b\">safe</a> ",
            "<a href=\"javascript:alert(1)\">unsafe label</a> ",
            "<img src=\"https://ignored.test/id\" alt=\"diagram [v2]\"></p>"
        );
        assert_eq!(
            render_storage(source, ReadContentFormat::Markdown),
            "## Plan & scope\n\nHello **bold**, _careful_, ~~old~~, ``a`b`` & \\*literal\\*\\.\n\n> quoted\n> again\n\n[safe](https://example.test/a%20b) unsafe label [image: diagram \\[v2\\]]"
        );
        assert_eq!(
            render_storage(source, ReadContentFormat::Text),
            "Plan & scope\n\nHello bold, careful, old, a`b & *literal*.\n\nquoted\nagain\n\nsafe unsafe label [image: diagram [v2]]"
        );
    }

    #[test]
    fn storage_preserves_significant_inline_boundary_spaces() {
        let source =
            "<p>a<strong> b </strong>c <em> d</em> e<a href=\"https://example.test\"> f </a>g</p>";
        assert_eq!(
            render_storage(source, ReadContentFormat::Markdown),
            "a **b** c _d_ e [f](https://example.test/) g"
        );
        assert_eq!(
            render_storage(source, ReadContentFormat::Text),
            "a b c d e f g"
        );
    }

    #[test]
    fn storage_preflight_keeps_comments_cdata_and_raw_text_atomic() {
        let source = concat!(
            "<!-- <ri:user ri:account-id=\"comment-secret\" /> -->",
            "<script>const literal = '<ri:user ri:account-id=\"script-secret\" />';</script>",
            "<p>visible</p>",
            "<ac:structured-macro ac:name=\"code\"><ac:plain-text-body>",
            "<![CDATA[<ri:user ri:account-id=\"literal-id\" /> *literal*]]>",
            "</ac:plain-text-body></ac:structured-macro>"
        );
        let rendered = render_storage(source, ReadContentFormat::Markdown);
        assert_eq!(
            rendered,
            "visible\n\n```\n<ri:user ri:account-id=\"literal-id\" /> *literal*\n```"
        );
        assert!(!rendered.contains("comment-secret"));
        assert!(!rendered.contains("script-secret"));
    }

    #[test]
    fn storage_plain_prose_is_escaped_but_code_cdata_stays_literal() {
        let source = concat!(
            "<p><ac:link><ac:plain-text-link-body><![CDATA[*label* [x](https://evil.test)]]>",
            "</ac:plain-text-link-body></ac:link></p>",
            "<ac:structured-macro ac:name=\"excerpt\"><ac:plain-text-body>",
            "<![CDATA[# prose *literal*]]></ac:plain-text-body></ac:structured-macro>",
            "<ac:structured-macro ac:name=\"noformat\"><ac:plain-text-body>",
            "<![CDATA[*code* <ri:user/>]]></ac:plain-text-body></ac:structured-macro>"
        );
        assert_eq!(
            render_storage(source, ReadContentFormat::Markdown),
            "\\*label\\* \\[x\\]\\(https://evil\\.test\\)\n\n\\# prose \\*literal\\*\n\n```\n*code* <ri:user/>\n```"
        );
        assert_eq!(
            render_storage(source, ReadContentFormat::Text),
            "*label* [x](https://evil.test)\n\n# prose *literal*\n\n*code* <ri:user/>"
        );
    }

    #[test]
    fn storage_plain_collection_suppresses_active_descendants() {
        let source = concat!(
            "<pre>before<script>script-secret</script><style>style-secret</style>",
            "<iframe>frame-secret</iframe><object>object-secret</object>",
            "<embed src=\"embed-secret\">after</pre>",
            "<ac:structured-macro ac:name=\"excerpt\"><ac:plain-text-body>",
            "safe<script>macro-secret</script>end</ac:plain-text-body></ac:structured-macro>"
        );
        let rendered = render_storage(source, ReadContentFormat::Text);
        assert_eq!(rendered, "beforeafter\n\nsafeend");
        for secret in [
            "script-secret",
            "style-secret",
            "frame-secret",
            "object-secret",
            "embed-secret",
            "macro-secret",
        ] {
            assert!(!rendered.contains(secret));
        }
    }

    #[test]
    fn storage_rejects_malformed_lexical_and_custom_structure() {
        for source in [
            "<p title=\"unterminated>",
            "<ac:link>",
            "<ac:link><ri:page></ac:link></ri:page>",
            "</future-node>",
            "<future-node><p>x</p></other-node>",
            "<!-- unterminated",
            "<![CDATA[unterminated",
            "<script>unterminated",
        ] {
            assert_eq!(
                render_confluence_storage_bounded(source, ReadContentFormat::Markdown, 1024),
                Err(ContentRenderError::MalformedDocument),
                "source must be rejected without exposing it: {source:?}"
            );
        }
    }

    #[test]
    fn storage_preflight_rejects_node_work_and_expansion_overages_before_parsing() {
        let too_many_nodes = "<br>".repeat(MAX_ADF_RENDER_NODES + 1);
        assert_eq!(
            render_confluence_storage_bounded(&too_many_nodes, ReadContentFormat::Text, 1024,),
            Err(ContentRenderError::NodeLimitExceeded)
        );

        let tight_work = RenderLimits {
            max_depth: 32,
            max_nodes: 100,
            max_work_units: 4,
        };
        assert_eq!(
            render_confluence_storage_with_limits(
                "<p a=1 b=2 c=3 d=4>x</p>",
                ReadContentFormat::Text,
                1024,
                tight_work,
            ),
            Err(ContentRenderError::WorkLimitExceeded)
        );

        let tight_expansion = RenderLimits {
            max_depth: 32,
            max_nodes: 100,
            max_work_units: 8,
        };
        assert_eq!(
            render_confluence_storage_with_limits(
                "<future-node /><future-node />",
                ReadContentFormat::Text,
                1024,
                tight_expansion,
            ),
            Err(ContentRenderError::WorkLimitExceeded)
        );
    }

    #[test]
    fn renders_storage_lists_tables_and_code_deterministically() {
        let source = concat!(
            "<ul><li>one</li><li>two<ol><li>nested</li></ol></li></ul>",
            "<table><tr><th>Name</th><th>Value | detail</th></tr>",
            "<tr><td>Ada<br>Lovelace</td></tr></table>",
            "<pre><code>let ticks = ```;</code></pre>"
        );
        assert_eq!(
            render_storage(source, ReadContentFormat::Markdown),
            "- one\n- two\n  1. nested\n\n| Name | Value \\| detail |\n| --- | --- |\n| Ada Lovelace |  |\n\n````\nlet ticks = ```;\n````"
        );
        assert_eq!(
            render_storage(source, ReadContentFormat::Text),
            "• one\n• two\n  1. nested\n\nName | Value | detail\nAda Lovelace |\n\nlet ticks = ```;"
        );

        assert_eq!(
            render_storage(
                "<ol start=\"42\"><li>first</li><li>second</li></ol>",
                ReadContentFormat::Markdown,
            ),
            "42. first\n43. second"
        );
        assert_eq!(
            render_storage(
                "<ol start=\"42\"><li></li><li>visible</li></ol>",
                ReadContentFormat::Markdown,
            ),
            "43. visible"
        );
        for invalid in ["0", "-2", "+3", "4 other"] {
            let source = format!("<ol start=\"{invalid}\"><li>first</li></ol>");
            assert_eq!(
                render_storage(&source, ReadContentFormat::Markdown),
                "1. first"
            );
        }

        assert_eq!(
            render_storage(
                "<pre><code class=\"language-rust\">fn main() {}\n</code></pre>",
                ReadContentFormat::Markdown,
            ),
            "```rust\nfn main() {}\n```"
        );
        for class in [
            "language-rust extra",
            "language-rust!",
            "language-",
            "other-rust",
        ] {
            let source = format!("<pre><code class=\"{class}\">x\n</code></pre>");
            assert_eq!(
                render_storage(&source, ReadContentFormat::Markdown),
                "```\nx\n```"
            );
        }
    }

    #[test]
    fn renders_confluence_namespaced_elements_without_opaque_id_leakage() {
        let source = concat!(
            "<p><ac:link><ri:page ri:content-title=\"Roadmap\" ri:content-id=\"secret-page\" />",
            "<ac:plain-text-link-body><![CDATA[read roadmap]]></ac:plain-text-link-body></ac:link></p>",
            "<p><ri:attachment ri:filename=\"design.png\" ri:content-id=\"secret-file\" /> ",
            "<ri:user ri:display-name=\"Ada\" ri:account-id=\"secret-user\" /></p>",
            "<ac:image ac:alt=\"overview\"><ri:attachment ri:filename=\"chart.png\" /></ac:image>",
            "<ac:structured-macro ac:name=\"code\" ac:macro-id=\"secret-macro\">",
            "<ac:parameter ac:name=\"language\">rust</ac:parameter>",
            "<ac:plain-text-body><![CDATA[fn main() {}]]></ac:plain-text-body>",
            "</ac:structured-macro>",
            "<ac:structured-macro ac:name=\"info\"><ac:rich-text-body><p>Useful info</p>",
            "</ac:rich-text-body></ac:structured-macro>"
        );
        let markdown = render_storage(source, ReadContentFormat::Markdown);
        assert_eq!(
            markdown,
            "read roadmap\n\n[attachment: design\\.png] [user: Ada]\n\n[image: chart\\.png]\n\n```rust\nfn main() {}\n```\n\nUseful info"
        );
        for secret in ["secret-page", "secret-file", "secret-user", "secret-macro"] {
            assert!(!markdown.contains(secret));
        }
        assert_eq!(
            render_storage(source, ReadContentFormat::Text),
            "read roadmap\n\n[attachment: design.png] [user: Ada]\n\n[image: chart.png]\n\nfn main() {}\n\nUseful info"
        );
    }

    #[test]
    fn renders_storage_tasks_without_exposing_task_metadata() {
        let source = concat!(
            "<ac:task-list ac:local-id=\"task-list-sentinel\">",
            "<ac:task><ac:task-id>task-id-sentinel</ac:task-id>",
            "<ac:task-uuid>task-uuid-sentinel</ac:task-uuid>",
            "<ac:task-status>complete</ac:task-status>",
            "<ac:task-body><p>Ship <strong>release</strong></p></ac:task-body></ac:task>",
            "<ac:task><ac:task-status>incomplete</ac:task-status>",
            "<ac:task-body><p>Write docs</p><ac:task-id>nested-id-sentinel</ac:task-id>",
            "</ac:task-body></ac:task></ac:task-list>"
        );

        let markdown = render_storage(source, ReadContentFormat::Markdown);
        assert_eq!(markdown, "- [x] Ship **release**\n\n- [ ] Write docs");
        let text = render_storage(source, ReadContentFormat::Text);
        assert_eq!(text, "☑ Ship release\n\n☐ Write docs");
        for sentinel in [
            "task-list-sentinel",
            "task-id-sentinel",
            "task-uuid-sentinel",
            "nested-id-sentinel",
            "complete",
            "incomplete",
        ] {
            assert!(!markdown.contains(sentinel));
            assert!(!text.contains(sentinel));
        }
    }

    #[test]
    fn storage_adf_wrappers_render_content_but_suppress_metadata() {
        let source = concat!(
            "<ac:adf-extension ac:extension-key=\"extension-attribute-sentinel\">",
            "<ac:adf-attribute key=\"attribute-key-sentinel\">attribute-value-sentinel</ac:adf-attribute>",
            "<ac:adf-parameter key=\"parameter-key-sentinel\">parameter-value-sentinel</ac:adf-parameter>",
            "<ac:adf-node ac:local-id=\"node-attribute-sentinel\"><ac:adf-content>",
            "<p>Readable <em>ADF content</em></p>",
            "</ac:adf-content></ac:adf-node></ac:adf-extension>"
        );

        let markdown = render_storage(source, ReadContentFormat::Markdown);
        assert_eq!(markdown, "Readable _ADF content_");
        let text = render_storage(source, ReadContentFormat::Text);
        assert_eq!(text, "Readable ADF content");
        for sentinel in [
            "extension-attribute-sentinel",
            "attribute-key-sentinel",
            "attribute-value-sentinel",
            "parameter-key-sentinel",
            "parameter-value-sentinel",
            "node-attribute-sentinel",
        ] {
            assert!(!markdown.contains(sentinel));
            assert!(!text.contains(sentinel));
        }
    }

    #[test]
    fn storage_adf_extension_primary_content_suppresses_fallback() {
        let source = concat!(
            "<ac:adf-extension>",
            "<ac:adf-node><ac:adf-content>",
            "<ac:adf-node><ac:adf-content><p>First <strong>item</strong></p>",
            "</ac:adf-content></ac:adf-node>",
            "<ac:adf-node><ac:adf-content><p>Second <em>item</em></p>",
            "</ac:adf-content></ac:adf-node>",
            "</ac:adf-content></ac:adf-node>",
            "<ac:adf-fallback><p>fallback-prose-sentinel</p></ac:adf-fallback>",
            "</ac:adf-extension>"
        );

        let markdown = render_storage(source, ReadContentFormat::Markdown);
        assert_eq!(markdown, "First **item**\n\nSecond _item_");
        assert!(!markdown.contains("fallback-prose-sentinel"));
        let text = render_storage(source, ReadContentFormat::Text);
        assert_eq!(text, "First item\n\nSecond item");
        assert!(!text.contains("fallback-prose-sentinel"));

        let empty_primary = concat!(
            "<ac:adf-extension><ac:adf-content></ac:adf-content>",
            "<ac:adf-fallback><p>must-not-render</p></ac:adf-fallback></ac:adf-extension>"
        );
        assert_eq!(
            render_storage(empty_primary, ReadContentFormat::Markdown),
            ""
        );
        assert_eq!(render_storage(empty_primary, ReadContentFormat::Text), "");
    }

    #[test]
    fn storage_adf_extension_renders_fallback_without_primary_content() {
        let source = concat!(
            "<ac:adf-extension>",
            "<ac:adf-attribute key=\"metadata\">metadata-sentinel</ac:adf-attribute>",
            "<ac:adf-fallback><p>Readable <em>fallback</em></p></ac:adf-fallback>",
            "</ac:adf-extension>"
        );

        let markdown = render_storage(source, ReadContentFormat::Markdown);
        assert_eq!(markdown, "Readable _fallback_");
        assert!(!markdown.contains("metadata-sentinel"));
        let text = render_storage(source, ReadContentFormat::Text);
        assert_eq!(text, "Readable fallback");
        assert!(!text.contains("metadata-sentinel"));
    }

    #[test]
    fn storage_links_use_readable_user_and_attachment_fallbacks() {
        let source = concat!(
            "<p><ac:link ac:anchor=\"link-attribute-sentinel\">",
            "<ri:user ri:display-name=\"Ada\" ri:account-id=\"user-id-sentinel\" />",
            "</ac:link> <ac:link><ri:attachment ri:filename=\"design [final].pdf\" ",
            "ri:content-id=\"attachment-id-sentinel\" /></ac:link></p>"
        );

        let markdown = render_storage(source, ReadContentFormat::Markdown);
        assert_eq!(
            markdown,
            "[user: Ada] [attachment: design \\[final\\]\\.pdf]"
        );
        let text = render_storage(source, ReadContentFormat::Text);
        assert_eq!(text, "[user: Ada] [attachment: design [final].pdf]");
        for sentinel in [
            "link-attribute-sentinel",
            "user-id-sentinel",
            "attachment-id-sentinel",
        ] {
            assert!(!markdown.contains(sentinel));
            assert!(!text.contains(sentinel));
        }
    }

    #[test]
    fn storage_code_macros_without_bodies_never_render_parameters_as_content() {
        let source = concat!(
            "<ac:structured-macro ac:name=\"code\">",
            "<ac:parameter ac:name=\"language\">rust</ac:parameter>",
            "<ac:parameter ac:name=\"title\">code-parameter-secret</ac:parameter>",
            "</ac:structured-macro>",
            "<ac:structured-macro ac:name=\"noformat\">",
            "<ac:parameter ac:name=\"title\">noformat-parameter-secret</ac:parameter>",
            "</ac:structured-macro>"
        );
        let markdown = render_storage(source, ReadContentFormat::Markdown);
        assert_eq!(markdown, "```rust\n\n```\n\n```\n\n```");
        assert!(!markdown.contains("code-parameter-secret"));
        assert!(!markdown.contains("noformat-parameter-secret"));

        let text = render_storage(source, ReadContentFormat::Text);
        assert_eq!(text, "");
        assert!(!text.contains("code-parameter-secret"));
        assert!(!text.contains("noformat-parameter-secret"));
    }

    #[test]
    fn suppresses_active_storage_content_and_uses_safe_unknown_fallbacks() {
        let source = concat!(
            "<p>before<script>script secret</script><style>style secret</style>",
            "<iframe>frame secret</iframe><object>object secret</object>after</p>",
            "<future-container data-id=\"secret-container\"><p>safe child</p></future-container>",
            "<future-leaf data-id=\"secret-leaf\"></future-leaf>",
            "<ac:structured-macro ac:name=\"html\"><ac:plain-text-body>",
            "active macro secret</ac:plain-text-body></ac:structured-macro>"
        );
        let rendered = render_storage(source, ReadContentFormat::Markdown);
        assert_eq!(
            rendered,
            "beforeafter\n\nsafe child\n\n[unsupported content]\n\n[unsupported content]"
        );
        for secret in [
            "script secret",
            "style secret",
            "frame secret",
            "object secret",
            "active macro secret",
            "secret-container",
            "secret-leaf",
        ] {
            assert!(!rendered.contains(secret));
        }
    }

    #[test]
    fn storage_links_reject_credentials_controls_and_markdown_injection() {
        let source = concat!(
            "<p><a href=\"https://user:secret@example.test/\">credentials</a> ",
            "<a href=\"https://example.test/a) [injected](https://evil.test/\">attack</a> ",
            "<a href=\"mailto:user@example.test\">mail</a></p>"
        );
        let rendered = render_storage(source, ReadContentFormat::Markdown);
        assert_eq!(
            rendered,
            "credentials [attack](https://example.test/a%29%20[injected]%28https://evil.test/) [mail](mailto:user@example.test)"
        );
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("](https://evil.test/)"));
    }

    #[test]
    fn storage_enforces_depth_node_work_and_exact_output_caps() {
        let limits = RenderLimits {
            max_depth: 3,
            max_nodes: 100,
            max_work_units: 1000,
        };
        assert_eq!(
            render_confluence_storage_with_limits(
                "<div><div><div><div>deep</div></div></div></div>",
                ReadContentFormat::Text,
                1024,
                limits,
            ),
            Err(ContentRenderError::NestingLimitExceeded)
        );
        let node_limits = RenderLimits {
            max_depth: 20,
            max_nodes: 3,
            max_work_units: 100,
        };
        assert_eq!(
            render_confluence_storage_with_limits(
                "<p><span>one</span><span>two</span></p>",
                ReadContentFormat::Text,
                1024,
                node_limits,
            ),
            Err(ContentRenderError::NodeLimitExceeded)
        );
        let work_limits = RenderLimits {
            max_depth: 20,
            max_nodes: 100,
            max_work_units: 3,
        };
        assert_eq!(
            render_confluence_storage_with_limits(
                "<p><strong>x</strong></p>",
                ReadContentFormat::Text,
                1024,
                work_limits,
            ),
            Err(ContentRenderError::WorkLimitExceeded)
        );

        assert_eq!(
            render_confluence_storage_bounded("<p>é🙂</p>", ReadContentFormat::Text, 6)
                .unwrap()
                .unwrap()
                .value,
            "é🙂"
        );
        assert_eq!(
            render_confluence_storage_bounded("<p>é🙂</p>", ReadContentFormat::Text, 5),
            Err(ContentRenderError::OutputTooLarge { max_bytes: 5 })
        );
        assert_eq!(
            render_confluence_storage_bounded("<p>***</p>", ReadContentFormat::Markdown, 5),
            Err(ContentRenderError::OutputTooLarge { max_bytes: 5 })
        );
    }

    #[test]
    fn rejects_malformed_roots_nodes_content_attrs_and_marks() {
        let malformed = [
            json!(null),
            json!({ "type": "doc", "version": 2, "content": [] }),
            json!({ "type": "doc", "version": 1 }),
            doc(vec![json!({ "content": [] })]),
            doc(vec![json!({ "type": "paragraph", "content": {} })]),
            doc(vec![json!({ "type": "paragraph", "attrs": [] })]),
            doc(vec![json!({ "type": "text", "text": 7 })]),
            doc(vec![json!({ "type": "text", "text": "x", "marks": {} })]),
            doc(vec![json!({ "type": "text", "text": "x", "marks": [{}] })]),
        ];
        for document in malformed {
            assert_eq!(
                render_adf_bounded(&document, ReadContentFormat::Markdown, 1024),
                Err(ContentRenderError::MalformedDocument)
            );
        }
    }

    #[test]
    fn enforces_depth_limit() {
        fn nested(depth: usize) -> Value {
            let mut node = paragraph("deep");
            for _ in 0..depth {
                node = json!({ "type": "panel", "content": [node] });
            }
            doc(vec![node])
        }
        let limits = RenderLimits {
            max_depth: 4,
            max_nodes: 100,
            max_work_units: 1000,
        };
        let mut budget = RenderBudget::default();
        assert!(
            render_adf_with_limits(
                &nested(2),
                ReadContentFormat::Text,
                u64::MAX,
                1024,
                limits,
                &mut budget,
            )
            .is_ok()
        );
        let mut budget = RenderBudget::default();
        assert_eq!(
            render_adf_with_limits(
                &nested(4),
                ReadContentFormat::Text,
                u64::MAX,
                1024,
                limits,
                &mut budget,
            ),
            Err(ContentRenderError::NestingLimitExceeded)
        );
    }

    #[test]
    fn enforces_explicit_65536_node_budget() {
        assert_eq!(MAX_ADF_RENDER_NODES, 65_536);
        let within = doc((0..MAX_ADF_RENDER_NODES - 1)
            .map(|_| json!({ "type": "mention" }))
            .collect());
        assert!(render_adf_bounded(&within, ReadContentFormat::Text, 0).is_ok());

        let over = doc((0..MAX_ADF_RENDER_NODES)
            .map(|_| json!({ "type": "mention" }))
            .collect());
        assert_eq!(
            render_adf_bounded(&over, ReadContentFormat::Text, 0),
            Err(ContentRenderError::NodeLimitExceeded)
        );
    }

    #[test]
    fn enforces_independent_work_budget() {
        let document = doc(vec![json!({
            "type": "paragraph",
            "content": [{
                "type": "text",
                "text": "x",
                "marks": [
                    { "type": "underline" },
                    { "type": "textColor" },
                    { "type": "backgroundColor" }
                ]
            }]
        })]);
        let limits = RenderLimits {
            max_depth: 10,
            max_nodes: 100,
            max_work_units: 7,
        };
        assert_eq!(
            render_adf_with_limits(
                &document,
                ReadContentFormat::Markdown,
                u64::MAX,
                1024,
                limits,
                &mut RenderBudget::default(),
            ),
            Err(ContentRenderError::WorkLimitExceeded)
        );
    }

    #[test]
    fn enforces_exact_byte_and_multibyte_caps_without_truncation() {
        let ascii = doc(vec![paragraph("abcd")]);
        assert_eq!(
            render_adf_bounded(&ascii, ReadContentFormat::Text, 4)
                .unwrap()
                .unwrap()
                .value,
            "abcd"
        );
        assert_eq!(
            render_adf_bounded(&ascii, ReadContentFormat::Text, 3),
            Err(ContentRenderError::OutputTooLarge { max_bytes: 3 })
        );

        let multibyte = doc(vec![paragraph("é🙂")]);
        assert_eq!("é🙂".len(), 6);
        assert!(render_adf_bounded(&multibyte, ReadContentFormat::Text, 6).is_ok());
        assert_eq!(
            render_adf_bounded(&multibyte, ReadContentFormat::Text, 5),
            Err(ContentRenderError::OutputTooLarge { max_bytes: 5 })
        );
    }

    #[test]
    fn serialization_uses_the_contract_shape() {
        let rendered = RenderedBody::new(ReadContentFormat::Markdown, "hello".to_string());
        assert_eq!(
            serde_json::to_value(rendered).unwrap(),
            json!({ "format": "markdown", "value": "hello" })
        );
        assert_eq!(ReadContentFormat::Text.as_str(), "text");
    }

    #[test]
    fn confluence_adf_string_is_bounded_before_parsing_and_uses_shared_rendering() {
        let source = serde_json::to_string(&doc(vec![paragraph("ADF *body*")])).unwrap();
        let mut budget = RenderBudget::default();
        assert_eq!(
            render_confluence_adf_bounded_with_budget(
                &source,
                ReadContentFormat::Markdown,
                source.len() as u64,
                1024,
                &mut budget,
            )
            .unwrap()
            .unwrap()
            .value,
            "ADF \\*body\\*"
        );

        let mut budget = RenderBudget::default();
        assert_eq!(
            render_confluence_adf_bounded_with_budget(
                &source,
                ReadContentFormat::Native,
                source.len() as u64 - 1,
                1024,
                &mut budget,
            ),
            Err(ContentRenderError::SourceTooLarge {
                max_bytes: source.len() as u64 - 1
            })
        );

        let malformed = "{not-json}";
        let mut budget = RenderBudget::default();
        assert_eq!(
            render_confluence_adf_bounded_with_budget(
                malformed,
                ReadContentFormat::Native,
                malformed.len() as u64,
                1024,
                &mut budget,
            ),
            Err(ContentRenderError::MalformedDocument)
        );

        let malformed_structure = r#"{"type":"doc","version":1}"#;
        let mut budget = RenderBudget::default();
        assert_eq!(
            render_confluence_adf_bounded_with_budget(
                malformed_structure,
                ReadContentFormat::Native,
                malformed_structure.len() as u64,
                1024,
                &mut budget,
            ),
            Err(ContentRenderError::MalformedDocument)
        );
    }

    #[test]
    fn confluence_storage_source_and_aggregate_work_are_bounded_in_native_mode() {
        let source = "<p>body</p>";
        let mut budget = RenderBudget::default();
        assert_eq!(
            render_confluence_storage_bounded_with_budget(
                source,
                ReadContentFormat::Native,
                source.len() as u64 - 1,
                1024,
                &mut budget,
            ),
            Err(ContentRenderError::SourceTooLarge {
                max_bytes: source.len() as u64 - 1
            })
        );

        let mut exhausted = RenderBudget::with_limits(0, 1);
        assert_eq!(
            render_confluence_storage_bounded_with_budget(
                source,
                ReadContentFormat::Native,
                source.len() as u64,
                1024,
                &mut exhausted,
            ),
            Err(ContentRenderError::NodeLimitExceeded)
        );
    }

    #[test]
    fn source_size_and_aggregate_work_are_bounded_in_native_mode() {
        let document = doc(vec![paragraph("body")]);
        let serialized = serde_json::to_vec(&document).unwrap().len() as u64;
        let mut budget = RenderBudget::default();
        assert_eq!(
            render_adf_bounded_with_budget(
                &document,
                ReadContentFormat::Native,
                serialized - 1,
                1024,
                &mut budget,
            ),
            Err(ContentRenderError::SourceTooLarge {
                max_bytes: serialized - 1
            })
        );

        let mut exhausted = RenderBudget::with_limits(0, 1);
        assert_eq!(
            render_adf_bounded_with_budget(
                &document,
                ReadContentFormat::Native,
                serialized,
                1024,
                &mut exhausted,
            ),
            Err(ContentRenderError::NodeLimitExceeded)
        );
    }
}
