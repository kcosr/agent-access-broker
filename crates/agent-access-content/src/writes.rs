use pulldown_cmark::{CodeBlockKind, Event, HeadingLevel, Options, Parser, Tag, TagEnd};
use serde_json::{Map, Value, json};
use thiserror::Error;

const MAX_DEPTH: usize = 128;
const MAX_EVENTS: usize = 200_000;
const MAX_NODES: usize = 100_000;
const NODE_WORK_UNITS: u64 = 32;

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum ContentWriteError {
    #[error("converted content exceeds the configured body size limit")]
    SizeDenied,
    #[error("content exceeds conversion complexity limits")]
    ComplexityDenied,
    #[error("content cannot be converted to a valid native document")]
    Malformed,
}

pub fn markdown_to_adf_bounded(
    source: &str,
    max_output_bytes: u64,
) -> Result<Value, ContentWriteError> {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_TASKLISTS);

    let mut builder = AdfBuilder::new(max_output_bytes)?;
    for event in Parser::new_ext(source, options) {
        builder.consume(event)?;
    }
    builder.finish()
}

pub fn plain_text_to_adf_bounded(
    source: &str,
    max_output_bytes: u64,
) -> Result<Value, ContentWriteError> {
    let mut builder = AdfBuilder::new(max_output_bytes)?;
    let normalized = source.replace("\r\n", "\n").replace('\r', "\n");
    for paragraph in normalized.split("\n\n") {
        builder.start_frame(FrameKind::Paragraph)?;
        for (index, line) in paragraph.split('\n').enumerate() {
            if index > 0 {
                builder.add_leaf(json!({ "type": "hardBreak" }))?;
            }
            builder.add_text(line)?;
        }
        builder.close_expected(FrameKindTag::Paragraph)?;
    }
    builder.finish()
}

pub fn markdown_to_confluence_storage_bounded(
    source: &str,
    max_output_bytes: u64,
) -> Result<String, ContentWriteError> {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_TASKLISTS);

    let mut builder = StorageBuilder::new(source, max_output_bytes)?;
    for event in Parser::new_ext(source, options) {
        builder.consume(event)?;
    }
    builder.finish()
}

pub fn plain_text_to_confluence_storage_bounded(
    source: &str,
    max_output_bytes: u64,
) -> Result<String, ContentWriteError> {
    let normalized = source.replace("\r\n", "\n").replace('\r', "\n");
    let mut builder = StorageBuilder::new(source, max_output_bytes)?;
    for paragraph in normalized.split("\n\n") {
        builder.append_node("<p>")?;
        for (index, line) in paragraph.split('\n').enumerate() {
            if index > 0 {
                builder.append_node("<br />")?;
            }
            builder.append_escaped_text(line)?;
        }
        builder.append("</p>")?;
    }
    builder.finish()
}

pub fn plain_text_to_gitlab_markdown_bounded(
    source: &str,
    max_output_bytes: u64,
) -> Result<String, ContentWriteError> {
    let source_bytes = u64::try_from(source.len()).map_err(|_| ContentWriteError::SizeDenied)?;
    if source_bytes > max_output_bytes {
        return Err(ContentWriteError::SizeDenied);
    }

    let mut output = String::new();
    let mut characters = source.chars().peekable();
    let mut line_start = true;
    while let Some(character) = characters.next() {
        if character == '\r' {
            if characters.peek() == Some(&'\n') {
                characters.next();
            }
            append_gitlab_literal(&mut output, "\n", max_output_bytes)?;
            line_start = true;
            continue;
        }
        if character == '\n' {
            append_gitlab_literal(&mut output, "\n", max_output_bytes)?;
            line_start = true;
            continue;
        }

        // Four leading spaces or a tab would turn otherwise literal input into a
        // Markdown code block. An entity for the first indentation character
        // preserves its rendered value while making the line inline content.
        if line_start && matches!(character, ' ' | '\t') {
            append_gitlab_literal(
                &mut output,
                if character == ' ' { "&#32;" } else { "&#9;" },
                max_output_bytes,
            )?;
            line_start = false;
            continue;
        }
        line_start = false;

        if character.is_ascii_punctuation() {
            append_gitlab_literal(&mut output, "\\", max_output_bytes)?;
        }
        let mut encoded = [0; 4];
        append_gitlab_literal(
            &mut output,
            character.encode_utf8(&mut encoded),
            max_output_bytes,
        )?;
    }
    Ok(output)
}

fn append_gitlab_literal(
    output: &mut String,
    value: &str,
    max_output_bytes: u64,
) -> Result<(), ContentWriteError> {
    let value_bytes = u64::try_from(value.len()).map_err(|_| ContentWriteError::SizeDenied)?;
    let output_bytes = u64::try_from(output.len())
        .map_err(|_| ContentWriteError::SizeDenied)?
        .saturating_add(value_bytes);
    if output_bytes > max_output_bytes {
        return Err(ContentWriteError::SizeDenied);
    }
    output.push_str(value);
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StorageTag {
    Paragraph,
    Heading,
    Blockquote,
    CodeBlock,
    BulletList,
    OrderedList,
    ListItem,
    Emphasis,
    Strong,
    Strikethrough,
    Link,
    UnsafeLink,
    HtmlBlock,
    Table,
    TableHead,
    TableRow,
    TableHeader,
    TableCell,
    Footnote,
    Silent,
}

struct StorageBuilder {
    output: String,
    max_output_bytes: u64,
    open: Vec<StorageTag>,
    events: usize,
    nodes: usize,
    work: u64,
    work_limit: u64,
    image_depth: usize,
    image_alt: String,
}

impl StorageBuilder {
    fn new(source: &str, max_output_bytes: u64) -> Result<Self, ContentWriteError> {
        let source_bytes =
            u64::try_from(source.len()).map_err(|_| ContentWriteError::SizeDenied)?;
        if max_output_bytes == 0 || source_bytes > max_output_bytes {
            return Err(ContentWriteError::SizeDenied);
        }
        Ok(Self {
            output: String::new(),
            max_output_bytes,
            open: Vec::new(),
            events: 0,
            nodes: 0,
            work: source_bytes,
            work_limit: max_output_bytes.saturating_mul(16).max(1_024),
            image_depth: 0,
            image_alt: String::new(),
        })
    }

    fn consume(&mut self, event: Event<'_>) -> Result<(), ContentWriteError> {
        self.events = self.events.saturating_add(1);
        self.work = self.work.saturating_add(NODE_WORK_UNITS);
        if self.events > MAX_EVENTS || self.work > self.work_limit {
            return Err(ContentWriteError::ComplexityDenied);
        }
        match event {
            Event::Start(tag) => self.start(tag),
            Event::End(tag) => self.end(tag),
            Event::Text(text) => self.add_readable_text(&text),
            Event::Code(code) => {
                if self.image_depth > 0 {
                    self.append_image_alt(&code)
                } else {
                    self.append_node("<code>")?;
                    self.append_escaped_text(&code)?;
                    self.append("</code>")
                }
            }
            Event::Html(html) | Event::InlineHtml(html) => self.add_readable_text(&html),
            Event::SoftBreak => self.add_readable_text("\n"),
            Event::HardBreak => {
                if self.image_depth > 0 {
                    self.append_image_alt(" ")
                } else {
                    self.append_node("<br />")
                }
            }
            Event::Rule => self.append_node("<hr />"),
            Event::TaskListMarker(checked) => {
                self.add_readable_text(if checked { "[x] " } else { "[ ] " })
            }
            Event::FootnoteReference(label) => self.add_readable_text(&format!("[^{label}]")),
            Event::InlineMath(value) => self.add_readable_text(&format!("${value}$")),
            Event::DisplayMath(value) => self.add_readable_text(&format!("$${value}$$")),
        }
    }

    fn start(&mut self, tag: Tag<'_>) -> Result<(), ContentWriteError> {
        if self.image_depth > 0 {
            if self.image_depth >= MAX_DEPTH {
                return Err(ContentWriteError::ComplexityDenied);
            }
            self.image_depth = self.image_depth.saturating_add(1);
            return Ok(());
        }
        match tag {
            Tag::Paragraph => self.open_tag(StorageTag::Paragraph, "<p>"),
            Tag::Heading { level, .. } => {
                let level = heading_level(level);
                self.open_tag(StorageTag::Heading, &format!("<h{level}>"))
            }
            Tag::BlockQuote(_) => self.open_tag(StorageTag::Blockquote, "<blockquote>"),
            Tag::CodeBlock(_) => self.open_tag(StorageTag::CodeBlock, "<pre><code>"),
            Tag::List(start) => match start {
                Some(1) => self.open_tag(StorageTag::OrderedList, "<ol>"),
                Some(start) => {
                    self.open_tag(StorageTag::OrderedList, &format!("<ol start=\"{start}\">"))
                }
                None => self.open_tag(StorageTag::BulletList, "<ul>"),
            },
            Tag::Item => self.open_tag(StorageTag::ListItem, "<li>"),
            Tag::Emphasis => self.open_tag(StorageTag::Emphasis, "<em>"),
            Tag::Strong => self.open_tag(StorageTag::Strong, "<strong>"),
            Tag::Strikethrough => self.open_tag(StorageTag::Strikethrough, "<s>"),
            Tag::Link { dest_url, .. } if safe_link(&dest_url) => {
                self.check_depth()?;
                self.append_node("<a href=\"")?;
                self.append_escaped_attribute(&dest_url)?;
                self.append("\">")?;
                self.open.push(StorageTag::Link);
                Ok(())
            }
            Tag::Link { .. } => self.open_silent(StorageTag::UnsafeLink),
            Tag::Image { .. } => {
                if self.open.len() >= MAX_DEPTH {
                    return Err(ContentWriteError::ComplexityDenied);
                }
                self.image_depth = 1;
                self.image_alt.clear();
                Ok(())
            }
            Tag::HtmlBlock => self.open_silent(StorageTag::HtmlBlock),
            Tag::Table(_) => self.open_tag(StorageTag::Table, "<table>"),
            Tag::TableHead => self.open_tag(StorageTag::TableHead, "<thead><tr>"),
            Tag::TableRow => self.open_tag(StorageTag::TableRow, "<tr>"),
            Tag::TableCell => {
                if self.open.contains(&StorageTag::TableHead) {
                    self.open_tag(StorageTag::TableHeader, "<th>")
                } else {
                    self.open_tag(StorageTag::TableCell, "<td>")
                }
            }
            Tag::FootnoteDefinition(label) => {
                self.open_tag(StorageTag::Footnote, "<p>")?;
                self.append_escaped_text(&format!("[^{label}]: "))
            }
            Tag::MetadataBlock(_) => self.open_silent(StorageTag::Silent),
            _ => self.open_silent(StorageTag::Silent),
        }
    }

    fn end(&mut self, tag: TagEnd) -> Result<(), ContentWriteError> {
        if self.image_depth > 0 {
            self.image_depth -= 1;
            if self.image_depth == 0 {
                let alt = std::mem::take(&mut self.image_alt);
                self.append_escaped_text(&alt)?;
            }
            return Ok(());
        }
        match tag {
            TagEnd::Paragraph => self.close_tag(StorageTag::Paragraph, "</p>"),
            TagEnd::Heading(level) => {
                let level = heading_level(level);
                self.close_tag(StorageTag::Heading, &format!("</h{level}>"))
            }
            TagEnd::BlockQuote(_) => self.close_tag(StorageTag::Blockquote, "</blockquote>"),
            TagEnd::CodeBlock => self.close_tag(StorageTag::CodeBlock, "</code></pre>"),
            TagEnd::List(true) => self.close_tag(StorageTag::OrderedList, "</ol>"),
            TagEnd::List(false) => self.close_tag(StorageTag::BulletList, "</ul>"),
            TagEnd::Item => self.close_tag(StorageTag::ListItem, "</li>"),
            TagEnd::Emphasis => self.close_tag(StorageTag::Emphasis, "</em>"),
            TagEnd::Strong => self.close_tag(StorageTag::Strong, "</strong>"),
            TagEnd::Strikethrough => self.close_tag(StorageTag::Strikethrough, "</s>"),
            TagEnd::Link => match self.open.last() {
                Some(StorageTag::Link) => self.close_tag(StorageTag::Link, "</a>"),
                Some(StorageTag::UnsafeLink) => self.close_silent(StorageTag::UnsafeLink),
                _ => Err(ContentWriteError::Malformed),
            },
            TagEnd::Image => Ok(()),
            TagEnd::HtmlBlock => self.close_silent(StorageTag::HtmlBlock),
            TagEnd::Table => self.close_tag(StorageTag::Table, "</table>"),
            TagEnd::TableHead => self.close_tag(StorageTag::TableHead, "</tr></thead>"),
            TagEnd::TableRow => self.close_tag(StorageTag::TableRow, "</tr>"),
            TagEnd::TableCell => match self.open.last() {
                Some(StorageTag::TableHeader) => self.close_tag(StorageTag::TableHeader, "</th>"),
                Some(StorageTag::TableCell) => self.close_tag(StorageTag::TableCell, "</td>"),
                _ => Err(ContentWriteError::Malformed),
            },
            TagEnd::FootnoteDefinition => self.close_tag(StorageTag::Footnote, "</p>"),
            TagEnd::MetadataBlock(_) => self.close_silent(StorageTag::Silent),
            _ => self.close_silent(StorageTag::Silent),
        }
    }

    fn add_readable_text(&mut self, text: &str) -> Result<(), ContentWriteError> {
        if self.image_depth > 0 {
            self.append_image_alt(text)
        } else {
            self.append_escaped_text(text)
        }
    }

    fn append_image_alt(&mut self, text: &str) -> Result<(), ContentWriteError> {
        self.charge_work(text.len())?;
        self.image_alt.push_str(text);
        Ok(())
    }

    fn open_tag(&mut self, tag: StorageTag, opening: &str) -> Result<(), ContentWriteError> {
        self.check_depth()?;
        self.append_node(opening)?;
        self.open.push(tag);
        Ok(())
    }

    fn open_silent(&mut self, tag: StorageTag) -> Result<(), ContentWriteError> {
        self.check_depth()?;
        self.open.push(tag);
        Ok(())
    }

    fn close_tag(&mut self, expected: StorageTag, closing: &str) -> Result<(), ContentWriteError> {
        self.close_silent(expected)?;
        self.append(closing)
    }

    fn close_silent(&mut self, expected: StorageTag) -> Result<(), ContentWriteError> {
        if self.open.pop() != Some(expected) {
            return Err(ContentWriteError::Malformed);
        }
        Ok(())
    }

    fn check_depth(&self) -> Result<(), ContentWriteError> {
        if self.open.len() >= MAX_DEPTH {
            Err(ContentWriteError::ComplexityDenied)
        } else {
            Ok(())
        }
    }

    fn append_node(&mut self, value: &str) -> Result<(), ContentWriteError> {
        self.nodes = self.nodes.saturating_add(1);
        self.work = self.work.saturating_add(NODE_WORK_UNITS);
        if self.nodes > MAX_NODES || self.work > self.work_limit {
            return Err(ContentWriteError::ComplexityDenied);
        }
        self.append(value)
    }

    fn append_escaped_text(&mut self, text: &str) -> Result<(), ContentWriteError> {
        self.nodes = self.nodes.saturating_add(1);
        self.charge_work(text.len())?;
        if self.nodes > MAX_NODES {
            return Err(ContentWriteError::ComplexityDenied);
        }
        for character in text.chars() {
            match character {
                '&' => self.append("&amp;")?,
                '<' => self.append("&lt;")?,
                '>' => self.append("&gt;")?,
                _ => {
                    let mut encoded = [0; 4];
                    self.append(character.encode_utf8(&mut encoded))?;
                }
            }
        }
        Ok(())
    }

    fn append_escaped_attribute(&mut self, text: &str) -> Result<(), ContentWriteError> {
        self.charge_work(text.len())?;
        for character in text.chars() {
            match character {
                '&' => self.append("&amp;")?,
                '<' => self.append("&lt;")?,
                '>' => self.append("&gt;")?,
                '\"' => self.append("&quot;")?,
                '\'' => self.append("&#39;")?,
                _ => {
                    let mut encoded = [0; 4];
                    self.append(character.encode_utf8(&mut encoded))?;
                }
            }
        }
        Ok(())
    }

    fn charge_work(&mut self, bytes: usize) -> Result<(), ContentWriteError> {
        let bytes = u64::try_from(bytes).map_err(|_| ContentWriteError::SizeDenied)?;
        self.work = self.work.saturating_add(bytes);
        if self.work > self.work_limit {
            Err(ContentWriteError::ComplexityDenied)
        } else {
            Ok(())
        }
    }

    fn append(&mut self, value: &str) -> Result<(), ContentWriteError> {
        let value_bytes = u64::try_from(value.len()).map_err(|_| ContentWriteError::SizeDenied)?;
        let output_bytes = u64::try_from(self.output.len())
            .map_err(|_| ContentWriteError::SizeDenied)?
            .saturating_add(value_bytes);
        if output_bytes > self.max_output_bytes {
            return Err(ContentWriteError::SizeDenied);
        }
        self.work = self.work.saturating_add(value_bytes);
        if self.work > self.work_limit {
            return Err(ContentWriteError::ComplexityDenied);
        }
        self.output.push_str(value);
        Ok(())
    }

    fn finish(self) -> Result<String, ContentWriteError> {
        if self.image_depth != 0 || !self.open.is_empty() {
            return Err(ContentWriteError::Malformed);
        }
        let size = u64::try_from(self.output.len()).map_err(|_| ContentWriteError::SizeDenied)?;
        if size > self.max_output_bytes {
            return Err(ContentWriteError::SizeDenied);
        }
        Ok(self.output)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameKindTag {
    Root,
    Paragraph,
    Heading,
    Blockquote,
    BulletList,
    OrderedList,
    ListItem,
    CodeBlock,
    Table,
    TableHead,
    TableRow,
    TableCell,
    HtmlBlock,
}

#[derive(Debug)]
enum FrameKind {
    Root,
    Paragraph,
    Heading(u8),
    Blockquote,
    BulletList,
    OrderedList(u64),
    ListItem,
    CodeBlock(Option<String>),
    Table,
    TableHead,
    TableRow,
    TableCell { header: bool },
    HtmlBlock,
}

impl FrameKind {
    fn tag(&self) -> FrameKindTag {
        match self {
            Self::Root => FrameKindTag::Root,
            Self::Paragraph => FrameKindTag::Paragraph,
            Self::Heading(_) => FrameKindTag::Heading,
            Self::Blockquote => FrameKindTag::Blockquote,
            Self::BulletList => FrameKindTag::BulletList,
            Self::OrderedList(_) => FrameKindTag::OrderedList,
            Self::ListItem => FrameKindTag::ListItem,
            Self::CodeBlock(_) => FrameKindTag::CodeBlock,
            Self::Table => FrameKindTag::Table,
            Self::TableHead => FrameKindTag::TableHead,
            Self::TableRow => FrameKindTag::TableRow,
            Self::TableCell { .. } => FrameKindTag::TableCell,
            Self::HtmlBlock => FrameKindTag::HtmlBlock,
        }
    }
}

#[derive(Debug)]
struct Frame {
    kind: FrameKind,
    content: Vec<Value>,
    serialized_content_bytes: u64,
}

struct AdfBuilder {
    frames: Vec<Frame>,
    marks: Vec<Value>,
    events: usize,
    nodes: usize,
    work: u64,
    text_bytes: u64,
    estimated_output_bytes: u64,
    max_output_bytes: u64,
    image_depth: usize,
    image_alt: String,
}

impl AdfBuilder {
    fn new(max_output_bytes: u64) -> Result<Self, ContentWriteError> {
        if max_output_bytes == 0 {
            return Err(ContentWriteError::SizeDenied);
        }
        let empty_document_bytes = serialized_len(&json!({
            "version": 1,
            "type": "doc",
            "content": [],
        }))?;
        if empty_document_bytes > max_output_bytes {
            return Err(ContentWriteError::SizeDenied);
        }
        Ok(Self {
            frames: vec![Frame {
                kind: FrameKind::Root,
                content: Vec::new(),
                serialized_content_bytes: 0,
            }],
            marks: Vec::new(),
            events: 0,
            nodes: 0,
            work: 0,
            text_bytes: 0,
            estimated_output_bytes: empty_document_bytes,
            max_output_bytes,
            image_depth: 0,
            image_alt: String::new(),
        })
    }

    fn consume(&mut self, event: Event<'_>) -> Result<(), ContentWriteError> {
        self.events = self.events.saturating_add(1);
        if self.events > MAX_EVENTS {
            return Err(ContentWriteError::ComplexityDenied);
        }
        match event {
            Event::Start(tag) => self.start(tag),
            Event::End(tag) => self.end(tag),
            Event::Text(text) => {
                if self.image_depth > 0 {
                    self.append_image_alt(&text)
                } else {
                    self.add_text(&text)
                }
            }
            Event::Code(code) => {
                if self.image_depth > 0 {
                    self.append_image_alt(&code)
                } else {
                    self.with_mark(json!({ "type": "code" }), |this| this.add_text(&code))
                }
            }
            Event::Html(html) | Event::InlineHtml(html) => {
                if self.image_depth > 0 {
                    self.append_image_alt(&html)
                } else {
                    self.add_text(&html)
                }
            }
            Event::SoftBreak | Event::HardBreak => {
                if self.image_depth > 0 {
                    self.append_image_alt(" ")
                } else {
                    self.add_leaf(json!({ "type": "hardBreak" }))
                }
            }
            Event::Rule => self.add_leaf(json!({ "type": "rule" })),
            Event::TaskListMarker(checked) => self.add_text(if checked { "[x] " } else { "[ ] " }),
            Event::FootnoteReference(label) => self.add_text(&format!("[^{label}]")),
            Event::InlineMath(value) => self.add_text(&format!("${value}$")),
            Event::DisplayMath(value) => self.add_text(&format!("$${value}$$")),
        }
    }

    fn start(&mut self, tag: Tag<'_>) -> Result<(), ContentWriteError> {
        if self.image_depth > 0 {
            if self.image_depth >= MAX_DEPTH {
                return Err(ContentWriteError::ComplexityDenied);
            }
            self.image_depth = self.image_depth.saturating_add(1);
            return Ok(());
        }
        match tag {
            Tag::Paragraph => self.start_frame(FrameKind::Paragraph),
            Tag::Heading { level, .. } => {
                self.start_frame(FrameKind::Heading(heading_level(level)))
            }
            Tag::BlockQuote(_) => self.start_frame(FrameKind::Blockquote),
            Tag::CodeBlock(kind) => {
                let language = match kind {
                    CodeBlockKind::Indented => None,
                    CodeBlockKind::Fenced(info) => info
                        .split_whitespace()
                        .next()
                        .filter(|value| !value.is_empty())
                        .map(str::to_owned),
                };
                self.start_frame(FrameKind::CodeBlock(language))
            }
            Tag::List(start) => self.start_frame(match start {
                Some(order) => FrameKind::OrderedList(order),
                None => FrameKind::BulletList,
            }),
            Tag::Item => self.start_frame(FrameKind::ListItem),
            Tag::Emphasis => self.push_mark(json!({ "type": "em" })),
            Tag::Strong => self.push_mark(json!({ "type": "strong" })),
            Tag::Strikethrough => self.push_mark(json!({ "type": "strike" })),
            Tag::Link { dest_url, .. } => {
                if safe_link(&dest_url) {
                    self.push_mark(
                        json!({ "type": "link", "attrs": { "href": dest_url.as_ref() } }),
                    )
                } else {
                    self.push_mark(Value::Null)
                }
            }
            Tag::Image { .. } => {
                if self.frames.len() + self.marks.len() >= MAX_DEPTH {
                    return Err(ContentWriteError::ComplexityDenied);
                }
                self.image_depth = 1;
                self.image_alt.clear();
                Ok(())
            }
            Tag::HtmlBlock => self.start_frame(FrameKind::HtmlBlock),
            Tag::Table(_) => self.start_frame(FrameKind::Table),
            Tag::TableHead => self.start_frame(FrameKind::TableHead),
            Tag::TableRow => self.start_frame(FrameKind::TableRow),
            Tag::TableCell => {
                let header = self
                    .frames
                    .last()
                    .is_some_and(|frame| frame.kind.tag() == FrameKindTag::TableHead);
                self.start_frame(FrameKind::TableCell { header })?;
                self.start_frame(FrameKind::Paragraph)
            }
            Tag::FootnoteDefinition(label) => {
                self.start_frame(FrameKind::Paragraph)?;
                self.add_text(&format!("[^{label}]: "))
            }
            Tag::MetadataBlock(_) => Ok(()),
            _ => Ok(()),
        }
    }

    fn end(&mut self, tag: TagEnd) -> Result<(), ContentWriteError> {
        if self.image_depth > 0 {
            self.image_depth -= 1;
            if self.image_depth == 0 {
                let alt = std::mem::take(&mut self.image_alt);
                if !alt.is_empty() {
                    self.add_text_node(&alt)?;
                }
            }
            return Ok(());
        }
        match tag {
            TagEnd::Paragraph => self.close_expected(FrameKindTag::Paragraph),
            TagEnd::Heading(_) => self.close_expected(FrameKindTag::Heading),
            TagEnd::BlockQuote(_) => self.close_expected(FrameKindTag::Blockquote),
            TagEnd::CodeBlock => self.close_expected(FrameKindTag::CodeBlock),
            TagEnd::List(true) => self.close_expected(FrameKindTag::OrderedList),
            TagEnd::List(false) => self.close_expected(FrameKindTag::BulletList),
            TagEnd::Item => self.close_expected(FrameKindTag::ListItem),
            TagEnd::Emphasis | TagEnd::Strong | TagEnd::Strikethrough | TagEnd::Link => {
                self.marks.pop().ok_or(ContentWriteError::Malformed)?;
                Ok(())
            }
            TagEnd::Image => Ok(()),
            TagEnd::HtmlBlock => self.close_expected(FrameKindTag::HtmlBlock),
            TagEnd::Table => self.close_expected(FrameKindTag::Table),
            TagEnd::TableHead => self.close_expected(FrameKindTag::TableHead),
            TagEnd::TableRow => self.close_expected(FrameKindTag::TableRow),
            TagEnd::TableCell => {
                self.close_expected(FrameKindTag::Paragraph)?;
                self.close_expected(FrameKindTag::TableCell)
            }
            TagEnd::FootnoteDefinition => self.close_expected(FrameKindTag::Paragraph),
            TagEnd::MetadataBlock(_) => Ok(()),
            _ => Ok(()),
        }
    }

    fn start_frame(&mut self, kind: FrameKind) -> Result<(), ContentWriteError> {
        if self.frames.len() + self.marks.len() >= MAX_DEPTH {
            return Err(ContentWriteError::ComplexityDenied);
        }
        self.frames.push(Frame {
            kind,
            content: Vec::new(),
            serialized_content_bytes: 0,
        });
        Ok(())
    }

    fn push_mark(&mut self, mark: Value) -> Result<(), ContentWriteError> {
        if self.frames.len() + self.marks.len() >= MAX_DEPTH {
            return Err(ContentWriteError::ComplexityDenied);
        }
        self.marks.push(mark);
        Ok(())
    }

    fn close_expected(&mut self, expected: FrameKindTag) -> Result<(), ContentWriteError> {
        let mut frame = self.frames.pop().ok_or(ContentWriteError::Malformed)?;
        if frame.kind.tag() != expected || expected == FrameKindTag::Root {
            return Err(ContentWriteError::Malformed);
        }
        let previous_content_bytes = frame.serialized_content_bytes;
        self.estimated_output_bytes = self
            .estimated_output_bytes
            .checked_sub(previous_content_bytes)
            .ok_or(ContentWriteError::Malformed)?;
        frame.normalize_adf_containment()?;
        let node_bytes = frame.serialized_node_bytes()?;
        let node = frame.into_adf()?;
        self.add_leaf_with_size(node, node_bytes)
    }

    fn add_text(&mut self, text: &str) -> Result<(), ContentWriteError> {
        if text.is_empty() {
            return Ok(());
        }
        self.charge_text(text.len())?;
        self.add_text_node(text)
    }

    fn append_image_alt(&mut self, text: &str) -> Result<(), ContentWriteError> {
        self.charge_text(text.len())?;
        self.image_alt.push_str(text);
        Ok(())
    }

    fn add_text_node(&mut self, text: &str) -> Result<(), ContentWriteError> {
        let mut node = Map::new();
        node.insert("type".into(), json!("text"));
        node.insert("text".into(), json!(text));
        let marks = self
            .marks
            .iter()
            .filter(|mark| !mark.is_null())
            .cloned()
            .collect::<Vec<_>>();
        if !marks.is_empty() {
            node.insert("marks".into(), Value::Array(marks));
        }
        self.add_leaf(Value::Object(node))
    }

    fn add_leaf(&mut self, node: Value) -> Result<(), ContentWriteError> {
        let bytes = serialized_len(&node)?;
        self.add_leaf_with_size(node, bytes)
    }

    fn add_leaf_with_size(&mut self, node: Value, mut bytes: u64) -> Result<(), ContentWriteError> {
        self.nodes = self.nodes.saturating_add(1);
        self.work = self.work.saturating_add(NODE_WORK_UNITS);
        if self.nodes > MAX_NODES || self.work > self.work_limit() {
            return Err(ContentWriteError::ComplexityDenied);
        }
        let frame = self.frames.last_mut().ok_or(ContentWriteError::Malformed)?;
        if !frame.content.is_empty() {
            bytes = bytes.saturating_add(1);
        }
        let estimated_output_bytes = self.estimated_output_bytes.saturating_add(bytes);
        if estimated_output_bytes > self.max_output_bytes {
            return Err(ContentWriteError::SizeDenied);
        }
        frame.serialized_content_bytes = frame.serialized_content_bytes.saturating_add(bytes);
        frame.content.push(node);
        self.estimated_output_bytes = estimated_output_bytes;
        Ok(())
    }

    fn charge_text(&mut self, bytes: usize) -> Result<(), ContentWriteError> {
        let bytes = u64::try_from(bytes).map_err(|_| ContentWriteError::SizeDenied)?;
        self.text_bytes = self.text_bytes.saturating_add(bytes);
        self.work = self.work.saturating_add(bytes);
        if self.text_bytes > self.max_output_bytes {
            return Err(ContentWriteError::SizeDenied);
        }
        if self.work > self.work_limit() {
            return Err(ContentWriteError::ComplexityDenied);
        }
        Ok(())
    }

    fn work_limit(&self) -> u64 {
        self.max_output_bytes.saturating_mul(8).max(1_024)
    }

    fn with_mark<F>(&mut self, mark: Value, operation: F) -> Result<(), ContentWriteError>
    where
        F: FnOnce(&mut Self) -> Result<(), ContentWriteError>,
    {
        self.push_mark(mark)?;
        let result = operation(self);
        self.marks.pop();
        result
    }

    fn finish(mut self) -> Result<Value, ContentWriteError> {
        if self.image_depth != 0 || !self.marks.is_empty() || self.frames.len() != 1 {
            return Err(ContentWriteError::Malformed);
        }
        let root = self.frames.pop().ok_or(ContentWriteError::Malformed)?;
        let document = json!({
            "version": 1,
            "type": "doc",
            "content": root.content,
        });
        validate_generated_complexity(&document)?;
        let size = serde_json::to_vec(&document)
            .map_err(|_| ContentWriteError::Malformed)?
            .len();
        if u64::try_from(size).map_or(true, |size| size > self.max_output_bytes) {
            return Err(ContentWriteError::SizeDenied);
        }
        debug_assert_eq!(u64::try_from(size).ok(), Some(self.estimated_output_bytes));
        Ok(document)
    }
}

impl Frame {
    fn normalize_adf_containment(&mut self) -> Result<(), ContentWriteError> {
        match self.kind.tag() {
            FrameKindTag::ListItem => {
                self.content = normalize_contained_blocks(
                    std::mem::take(&mut self.content),
                    true,
                    &["paragraph", "bulletList", "orderedList", "codeBlock"],
                );
            }
            FrameKindTag::Blockquote => {
                self.content = normalize_contained_blocks(
                    std::mem::take(&mut self.content),
                    false,
                    &["paragraph", "bulletList", "orderedList", "codeBlock"],
                );
            }
            _ => return Ok(()),
        }
        self.serialized_content_bytes = serialized_content_len(&self.content)?;
        Ok(())
    }

    fn serialized_node_bytes(&self) -> Result<u64, ContentWriteError> {
        let empty = match &self.kind {
            FrameKind::Root => return Err(ContentWriteError::Malformed),
            FrameKind::Paragraph | FrameKind::HtmlBlock => {
                json!({ "type": "paragraph", "content": [] })
            }
            FrameKind::Heading(level) => {
                json!({ "type": "heading", "attrs": { "level": level }, "content": [] })
            }
            FrameKind::Blockquote => json!({ "type": "blockquote", "content": [] }),
            FrameKind::BulletList => json!({ "type": "bulletList", "content": [] }),
            FrameKind::OrderedList(order) => {
                json!({ "type": "orderedList", "attrs": { "order": order }, "content": [] })
            }
            FrameKind::ListItem => json!({ "type": "listItem", "content": [] }),
            FrameKind::CodeBlock(language) => match language {
                Some(language) => {
                    json!({ "type": "codeBlock", "attrs": { "language": language }, "content": [] })
                }
                None => json!({ "type": "codeBlock", "content": [] }),
            },
            FrameKind::Table => json!({ "type": "table", "content": [] }),
            FrameKind::TableHead | FrameKind::TableRow => {
                json!({ "type": "tableRow", "content": [] })
            }
            FrameKind::TableCell { header } => json!({
                "type": if *header { "tableHeader" } else { "tableCell" },
                "content": []
            }),
        };
        Ok(serialized_len(&empty)?.saturating_add(self.serialized_content_bytes))
    }

    fn into_adf(self) -> Result<Value, ContentWriteError> {
        let content = self.content;
        Ok(match self.kind {
            FrameKind::Root => return Err(ContentWriteError::Malformed),
            FrameKind::Paragraph | FrameKind::HtmlBlock => {
                json!({ "type": "paragraph", "content": content })
            }
            FrameKind::Heading(level) => {
                json!({ "type": "heading", "attrs": { "level": level }, "content": content })
            }
            FrameKind::Blockquote => json!({ "type": "blockquote", "content": content }),
            FrameKind::BulletList => json!({ "type": "bulletList", "content": content }),
            FrameKind::OrderedList(order) => {
                json!({ "type": "orderedList", "attrs": { "order": order }, "content": content })
            }
            FrameKind::ListItem => json!({ "type": "listItem", "content": content }),
            FrameKind::CodeBlock(language) => {
                let mut node = Map::new();
                node.insert("type".into(), json!("codeBlock"));
                if let Some(language) = language {
                    node.insert("attrs".into(), json!({ "language": language }));
                }
                node.insert("content".into(), Value::Array(content));
                Value::Object(node)
            }
            FrameKind::Table => json!({ "type": "table", "content": content }),
            FrameKind::TableHead => json!({ "type": "tableRow", "content": content }),
            FrameKind::TableRow => json!({ "type": "tableRow", "content": content }),
            FrameKind::TableCell { header } => json!({
                "type": if header { "tableHeader" } else { "tableCell" },
                "content": content
            }),
        })
    }
}

fn normalize_contained_blocks(
    content: Vec<Value>,
    require_leading_paragraph: bool,
    allowed: &[&str],
) -> Vec<Value> {
    let mut normalized = Vec::new();
    let mut pending_inline = Vec::new();
    for node in content {
        let node_type = node.get("type").and_then(Value::as_str).unwrap_or_default();
        if matches!(node_type, "text" | "hardBreak") {
            pending_inline.push(node);
            continue;
        }
        flush_inline_paragraph(&mut normalized, &mut pending_inline);
        if allowed.contains(&node_type) {
            normalized.push(node);
        } else if node_type == "heading" {
            normalized.push(json!({
                "type": "paragraph",
                "content": node.get("content").cloned().unwrap_or_else(|| json!([])),
            }));
        } else if node_type == "rule" {
            normalized.push(text_paragraph("---"));
        } else {
            normalized.push(readable_fallback_paragraph(&node));
        }
    }
    flush_inline_paragraph(&mut normalized, &mut pending_inline);
    if normalized.is_empty()
        || (require_leading_paragraph
            && normalized
                .first()
                .and_then(|node| node.get("type"))
                .and_then(Value::as_str)
                != Some("paragraph"))
    {
        normalized.insert(0, json!({ "type": "paragraph", "content": [] }));
    }
    normalized
}

fn flush_inline_paragraph(normalized: &mut Vec<Value>, pending: &mut Vec<Value>) {
    if !pending.is_empty() {
        normalized.push(json!({
            "type": "paragraph",
            "content": std::mem::take(pending),
        }));
    }
}

fn readable_fallback_paragraph(node: &Value) -> Value {
    let mut content = Vec::new();
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        match current.get("type").and_then(Value::as_str) {
            Some("text" | "hardBreak") => content.push(current.clone()),
            _ => {
                if let Some(children) = current.get("content").and_then(Value::as_array) {
                    pending.extend(children.iter().rev());
                }
            }
        }
    }
    json!({ "type": "paragraph", "content": content })
}

fn text_paragraph(text: &str) -> Value {
    json!({
        "type": "paragraph",
        "content": [{ "type": "text", "text": text }],
    })
}

fn serialized_content_len(content: &[Value]) -> Result<u64, ContentWriteError> {
    let mut bytes = 0_u64;
    for (index, node) in content.iter().enumerate() {
        bytes = bytes.saturating_add(serialized_len(node)?);
        if index > 0 {
            bytes = bytes.saturating_add(1);
        }
    }
    Ok(bytes)
}

fn heading_level(level: HeadingLevel) -> u8 {
    match level {
        HeadingLevel::H1 => 1,
        HeadingLevel::H2 => 2,
        HeadingLevel::H3 => 3,
        HeadingLevel::H4 => 4,
        HeadingLevel::H5 => 5,
        HeadingLevel::H6 => 6,
    }
}

fn safe_link(destination: &str) -> bool {
    let Some((scheme, _)) = destination.split_once(':') else {
        return false;
    };
    matches!(
        scheme.to_ascii_lowercase().as_str(),
        "http" | "https" | "mailto"
    )
}

fn serialized_len(value: &Value) -> Result<u64, ContentWriteError> {
    let size = serde_json::to_vec(value)
        .map_err(|_| ContentWriteError::Malformed)?
        .len();
    u64::try_from(size).map_err(|_| ContentWriteError::SizeDenied)
}

fn validate_generated_complexity(value: &Value) -> Result<(), ContentWriteError> {
    let mut pending = vec![(value, 0_usize)];
    let mut nodes = 0_usize;
    let mut work = 0_u64;
    while let Some((node, depth)) = pending.pop() {
        if depth > MAX_DEPTH {
            return Err(ContentWriteError::ComplexityDenied);
        }
        nodes = nodes.saturating_add(1);
        if nodes > MAX_NODES {
            return Err(ContentWriteError::ComplexityDenied);
        }
        let object = node.as_object().ok_or(ContentWriteError::Malformed)?;
        work = work.saturating_add(u64::try_from(object.len()).unwrap_or(u64::MAX));
        if let Some(children) = object.get("content").and_then(Value::as_array) {
            work = work.saturating_add(u64::try_from(children.len()).unwrap_or(u64::MAX));
            pending.extend(children.iter().rev().map(|child| (child, depth + 1)));
        }
        if work > MAX_NODES as u64 * NODE_WORK_UNITS {
            return Err(ContentWriteError::ComplexityDenied);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn convert(source: &str) -> Value {
        markdown_to_adf_bounded(source, 64 * 1024).unwrap()
    }

    fn convert_storage(source: &str) -> String {
        markdown_to_confluence_storage_bounded(source, 64 * 1024).unwrap()
    }

    #[test]
    fn converts_common_mark_blocks_and_marks_deterministically() {
        let document = convert(
            "# Release\n\nA **bold** and *small* ~~change~~ with `code` and [safe](https://example.test).\n\n> Quote\n\n- one\n  1. nested\n\n```rust\nfn main() {}\n```\n\n---",
        );

        assert_eq!(document["type"], "doc");
        assert_eq!(document["version"], 1);
        assert_eq!(document["content"][0]["type"], "heading");
        assert_eq!(document["content"][0]["attrs"]["level"], 1);
        assert_eq!(
            document["content"][1]["content"][1]["marks"][0]["type"],
            "strong"
        );
        assert_eq!(document["content"][2]["type"], "blockquote");
        assert_eq!(document["content"][3]["type"], "bulletList");
        assert_eq!(document["content"][4]["type"], "codeBlock");
        assert_eq!(document["content"][4]["attrs"]["language"], "rust");
        assert_eq!(document["content"][5]["type"], "rule");
        assert_eq!(convert("hello"), convert("hello"));
    }

    #[test]
    fn preserves_raw_html_as_literal_text_and_drops_unsafe_link_destinations() {
        let document = convert(
            "<script>alert('x')</script>\n\n[readable](javascript:alert(1)) ![diagram](https://example.test/image.png)",
        );
        let encoded = serde_json::to_string(&document).unwrap();

        assert!(encoded.contains("<script>alert('x')</script>"));
        assert!(encoded.contains("readable"));
        assert!(encoded.contains("diagram"));
        assert!(!encoded.contains("javascript:"));
        assert!(!encoded.contains("image.png"));
    }

    #[test]
    fn converts_tables_to_adf_cells() {
        let document = convert("| A | B |\n|---|---|\n| 1 | 2 |");
        assert_eq!(document["content"][0]["type"], "table");
        assert_eq!(document["content"][0]["content"][0]["type"], "tableRow");
        assert_eq!(
            document["content"][0]["content"][0]["content"][0]["type"],
            "tableHeader"
        );
        assert_eq!(
            document["content"][0]["content"][1]["content"][0]["type"],
            "tableCell"
        );
    }

    #[test]
    fn list_items_always_have_valid_block_containment() {
        let document = convert("- [x] task\n-\n- tight\n  - nested");
        let items = document["content"][0]["content"].as_array().unwrap();
        assert_eq!(items.len(), 3);
        for item in items {
            assert_eq!(item["type"], "listItem");
            assert_eq!(item["content"][0]["type"], "paragraph");
            assert!(item["content"].as_array().unwrap().iter().all(|child| {
                matches!(
                    child["type"].as_str(),
                    Some("paragraph" | "bulletList" | "orderedList" | "codeBlock")
                )
            }));
        }
        assert_eq!(items[0]["content"][0]["content"][0]["text"], "[x] ");
        assert!(
            items[1]["content"][0]["content"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(items[2]["content"][1]["type"], "bulletList");
    }

    #[test]
    fn blockquotes_convert_headings_and_rules_to_readable_paragraphs() {
        let document = convert("> # Heading\n>\n> ---");
        let blocks = document["content"][0]["content"].as_array().unwrap();
        assert_eq!(blocks.len(), 2);
        assert!(blocks.iter().all(|block| block["type"] == "paragraph"));
        assert_eq!(blocks[0]["content"][0]["text"], "Heading");
        assert_eq!(blocks[1]["content"][0]["text"], "---");
    }

    #[test]
    fn plain_text_preserves_punctuation_and_line_breaks_without_marks() {
        let document = plain_text_to_adf_bounded(
            "# literal * punctuation\nsecond line\n\nnext paragraph",
            4_096,
        )
        .unwrap();
        assert_eq!(document["content"].as_array().unwrap().len(), 2);
        assert_eq!(
            document["content"][0]["content"][0]["text"],
            "# literal * punctuation"
        );
        assert_eq!(document["content"][0]["content"][1]["type"], "hardBreak");
        assert!(document["content"][0]["content"][0].get("marks").is_none());
    }

    #[test]
    fn enforces_final_serialized_size_without_truncation() {
        assert_eq!(
            markdown_to_adf_bounded("small", 16),
            Err(ContentWriteError::SizeDenied)
        );
        let document = markdown_to_adf_bounded("small", 256).unwrap();
        assert_eq!(document["content"][0]["content"][0]["text"], "small");
    }

    #[test]
    fn rejects_hostile_nesting_and_event_counts() {
        let deeply_nested = format!("{}x", "> ".repeat(MAX_DEPTH + 8));
        assert_eq!(
            markdown_to_adf_bounded(&deeply_nested, 1_000_000),
            Err(ContentWriteError::ComplexityDenied)
        );

        let event_heavy = "*x* ".repeat(MAX_EVENTS / 2 + 1);
        assert_eq!(
            markdown_to_adf_bounded(&event_heavy, 16_000_000),
            Err(ContentWriteError::ComplexityDenied)
        );
    }

    #[test]
    fn converts_common_mark_to_constrained_confluence_storage() {
        let source = "# Release\n\nA **bold** and *small* ~~change~~ with `code`.\n\n> Quote\n\n- one\n  1. nested\n\n```rust\nfn main() {}\n```\n\n---";
        let storage = convert_storage(source);

        assert_eq!(
            storage,
            "<h1>Release</h1><p>A <strong>bold</strong> and <em>small</em> <s>change</s> with <code>code</code>.</p><blockquote><p>Quote</p></blockquote><ul><li>one<ol><li>nested</li></ol></li></ul><pre><code>fn main() {}\n</code></pre><hr />"
        );
        assert_eq!(storage, convert_storage(source));
    }

    #[test]
    fn confluence_storage_escapes_html_and_only_activates_safe_links() {
        let storage = convert_storage(
            "<script onclick=\"bad()\">alert('&')</script>\n\n[safe](https://example.test/?a=1&b=2) [unsafe](javascript:alert(1)) ![diagram <one>](https://example.test/image.png)",
        );

        assert!(storage.contains("&lt;script onclick=\"bad()\"&gt;alert('&amp;')&lt;/script&gt;"));
        assert!(storage.contains("<a href=\"https://example.test/?a=1&amp;b=2\">safe</a>"));
        assert!(storage.contains("unsafe"));
        assert!(storage.contains("diagram &lt;one&gt;"));
        assert!(!storage.contains("javascript:"));
        assert!(!storage.contains("image.png"));
        assert!(!storage.contains("<script"));
    }

    #[test]
    fn converts_tables_and_ordered_list_starts_to_well_formed_storage() {
        let storage = convert_storage("3. third\n4. fourth\n\n| A | B |\n|---|---|\n| 1 | 2 |");

        assert_eq!(
            storage,
            "<ol start=\"3\"><li>third</li><li>fourth</li></ol><table><thead><tr><th>A</th><th>B</th></tr></thead><tr><td>1</td><td>2</td></tr></table>"
        );
    }

    #[test]
    fn confluence_plain_text_literalizes_markup_and_normalizes_line_endings() {
        let storage = plain_text_to_confluence_storage_bounded(
            "# literal <tag> & *markup*\r\nsecond\rparagraph\r\n\r\nnext",
            4_096,
        )
        .unwrap();

        assert_eq!(
            storage,
            "<p># literal &lt;tag&gt; &amp; *markup*<br />second<br />paragraph</p><p>next</p>"
        );
    }

    #[test]
    fn confluence_conversion_enforces_source_and_output_bounds_without_truncation() {
        assert_eq!(
            markdown_to_confluence_storage_bounded("source exceeds", 8),
            Err(ContentWriteError::SizeDenied)
        );
        assert_eq!(
            markdown_to_confluence_storage_bounded("<&>", 8),
            Err(ContentWriteError::SizeDenied)
        );
        assert_eq!(
            markdown_to_confluence_storage_bounded("<&>", 64).unwrap(),
            "<p>&lt;&amp;&gt;</p>"
        );
        assert_eq!(
            plain_text_to_confluence_storage_bounded("", 6),
            Err(ContentWriteError::SizeDenied)
        );
        assert_eq!(
            plain_text_to_confluence_storage_bounded("", 7).unwrap(),
            "<p></p>"
        );
    }

    #[test]
    fn confluence_conversion_rejects_hostile_depth_and_event_counts() {
        let deeply_nested = format!("{}x", "> ".repeat(MAX_DEPTH + 8));
        assert_eq!(
            markdown_to_confluence_storage_bounded(&deeply_nested, 1_000_000),
            Err(ContentWriteError::ComplexityDenied)
        );

        let event_heavy = "*x* ".repeat(MAX_EVENTS / 2 + 1);
        assert_eq!(
            markdown_to_confluence_storage_bounded(&event_heavy, 16_000_000),
            Err(ContentWriteError::ComplexityDenied)
        );
    }

    #[test]
    fn gitlab_plain_text_escapes_common_mark_and_gitlab_references() {
        let source = "# heading *em* **strong** _under_ ~~strike~~ `code` \\\\ [link](url)\n@user #123 !456 ~789 $label ^up |table| > quote - list + list 1. list";
        let markdown = plain_text_to_gitlab_markdown_bounded(source, 4_096).unwrap();

        assert_eq!(
            markdown,
            "\\# heading \\*em\\* \\*\\*strong\\*\\* \\_under\\_ \\~\\~strike\\~\\~ \\`code\\` \\\\\\\\ \\[link\\]\\(url\\)\n\\@user \\#123 \\!456 \\~789 \\$label \\^up \\|table\\| \\> quote \\- list \\+ list 1\\. list"
        );
        assert_eq!(
            markdown,
            plain_text_to_gitlab_markdown_bounded(source, 4_096).unwrap()
        );
    }

    #[test]
    fn gitlab_plain_text_escapes_every_ascii_punctuation_character() {
        let punctuation = (0_u8..=127)
            .map(char::from)
            .filter(|character| character.is_ascii_punctuation())
            .collect::<String>();
        let expected = punctuation
            .chars()
            .flat_map(|character| ['\\', character])
            .collect::<String>();

        assert_eq!(
            plain_text_to_gitlab_markdown_bounded(&punctuation, 4_096).unwrap(),
            expected
        );
    }

    #[test]
    fn gitlab_plain_text_backslashes_cannot_reenable_markdown_constructs() {
        let source = r"    \#123 \@user \!456 \https://example.test \<tag> \**bold**";
        let markdown = plain_text_to_gitlab_markdown_bounded(source, 4_096).unwrap();
        let mut rendered_text = String::new();

        for event in Parser::new_ext(&markdown, Options::all()) {
            match event {
                Event::Start(Tag::Paragraph) | Event::End(TagEnd::Paragraph) => {}
                Event::Text(text) => rendered_text.push_str(&text),
                unexpected => {
                    panic!("literal Markdown produced a structural event: {unexpected:?}")
                }
            }
        }

        assert_eq!(rendered_text, source);
        assert!(markdown.starts_with("&#32;   \\\\\\#123"));
        assert!(markdown.contains("\\\\\\@user"));
        assert!(markdown.contains("\\\\\\!456"));
        assert!(markdown.contains("\\\\https\\:\\/\\/example\\.test"));
    }

    #[test]
    fn gitlab_plain_text_neutralizes_autolinks_html_and_entities() {
        let markdown = plain_text_to_gitlab_markdown_bounded(
            "https://example.test/a?x=1&y=2 user@example.test <https://example.test>\n<script data-x='&amp;'>alert(1)</script>",
            4_096,
        )
        .unwrap();

        assert_eq!(
            markdown,
            "https\\:\\/\\/example\\.test\\/a\\?x\\=1\\&y\\=2 user\\@example\\.test \\<https\\:\\/\\/example\\.test\\>\n\\<script data\\-x\\=\\'\\&amp\\;\\'\\>alert\\(1\\)\\<\\/script\\>"
        );
    }

    #[test]
    fn gitlab_plain_text_preserves_unicode_and_normalizes_line_endings() {
        let markdown = plain_text_to_gitlab_markdown_bounded(
            "  indented\r\n\tTabbed\rUnicode café 漢字 🚀\n\nlast",
            4_096,
        )
        .unwrap();

        assert_eq!(
            markdown,
            "&#32; indented\n&#9;Tabbed\nUnicode café 漢字 🚀\n\nlast"
        );
    }

    #[test]
    fn gitlab_plain_text_enforces_source_and_expanded_output_bounds() {
        assert_eq!(plain_text_to_gitlab_markdown_bounded("", 0).unwrap(), "");
        assert_eq!(
            plain_text_to_gitlab_markdown_bounded("   ", 3),
            Err(ContentWriteError::SizeDenied)
        );
        assert_eq!(
            plain_text_to_gitlab_markdown_bounded("abcd", 3),
            Err(ContentWriteError::SizeDenied)
        );
        assert_eq!(
            plain_text_to_gitlab_markdown_bounded("#", 1),
            Err(ContentWriteError::SizeDenied)
        );
        assert_eq!(
            plain_text_to_gitlab_markdown_bounded("#", 2).unwrap(),
            "\\#"
        );
        assert_eq!(
            plain_text_to_gitlab_markdown_bounded("plain", 5).unwrap(),
            "plain"
        );
        assert_eq!(
            plain_text_to_gitlab_markdown_bounded(" \n", 6).unwrap(),
            "&#32;\n"
        );
    }
}
