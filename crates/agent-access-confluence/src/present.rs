//! Configured Confluence body selection. Provider results retain their semantic
//! metadata; shared finalization replaces each declared body after authorization.
use super::ConfluenceContentConfig;
use agent_access_content::{
    select_confluence_adf_bounded_with_budget, select_confluence_storage_bounded_with_budget,
    validate_confluence_adf_bounded_with_budget, validate_confluence_storage_bounded_with_budget,
};
use agent_access_provider::presentation::*;
use serde_json::{Map, Value};

const ALL_FORMATS: &[OutputContentFormat] = &[
    OutputContentFormat::Markdown,
    OutputContentFormat::Text,
    OutputContentFormat::Adf,
    OutputContentFormat::Storage,
];
const ADF_FORMATS: &[OutputContentFormat] = &[
    OutputContentFormat::Markdown,
    OutputContentFormat::Text,
    OutputContentFormat::Adf,
];
const STORAGE_FORMATS: &[OutputContentFormat] = &[
    OutputContentFormat::Markdown,
    OutputContentFormat::Text,
    OutputContentFormat::Storage,
];

const PAGE_BODY: &[EmbeddedBody] = &[EmbeddedBody::new(&[], "body", &ConfluenceBodyMap).optional()];
const BLOG_BODY: &[EmbeddedBody] =
    &[EmbeddedBody::new(&[], "body", &ConfluenceBlogStorage).optional()];
const DRAFT_BODY: &[EmbeddedBody] = &[EmbeddedBody::new(&[], "body", &ConfluenceBodyMap)];
// Reads may lose their configured source on reload. Provider construction still
// requires the configured source; optional metadata is for clients of old catalogs.
const COMMENT_READ_BODY: &[EmbeddedBody] = &[EmbeddedBody::new(
    &[BodyPathSegment::Field("comment")],
    "body",
    &ConfluenceBodyMap,
)
.optional()];
const COMMENT_WRITE_BODY: &[EmbeddedBody] = &[EmbeddedBody::new(
    &[BodyPathSegment::Field("comment")],
    "body",
    &ConfluenceBodyMap,
)];
const COMMENT_BODIES: &[EmbeddedBody] = &[EmbeddedBody::new(
    &[BodyPathSegment::Field("comments"), BodyPathSegment::Each],
    "body",
    &ConfluenceBodyMap,
)
.optional()];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyKind {
    Page,
    Blog,
    Draft,
    CommentRead,
    CommentWrite,
    Comments,
}
const BODY_ACTIONS: &[(&str, BodyKind)] = &[
    ("page.view", BodyKind::Page),
    ("blog.view", BodyKind::Blog),
    ("page.draft.view", BodyKind::Draft),
    ("blog.draft.view", BodyKind::Draft),
    ("page.footer_comment.list", BodyKind::Comments),
    ("page.footer_comment.view", BodyKind::CommentRead),
    ("page.footer_comment.reply.list", BodyKind::Comments),
    ("page.inline_comment.list", BodyKind::Comments),
    ("page.inline_comment.view", BodyKind::CommentRead),
    ("page.inline_comment.reply.list", BodyKind::Comments),
    ("blog.footer_comment.list", BodyKind::Comments),
    ("blog.footer_comment.view", BodyKind::CommentRead),
    ("blog.footer_comment.reply.list", BodyKind::Comments),
    ("blog.inline_comment.list", BodyKind::Comments),
    ("blog.inline_comment.view", BodyKind::CommentRead),
    ("blog.inline_comment.reply.list", BodyKind::Comments),
    ("page.footer_comment.add", BodyKind::CommentWrite),
    ("blog.footer_comment.add", BodyKind::CommentWrite),
    ("page.footer_comment.update", BodyKind::CommentWrite),
    ("page.inline_comment.update", BodyKind::CommentWrite),
    ("blog.footer_comment.update", BodyKind::CommentWrite),
    ("blog.inline_comment.update", BodyKind::CommentWrite),
    ("page.footer_comment.reply.add", BodyKind::CommentWrite),
    ("page.inline_comment.reply.add", BodyKind::CommentWrite),
    ("blog.footer_comment.reply.add", BodyKind::CommentWrite),
    ("blog.inline_comment.reply.add", BodyKind::CommentWrite),
];

pub(super) fn presentation(
    action: &str,
    config: &ConfluenceContentConfig,
) -> Option<ActionPresentation> {
    let kind = BODY_ACTIONS.iter().find(|(name, _)| *name == action)?.1;
    let (bodies, formats, native) = match kind {
        BodyKind::Page => {
            let adf = config
                .page_formats
                .iter()
                .any(|format| format == "atlas_doc_format");
            let storage = config.page_formats.iter().any(|format| format == "storage");
            let (formats, native) = match (adf, storage) {
                (true, true) => (ALL_FORMATS, OutputContentFormat::Adf),
                (true, false) => (ADF_FORMATS, OutputContentFormat::Adf),
                (false, true) => (STORAGE_FORMATS, OutputContentFormat::Storage),
                (false, false) => return None,
            };
            (PAGE_BODY, formats, native)
        }
        BodyKind::Blog => (BLOG_BODY, STORAGE_FORMATS, OutputContentFormat::Storage),
        BodyKind::Draft => (DRAFT_BODY, STORAGE_FORMATS, OutputContentFormat::Storage),
        BodyKind::CommentRead | BodyKind::CommentWrite | BodyKind::Comments => {
            if !config
                .comment_formats
                .iter()
                .any(|format| format == "storage")
            {
                return None;
            }
            let bodies = match kind {
                BodyKind::CommentRead => COMMENT_READ_BODY,
                BodyKind::CommentWrite => COMMENT_WRITE_BODY,
                BodyKind::Comments => COMMENT_BODIES,
                _ => unreachable!("only comment kinds reach this arm"),
            };
            (bodies, STORAGE_FORMATS, OutputContentFormat::Storage)
        }
    };
    Some(ActionPresentation::new(bodies, formats, native))
}

struct ConfluenceBodyMap;
impl EmbeddedBodyCodec for ConfluenceBodyMap {
    fn supported_formats(&self) -> &'static [OutputContentFormat] {
        ALL_FORMATS
    }

    fn select(
        &self,
        source: &Value,
        format: OutputContentFormat,
        max_body_bytes: u64,
        budget: &mut RenderBudget,
    ) -> Result<Option<SelectedContent>, RenderError> {
        let source = source.as_object().ok_or(RenderError)?;
        let adf = representation(source, "atlas_doc_format")?;
        let storage = representation(source, "storage")?;
        let use_adf = match format {
            OutputContentFormat::Markdown | OutputContentFormat::Text => adf.is_some(),
            OutputContentFormat::Adf => true,
            OutputContentFormat::Storage => false,
            _ => return Err(RenderError),
        };
        let mut selected = None;
        if let Some(source) = adf {
            if use_adf {
                selected = Some(
                    select_confluence_adf_bounded_with_budget(
                        source,
                        format,
                        max_body_bytes,
                        max_body_bytes,
                        budget,
                    )
                    .map_err(|_| RenderError)?,
                );
            } else {
                validate_confluence_adf_bounded_with_budget(source, max_body_bytes, budget)
                    .map_err(|_| RenderError)?;
            }
        }
        if let Some(source) = storage {
            if !use_adf {
                selected = Some(
                    select_confluence_storage_bounded_with_budget(
                        source,
                        format,
                        max_body_bytes,
                        max_body_bytes,
                        budget,
                    )
                    .map_err(|_| RenderError)?,
                );
            } else {
                validate_confluence_storage_bounded_with_budget(source, max_body_bytes, budget)
                    .map_err(|_| RenderError)?;
            }
        }
        Ok(selected)
    }
}

fn representation<'a>(
    source: &'a Map<String, Value>,
    name: &str,
) -> Result<Option<&'a str>, RenderError> {
    let Some(value) = source.get(name) else {
        return Ok(None);
    };
    let value = value.as_object().ok_or(RenderError)?;
    if value.get("representation").and_then(Value::as_str) != Some(name) {
        return Err(RenderError);
    }
    value
        .get("value")
        .and_then(Value::as_str)
        .map(Some)
        .ok_or(RenderError)
}

// The native blog adapter returns bare storage text inside its body map.
struct ConfluenceBlogStorage;
impl EmbeddedBodyCodec for ConfluenceBlogStorage {
    fn supported_formats(&self) -> &'static [OutputContentFormat] {
        STORAGE_FORMATS
    }

    fn select(
        &self,
        source: &Value,
        format: OutputContentFormat,
        max_body_bytes: u64,
        budget: &mut RenderBudget,
    ) -> Result<Option<SelectedContent>, RenderError> {
        let source = source.as_object().ok_or(RenderError)?;
        let Some(storage) = source.get("storage") else {
            return Ok(None);
        };
        let storage = storage.as_str().ok_or(RenderError)?;
        select_confluence_storage_bounded_with_budget(
            storage,
            format,
            max_body_bytes,
            max_body_bytes,
            budget,
        )
        .map(Some)
        .map_err(|_| RenderError)
    }
}

#[cfg(test)]
mod tests;
