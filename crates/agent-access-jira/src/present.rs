//! Selected rich-content fields in structured Jira results.
use agent_access_content::select_adf_bounded_with_budget;
use agent_access_provider::presentation::*;
use serde_json::Value;

const FORMATS: &[OutputContentFormat] = &[
    OutputContentFormat::Markdown,
    OutputContentFormat::Text,
    OutputContentFormat::Adf,
];

const ISSUE_BODIES: &[EmbeddedBody] = &[
    EmbeddedBody::new(&[], "description", &AdfBody)
        .optional()
        .nullable(),
    EmbeddedBody::new(
        &[
            BodyPathSegment::Field("customFields"),
            BodyPathSegment::Each,
        ],
        "value",
        &AdfBody,
    )
    .nullable()
    .owner_equals(&[("status", "supported"), ("type", "adf")]),
    EmbeddedBody::new(
        &[
            BodyPathSegment::OptionalField("commentPage"),
            BodyPathSegment::Field("comments"),
            BodyPathSegment::Each,
        ],
        "body",
        &AdfBody,
    )
    .optional()
    .nullable(),
];

const NESTED_ISSUE_DESCRIPTION: &[EmbeddedBody] =
    &[
        EmbeddedBody::new(&[BodyPathSegment::Field("issue")], "description", &AdfBody)
            .optional()
            .nullable(),
    ];

const COMMENT_BODY: &[EmbeddedBody] =
    &[
        EmbeddedBody::new(&[BodyPathSegment::Field("comment")], "body", &AdfBody)
            .optional()
            .nullable(),
    ];

const COMMENT_LIST_BODIES: &[EmbeddedBody] = &[EmbeddedBody::new(
    &[BodyPathSegment::Field("comments"), BodyPathSegment::Each],
    "body",
    &AdfBody,
)
.optional()
.nullable()];

pub(super) fn presentation(action: &str) -> Option<ActionPresentation> {
    let bodies = match action {
        "issue.view" => ISSUE_BODIES,
        "issue.create" | "issue.update" => NESTED_ISSUE_DESCRIPTION,
        "comment.view" | "comment.add" | "comment.reply" | "comment.update" => COMMENT_BODY,
        "comment.list" => COMMENT_LIST_BODIES,
        _ => return None,
    };
    Some(ActionPresentation::new(
        bodies,
        FORMATS,
        OutputContentFormat::Adf,
    ))
}

struct AdfBody;

impl EmbeddedBodyCodec for AdfBody {
    fn supported_formats(&self) -> &'static [OutputContentFormat] {
        FORMATS
    }

    fn select(
        &self,
        source: &Value,
        format: OutputContentFormat,
        max_body_bytes: u64,
        budget: &mut RenderBudget,
    ) -> Result<Option<SelectedContent>, RenderError> {
        select_adf_bounded_with_budget(source, format, max_body_bytes, max_body_bytes, budget)
            .map(Some)
            .map_err(|_| RenderError)
    }
}

#[cfg(test)]
mod tests;
