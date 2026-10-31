//! Jira response presentation: which results carry embedded upstream
//! bodies, how those bodies render, and the whole-result Markdown templates.
use agent_access_content::render_adf_bounded_with_budget;
use agent_access_provider::presentation::*;
use serde_json::{Map, Value};

#[cfg(test)]
#[path = "../tests/fixtures/custom_fields.rs"]
mod custom_fields_fixture;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WholeRenderer {
    ProjectList,
    ProjectView,
    IssueTypeList,
    Issue,
    Search,
    CommentList,
    Comment,
    PropertyList,
    Property,
    AttachmentList,
    Verify,
}

#[derive(Debug, Clone, Copy)]
struct ResultDescriptor {
    action: &'static str,
    embedded_bodies: &'static [EmbeddedBody],
    whole: Option<WholeRenderer>,
}

const NO_BODIES: &[EmbeddedBody] = &[];

const ISSUE_BODIES: &[EmbeddedBody] = &[
    EmbeddedBody::new(&[], &AdfBody("description")),
    EmbeddedBody::new(
        &[
            BodyPathSegment::Field("customFields"),
            BodyPathSegment::Each,
        ],
        &CustomFieldBody,
    ),
    EmbeddedBody::new(
        &[
            BodyPathSegment::OptionalField("commentPage"),
            BodyPathSegment::Field("comments"),
            BodyPathSegment::Each,
        ],
        &AdfBody("body"),
    ),
];

const NESTED_ISSUE_DESCRIPTION: &[EmbeddedBody] = &[EmbeddedBody::new(
    &[BodyPathSegment::Field("issue")],
    &AdfBody("description"),
)];

const COMMENT_BODY: &[EmbeddedBody] = &[EmbeddedBody::new(
    &[BodyPathSegment::Field("comment")],
    &AdfBody("body"),
)];

const COMMENT_LIST_BODIES: &[EmbeddedBody] = &[EmbeddedBody::new(
    &[BodyPathSegment::Field("comments"), BodyPathSegment::Each],
    &AdfBody("body"),
)];

const RESULT_DESCRIPTORS: &[ResultDescriptor] = &[
    ResultDescriptor {
        action: "project.list",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::ProjectList),
    },
    ResultDescriptor {
        action: "project.view",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::ProjectView),
    },
    ResultDescriptor {
        action: "issue_type.list",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::IssueTypeList),
    },
    ResultDescriptor {
        action: "issue.view",
        embedded_bodies: ISSUE_BODIES,
        whole: Some(WholeRenderer::Issue),
    },
    ResultDescriptor {
        action: "issue.create",
        embedded_bodies: NESTED_ISSUE_DESCRIPTION,
        whole: None,
    },
    ResultDescriptor {
        action: "issue.update",
        embedded_bodies: NESTED_ISSUE_DESCRIPTION,
        whole: None,
    },
    ResultDescriptor {
        action: "comment.view",
        embedded_bodies: COMMENT_BODY,
        whole: Some(WholeRenderer::Comment),
    },
    ResultDescriptor {
        action: "comment.add",
        embedded_bodies: COMMENT_BODY,
        whole: None,
    },
    ResultDescriptor {
        action: "comment.reply",
        embedded_bodies: COMMENT_BODY,
        whole: None,
    },
    ResultDescriptor {
        action: "comment.update",
        embedded_bodies: COMMENT_BODY,
        whole: None,
    },
    ResultDescriptor {
        action: "search",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::Search),
    },
    ResultDescriptor {
        action: "comment.list",
        embedded_bodies: COMMENT_LIST_BODIES,
        whole: Some(WholeRenderer::CommentList),
    },
    ResultDescriptor {
        action: "comment.property.list",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::PropertyList),
    },
    ResultDescriptor {
        action: "comment.property.get",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::Property),
    },
    ResultDescriptor {
        action: "attachment.list",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::AttachmentList),
    },
    ResultDescriptor {
        action: "verify",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::Verify),
    },
];

/// The presentation of `action`'s results, if it has one.
pub(super) fn presentation(action: &str) -> Option<ActionPresentation> {
    descriptor(action).map(|descriptor| {
        ActionPresentation::new(
            descriptor.embedded_bodies,
            descriptor
                .whole
                .as_ref()
                .map(|whole| whole as &'static dyn WholeResultRenderer),
        )
    })
}

fn descriptor(action: &str) -> Option<&'static ResultDescriptor> {
    RESULT_DESCRIPTORS
        .iter()
        .find(|descriptor| descriptor.action == action)
}

/// An ADF document in a named field of each owner.
struct AdfBody(&'static str);

impl EmbeddedBodyCodec for AdfBody {
    fn render(
        &self,
        owner: &Map<String, Value>,
        format: ReadContentFormat,
        max_body_bytes: u64,
        budget: &mut RenderBudget,
    ) -> Result<Option<RenderedBody>, RenderError> {
        let Some(native) = owner.get(self.0).filter(|native| !native.is_null()) else {
            return Ok(None);
        };
        render_adf_bounded_with_budget(native, format, max_body_bytes, max_body_bytes, budget)
            .map_err(|_| RenderError)
    }
}

/// Only the provider's supported ADF projection declares a rich-content body.
struct CustomFieldBody;

impl EmbeddedBodyCodec for CustomFieldBody {
    fn render(
        &self,
        owner: &Map<String, Value>,
        format: ReadContentFormat,
        max_body_bytes: u64,
        budget: &mut RenderBudget,
    ) -> Result<Option<RenderedBody>, RenderError> {
        if owner.get("status").and_then(Value::as_str) != Some("supported")
            || owner.get("type").and_then(Value::as_str) != Some("adf")
        {
            return Ok(None);
        }
        AdfBody("value").render(owner, format, max_body_bytes, budget)
    }
}

impl WholeResultRenderer for WholeRenderer {
    fn render(&self, result: &Value, context: &mut RenderContext) -> Result<(), RenderError> {
        let RenderContext {
            out,
            max_body_bytes,
            budget,
            ..
        } = context;
        let max_body_bytes = *max_body_bytes;
        match *self {
            WholeRenderer::ProjectList => render_project_list(result, out, budget)?,
            WholeRenderer::ProjectView => render_project_view(result, out, budget)?,
            WholeRenderer::IssueTypeList => render_issue_type_list(result, out, budget)?,
            WholeRenderer::Issue => render_issue(result, true, "# ", out, max_body_bytes, budget)?,
            WholeRenderer::Search => render_search(result, out, budget)?,
            WholeRenderer::CommentList => render_comment_list(result, out, max_body_bytes, budget)?,
            WholeRenderer::Comment => render_comment_view(result, out, max_body_bytes, budget)?,
            WholeRenderer::PropertyList => render_property_list(result, out, budget)?,
            WholeRenderer::Property => render_property(result, out, budget)?,
            WholeRenderer::AttachmentList => render_attachment_list(result, out, budget)?,
            WholeRenderer::Verify => render_verify(result, out, budget)?,
        }
        Ok(())
    }
}

fn render_issue(
    value: &Value,
    include_view_details: bool,
    heading: &str,
    out: &mut MarkdownWriter,
    max_body_bytes: u64,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    budget.charge_work(object.len())?;
    let key = required_scalar(object, "key")?;
    let summary = optional_scalar(object, "summary")?;
    out.push(heading)?;
    out.push_code(key)?;
    if let Some(summary) = summary {
        out.push(" — ")?;
        out.push_heading_text(summary)?;
    }
    out.push("\n")?;
    code_fields(
        out,
        &[
            ("ID", optional_scalar(object, "id")?),
            ("Project", optional_scalar(object, "project")?),
        ],
    )?;
    fields(
        out,
        &[
            ("Status", optional_scalar(object, "status")?),
            ("Issue type", optional_scalar(object, "issueType")?),
        ],
    )?;
    if let Some(priority) = object.get("priority").filter(|value| !value.is_null()) {
        field_raw(out, "Priority", &render_named_object(priority)?)?;
    }
    for (label, key) in [
        ("Assignee", "assignee"),
        ("Reporter", "reporter"),
        ("Creator", "creator"),
    ] {
        if let Some(user) = object.get(key).filter(|value| !value.is_null()) {
            field_raw(out, label, &render_user(user)?)?;
        }
    }
    if let Some(labels) = object.get("labels").filter(|value| !value.is_null()) {
        let labels = array(labels)?;
        budget.charge_work(labels.len())?;
        let labels = labels.iter().map(scalar).collect::<Result<Vec<_>, _>>()?;
        out.push("- Labels: ")?;
        for (index, label) in labels.iter().enumerate() {
            if index > 0 {
                out.push(", ")?;
            }
            out.push_code(label)?;
        }
        out.push("\n")?;
    }
    code_fields(
        out,
        &[
            ("Created", optional_scalar(object, "created")?),
            ("Updated", optional_scalar(object, "updated")?),
        ],
    )?;
    if let Some(url) = optional_scalar(object, "webUrl")? {
        field_url(out, "URL", url)?;
    }
    if include_view_details {
        render_issue_context(object, out, budget)?;
        render_issue_hierarchy(object, out, budget)?;
    }
    if include_view_details && let Some(links) = object.get("issueLinks") {
        let links = array(links)?;
        budget.charge_work(links.len())?;
        out.push("\n## Issue links\n\n")?;
        if links.is_empty() {
            out.push("None.\n")?;
        }
        for link in links {
            let link = as_object(link)?;
            budget.charge_work(link.len())?;
            out.push("- This issue ")?;
            out.push_escaped(required_scalar(link, "relationship")?)?;
            out.push(" ")?;
            out.push_code(required_scalar(link, "key")?)?;
            out.push(" (type: ")?;
            out.push_escaped(required_scalar(link, "type")?)?;
            out.push("; direction: ")?;
            out.push_escaped(required_scalar(link, "direction")?)?;
            if let Some(issue_type) = optional_scalar(link, "issueType")? {
                out.push("; issue type: ")?;
                out.push_escaped(issue_type)?;
            }
            out.push(")")?;
            if let Some(summary) = optional_scalar(link, "summary")? {
                out.push(" — ")?;
                out.push_escaped(summary)?;
            }
            out.push("\n")?;
        }
    }
    if include_view_details
        && let Some(description) = object.get("description").filter(|value| !value.is_null())
    {
        let rendered = render_adf_bounded_with_budget(
            description,
            ReadContentFormat::Markdown,
            max_body_bytes,
            max_body_bytes,
            &mut budget.rich_content,
        )
        .map_err(|_| RenderError)?
        .ok_or(RenderError)?;
        out.push("\n## Description\n\n")?;
        out.push(&rendered.value)?;
        out.push("\n")?;
    }
    if include_view_details {
        render_custom_fields(
            required(object, "customFields")?,
            out,
            max_body_bytes,
            budget,
        )?;
        if let Some(page) = object.get("commentPage") {
            out.push("\n## Comments\n")?;
            render_comment_page(as_object(page)?, out, max_body_bytes, budget, true)?;
        }
    }
    Ok(())
}

fn render_issue_context(
    object: &Map<String, Value>,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    if let Some(resolution) = object.get("resolution").filter(|value| !value.is_null()) {
        out.push("- Resolution: ")?;
        render_context_named_object(resolution, out, budget)?;
        out.push("\n")?;
    }
    code_fields(
        out,
        &[
            (
                "Resolution date",
                optional_scalar(object, "resolutionDate")?,
            ),
            ("Due date", optional_scalar(object, "dueDate")?),
        ],
    )?;
    if let Some(category) = object
        .get("statusCategory")
        .filter(|value| !value.is_null())
    {
        let category = as_object(category)?;
        budget.charge_work(category.len())?;
        let id = required(category, "id")?.as_u64().ok_or(RenderError)?;
        let key = required_scalar(category, "key")?;
        out.push("- Status category: ")?;
        if let Some(name) = optional_scalar(category, "name")? {
            out.push_escaped(name)?;
            out.push(" (key: ")?;
            out.push_code(key)?;
            out.push("; ID: ")?;
        } else {
            out.push_code(key)?;
            out.push(" (ID: ")?;
        }
        out.push_code(&id.to_string())?;
        out.push(")\n")?;
    }
    for (key, heading, label) in [
        ("components", "Components", "Component"),
        ("fixVersions", "Fix versions", "Version"),
        ("affectedVersions", "Affected versions", "Version"),
    ] {
        let Some(values) = object.get(key).filter(|value| !value.is_null()) else {
            continue;
        };
        let values = array(values)?;
        budget.charge_work(values.len())?;
        out.push("\n## ")?;
        out.push(heading)?;
        out.push("\n\n")?;
        if values.is_empty() {
            out.push("None.\n")?;
        }
        for value in values {
            out.push("- ")?;
            out.push(label)?;
            out.push(": ")?;
            render_context_named_object(value, out, budget)?;
            out.push("\n")?;
        }
    }
    Ok(())
}

fn render_context_named_object(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    budget.charge_work(object.len())?;
    let id = required_scalar(object, "id")?;
    if let Some(name) = optional_scalar(object, "name")? {
        out.push_escaped(name)?;
        out.push(" (ID: ")?;
        out.push_code(id)?;
        out.push(")")
    } else {
        out.push_code(id)
    }
}

fn render_issue_hierarchy(
    object: &Map<String, Value>,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    if let Some(parent) = object.get("parent") {
        out.push("\n## Parent\n\n")?;
        if parent.is_null() {
            out.push("No parent returned.\n")?;
        } else {
            out.push("- Parent: ")?;
            render_issue_reference(parent, out, budget)?;
            out.push("\n")?;
        }
    }
    if let Some(subtasks) = object.get("subtasks") {
        let subtasks = array(subtasks)?;
        budget.charge_work(subtasks.len())?;
        out.push("\n## Subtasks\n\n")?;
        if subtasks.is_empty() {
            out.push("None.\n")?;
        }
        for subtask in subtasks {
            out.push("- Subtask: ")?;
            render_issue_reference(subtask, out, budget)?;
            out.push("\n")?;
        }
    }
    Ok(())
}

fn render_issue_reference(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let issue = as_object(value)?;
    budget.charge_work(issue.len())?;
    out.push_code(required_scalar(issue, "key")?)?;
    if let Some(issue_type) = optional_scalar(issue, "issueType")? {
        out.push(" (issue type: ")?;
        out.push_escaped(issue_type)?;
        out.push(")")?;
    }
    if let Some(summary) = optional_scalar(issue, "summary")? {
        out.push(" — ")?;
        out.push_escaped(summary)?;
    }
    Ok(())
}

fn render_custom_fields(
    value: &Value,
    out: &mut MarkdownWriter,
    max_body_bytes: u64,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let fields = array(value)?;
    budget.charge_work(fields.len())?;
    out.push("\n## Custom fields\n\n")?;
    if fields.is_empty() {
        return out.push("No custom fields returned.\n");
    }
    for field_value in fields {
        let entry = as_object(field_value)?;
        budget.charge_work(entry.len())?;
        out.push("### ")?;
        if let Some(name) = optional_scalar(entry, "name")? {
            out.push_heading_text(name)?;
            out.push(" (")?;
            out.push_code(required_scalar(entry, "id")?)?;
            out.push(")")?;
        } else {
            out.push_code(required_scalar(entry, "id")?)?;
        }
        out.push("\n\n")?;
        if let Some(kind) = optional_scalar(entry, "type")? {
            field_code(out, "Type", kind)?;
        }
        let status = required_scalar(entry, "status")?;
        match status {
            "supported" => {}
            "unsupported" | "withheld" => field_code(out, "Status", status)?,
            _ => return Err(RenderError),
        }
        let value = entry.get("value");
        if value.is_some_and(|value| value.is_null() || value.as_array().is_some_and(Vec::is_empty))
        {
            out.push("- Value: not set\n\n")?;
            continue;
        }
        if status != "supported" {
            out.push("\n")?;
            continue;
        }
        let value = value.ok_or(RenderError)?;
        match required_scalar(entry, "type")? {
            "text" => field(out, "Value", scalar(value)?)?,
            "url" | "date" | "datetime" => field_code(out, "Value", scalar(value)?)?,
            "number" => {
                let Value::Number(number) = value else {
                    return Err(RenderError);
                };
                field(out, "Value", &number.to_string())?;
            }
            "option" | "cascadingOption" => {
                out.push("- Value: ")?;
                render_custom_option(value, out, budget)?;
                if required_scalar(entry, "type")? == "cascadingOption"
                    && let Some(child) = value.get("child").filter(|child| !child.is_null())
                {
                    out.push(" → ")?;
                    render_custom_option(child, out, budget)?;
                }
                out.push("\n")?;
            }
            "user" => {
                budget.charge_work(as_object(value)?.len())?;
                field_raw(out, "Value", &render_user(value)?)?;
            }
            "labels" => {
                let values = array(value)?;
                budget.charge_work(values.len())?;
                out.push("\nValues:\n\n")?;
                for value in values {
                    out.push("- Label: ")?;
                    out.push_code(scalar(value)?)?;
                    out.push("\n")?;
                }
            }
            "options" | "users" => {
                let values = array(value)?;
                budget.charge_work(values.len())?;
                out.push("\nValues:\n\n")?;
                for value in values {
                    if required_scalar(entry, "type")? == "options" {
                        out.push("- Option: ")?;
                        render_custom_option(value, out, budget)?;
                    } else {
                        out.push("- User: ")?;
                        budget.charge_work(as_object(value)?.len())?;
                        out.push(&render_user(value)?)?;
                    }
                    out.push("\n")?;
                }
            }
            "adf" => {
                let rendered = render_adf_bounded_with_budget(
                    value,
                    ReadContentFormat::Markdown,
                    max_body_bytes,
                    max_body_bytes,
                    &mut budget.rich_content,
                )
                .map_err(|_| RenderError)?
                .ok_or(RenderError)?;
                out.push("\n")?;
                out.push(&rendered.value)?;
                out.push("\n")?;
            }
            _ => return Err(RenderError),
        }
        out.push("\n")?;
    }
    Ok(())
}

fn render_custom_option(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let option = as_object(value)?;
    budget.charge_work(option.len())?;
    out.push_escaped(required_scalar(option, "value")?)?;
    out.push(" (ID: ")?;
    out.push_code(required_scalar(option, "id")?)?;
    out.push(")")
}

fn render_issue_type_list(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let issue_types = array(required(object, "issueTypes")?)?;
    budget.charge_work(issue_types.len().saturating_add(object.len()))?;
    out.push("# Jira issue types for ")?;
    out.push_code(required_scalar(object, "project")?)?;
    out.push("\n")?;
    field(out, "Count", &issue_types.len().to_string())?;
    if issue_types.is_empty() {
        out.push("\nNo results.\n")?;
    }
    for issue_type in issue_types {
        let item = as_object(issue_type)?;
        budget.charge_work(item.len())?;
        out.push("\n## ")?;
        out.push_heading_text(required_scalar(item, "name")?)?;
        out.push("\n")?;
        code_fields(out, &[("ID", Some(required_scalar(item, "id")?))])?;
        let subtask = optional_display(item, "subtask")?;
        field(out, "Subtask", subtask.as_deref().ok_or(RenderError)?)?;
        field(out, "Description", required_scalar(item, "description")?)?;
    }
    out.push("\n## Pagination\n")?;
    for (label, key) in [
        ("Start at", "startAt"),
        ("Maximum results", "maxResults"),
        ("Total", "total"),
        ("Last page", "isLast"),
        ("Next start at", "nextStartAt"),
    ] {
        if let Some(value) = optional_display(object, key)? {
            field(out, label, &value)?;
        }
    }
    Ok(())
}

fn render_project_view(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let project = as_object(required(object, "project")?)?;
    budget.charge_work(object.len().saturating_add(project.len()))?;
    out.push("# Jira project ")?;
    out.push_code(required_scalar(project, "key")?)?;
    out.push("\n\n")?;
    for (key, label) in [
        ("id", "ID"),
        ("name", "Name"),
        ("description", "Description"),
        ("webUrl", "Web URL"),
        ("previewTruncated", "Preview truncated"),
    ] {
        if let Some(value) = optional_display(project, key)? {
            field(out, label, &value)?;
        }
    }
    for (key, label) in [
        ("fields", "Searchable fields"),
        ("versions", "Versions"),
        ("components", "Components"),
        ("issueTypes", "Issue types"),
        ("statuses", "Statuses"),
    ] {
        let Some(section) = object.get(key) else {
            continue;
        };
        let section = as_object(section)?;
        let items = array(required(section, "items")?)?;
        budget.charge_work(section.len().saturating_add(items.len()))?;
        out.push("\n## ")?;
        out.push(label)?;
        out.push("\n\n")?;
        for (key, label) in [("count", "Count"), ("truncated", "Truncated")] {
            field(
                out,
                label,
                &optional_display(section, key)?.ok_or(RenderError)?,
            )?;
        }
        for item in items {
            let item = as_object(item)?;
            budget.charge_work(item.len())?;
            out.push("\n### ")?;
            out.push_heading_text(required_scalar(item, "name")?)?;
            out.push("\n")?;
            code_fields(
                out,
                &[
                    ("ID", optional_scalar(item, "id")?),
                    ("JQL reference", optional_scalar(item, "jqlReference")?),
                ],
            )?;
            for (key, label) in [
                ("description", "Description"),
                ("released", "Released"),
                ("archived", "Archived"),
                ("releaseDate", "Release date"),
                ("startDate", "Start date"),
                ("subtask", "Subtask"),
                ("previewTruncated", "Preview truncated"),
            ] {
                if let Some(value) = optional_display(item, key)? {
                    field(out, label, &value)?;
                }
            }
            for (key, label) in [("types", "Types"), ("operators", "Operators")] {
                if let Some(values) = item.get(key) {
                    let values = array(values)?;
                    budget.charge_work(values.len())?;
                    let values = values.iter().map(scalar).collect::<Result<Vec<_>, _>>()?;
                    field(out, label, &values.join(", "))?;
                }
            }
            if let Some(category) = item.get("statusCategory") {
                let category = as_object(category)?;
                budget.charge_work(category.len())?;
                for (key, label) in [
                    ("id", "Status category ID"),
                    ("key", "Status category key"),
                    ("name", "Status category"),
                    ("previewTruncated", "Status category preview truncated"),
                ] {
                    if let Some(value) = optional_display(category, key)? {
                        field(out, label, &value)?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn render_project_list(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let items = array(required(object, "items")?)?;
    budget.charge_work(items.len().saturating_add(object.len()))?;
    out.push("# Jira projects\n\n")?;
    field(out, "Count", &items.len().to_string())?;
    for item in items {
        let item = as_object(item)?;
        budget.charge_work(item.len())?;
        out.push("\n## ")?;
        out.push_heading_text(scalar(required(item, "key")?)?)?;
        out.push("\n\n")?;
        for (key, label) in [
            ("id", "ID"),
            ("name", "Name"),
            ("projectTypeKey", "Project type"),
            ("webUrl", "Web URL"),
            ("previewTruncated", "Preview truncated"),
        ] {
            if let Some(value) = optional_display(item, key)? {
                field(out, label, &value)?;
            }
        }
    }
    out.push("\n## Pagination\n\n")?;
    for (key, label) in [
        ("maxResults", "Maximum results"),
        ("scanStatus", "Scan status"),
    ] {
        if let Some(value) = optional_display(object, key)? {
            field(out, label, &value)?;
        }
    }
    if let Some(token) = optional_scalar(object, "nextPageToken")? {
        out.push("- Next page token: ")?;
        out.push_code(token)?;
        out.push("\n")?;
    }
    Ok(())
}

fn render_search(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let issues = array(required(object, "issues")?)?;
    budget.charge_work(issues.len().saturating_add(object.len()))?;
    out.push("# Jira issue search\n\n")?;
    field(out, "Count", &issues.len().to_string())?;
    if issues.is_empty() {
        out.push("\nNo results.\n")?;
    } else {
        for issue in issues {
            out.push("\n")?;
            render_issue(issue, false, "## ", out, 0, budget)?;
        }
    }
    out.push("\n## Pagination\n")?;
    let maximum_results = optional_display(object, "maxResults")?;
    let start_at = optional_display(object, "startAt")?;
    let total = optional_display(object, "total")?;
    let last_page = optional_display(object, "isLast")?;
    fields(
        out,
        &[
            ("Maximum results", maximum_results.as_deref()),
            ("Start at", start_at.as_deref()),
            ("Total", total.as_deref()),
            ("Last page", last_page.as_deref()),
        ],
    )?;
    if let Some(token) = optional_scalar(object, "nextPageToken")? {
        out.push("- Next page token: ")?;
        out.push_code(token)?;
        out.push("\n")?;
    }
    Ok(())
}

fn render_comment_list(
    value: &Value,
    out: &mut MarkdownWriter,
    max_body_bytes: u64,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let issue = as_object(required(object, "issue")?)?;
    out.push("# Jira comments for ")?;
    out.push_code(required_scalar(issue, "key")?)?;
    out.push("\n")?;
    render_issue_metadata(issue, out)?;
    render_comment_page(object, out, max_body_bytes, budget, false)
}

fn render_comment_page(
    object: &Map<String, Value>,
    out: &mut MarkdownWriter,
    max_body_bytes: u64,
    budget: &mut PresentationBudget,
    embedded: bool,
) -> Result<(), RenderError> {
    let comments = array(required(object, "comments")?)?;
    budget.charge_work(comments.len().saturating_add(object.len()))?;
    field(out, "Count", &comments.len().to_string())?;
    if let Some(include_bodies) = optional_display(object, "includeBodies")? {
        field(out, "Bodies included", &include_bodies)?;
    }
    if comments.is_empty() {
        out.push("\nNo results.\n")?;
    }
    for comment in comments {
        let comment = as_object(comment)?;
        budget.charge_work(comment.len())?;
        out.push("\n")?;
        out.push(if embedded {
            "### Comment "
        } else {
            "## Comment "
        })?;
        out.push_code(required_scalar(comment, "commentId")?)?;
        out.push("\n")?;
        render_comment_fields(comment, out)?;
        render_comment_body(
            comment,
            out,
            max_body_bytes,
            budget,
            if embedded { "#### Body" } else { "### Body" },
        )?;
    }
    out.push(if embedded {
        "\n### Pagination\n"
    } else {
        "\n## Pagination\n"
    })?;
    let start_at = optional_display(object, "startAt")?;
    let maximum_results = optional_display(object, "maxResults")?;
    let total = match object.get("total") {
        Some(Value::Null) => Some("unknown".to_string()),
        _ => optional_display(object, "total")?,
    };
    let is_last = match object.get("isLast") {
        Some(Value::Null) => Some("unknown".to_string()),
        _ => optional_display(object, "isLast")?,
    };
    let next_start_at = optional_display(object, "nextStartAt")?;
    fields(
        out,
        &[
            ("Start at", start_at.as_deref()),
            ("Maximum results", maximum_results.as_deref()),
            ("Total", total.as_deref()),
            ("Last page", is_last.as_deref()),
            ("Next start at", next_start_at.as_deref()),
        ],
    )?;
    if let Some(order) = optional_scalar(object, "orderBy")? {
        field_code(out, "Order by", order)?;
    }
    if let Some(limit) = optional_scalar(object, "limitedBy")? {
        field_code(out, "Limited by", limit)?;
    }
    Ok(())
}

fn render_comment_view(
    value: &Value,
    out: &mut MarkdownWriter,
    max_body_bytes: u64,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let issue = as_object(required(object, "issue")?)?;
    let comment = as_object(required(object, "comment")?)?;
    budget.charge_work(object.len().saturating_add(comment.len()))?;
    out.push("# Jira comment ")?;
    out.push_code(required_scalar(comment, "commentId")?)?;
    out.push(" on ")?;
    out.push_code(required_scalar(issue, "key")?)?;
    out.push("\n")?;
    render_issue_metadata(issue, out)?;
    render_comment_fields(comment, out)?;
    render_comment_body(comment, out, max_body_bytes, budget, "## Body")
}

fn render_comment_body(
    comment: &Map<String, Value>,
    out: &mut MarkdownWriter,
    max_body_bytes: u64,
    budget: &mut PresentationBudget,
    heading: &str,
) -> Result<(), RenderError> {
    if let Some(body) = comment.get("body").filter(|value| !value.is_null()) {
        let rendered = render_adf_bounded_with_budget(
            body,
            ReadContentFormat::Markdown,
            max_body_bytes,
            max_body_bytes,
            &mut budget.rich_content,
        )
        .map_err(|_| RenderError)?
        .ok_or(RenderError)?;
        out.push("\n")?;
        out.push(heading)?;
        out.push("\n\n")?;
        out.push(&rendered.value)?;
        out.push("\n")?;
    }
    Ok(())
}

fn render_property_list(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let issue = as_object(required(object, "issue")?)?;
    let keys = array(required(object, "keys")?)?;
    budget.charge_work(keys.len().saturating_add(object.len()))?;
    out.push("# Jira comment properties\n")?;
    render_issue_metadata(issue, out)?;
    field_code(out, "Comment ID", required_scalar(object, "commentId")?)?;
    field(out, "Count", &keys.len().to_string())?;
    if keys.is_empty() {
        out.push("\nNo results.\n")?;
    } else {
        out.push("\n## Keys\n")?;
        for key in keys {
            out.push("- ")?;
            out.push_code(required_scalar(as_object(key)?, "key")?)?;
            out.push("\n")?;
        }
    }
    Ok(())
}

fn render_property(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let issue = as_object(required(object, "issue")?)?;
    budget.charge_work(object.len())?;
    out.push("# Jira comment property ")?;
    out.push_code(required_scalar(object, "propertyKey")?)?;
    out.push("\n")?;
    render_issue_metadata(issue, out)?;
    field_code(out, "Comment ID", required_scalar(object, "commentId")?)?;
    let json =
        serialize_json_pretty_bounded(object.get("value").ok_or(RenderError)?, out.remaining())?;
    let fence = fence_for(&json, '`');
    out.push("\n## Value\n\n")?;
    out.push(&fence)?;
    out.push("json\n")?;
    out.push(&json)?;
    out.push("\n")?;
    out.push(&fence)?;
    out.push("\n")
}

fn render_attachment_list(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let issue = as_object(required(object, "issue")?)?;
    let attachments = array(required(object, "attachments")?)?;
    budget.charge_work(attachments.len().saturating_add(object.len()))?;
    out.push("# Jira attachments\n")?;
    render_issue_metadata(issue, out)?;
    field(out, "Count", &attachments.len().to_string())?;
    if attachments.is_empty() {
        out.push("\nNo results.\n")?;
    }
    for attachment in attachments {
        let attachment = as_object(attachment)?;
        let size = optional_display(attachment, "size")?;
        out.push("\n## ")?;
        out.push_heading_text(required_scalar(attachment, "filename")?)?;
        out.push("\n")?;
        code_fields(
            out,
            &[
                (
                    "Attachment ID",
                    optional_scalar(attachment, "attachmentId")?,
                ),
                ("Size", size.as_deref()),
                ("Content type", optional_scalar(attachment, "contentType")?),
            ],
        )?;
    }
    Ok(())
}

fn render_verify(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let verification = as_object(required(object, "verification")?)?;
    let checked = array(required(verification, "checked")?)?;
    budget.charge_work(checked.len().saturating_add(verification.len()))?;
    out.push("# Jira verification for ")?;
    out.push_code(required_scalar(object, "issueKey")?)?;
    out.push("\n")?;
    field_code(out, "Project", required_scalar(object, "project")?)?;
    field(out, "Status", required_scalar(verification, "status")?)?;
    out.push("\n## Checked\n")?;
    if checked.is_empty() {
        out.push("No items.\n")?;
    }
    for item in checked {
        render_typed_id(item, "- ", out)?;
    }
    if let Some(mismatch) = verification
        .get("mismatch")
        .filter(|value| !value.is_null())
    {
        out.push("\n## Mismatch\n")?;
        render_typed_id(mismatch, "- ", out)?;
    }
    Ok(())
}

fn render_typed_id(
    value: &Value,
    prefix: &str,
    out: &mut MarkdownWriter,
) -> Result<(), RenderError> {
    let value = as_object(value)?;
    out.push(prefix)?;
    out.push_escaped(required_scalar(value, "type")?)?;
    out.push(": ")?;
    out.push_code(required_scalar(value, "id")?)?;
    out.push("\n")
}

fn render_issue_metadata(
    issue: &Map<String, Value>,
    out: &mut MarkdownWriter,
) -> Result<(), RenderError> {
    code_fields(
        out,
        &[
            ("Issue ID", optional_scalar(issue, "id")?),
            ("Issue key", optional_scalar(issue, "key")?),
            ("Project", optional_scalar(issue, "project")?),
        ],
    )?;
    if let Some(url) = optional_scalar(issue, "webUrl")? {
        field_url(out, "URL", url)?;
    }
    Ok(())
}

fn render_comment_fields(
    comment: &Map<String, Value>,
    out: &mut MarkdownWriter,
) -> Result<(), RenderError> {
    code_fields(
        out,
        &[
            (
                "Parent comment ID",
                optional_scalar(comment, "parentCommentId")?,
            ),
            ("Created", optional_scalar(comment, "created")?),
            ("Updated", optional_scalar(comment, "updated")?),
        ],
    )?;
    if let Some(author) = comment.get("author").filter(|value| !value.is_null()) {
        field_raw(out, "Author", &render_user(author)?)?;
    }
    if let Some(visibility) = comment.get("visibility").filter(|value| !value.is_null()) {
        let visibility = as_object(visibility)?;
        fields(
            out,
            &[
                ("Visibility type", optional_scalar(visibility, "type")?),
                ("Visibility value", optional_scalar(visibility, "value")?),
                (
                    "Visibility identifier",
                    optional_scalar(visibility, "identifier")?,
                ),
            ],
        )?;
    }
    Ok(())
}

fn render_user(value: &Value) -> Result<String, RenderError> {
    let object = as_object(value)?;
    let display = optional_scalar(object, "displayName")?;
    let account = optional_scalar(object, "accountId")?;
    Ok(match (display, account) {
        (Some(display), Some(account)) => {
            format!("{} (account ID: {})", escaped(display), code_span(account))
        }
        (Some(display), None) => escaped(display),
        (None, Some(account)) => format!("account ID: {}", code_span(account)),
        (None, None) => String::new(),
    })
}

fn render_named_object(value: &Value) -> Result<String, RenderError> {
    let object = as_object(value)?;
    let name = optional_scalar(object, "name")?;
    let id = optional_scalar(object, "id")?;
    Ok(match (name, id) {
        (Some(name), Some(id)) => format!("{} (ID: {})", escaped(name), code_span(id)),
        (Some(name), None) => escaped(name),
        (None, Some(id)) => format!("ID: {}", code_span(id)),
        (None, None) => String::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_provider::{ProviderError, ReasonCode};
    use serde_json::json;

    fn present_provider_result(
        action: &str,
        result: &mut Value,
        options: ResponseOptions,
        max_body_bytes: u64,
        max_result_bytes: u64,
    ) -> Result<(), ProviderError> {
        present_result(
            presentation(action).as_ref(),
            result,
            options,
            max_body_bytes,
            max_result_bytes,
        )
    }

    fn response_capabilities(action: &str) -> ResponseCapabilities {
        agent_access_provider::presentation::response_capabilities(presentation(action).as_ref())
    }

    fn adf(text: &str) -> Value {
        json!({
            "type": "doc",
            "version": 1,
            "content": [{"type": "paragraph", "content": [{"type": "text", "text": text}]}]
        })
    }

    fn comment_page_with_bodies() -> Value {
        json!({
            "comments":[
                {"commentId":"21","body":adf("first *body*"),
                 "author":{"accountId":"a1","displayName":"Ada\n## forged"},
                 "created":"2026-10-01T12:00:00Z"},
                {"commentId":"22","parentCommentId":"21","body":adf("reply body"),
                 "updated":"2026-10-02T12:00:00Z"}
            ],
            "startAt":0,"maxResults":20,"count":2,"total":3,
            "isLast":false,"nextStartAt":2,"orderBy":"+created",
            "includeBodies":true,"limitedBy":"body_bytes"
        })
    }

    #[test]
    fn comment_pages_normalize_every_body_and_metadata_is_a_no_op() {
        for embedded in [false, true] {
            let mut page = comment_page_with_bodies();
            if !embedded {
                page["issue"] = json!({"key":"PROJ-1"});
            }
            let source = if embedded {
                json!({"key":"PROJ-1","description":adf("issue body"),
                       "customFields":[],"commentPage":page})
            } else {
                page
            };
            let action = if embedded {
                "issue.view"
            } else {
                "comment.list"
            };
            let mut result = source.clone();
            present_provider_result(
                action,
                &mut result,
                ResponseOptions::new(ReadContentFormat::Text, ResponseFormat::Json),
                4096,
                16384,
            )
            .unwrap();
            let page = if embedded {
                &result["commentPage"]
            } else {
                &result
            };
            assert_eq!(page["comments"][0]["body"], adf("first *body*"));
            assert_eq!(
                page["comments"][0]["renderedBody"],
                json!({"format":"text","value":"first *body*"})
            );
            assert_eq!(page["comments"][1]["renderedBody"]["value"], "reply body");
            assert_eq!(page["comments"][1]["parentCommentId"], "21");
            assert_eq!(page["nextStartAt"], 2);
            if embedded {
                assert_eq!(result["renderedBody"]["value"], "issue body");
            }

            let mut native = source;
            present_provider_result(action, &mut native, ResponseOptions::default(), 4096, 16384)
                .unwrap();
            let page = if embedded {
                &native["commentPage"]
            } else {
                &native
            };
            assert!(page["comments"][0].get("renderedBody").is_none());
        }

        let mut metadata = comment_page_with_bodies();
        metadata["issue"] = json!({"key":"PROJ-1"});
        metadata["includeBodies"] = json!(false);
        for comment in metadata["comments"].as_array_mut().unwrap() {
            comment.as_object_mut().unwrap().remove("body");
        }
        let original = metadata.clone();
        present_provider_result(
            "comment.list",
            &mut metadata,
            ResponseOptions::new(ReadContentFormat::Text, ResponseFormat::Json),
            4096,
            16384,
        )
        .unwrap();
        assert_eq!(metadata, original);
    }

    #[test]
    fn comment_page_markdown_preserves_bodies_reply_order_and_continuation() {
        for embedded in [false, true] {
            let mut page = comment_page_with_bodies();
            page["issue"] = json!({"key":"PROJ-1"});
            let mut result = if embedded {
                page.as_object_mut().unwrap().remove("issue");
                json!({"key":"PROJ-1","description":adf("issue body"),
                       "customFields":[],"commentPage":page})
            } else {
                page
            };
            present_provider_result(
                if embedded {
                    "issue.view"
                } else {
                    "comment.list"
                },
                &mut result,
                ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
                4096,
                16384,
            )
            .unwrap();
            let markdown = result["value"].as_str().unwrap();
            for expected in [
                "Comment `21`",
                "Comment `22`",
                "first \\*body\\*",
                "reply body",
                "- Parent comment ID: `21`",
                "- Bodies included: true",
                "- Start at: 0",
                "- Maximum results: 20",
                "- Total: 3",
                "- Last page: false",
                "- Next start at: 2",
                "- Order by: `+created`",
                "- Limited by: `body_bytes`",
            ] {
                assert!(
                    markdown.contains(expected),
                    "missing {expected:?}: {markdown}"
                );
            }
            assert!(
                markdown.find("Comment `21`").unwrap() < markdown.find("Comment `22`").unwrap()
            );
            assert!(!markdown.contains("\n## forged"));
            if embedded {
                assert!(
                    markdown.find("issue body").unwrap() < markdown.find("## Comments").unwrap()
                );
                assert!(markdown.contains("\n### Comment `21`\n"));
                assert!(markdown.contains("\n#### Body\n"));
                assert!(markdown.contains("\n### Pagination\n"));
            }
        }
    }

    #[test]
    fn issue_comments_distinguish_not_requested_from_an_empty_page() {
        let source = json!({"key":"PROJ-1","description":null,"customFields":[]});
        for format in [
            ReadContentFormat::Native,
            ReadContentFormat::Text,
            ReadContentFormat::Markdown,
        ] {
            let mut absent = source.clone();
            present_provider_result(
                "issue.view",
                &mut absent,
                ResponseOptions::new(format, ResponseFormat::Json),
                4096,
                16384,
            )
            .unwrap();
            assert_eq!(absent, source);
        }
        let options = ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown);
        let mut absent = source.clone();
        present_provider_result("issue.view", &mut absent, options, 4096, 16384).unwrap();
        assert!(!absent["value"].as_str().unwrap().contains("## Comments"));

        let mut empty = source;
        empty["commentPage"] = json!({
            "comments":[],"count":0,"total":0,"startAt":0,"maxResults":20,
            "isLast":true,"nextStartAt":null,"orderBy":"+created","includeBodies":true
        });
        present_provider_result("issue.view", &mut empty, options, 4096, 16384).unwrap();
        let markdown = empty["value"].as_str().unwrap();
        assert!(markdown.contains("\n## Comments\n"));
        assert!(markdown.contains("- Count: 0\n"));
        assert!(markdown.contains("- Total: 0\n"));
        assert!(markdown.contains("- Last page: true\n"));
        assert!(!markdown.contains("Next start at"));
    }

    #[test]
    fn issue_comment_page_requires_valid_structure_when_present() {
        for page in [
            Value::Null,
            json!([]),
            json!({}),
            json!({"comments":null}),
            json!({"comments":{}}),
        ] {
            for options in [
                ResponseOptions::default(),
                ResponseOptions::new(ReadContentFormat::Text, ResponseFormat::Json),
                ResponseOptions::new(ReadContentFormat::Markdown, ResponseFormat::Json),
                ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            ] {
                let mut result = json!({
                    "key":"PROJ-1","description":null,"customFields":[],"commentPage":page
                });
                let error =
                    present_provider_result("issue.view", &mut result, options, 4096, 16384)
                        .unwrap_err();
                assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
            }
        }
    }

    #[test]
    fn comment_page_markdown_marks_unknown_total_and_completion_explicitly() {
        for empty in [false, true] {
            let mut result = json!({
                "issue":{"key":"PROJ-1"},"comments":[{"commentId":"21"}],
                "startAt":20,"maxResults":20,"total":null,"isLast":null,
                "nextStartAt":21,"orderBy":"+created","includeBodies":false
            });
            if empty {
                result["comments"] = json!([]);
                result["nextStartAt"] = Value::Null;
            }
            present_provider_result(
                "comment.list",
                &mut result,
                ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
                4096,
                16384,
            )
            .unwrap();
            let markdown = result["value"].as_str().unwrap();
            assert!(markdown.contains("- Total: unknown\n"));
            assert!(markdown.contains("- Last page: unknown\n"));
            assert!(!markdown.contains("- Last page: true\n"));
            if empty {
                assert!(!markdown.contains("Next start at"));
            } else {
                assert!(markdown.contains("- Next start at: 21\n"));
            }
        }
    }

    #[test]
    fn comment_collections_share_complexity_budget_with_the_issue() {
        const BODY_LIMIT: u64 = 1024 * 1024;
        const RESULT_LIMIT: u64 = 16 * 1024 * 1024;
        let body = json!({
            "type":"doc","version":1,
            "content":vec![json!({"type":"paragraph","content":[]});22_000]
        });
        for options in [
            ResponseOptions::default(),
            ResponseOptions::new(ReadContentFormat::Text, ResponseFormat::Json),
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
        ] {
            let mut single = json!({"issue":{"key":"PROJ-1"},
                                    "comment":{"commentId":"1","body":body}});
            present_provider_result(
                "comment.view",
                &mut single,
                options,
                BODY_LIMIT,
                RESULT_LIMIT,
            )
            .unwrap();
            for embedded in [false, true] {
                let count = if embedded { 5 } else { 6 };
                let comments = (1..=count)
                    .map(|id| json!({"commentId":id.to_string(),"body":body}))
                    .collect::<Vec<_>>();
                let mut result = if embedded {
                    json!({"key":"PROJ-1","description":body,"customFields":[],
                           "commentPage":{"comments":comments}})
                } else {
                    json!({"issue":{"key":"PROJ-1"},"comments":comments})
                };
                let error = present_provider_result(
                    if embedded {
                        "issue.view"
                    } else {
                        "comment.list"
                    },
                    &mut result,
                    options,
                    BODY_LIMIT,
                    RESULT_LIMIT,
                )
                .unwrap_err();
                assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
                assert_eq!(error.message, RENDER_FAILURE_MESSAGE);
                assert!(error.result.is_none());
            }
        }
    }

    #[test]
    fn project_view_markdown_keeps_search_references_and_collection_limits() {
        let source = json!({
            "project": {"id":"1","key":"PROJ","name":"Example project", "description":"Project details", "webUrl":"https://example.atlassian.net/plugins/servlet/project-config/PROJ"},
            "fields": {"items":[{"id":"customfield_12345","name":"External ticket","jqlReference":"cf[12345]","types":["java.lang.String"],"operators":["~","IS EMPTY"]}],"count":1,"truncated":true},
            "versions": {"items":[{"id":"2","name":"2.4","released":false,"archived":false}],"count":1,"truncated":false},
            "components": {"items":[],"count":0,"truncated":false},
            "issueTypes": {"items":[{"id":"3","name":"Task","subtask":false}],"count":1,"truncated":false},
            "statuses": {"items":[{"id":"4","name":"Done","statusCategory":{"id":"5","key":"done","name":"Done"}}],"count":1,"truncated":false}
        });
        let options = ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown);
        let mut result = source.clone();
        present_provider_result("project.view", &mut result, options, 4096, 16384).unwrap();
        let rendered = result["value"].as_str().unwrap();
        for expected in [
            "Jira project",
            "Searchable fields",
            "cf[12345]",
            "External ticket",
            "IS EMPTY",
            "Truncated",
            "true",
            "Versions",
            "2.4",
            "Components",
            "Issue types",
            "Statuses",
            "Status category",
            "Status category ID",
            "Status category key",
        ] {
            assert!(rendered.contains(expected), "{expected}: {rendered}");
        }
        let mut result = source;
        assert!(present_provider_result("project.view", &mut result, options, 4096, 32).is_err());
    }

    #[test]
    fn registry_has_exact_jira_coverage_and_derived_capabilities() {
        let embedded = RESULT_DESCRIPTORS
            .iter()
            .filter(|descriptor| !descriptor.embedded_bodies.is_empty())
            .map(|descriptor| descriptor.action)
            .collect::<Vec<_>>();
        assert_eq!(
            embedded,
            [
                "issue.view",
                "issue.create",
                "issue.update",
                "comment.view",
                "comment.add",
                "comment.reply",
                "comment.update",
                "comment.list",
            ]
        );
        let whole = RESULT_DESCRIPTORS
            .iter()
            .filter(|descriptor| descriptor.whole.is_some())
            .map(|descriptor| descriptor.action)
            .collect::<Vec<_>>();
        assert_eq!(
            whole,
            [
                "project.list",
                "project.view",
                "issue_type.list",
                "issue.view",
                "comment.view",
                "search",
                "comment.list",
                "comment.property.list",
                "comment.property.get",
                "attachment.list",
                "verify",
            ]
        );
        assert_eq!(
            response_capabilities("issue.view"),
            ResponseCapabilities::new(Some(READ_CONTENT_FORMATS), Some(RESPONSE_FORMATS))
        );
        assert_eq!(
            response_capabilities("issue.delete"),
            ResponseCapabilities::new(None, None)
        );
    }

    #[test]
    fn embedded_rendering_preserves_native_and_places_companion_at_owner() {
        let native = adf("hello *world*");
        let mut result =
            json!({"operation":"comment.add", "comment":{"commentId":"7", "body":native}});
        present_provider_result(
            "comment.add",
            &mut result,
            ResponseOptions::new(ReadContentFormat::Markdown, ResponseFormat::Json),
            4096,
            16384,
        )
        .unwrap();
        assert_eq!(result["comment"]["body"], adf("hello *world*"));
        assert_eq!(
            result["comment"]["renderedBody"],
            json!({"format":"markdown", "value":"hello \\*world\\*"})
        );
    }

    #[test]
    fn native_mode_validates_declared_content_and_omits_companion() {
        let mut result = json!({"description":{"type":"not-a-doc"},"customFields":[]});
        let error = present_provider_result(
            "issue.view",
            &mut result,
            ResponseOptions::default(),
            4096,
            16384,
        )
        .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
        assert_eq!(error.message, RENDER_FAILURE_MESSAGE);
    }

    #[test]
    fn issue_markdown_is_complete_deterministic_and_keeps_present_empty_body() {
        let mut result = json!({
            "id":"100", "key":"SBC-1", "project":"SBC", "summary":"Ship *it*",
            "status":"Open", "issueType":"Task", "priority":{"id":"3","name":"High"},
            "assignee":{"displayName":"Ada","accountId":"a`b"}, "reporter":null,
            "creator":{"accountId":"creator"}, "labels":["one","two"],
            "created":"2026-08-01", "updated":"2026-08-02",
            "webUrl":"https://example.test/browse/SBC-1", "description":adf(""),
            "customFields":[]
        });
        present_provider_result(
            "issue.view",
            &mut result,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        let text = result["value"].as_str().unwrap();
        assert!(text.starts_with("# `SBC-1` — Ship \\*it\\*\n"));
        assert!(text.contains("- Priority: High (ID: `3`)\n"));
        assert!(text.contains("- Assignee: Ada (account ID: ``a`b``)\n"));
        assert!(text.contains("\n## Description\n"));
        assert!(text.ends_with("\n## Custom fields\n\nNo custom fields returned.\n"));
        assert_eq!(result["format"], "markdown");
    }

    #[test]
    fn whole_markdown_charges_rendered_adf_once_at_the_final_document_bound() {
        let source = json!({
            "id":"100", "key":"SBC-1", "summary":"Near the result limit",
            "description":adf(&"x".repeat(1024)),"customFields":[]
        });
        let mut generously_bounded = source.clone();
        present_provider_result(
            "issue.view",
            &mut generously_bounded,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        let exact_serialized_bytes = serde_json::to_vec(&generously_bounded).unwrap().len() as u64;

        let mut exactly_bounded = source;
        present_provider_result(
            "issue.view",
            &mut exactly_bounded,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            exact_serialized_bytes,
        )
        .unwrap();
        assert_eq!(exactly_bounded, generously_bounded);
    }

    #[test]
    fn issue_type_markdown_keeps_ids_descriptions_and_pagination_without_markup_injection() {
        let source = json!({
            "project":"PROJ", "issueTypes":[
                {"id":"10001","name":"Bug\n## forged","description":"Fix *errors*\n## injected","subtask":false},
                {"id":"10002","name":"Subtask","description":"","subtask":true}
            ],
            "startAt":0, "maxResults":2, "total":3, "isLast":false, "nextStartAt":2
        });
        let options = ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown);
        let mut result = source.clone();
        present_provider_result("issue_type.list", &mut result, options, 4096, 16384).unwrap();
        let markdown = result["value"].as_str().unwrap();
        assert!(markdown.starts_with("# Jira issue types for `PROJ`\n"));
        assert!(markdown.contains("- ID: `10001`\n"));
        assert!(markdown.contains("- ID: `10002`\n"));
        assert!(markdown.contains("- Subtask: true\n"));
        assert!(markdown.contains("Fix \\*errors\\*"));
        assert!(markdown.contains("- Next start at: 2\n"));
        assert!(markdown.contains("- Last page: false\n"));
        assert!(!markdown.contains("\n## forged"));
        assert!(!markdown.contains("\n## injected"));
        let mut result = source;
        let error =
            present_provider_result("issue_type.list", &mut result, options, 4096, 32).unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    }

    #[test]
    fn every_whole_markdown_template_has_exactly_one_terminal_lf() {
        let cases = [
            ("issue_type.list", json!({"project":"PROJ","issueTypes":[]})),
            (
                "issue.view",
                json!({"key":"SBC-1","description":adf(""),"customFields":[]}),
            ),
            (
                "comment.view",
                json!({"issue":{"key":"SBC-1"},"comment":{"commentId":"7","body":adf("")}}),
            ),
            ("search", json!({"issues":[]})),
            (
                "comment.list",
                json!({"issue":{"key":"SBC-1"},"comments":[]}),
            ),
            (
                "comment.property.list",
                json!({"issue":{"key":"SBC-1"},"commentId":"7","keys":[]}),
            ),
            (
                "comment.property.get",
                json!({"issue":{"key":"SBC-1"},"commentId":"7","propertyKey":"key","value":{}}),
            ),
            (
                "attachment.list",
                json!({"issue":{"key":"SBC-1"},"attachments":[]}),
            ),
            (
                "verify",
                json!({"issueKey":"SBC-1","project":"SBC","verification":{"status":"matched","checked":[]}}),
            ),
        ];

        for (action, mut result) in cases {
            present_provider_result(
                action,
                &mut result,
                ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
                4096,
                16384,
            )
            .unwrap();
            let markdown = result["value"].as_str().unwrap();
            assert!(markdown.ends_with('\n'), "{action} lacks a terminal LF");
            assert!(
                !markdown.ends_with("\n\n"),
                "{action} has more than one terminal LF"
            );
        }
    }

    #[test]
    fn search_renders_issue_entries_as_subsections() {
        let mut result = json!({
            "issues":[
                {"key":"SBC-1","summary":"First"},
                {"key":"SBC-2","summary":"Second"}
            ]
        });
        present_provider_result(
            "search",
            &mut result,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        let markdown = result["value"].as_str().unwrap();
        assert_eq!(
            markdown
                .lines()
                .filter(|line| line.starts_with("# "))
                .count(),
            1
        );
        assert!(markdown.contains("\n## `SBC-1` — First\n"));
        assert!(markdown.contains("\n## `SBC-2` — Second\n"));
    }

    #[test]
    fn issue_context_and_hierarchy_markdown_preserve_identity_order_and_literal_text() {
        let mut result = json!({
            "key":"PROJ-1","description":null,"customFields":[],
            "resolution":{"id":"r`1","name":"Fixed *now*\n## forged"},
            "resolutionDate":"2026-10-23T12:34:56.000+0000",
            "dueDate":"2026-11-01",
            "statusCategory":{"id":3,"key":"done`key","name":"# Done"},
            "components":[{"id":"2","name":"# Main"},{"id":"1","name":null},{"id":"2","name":"# Main"}],
            "fixVersions":[],
            "affectedVersions":[{"id":"v`1","name":"1. Release\n## forged"}],
            "parent":{"key":"PLAN-2","summary":"# Deliver *this*\n## forged","issueType":"Epic"},
            "subtasks":[
                {"key":"PROJ-3","summary":"- Work","issueType":"Subtask"},
                {"key":"PROJ-2","summary":null,"issueType":null},
                {"key":"PROJ-3","summary":"- Work","issueType":"Subtask"}
            ]
        });
        present_provider_result(
            "issue.view",
            &mut result,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        let markdown = result["value"].as_str().unwrap();
        for expected in [
            "- Resolution: Fixed \\*now\\* ## forged (ID: ``r`1``)",
            "- Resolution date: `2026-10-23T12:34:56.000+0000`",
            "- Due date: `2026-11-01`",
            "- Status category: # Done (key: ``done`key``; ID: `3`)",
            "## Components\n\n- Component: # Main (ID: `2`)\n- Component: `1`\n- Component: # Main (ID: `2`)",
            "## Fix versions\n\nNone.",
            "## Affected versions\n\n- Version: 1. Release ## forged (ID: ``v`1``)",
            "## Parent\n\n- Parent: `PLAN-2` (issue type: Epic) — # Deliver \\*this\\* ## forged",
            "## Subtasks\n\n- Subtask: `PROJ-3` (issue type: Subtask) — - Work\n- Subtask: `PROJ-2`\n- Subtask: `PROJ-3` (issue type: Subtask) — - Work",
        ] {
            assert!(
                markdown.contains(expected),
                "missing {expected:?}: {markdown}"
            );
        }
        assert!(!markdown.contains("\n## forged"));
        assert!(!markdown.contains("\n- #"));
        assert!(!markdown.contains("\n- 1."));
    }

    #[test]
    fn issue_context_nulls_and_hierarchy_absence_do_not_claim_empty_values() {
        let source = json!({
            "key":"PROJ-1","description":null,"customFields":[],
            "resolution":null,"resolutionDate":null,"dueDate":null,
            "statusCategory":null,"components":null,"fixVersions":null,"affectedVersions":null
        });
        let options = ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown);
        let mut result = source.clone();
        present_provider_result("issue.view", &mut result, options, 4096, 16384).unwrap();
        let markdown = result["value"].as_str().unwrap();
        for absent in [
            "Resolution",
            "Due date",
            "Status category",
            "Components",
            "Fix versions",
            "Affected versions",
            "Parent",
            "Subtasks",
        ] {
            assert!(!markdown.contains(absent), "{markdown}");
        }
        let mut empty = source.clone();
        empty["parent"] = Value::Null;
        empty["subtasks"] = json!([]);
        for collection in ["components", "fixVersions", "affectedVersions"] {
            empty[collection] = json!([]);
        }
        present_provider_result("issue.view", &mut empty, options, 4096, 16384).unwrap();
        let markdown = empty["value"].as_str().unwrap();
        assert!(markdown.contains("## Parent\n\nNo parent returned.\n"));
        for heading in [
            "Components",
            "Fix versions",
            "Affected versions",
            "Subtasks",
        ] {
            assert!(
                markdown.contains(&format!("## {heading}\n\nNone.\n")),
                "{markdown}"
            );
        }
        let mut parent_only = source;
        parent_only["parent"] = Value::Null;
        present_provider_result("issue.view", &mut parent_only, options, 4096, 16384).unwrap();
        let markdown = parent_only["value"].as_str().unwrap();
        assert!(markdown.contains("No parent returned."));
        assert!(!markdown.contains("## Subtasks"));
    }

    #[test]
    fn unnamed_context_objects_keep_their_id_or_category_key() {
        let mut result = json!({
            "key":"PROJ-1","description":null,"customFields":[],
            "resolution":{"id":"resolution-1","name":null},
            "statusCategory":{"id":0,"key":"new","name":null},
            "components":[{"id":"component-1","name":null}],
            "fixVersions":[{"id":"fix-1","name":null}],
            "affectedVersions":[{"id":"affected-1","name":null}]
        });
        present_provider_result(
            "issue.view",
            &mut result,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        let markdown = result["value"].as_str().unwrap();
        for expected in [
            "- Resolution: `resolution-1`",
            "- Status category: `new` (ID: `0`)",
            "- Component: `component-1`",
            "- Version: `fix-1`",
            "- Version: `affected-1`",
        ] {
            assert!(markdown.contains(expected), "{markdown}");
        }
    }

    #[test]
    fn search_markdown_does_not_consume_view_only_context_or_hierarchy() {
        // Even malformed unsolicited view-only metadata cannot change a search result.
        let mut result = json!({"issues":[{
            "key":"PROJ-1","summary":"Search result",
            "resolution":{"invalid":"HIDDEN"},"resolutionDate":{},"dueDate":{},
            "statusCategory":true,"components":"HIDDEN","fixVersions":true,"affectedVersions":42,
            "parent":{"key":"HIDDEN-1"},"subtasks":"HIDDEN",
            "customFields":[{"type":"labels","value":["HIDDEN"]}]
        }]});
        present_provider_result(
            "search",
            &mut result,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        let markdown = result["value"].as_str().unwrap();
        assert!(markdown.contains("## `PROJ-1` — Search result"));
        for absent in [
            "HIDDEN",
            "Resolution",
            "Due date",
            "Status category",
            "Components",
            "Fix versions",
            "Affected versions",
            "Parent",
            "Subtasks",
            "Custom fields",
        ] {
            assert!(!markdown.contains(absent), "{markdown}");
        }
    }

    #[test]
    fn view_context_and_hierarchy_share_work_and_output_bounds() {
        let object = json!({
            "components":[{"id":"1","name":"component"}],
            "parent":{"key":"PROJ-2","summary":"PRIVATE_SUMMARY","issueType":"Task"}
        });
        let mut budget = PresentationBudget::new(16384);
        budget.charge_work(MAX_PRESENTATION_WORK_UNITS - 5).unwrap();
        let mut out = MarkdownWriter::new(16384);
        render_issue_context(object.as_object().unwrap(), &mut out, &mut budget).unwrap();
        assert!(
            render_issue_hierarchy(object.as_object().unwrap(), &mut out, &mut budget).is_err()
        );

        let mut result = json!({
            "key":"PROJ-1","customFields":[],
            "components":[{"id":"1","name":"PRIVATE_CONTEXT".repeat(40)}]
        });
        let error = present_provider_result(
            "issue.view",
            &mut result,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            128,
        )
        .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
        assert_eq!(error.message, RENDER_FAILURE_MESSAGE);
        assert!(error.result.is_none());
    }

    #[test]
    fn property_json_and_tokens_use_collision_safe_delimiters() {
        let mut property = json!({
            "issue":{"id":"1","key":"SBC-1","project":"SBC","webUrl":"https://example.test"},
            "commentId":"7", "propertyKey":"key", "value":{"literal":"```"}
        });
        present_provider_result(
            "comment.property.get",
            &mut property,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        assert!(property["value"].as_str().unwrap().contains("````json\n"));

        let mut search = json!({"issues":[],"maxResults":1,"startAt":0,"total":0,"isLast":false,"nextPageToken":"a`b"});
        present_provider_result(
            "search",
            &mut search,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        assert!(search["value"].as_str().unwrap().contains("``a`b``"));
    }

    #[test]
    fn property_json_preserves_a_present_null_value() {
        let mut property = json!({
            "issue":{"key":"SBC-1"}, "commentId":"7", "propertyKey":"key", "value":null
        });
        present_provider_result(
            "comment.property.get",
            &mut property,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        assert!(
            property["value"]
                .as_str()
                .unwrap()
                .contains("```json\nnull\n```")
        );
    }

    #[test]
    fn metadata_is_copyable_and_cannot_inject_markdown_structure() {
        let mut issue = json!({
            "id":"100-1", "key":"SBC-1", "project":"SBC.PROJECT",
            "summary":"Ship-it (v1.2)\r\n## forged", "status":"Open\n- forged: yes",
            "labels":["release-1.2", "bad\n## forged"],
            "created":"2026-08-29T01:02:03.000-0500",
            "updated":"2026-08-29T02:03:04.000-0500",
            "webUrl":"https://example.test/browse/SBC-1?x=1",
            "assignee":{"displayName":"Ada\n## forged","accountId":"acct\r\nforged"},
            "description":adf(""),"customFields":[]
        });
        present_provider_result(
            "issue.view",
            &mut issue,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        let markdown = issue["value"].as_str().unwrap();
        assert!(markdown.starts_with("# `SBC-1` — Ship-it (v1.2) ## forged\n"));
        assert!(markdown.contains("- ID: `100-1`\n"));
        assert!(markdown.contains("- Project: `SBC.PROJECT`\n"));
        assert!(markdown.contains("- Created: `2026-08-29T01:02:03.000-0500`\n"));
        assert!(markdown.contains("- URL: <https://example.test/browse/SBC-1?x=1>\n"));
        assert!(markdown.contains("- Labels: `release-1.2`, `bad ## forged`\n"));
        assert!(!markdown.contains("\n## forged\n"));
        assert!(!markdown.contains("SBC\\-1"));

        let mut unsafe_url = json!({
            "key":"SBC-2", "webUrl":"https://example.test/path\n## forged","customFields":[]
        });
        present_provider_result(
            "issue.view",
            &mut unsafe_url,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        assert!(
            unsafe_url["value"]
                .as_str()
                .unwrap()
                .contains("- URL: `https://example.test/path ## forged`\n")
        );

        let mut credential_url = json!({
            "key":"SBC-3", "webUrl":"https://user:secret@example.test/browse/SBC-3","customFields":[]
        });
        present_provider_result(
            "issue.view",
            &mut credential_url,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        assert!(
            credential_url["value"]
                .as_str()
                .unwrap()
                .contains("- URL: `https://user:secret@example.test/browse/SBC-3`\n")
        );
    }

    #[test]
    fn heading_metadata_preserves_trailing_hash_runs() {
        let mut issue = json!({
            "key":"SBC-4", "summary":"Fix flaky retry #","customFields":[]
        });
        present_provider_result(
            "issue.view",
            &mut issue,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        assert!(
            issue["value"]
                .as_str()
                .unwrap()
                .starts_with("# `SBC-4` — Fix flaky retry \\#\n")
        );

        let mut hash_only_issue = json!({"key":"SBC-5", "summary":"#","customFields":[]});
        present_provider_result(
            "issue.view",
            &mut hash_only_issue,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        assert!(
            hash_only_issue["value"]
                .as_str()
                .unwrap()
                .starts_with("# `SBC-5` — \\#\n")
        );

        let mut attachments = json!({
            "issue":{"key":"SBC-4"},
            "attachments":[{"filename":"notes ##"}, {"filename":"###"}]
        });
        present_provider_result(
            "attachment.list",
            &mut attachments,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        assert!(
            attachments["value"]
                .as_str()
                .unwrap()
                .contains("## notes \\#\\#\n")
        );
        assert!(
            attachments["value"]
                .as_str()
                .unwrap()
                .contains("## \\#\\#\\#\n")
        );
    }

    #[test]
    fn verify_template_accepts_matched_and_allow_with_result_mismatch_shapes() {
        for (status, mismatch) in [
            ("matched", None),
            ("mismatch", Some(json!({"type":"comment","id":"9"}))),
        ] {
            let mut verification =
                json!({"status":status,"checked":[{"type":"attachment","id":"8"}]});
            if let Some(mismatch) = mismatch {
                verification["mismatch"] = mismatch;
            }
            let mut result =
                json!({"issueKey":"SBC-1","project":"SBC","verification":verification});
            present_provider_result(
                "verify",
                &mut result,
                ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
                4096,
                16384,
            )
            .unwrap();
            let text = result["value"].as_str().unwrap();
            assert!(text.contains(&format!("- Status: {status}")));
            if status == "mismatch" {
                assert!(text.contains("## Mismatch"));
            }
        }
    }

    #[test]
    fn invalid_combinations_unsupported_actions_and_final_bounds_fail_closed() {
        let error = validate_response_options(
            presentation("issue.view").as_ref(),
            ResponseOptions::new(ReadContentFormat::Text, ResponseFormat::Markdown),
        )
        .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid);

        let error = validate_response_options(
            presentation("issue.delete").as_ref(),
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
        )
        .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::ResponseFormatUnsupported);

        let mut result =
            json!({"id":"1","key":"SBC-1","description":adf("body"),"customFields":[]});
        let error = present_provider_result(
            "issue.view",
            &mut result,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16,
        )
        .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
        assert_eq!(error.message, RENDER_FAILURE_MESSAGE);
    }

    #[test]
    fn missing_or_null_body_has_no_companion_but_present_empty_has_one() {
        for body in [None, Some(Value::Null)] {
            let mut result = json!({"comment":{"commentId":"1"}});
            if let Some(body) = body {
                result["comment"]["body"] = body;
            }
            present_provider_result(
                "comment.view",
                &mut result,
                ResponseOptions::new(ReadContentFormat::Text, ResponseFormat::Json),
                4096,
                16384,
            )
            .unwrap();
            assert!(result["comment"].get("renderedBody").is_none());
        }
        let mut result = json!({"comment":{"commentId":"1","body":adf("")}});
        present_provider_result(
            "comment.view",
            &mut result,
            ResponseOptions::new(ReadContentFormat::Text, ResponseFormat::Json),
            4096,
            16384,
        )
        .unwrap();
        assert_eq!(result["comment"]["renderedBody"]["value"], "");
    }

    fn supported_field(id: usize, kind: &str, value: Value) -> Value {
        json!({
            "id":format!("customfield_{id}"),"name":format!("Field {id}"),
            "type":kind,"status":"supported","value":value
        })
    }

    #[test]
    fn custom_field_body_owner_is_declared_only_for_issue_view() {
        let owners = |action| {
            presentation(action)
                .unwrap()
                .embedded_bodies()
                .iter()
                .map(EmbeddedBody::owner_pointer)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            owners("issue.view"),
            ["", "/customFields/*", "/commentPage/comments/*"]
        );
        assert_eq!(owners("comment.list"), ["/comments/*"]);
        assert_eq!(owners("issue.create"), ["/issue"]);
        assert_eq!(owners("issue.update"), ["/issue"]);
        assert!(owners("search").is_empty());
    }

    #[test]
    fn custom_null_empty_arrays_and_empty_adf_keep_their_meaning_in_every_format() {
        let mut fields = [
            "text",
            "url",
            "number",
            "date",
            "datetime",
            "adf",
            "option",
            "options",
            "cascadingOption",
            "user",
            "users",
        ]
        .iter()
        .enumerate()
        .map(|(index, kind)| supported_field(index + 1, kind, Value::Null))
        .collect::<Vec<_>>();
        fields.push(supported_field(12, "options", json!([])));
        fields.push(supported_field(13, "users", json!([])));
        for (index, status) in ["unsupported", "withheld"].into_iter().enumerate() {
            for (offset, value) in [Value::Null, json!([])].into_iter().enumerate() {
                fields.push(json!({
                    "id":format!("customfield_{}", 14 + index * 2 + offset),
                    "name":null,"type":null,"status":status,"value":value
                }));
            }
        }
        let empty_count = fields.len();
        fields.push(supported_field(18, "adf", adf("")));
        let source = json!({"key":"PROJ-1","description":null,"customFields":fields});

        for content in [
            ReadContentFormat::Native,
            ReadContentFormat::Markdown,
            ReadContentFormat::Text,
        ] {
            let mut result = source.clone();
            present_provider_result(
                "issue.view",
                &mut result,
                ResponseOptions::new(content, ResponseFormat::Json),
                4096,
                16384,
            )
            .unwrap();
            assert!(result.get("renderedBody").is_none());
            for index in 0..empty_count {
                assert_eq!(result["customFields"][index], source["customFields"][index]);
                assert!(result["customFields"][index].get("renderedBody").is_none());
            }
            let empty_adf = &result["customFields"][empty_count];
            assert_eq!(empty_adf["value"], adf(""));
            if content == ReadContentFormat::Native {
                assert!(empty_adf.get("renderedBody").is_none());
            } else {
                assert_eq!(
                    empty_adf["renderedBody"],
                    json!({"format":content,"value":""})
                );
            }
        }
        let mut result = source;
        present_provider_result(
            "issue.view",
            &mut result,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        let markdown = result["value"].as_str().unwrap();
        assert_eq!(markdown.matches("- Value: not set").count(), empty_count);
        assert_eq!(markdown.matches("- Status: `unsupported`").count(), 2);
        assert_eq!(markdown.matches("- Status: `withheld`").count(), 2);
        assert!(markdown.contains("### `customfield_14`"));
    }

    #[test]
    fn custom_multi_value_block_markers_remain_literal_text() {
        let labels = [
            "1. Must have",
            "2) Should",
            "# Blocker",
            "- Ada",
            "+ x",
            "---",
        ];
        let options = labels
            .iter()
            .enumerate()
            .map(|(id, label)| json!({"id": id.to_string(), "value": label}))
            .collect::<Vec<_>>();
        let users = labels
            .iter()
            .enumerate()
            .map(|(id, label)| json!({"accountId": id.to_string(), "displayName": label}))
            .collect::<Vec<_>>();
        let mut result = json!({
            "key": "PROJ-1", "description": null,
            "customFields": [supported_field(1, "options", json!(options)),
                             supported_field(2, "users", json!(users))]
        });
        present_provider_result(
            "issue.view",
            &mut result,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        let markdown = result["value"].as_str().unwrap();
        for (id, label) in labels.iter().enumerate() {
            assert!(markdown.contains(&format!("\n- Option: {label} (ID: `{id}`)\n")));
            assert!(markdown.contains(&format!("\n- User: {label} (account ID: `{id}`)\n")));
        }
    }

    #[test]
    fn custom_labels_preserve_empty_strings_duplicates_and_order_in_every_format() {
        let source = json!({
            "key":"PROJ-1","description":null,
            "resolution":{"id":"1","name":null},
            "resolutionDate":"2026-10-23T01:02:03.000+0000","dueDate":null,
            "components":[],"fixVersions":null,"affectedVersions":[],
            "statusCategory":{"id":3,"key":"done","name":"Done"},
            "parent":null,"subtasks":[],
            "customFields":[
                supported_field(1, "labels", Value::Null),
                supported_field(2, "labels", json!([])),
                supported_field(3, "labels", json!(["", "# Blocker", "1. Release", "one`two", "line\n## forged", "# Blocker"]))
            ]
        });
        for content in [
            ReadContentFormat::Native,
            ReadContentFormat::Markdown,
            ReadContentFormat::Text,
        ] {
            let mut result = source.clone();
            present_provider_result(
                "issue.view",
                &mut result,
                ResponseOptions::new(content, ResponseFormat::Json),
                4096,
                16384,
            )
            .unwrap();
            // Labels and standard context are typed metadata, never ADF companions.
            assert_eq!(result, source);
        }
        let mut result = source;
        present_provider_result(
            "issue.view",
            &mut result,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        let markdown = result["value"].as_str().unwrap();
        assert_eq!(markdown.matches("- Value: not set").count(), 2);
        assert_eq!(
            markdown
                .lines()
                .filter(|line| line.starts_with("- Label:"))
                .collect::<Vec<_>>(),
            [
                "- Label: `  `",
                "- Label: `# Blocker`",
                "- Label: `1. Release`",
                "- Label: ``one`two``",
                "- Label: `line ## forged`",
                "- Label: `# Blocker`",
            ]
        );
        assert!(!markdown.contains("\n## forged"));
    }

    #[test]
    fn custom_field_markdown_is_typed_copyable_and_escapes_dynamic_labels() {
        let mut fields = vec![
            supported_field(1, "text", json!("Customer *impact*\n## forged")),
            supported_field(2, "url", json!("https://user:secret@example.test/a`b")),
            supported_field(3, "number", json!(4.5)),
            supported_field(4, "date", json!("2026-10-23")),
            supported_field(5, "datetime", json!("2026-10-23T10:00:00.000Z")),
            supported_field(6, "option", json!({"id":"a`b","value":"High *priority*"})),
            supported_field(
                7,
                "options",
                json!([
                    {"id":"1","value":"First"},{"id":"2","value":"Second"}
                ]),
            ),
            supported_field(
                8,
                "cascadingOption",
                json!({
                    "id":"1","value":"Parent","child":{"id":"2","value":"Child"}
                }),
            ),
            supported_field(
                9,
                "user",
                json!({"accountId":"a`b","displayName":"Ada *Example*"}),
            ),
            supported_field(
                10,
                "users",
                json!([
                    {"accountId":"one","displayName":"Ada"},{"accountId":"two","displayName":null}
                ]),
            ),
            supported_field(11, "adf", adf("custom body")),
            json!({"id":"customfield_12","name":"Unknown","type":null,"status":"unsupported"}),
            json!({"id":"customfield_13","name":"Invalid","type":"text","status":"withheld"}),
        ];
        fields[0]["name"] = json!("Business *impact*\n### injected #");
        fields[1]["name"] = Value::Null;
        fields[2]["name"] = json!("Duplicate name");
        fields[3]["name"] = json!("Duplicate name");
        let mut result =
            json!({"key":"PROJ-1","description":adf("root body"),"customFields":fields});
        present_provider_result(
            "issue.view",
            &mut result,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        let text = result["value"].as_str().unwrap();
        for expected in [
            "### Business \\*impact\\* ### injected \\# (`customfield_1`)",
            "### `customfield_2`",
            "Customer \\*impact\\* ## forged",
            "- Value: ``https://user:secret@example.test/a`b``",
            "- Value: 4.5",
            "- Value: `2026-10-23`",
            "- Value: `2026-10-23T10:00:00.000Z`",
            "High \\*priority\\* (ID: ``a`b``)",
            "- Option: First (ID: `1`)\n- Option: Second (ID: `2`)",
            "Parent (ID: `1`) → Child (ID: `2`)",
            "Ada \\*Example\\* (account ID: ``a`b``)",
            "- User: Ada (account ID: `one`)\n- User: account ID: `two`",
            "custom body",
            "- Status: `unsupported`",
            "- Status: `withheld`",
        ] {
            assert!(text.contains(expected), "missing {expected:?}: {text}");
        }
        assert_eq!(text.matches("### Duplicate name").count(), 2);
        assert!(text.find("root body").unwrap() < text.find("## Custom fields").unwrap());
        assert!(!text.contains("\n### injected"));
        assert!(!text.contains("\n## forged"));
        assert!(!text.contains("<https://user:secret"));
    }

    #[test]
    fn custom_body_codec_does_not_guess_unsupported_or_withheld_content() {
        for status in ["unsupported", "withheld"] {
            let entry = json!({"status":status,"type":"adf","value":{"malformed":"body"}});
            let mut budget = RenderBudget::with_limits(0, 0);
            assert!(
                CustomFieldBody
                    .render(
                        entry.as_object().unwrap(),
                        ReadContentFormat::Markdown,
                        1,
                        &mut budget,
                    )
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn realistic_multi_mib_custom_fields_are_complete_in_every_format() {
        const BODY_LIMIT: u64 = 1024 * 1024;
        const RESULT_LIMIT: u64 = 16 * 1024 * 1024;
        let source = custom_fields_fixture::realistic_issue_view();
        let source_size = serde_json::to_vec(&source).unwrap().len();
        assert!(
            (2 * 1024 * 1024..3 * 1024 * 1024).contains(&source_size),
            "{source_size}"
        );
        assert_eq!(source["customFields"].as_array().unwrap().len(), 256);

        for content in [
            ReadContentFormat::Native,
            ReadContentFormat::Markdown,
            ReadContentFormat::Text,
        ] {
            let mut result = source.clone();
            present_provider_result(
                "issue.view",
                &mut result,
                ResponseOptions::new(content, ResponseFormat::Json),
                BODY_LIMIT,
                RESULT_LIMIT,
            )
            .unwrap();
            assert_eq!(result["description"], source["description"]);
            for (original, actual) in source["customFields"]
                .as_array()
                .unwrap()
                .iter()
                .zip(result["customFields"].as_array().unwrap())
            {
                assert_eq!(actual["value"], original["value"]);
                assert_eq!(actual["id"], original["id"]);
                assert_eq!(actual["name"], original["name"]);
                if original["type"] == "adf" {
                    assert!(
                        serde_json::to_vec(&original["value"]).unwrap().len() < BODY_LIMIT as usize
                    );
                    let expected = render_adf_bounded_with_budget(
                        &original["value"],
                        content,
                        BODY_LIMIT,
                        BODY_LIMIT,
                        &mut RenderBudget::default(),
                    )
                    .unwrap();
                    if let Some(expected) = expected {
                        assert_eq!(
                            actual["renderedBody"],
                            serde_json::to_value(expected).unwrap()
                        );
                    } else {
                        assert!(actual.get("renderedBody").is_none());
                    }
                } else {
                    assert_eq!(actual, original);
                }
            }
            if content == ReadContentFormat::Native {
                assert_eq!(result, source);
            } else {
                assert_eq!(
                    result["renderedBody"]["value"],
                    if content == ReadContentFormat::Markdown {
                        "ROOT\\_DESCRIPTION"
                    } else {
                        "ROOT_DESCRIPTION"
                    }
                );
            }
        }

        let mut result = source;
        present_provider_result(
            "issue.view",
            &mut result,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            BODY_LIMIT,
            RESULT_LIMIT,
        )
        .unwrap();
        let text = result["value"].as_str().unwrap();
        assert_eq!(text.matches("### Field ").count(), 256);
        for field in (32..=256).step_by(32) {
            for block in 0..128 {
                for boundary in ["START", "END"] {
                    assert!(text.contains(&format!("FIELD{field}\\_BLOCK{block}\\_{boundary}")));
                }
            }
        }
        assert!(text.contains("| Topic | Details |"));
        assert!(text.contains("- Confirm service health\\."));
        assert!(text.contains("[ Reference\\.](https://example.test/rollout)"));
    }

    #[test]
    fn custom_adf_fields_cannot_reset_the_shared_complexity_budget() {
        const BODY_LIMIT: u64 = 1024 * 1024;
        const RESULT_LIMIT: u64 = 16 * 1024 * 1024;
        let body = json!({
            "type":"doc","version":1,
            "content":vec![json!({"type":"paragraph","content":[]});22_000]
        });
        assert!(serde_json::to_vec(&body).unwrap().len() < BODY_LIMIT as usize);
        let fields = (1..=6)
            .map(|id| supported_field(id, "adf", body.clone()))
            .collect::<Vec<_>>();
        let source = json!({"key":"PROJ-1","description":adf("root"),"customFields":fields});
        for content in [
            ReadContentFormat::Native,
            ReadContentFormat::Markdown,
            ReadContentFormat::Text,
        ] {
            // Each field fits both the per-document byte and complexity guards.
            render_adf_bounded_with_budget(
                &body,
                content,
                BODY_LIMIT,
                BODY_LIMIT,
                &mut RenderBudget::default(),
            )
            .unwrap();
            let mut result = source.clone();
            let error = present_provider_result(
                "issue.view",
                &mut result,
                ResponseOptions::new(content, ResponseFormat::Json),
                BODY_LIMIT,
                RESULT_LIMIT,
            )
            .unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
            assert_eq!(error.message, RENDER_FAILURE_MESSAGE);
            assert!(error.result.is_none());
        }
        let mut result = source;
        let error = present_provider_result(
            "issue.view",
            &mut result,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            BODY_LIMIT,
            RESULT_LIMIT,
        )
        .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
        assert_eq!(error.message, RENDER_FAILURE_MESSAGE);
        assert!(error.result.is_none());
    }
}
