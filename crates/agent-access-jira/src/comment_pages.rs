//! A single, bounded comments page shared by issue inclusion and comment listing.
use super::*;

pub(super) struct ProjectedCommentPage {
    pub result: Value,
    pub audit: Value,
    pub comment_ids: Vec<String>,
}

fn invalid_page() -> ProviderError {
    ProviderError::error(
        ReasonCode::UpstreamProtocolFailed,
        "Jira comment page response was invalid",
    )
}

pub(super) fn project(
    page: &JiraCommentPage,
    inputs: &CommentListInputs,
    config: &JiraProviderConfig,
    budget: &mut RenderBudget,
) -> Result<ProjectedCommentPage, ProviderError> {
    if page.start_at != inputs.start_at
        || page.comments.len() > inputs.max_results as usize
        || page.comments.len() > page.max_results as usize
    {
        return Err(invalid_page());
    }
    let fetched_count = u32::try_from(page.comments.len()).map_err(|_| invalid_page())?;
    let fetched_end = page
        .start_at
        .checked_add(fetched_count)
        .ok_or_else(invalid_page)?;
    if page.total.is_some_and(|total| {
        (!page.comments.is_empty() && fetched_end > total)
            || (page.comments.is_empty() && page.start_at < total)
    }) {
        return Err(invalid_page());
    }

    let page_body_cap = config
        .comments
        .max_page_body_bytes
        .unwrap_or(config.content.max_body_bytes);
    let mut used_body_bytes = 0_u64;
    let mut disclosed_count = 0_usize;
    let mut limited = false;
    let mut seen = BTreeSet::new();
    for comment in &page.comments {
        validate_returned_comment_id(&comment.id, None)?;
        if !seen.insert(&comment.id) {
            return Err(invalid_page());
        }
        if let Some(parent) = &comment.parent_id {
            validate_returned_comment_id(parent, None)?;
        }
        if inputs.include_bodies {
            // Validate every fetched body, including a suffix outside the byte budget:
            // invalid upstream content cannot disappear behind pagination.
            validate_returned_comment_body(comment, config.content.max_body_bytes)?;
            let body_bytes = if let Some(body) = &comment.body {
                render_adf_bounded_with_budget(
                    body,
                    ReadContentFormat::Native,
                    config.content.max_body_bytes,
                    config.content.max_body_bytes,
                    &mut RenderBudget::default(),
                )
                .map_err(|_| invalid_page())?;
                serde_json::to_vec(body).map_err(|_| invalid_page())?.len() as u64
            } else {
                0
            };
            let next = used_body_bytes
                .checked_add(body_bytes)
                .ok_or_else(invalid_page)?;
            if limited || next > page_body_cap {
                limited = true;
                continue;
            }
            used_body_bytes = next;
        }
        disclosed_count += 1;
    }
    if limited && disclosed_count == 0 {
        return Err(invalid_page());
    }

    let disclosed = &page.comments[..disclosed_count];
    let mut comments = Vec::with_capacity(disclosed_count);
    for comment in disclosed {
        if inputs.include_bodies {
            if let Some(body) = &comment.body {
                // This budget may already contain the issue description and custom
                // fields. Native output must honor the same combined complexity cap.
                render_adf_bounded_with_budget(
                    body,
                    ReadContentFormat::Native,
                    config.content.max_body_bytes,
                    config.content.max_body_bytes,
                    budget,
                )
                .map_err(|_| invalid_page())?;
            }
            comments.push(comment_result(comment));
        } else {
            comments.push(comment_summary_result(comment));
        }
    }
    let count = u32::try_from(disclosed_count).map_err(|_| invalid_page())?;
    let end = page.start_at.checked_add(count).ok_or_else(invalid_page)?;
    let is_last = page.total.map(|total| end >= total);
    let next_start_at = if is_last == Some(true) || count == 0 {
        None
    } else {
        Some(end)
    };
    let order_by = inputs.order_by.as_deref().unwrap_or("+created");
    let mut result = json!({
        "comments": comments,
        "startAt": page.start_at,
        "maxResults": page.max_results,
        "count": count,
        "total": page.total,
        "isLast": is_last,
        "nextStartAt": next_start_at,
        "orderBy": order_by,
        "includeBodies": inputs.include_bodies,
    });
    let mut audit = json!({
        "startAt": page.start_at,
        "maxResults": page.max_results,
        "commentCount": count,
        "total": page.total,
        "isLast": is_last,
        "nextStartAt": next_start_at,
        "orderBy": order_by,
        "includeBodies": inputs.include_bodies,
    });
    if limited {
        result["limitedBy"] = json!("body_bytes");
        audit["limitedBy"] = json!("body_bytes");
    }
    Ok(ProjectedCommentPage {
        result,
        audit,
        comment_ids: disclosed.iter().map(|comment| comment.id.clone()).collect(),
    })
}
