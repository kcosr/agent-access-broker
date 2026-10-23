//! Generated large issue shared by presentation and real-CLI smoke tests.
use serde_json::{Value, json};

pub fn realistic_issue_view() -> Value {
    let custom_fields = (1..=256)
        .map(|index| {
            let (kind, value) = if index % 32 == 0 {
                ("adf", rich_document(index))
            } else {
                match index % 5 {
                    0 => ("number", json!(index)),
                    1 => ("text", json!(format!("FIELD{index}_VALUE"))),
                    2 => ("option", json!({"id":index.to_string(),"value":format!("FIELD{index}_VALUE")})),
                    3 => ("users", json!([{"accountId":format!("account-{index}"),"displayName":format!("FIELD{index}_VALUE")}])),
                    _ => ("date", json!("2026-10-23")),
                }
            };
            json!({
                "id": format!("customfield_{index}"),
                "name": format!("Field {index}"),
                "type": kind,
                "status": "supported",
                "value": value,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "id":"10001",
        "key":"PROJ-1",
        "project":"PROJ",
        "webUrl":"https://example.atlassian.net/browse/PROJ-1",
        "summary":"Large custom field issue",
        "status":"Open",
        "issueType":"Task",
        "description":{
            "type":"doc","version":1,
            "content":[paragraph("ROOT_DESCRIPTION".into())]
        },
        "created":null,"updated":null,"creator":null,"reporter":null,
        "assignee":null,"priority":null,"labels":[],
        "resolution":null,"resolutionDate":null,"dueDate":null,
        "components":null,"fixVersions":null,"affectedVersions":null,"statusCategory":null,
        "customFields":custom_fields,
    })
}

fn paragraph(text: String) -> Value {
    json!({"type":"paragraph","content":[{"type":"text","text":text}]})
}

fn rich_document(field: usize) -> Value {
    let prose = "The project team reviewed the rollout, deployment timing, service health, and recovery steps. ".repeat(24);
    let content = (0..128)
        .map(|block| {
            let text = format!("FIELD{field}_BLOCK{block}_START {prose} FIELD{field}_BLOCK{block}_END");
            if block % 16 == 0 {
                json!({"type":"table","content":[
                    {"type":"tableRow","content":[
                        {"type":"tableHeader","content":[paragraph("Topic".into())]},
                        {"type":"tableHeader","content":[paragraph("Details".into())]}
                    ]},
                    {"type":"tableRow","content":[
                        {"type":"tableCell","content":[paragraph("Rollout".into())]},
                        {"type":"tableCell","content":[paragraph(text)]}
                    ]}
                ]})
            } else if block % 8 == 0 {
                json!({"type":"bulletList","content":[
                    {"type":"listItem","content":[paragraph(text)]},
                    {"type":"listItem","content":[paragraph("Confirm service health.".into())]}
                ]})
            } else if block % 4 == 0 {
                json!({"type":"paragraph","content":[
                    {"type":"text","text":text,"marks":[{"type":"strong"},{"type":"em"}]},
                    {"type":"text","text":" Reference.","marks":[{"type":"link","attrs":{"href":"https://example.test/rollout"}}]}
                ]})
            } else {
                paragraph(text)
            }
        })
        .collect::<Vec<_>>();
    json!({"type":"doc","version":1,"content":content})
}
