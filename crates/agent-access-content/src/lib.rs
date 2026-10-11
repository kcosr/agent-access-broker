//! Rich-content formats shared by backends: bounded rendering of Atlassian
//! Document Format, Confluence storage (XHTML), and GitLab Markdown to
//! Markdown or text; bounded conversion of Markdown and plain text into
//! those formats; and attribution footers for each representation.

mod attribution;
mod rendering;
mod writes;

pub use attribution::*;
pub use rendering::*;
pub use writes::*;
