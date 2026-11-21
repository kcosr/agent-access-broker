//! Rich-content formats shared by backends: bounded native-source validation
//! and concrete selection of Atlassian Document Format, Confluence storage
//! (XHTML), Markdown or text; bounded write conversion and attribution footers.

mod attribution;
mod rendering;
mod writes;

pub use attribution::*;
pub use rendering::*;
pub use writes::*;
